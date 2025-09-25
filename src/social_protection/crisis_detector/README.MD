Nice — let’s nerd-out and design a robust, production-ready **Crisis Detector** for LinkShield. I’ll walk through the problem space, propose concrete detection signals, scoring, state-management (to avoid flapping), persistence, integration points with the existing pipeline (BrandMonitor / ReputationTracker / MentionDetector / AIService), and give a solid, copy-pasteable prototype implementation plan + code sketch you can drop into the repo and iterate on.

I’ll assume the caller supplies an async DB session (like your other components), and that we’ll use `ReputationTracker` as the canonical source of recent mentions & sentiment. We’ll also persist crisis alerts in the DB so we don’t recompute history each time.

---

# 1) What the Crisis Detector needs to do (high level)

* Watch brand mentions (volume + velocity), sentiment, and contextual signals.
* Combine rule-based signals with optional AI-based enrichment (AIService).
* Produce a single **crisis score** per brand (0..1) and map it to severity levels.
* Debounce / require persistence over short windows (hysteresis) to avoid noise.
* Persist alerts and state for auditing and to avoid duplicate notifications.
* Expose an async API usable from:

  * BrandMonitor after mention ingestion (event-driven)
  * Periodic scheduler (every 1–5 minutes) to run full checks
  * Manual queries (investigation UI)

---

# 2) Signals & features to examine (what feeds the score)

Use these signals (available from ReputationTracker / mentions / sentiment / BrandMonitor):

1. **Volume spike (velocity)**

   * Current mention count vs baseline (z-score or relative multiplier).
   * Use sliding windows: last `W` (e.g., 1h) vs historical baseline (same window across last N windows/days).

2. **Sentiment deterioration**

   * Drop in average sentiment compared to baseline.
   * High fraction of negative mentions (negative_ratio).

3. **Negative emotion + threat**

   * Count of mentions with `emotion` in `['anger','fear','disgust']` or high `threat_level` reported by SentimentAnalyzer.

4. **Crisis keywords**

   * Presence of known crisis keywords in mentions (fraud, lawsuit, breach, scandal, recall, explosion, death, arrest, investigation, lawsuit, hack, exploit). Weigh multi-occurrence and phrases like “class action”.

5. **Authoritative amplification**

   * Mentions coming from verified/authoritative accounts or accounts with high follower counts—amplifiers increase severity.

6. **Topic clustering / novelty** (optional advanced)

   * If many mentions concentrate on a new phrase/URL, it suggests an emergent issue.

7. **Rate of change**

   * Slope (mentions per minute) increasing quickly.

8. **Cross-platform presence**

   * Simultaneous spikes across *multiple platforms* increases severity.

9. **Trust metric of sources**

   * Weight mentions by estimated author credibility.

---

# 3) Scoring model (practical, interpretable, tunable)

A weighted linear/normalized score is simple and effective for early stage:

```
crisis_score = w_v * normalized_volume +
               w_s * normalized_sentiment_drop +
               w_k * normalized_crisis_keywords +
               w_e * normalized_emotion_score +
               w_a * amplification_score +
               w_c * cross_platform_score
```

* Normalize each signal into [0,1] (cap extremes).
* Default weights (example):
  `w_v=0.30, w_s=0.25, w_k=0.20, w_e=0.10, w_a=0.10, w_c=0.05`
* Map score -> severity:

  * `score < 0.4` → OK / monitor
  * `0.4 <= score < 0.65` → Warning / watch
  * `0.65 <= score < 0.85` → High / investigate
  * `score >= 0.85` → Critical / crisis

Make thresholds configurable via config file or env.

---

# 4) Hysteresis & debouncing (no flapping)

* Require `N` consecutive evaluation windows above threshold to raise alert (e.g., 2–3 windows).
* After alert, require cooldown (e.g., 15–30 minutes) before repeating same-level alert unless severity increases.
* Track the brand's last alert state and consecutive-high-count in DB.

This prevents one-off viral posts from creating repeated alerts.

---

# 5) Persistence & models (what to store)

Create new ORM (add to `src/models/social_protection.py`):

```py
class CrisisAlertORM(Base):
    __tablename__ = "sp_crisis_alerts"
    id = Column(Integer, primary_key=True, index=True)
    brand = Column(String(256), index=True)             # brand name or matched_term
    platform = Column(String(64), nullable=True)        # if platform-specific, else null
    score = Column(Float, nullable=False)
    severity = Column(String(16), nullable=False)       # ok, warning, high, critical
    reason = Column(String(128), nullable=True)         # dominant signal like 'volume_spike'
    window_from = Column(DateTime, nullable=False)
    window_to = Column(DateTime, nullable=False)
    payload = Column(JSON, default=dict)                # snapshot of signals, top mentions, etc.
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
```

Also a `CrisisStateORM` (optional) to store short-lived counters and the number of consecutive windows above threshold.

---

# 6) Integration points

* **Event-driven**: BrandMonitor (after it persists mentions via ReputationTracker) calls `CrisisDetector.evaluate_brand(brand, session)` for the brand(s) touched by that content. This is low-latency and responds to new signals quickly.
* **Periodic sweep**: A scheduler runs `evaluate_all_brands()` every `T` minutes to catch slow-moving or cross-platform crises.
* **Responders**: When a crisis crosses thresholds, call out to:

  * Notification service (email/Slack)
  * Pager or web UI
  * Auto-prepare a summary (top mentions, suggested response — AIService can help craft an initial draft)
* **Telemetry**: Expose metrics (Prometheus): `crisis_score`, `alerts_created_total`, `alert_severity_gauge`.

---

# 7) Using ReputationTracker (concrete) — data sources

Use `reputation_tracker.get_brand_metrics(brand, window_seconds)` for quick windowed aggregates (mention_count, avg_sentiment, sentiment_count, trend_score).

For richer signals (e.g., counts of crisis keywords, verified-author mentions, top URLs), use the tracker’s persistence:

```py
now = now_ts
window_from = now_ts - window_seconds
mentions = await reputation_tracker.persistence.range(brand, window_from, now_ts)
# mentions are list of payloads we stored earlier (payload contains text_snippet, metadata etc)
```

From those payloads you can compute:

* `keyword_count = sum(1 for m in mentions if any(k in m['text_snippet'].lower() for k in crisis_keywords))`
* `verified_mentions = sum(1 for m in mentions if m['metadata'].get('author_verified'))` (depends on your adapter adding author info)
* `emotion_counts = Counter(m['metadata'].get('sentiment_emotion'))`

---

# 8) AIService usage (where AI helps)

* **Summarization**: pass aggregated top mentions (or top 10 snippets) to AIService to produce human-readable summary.
* **Severity classification**: ask AI to classify the textual context as `not_issue|issue|severe_issue` to augment numeric score.
* **Suggested response**: generate a suggested statement or response template.

Use AIService outputs as extra signals with conservative weight (avoid overreliance).

---

# 9) Example algorithm flow (evaluate_brand)

1. Accept brand, platform (optional), `window_seconds` (default 3600), and `session` (AsyncSession).
2. `metrics = await reputation_tracker.get_brand_metrics(brand, window_seconds)`
3. If `metrics.mention_count < minimum_mentions` (e.g., 5) → return low score (avoid noise).
4. `mentions = await reputation_tracker.persistence.range(brand, window_from, now_ts)`
5. Compute signals:

   * normalized_volume = zscore or min(1, (current_count - mean)/max(std, eps) / 3) -> clamp
   * sentiment_drop = clamp((baseline_sentiment - current_sentiment)/1.0, 0, 1)
   * keyword_ratio = min(1, keyword_count / current_count)
   * emotion_score = weight of anger/fear
   * verified_amplification = min(1, verified_mentions / current_count)
   * cross_platform = query trending brands across reputation_tracker.get_trending_brands() (or evaluate multiple platforms)
6. Compute `crisis_score` via weights.
7. Map to severity and apply hysteresis (update consecutive-windows counter in DB).
8. If new alert condition met:

   * create `CrisisAlertORM` with payload (top mentions, signals, AI summary)
   * optionally call notifier / return result
9. Return a `CrisisReport` object (Pydantic) with score, severity, dominant_reasons, suggested_action, summary.

---

# 10) Prototype implementation sketch (async, copyable)

Below is a compact, practical prototype you can drop in as `src/social_protection/crisis_detector/core.py`. It uses `ReputationTracker` and expects an async session from the caller. This is purposely conservative and dependency-light.

```python
# src/social_protection/crisis_detector/core.py
from __future__ import annotations
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from collections import Counter

from sqlalchemy.ext.asyncio import AsyncSession

from ..reputation_monitor.reputation_tracker import ReputationTracker
from src.services.depends import get_ai_service

# We'll assume you add CrisisAlertORM in models.social_protection

@dataclass
class CrisisReport:
    brand: str
    score: float
    severity: str
    reasons: List[str]
    summary: Optional[str]
    window_from: datetime
    window_to: datetime
    payload: Dict[str, Any]

class CrisisDetector:
    def __init__(self, reputation_tracker: ReputationTracker, ai_service=None, config: Optional[Dict]=None):
        self.rt = reputation_tracker
        self.ai = ai_service or get_ai_service()
        self.config = config or {}
        # default config
        self.cfg = {
            "min_mentions": 5,
            "weights": {"volume":0.30,"sentiment":0.25,"keywords":0.2,"emotion":0.1,"amplification":0.1,"cross_platform":0.05},
            "crisis_keywords": ["scandal","breach","lawsuit","fraud","hack","recall","explosion","death","arrest","investigation"],
            "hysteresis_windows_required": 2,
            "cooldown_seconds": 900,
            **(self.config or {})
        }

    async def evaluate_brand(self, brand: str, session: AsyncSession, window_seconds: int = 3600) -> CrisisReport:
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()
        from_ts = now_ts - window_seconds

        metrics = await self.rt.get_brand_metrics(brand, window_seconds=window_seconds)
        mention_count = metrics.mention_count if metrics else 0
        if mention_count < self.cfg["min_mentions"]:
            return CrisisReport(brand, 0.0, "ok", [], None, datetime.fromtimestamp(from_ts, tz=timezone.utc), now, {})

        # fetch raw mentions
        mentions = await self.rt.persistence.range(brand, from_ts, now_ts)
        texts = [m.get("text_snippet","") for m in mentions]
        meta = [m.get("metadata",{}) for m in mentions]

        # signals
        # 1. volume normalized: use trend_score (already normalized a bit), or compute zscore from past days:
        vol_score = 0.0
        try:
            # use trend_score if present (preferred)
            vol_score = max(0.0, min(1.0, (metrics.trend_score or 0.0) / 5.0 ))  # scale-down
        except Exception:
            vol_score = 0.0

        # 2. sentiment drop: compare to historical baseline (simple fallback)
        sentiment_score = 0.0
        if metrics and metrics.avg_sentiment is not None:
            # smaller avg_sentiment -> more negative -> larger signal
            sentiment_score = max(0.0, min(1.0, (0.5 - metrics.avg_sentiment) * 2.0))  # map [-1..1] -> [0..1]
        # 3. keywords ratio
        keywords = self.cfg["crisis_keywords"]
        kw_count = sum(1 for t in texts if any(k in (t or "").lower() for k in keywords))
        kw_ratio = kw_count / max(1, len(texts))
        # 4. emotion: count anger/fear
        emotion_count = sum(1 for m in meta if m.get("sentiment_emotion") in ("anger","fear","disgust"))
        emotion_ratio = emotion_count / max(1, len(texts))
        # 5. amplification: verified authors
        verified_count = sum(1 for m in meta if m.get("author_verified"))
        amp_ratio = verified_count / max(1, len(texts))

        # compute weighted score
        w = self.cfg["weights"]
        score = (w["volume"]*vol_score +
                 w["sentiment"]*sentiment_score +
                 w["keywords"]*kw_ratio +
                 w["emotion"]*emotion_ratio +
                 w["amplification"]*amp_ratio)

        # cross-platform (quick heuristic: is brand trending elsewhere?)
        # you can implement more exact cross-platform checks using get_trending_brands
        # small boost if trending
        trending = await self.rt.get_trending_brands(limit=20, window_seconds=window_seconds)
        if any(t["brand"]==brand for t in trending):
            score = min(1.0, score + 0.05)

        # severity mapping
        severity = "ok"
        if score >= 0.85:
            severity = "critical"
        elif score >= 0.65:
            severity = "high"
        elif score >= 0.4:
            severity = "warning"

        # assemble reasons
        reasons = []
        if vol_score > 0.3: reasons.append("volume_spike")
        if sentiment_score > 0.25: reasons.append("negative_sentiment")
        if kw_ratio > 0.05: reasons.append("crisis_keywords")
        if emotion_ratio > 0.05: reasons.append("high_negative_emotion")
        if amp_ratio > 0.1: reasons.append("amplified_by_verified")

        # AI summary (optional, low-weight)
        summary = None
        try:
            if self.ai and len(texts):
                sample = "\\n".join(texts[:10])
                ai_resp = await self.ai.classify(f\"Summarize and label severity for these mentions: {sample}\")
                if isinstance(ai_resp, dict):
                    summary = ai_resp.get("summary") or ai_resp.get("label")
        except Exception:
            summary = None

        payload = {
            "mention_count": mention_count,
            "vol_score": vol_score,
            "sentiment_score": sentiment_score,
            "kw_ratio": kw_ratio,
            "emotion_ratio": emotion_ratio,
            "amp_ratio": amp_ratio,
            "top_samples": texts[:6],
        }

        # Persist alert if severity >= warning (persist record, handle hysteresis & cooldown)
        # Upsert logic for CrisisAlertORM is expected — we write a new alert entry when severity >= warning
        # and let a separate state table track consecutive windows
        # (or embed consecutive counter in CrisisStateORM)
        from src.models.social_protection import CrisisAlertORM  # ensure added to models file
        if severity != "ok":
            alert = CrisisAlertORM(
                brand=brand,
                platform=None,
                score=float(score),
                severity=severity,
                reason=", ".join(reasons[:3]),
                window_from=datetime.fromtimestamp(from_ts, tz=timezone.utc),
                window_to=now,
                payload=payload
            )
            session.add(alert)
            await session.flush()

        report = CrisisReport(
            brand=brand, score=float(score), severity=severity,
            reasons=reasons, summary=summary,
            window_from=datetime.fromtimestamp(from_ts, tz=timezone.utc),
            window_to=now, payload=payload
        )
        return report
```

Notes:

* That prototype expects `CrisisAlertORM` to exist. Add the ORM described above to `models/social_protection.py`.
* The code uses simple normalization — you should tune weights, scaling constants, windows, and minimum mention thresholds with sample/real data.

---

# 11) Practical considerations & tuning

* **Minimum mention count**: avoids noise — default 5 mentions.
* **Baseline computation**: ideally compute rolling mean & std from 7–30 day history to calculate z-scores; the prototype uses `trend_score` for simplicity.
* **Author metadata**: adapters should populate `mention.metadata` with author info (`author_verified`, `author_followers_count`) to compute amplification.
* **False positives**: tune weights and require consecutive windows before critical alerts.
* **Observability**: log both raw signals and final aggregated values. Expose Prometheus metrics.
* **Security/Cost**: AIService calls should be limited (e.g., only called when score exceeds a small pre-threshold).

---

# 12) Testing & validation

* **Synthetic tests**: generate mention streams with controlled sentiment/keywords to validate scoring.
* **Backtest on historical data**: run detector on past months of mentions and check whether it would have triggered on real incidents.
* **A/B thresholds**: keep a config file with thresholds per brand (some brands tolerate noise better).

---

# 13) Next concrete steps (I can implement these now)

1. Add `CrisisAlertORM` (and optional `CrisisStateORM`) to `src/models/social_protection.py`.
2. Implement `src/social_protection/crisis_detector/core.py` (the class above) with config hooks and unit tests.
3. Wire `BrandMonitor` to call `CrisisDetector.evaluate_brand(...)` after `reputation_tracker.add_mentions(...)` — event-driven immediate check. Also add a periodic job to run `evaluate_all_brands()` every `T` minutes.
4. Add Prometheus metrics and an async notifier (Slack/Email) that can be invoked from the detector when severity changes.
5. Add tests and a simulation harness to tune weights and thresholds.

If you want, I’ll implement step 1 and 2 now (create ORM and core implementation in the canvas), wire it into `BrandMonitor` as a non-blocking background task, and add a small unit-test harness to simulate a crisis. Which of those should I create first? I’ll start immediately with the ORM + core implementation unless you prefer a different order.
