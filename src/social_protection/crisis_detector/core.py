#!/usr/bin/env python3
"""
Crisis Detector core implementation

Evaluates brands using signals from ReputationTracker, Mention metadata, and
optional AI enrichment. Persists CrisisAlertORM and CrisisStateORM entries and
returns a CrisisReport dataclass.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..reputation_monitor.reputation_tracker import ReputationTracker
from src.services.depends import get_ai_service
from src.models.social_protection import CrisisAlertORM, CrisisStateORM


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
    def __init__(self, reputation_tracker: ReputationTracker, ai_service=None, config: Optional[Dict] = None):
        self.rt = reputation_tracker
        self.ai = ai_service or get_ai_service()
        self.config = config or {}
        self.cfg = {
            "min_mentions": 5,
            "weights": {"volume": 0.30, "sentiment": 0.25, "keywords": 0.20, "emotion": 0.10, "amplification": 0.10, "cross_platform": 0.05},
            "crisis_keywords": ["scandal", "breach", "lawsuit", "fraud", "hack", "recall", "explosion", "death", "arrest", "investigation"],
            "hysteresis_windows_required": 2,
            "cooldown_seconds": 900,
            **(self.config or {}),
        }

    async def evaluate_brand(self, brand: str, session: AsyncSession, window_seconds: int = 3600) -> CrisisReport:
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()
        from_ts = now_ts - window_seconds

        metrics = await self.rt.get_brand_metrics(brand, window_seconds=window_seconds)
        mention_count = metrics.mention_count if metrics else 0
        if mention_count < self.cfg["min_mentions"]:
            return CrisisReport(brand, 0.0, "ok", [], None, datetime.fromtimestamp(from_ts, tz=timezone.utc), now, {})

        # fetch raw mentions from persistence
        mentions = await self.rt.persistence.range(brand, from_ts, now_ts)
        texts = [m.get("text_snippet", "") for m in mentions]
        metas = [m.get("metadata", {}) for m in mentions]

        # 1. volume signal -> use trend_score scaled
        vol_score = 0.0
        try:
            vol_score = max(0.0, min(1.0, (metrics.trend_score or 0.0) / 5.0))
        except Exception:
            vol_score = 0.0

        # 2. sentiment deterioration: map avg_sentiment to [0,1] where lower sentiment -> higher signal
        sentiment_score = 0.0
        if metrics and metrics.avg_sentiment is not None:
            sentiment_score = max(0.0, min(1.0, (0.5 - metrics.avg_sentiment) * 2.0))

        # 3. crisis keywords ratio
        keywords = self.cfg["crisis_keywords"]
        kw_count = sum(1 for t in texts if any(k in (t or "").lower() for k in keywords))
        kw_ratio = kw_count / max(1, len(texts))

        # 4. emotion ratio
        emotion_count = sum(1 for m in metas if m.get("sentiment_emotion") in ("anger", "fear", "disgust"))
        emotion_ratio = emotion_count / max(1, len(texts))

        # 5. amplification: verified/authoritative mentions
        verified_count = sum(1 for m in metas if m.get("author_verified") or m.get("metadata", {}).get("author_verified"))
        amp_ratio = verified_count / max(1, len(texts))

        # compute weighted score
        w = self.cfg["weights"]
        score = (
            w["volume"] * vol_score
            + w["sentiment"] * sentiment_score
            + w["keywords"] * kw_ratio
            + w["emotion"] * emotion_ratio
            + w["amplification"] * amp_ratio
        )

        # cross-platform boost
        trending = await self.rt.get_trending_brands(limit=50, window_seconds=window_seconds)
        if any(t["brand"] == brand for t in trending):
            score = min(1.0, score + self.cfg.get("cross_platform_boost", 0.05))

        # map to severity
        severity = "ok"
        if score >= 0.85:
            severity = "critical"
        elif score >= 0.65:
            severity = "high"
        elif score >= 0.4:
            severity = "warning"

        reasons: List[str] = []
        if vol_score > 0.3:
            reasons.append("volume_spike")
        if sentiment_score > 0.25:
            reasons.append("negative_sentiment")
        if kw_ratio > 0.05:
            reasons.append("crisis_keywords")
        if emotion_ratio > 0.05:
            reasons.append("high_negative_emotion")
        if amp_ratio > 0.1:
            reasons.append("amplified_by_verified")

        # optional AI summary & classification
        summary = None
        try:
            if self.ai and texts:
                sample = "\n".join(texts[:10])
                ai_resp = await self.ai.classify(f"Summarize and label severity for these mentions: {sample}")
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

        # persist alert and update state with hysteresis
        # fetch existing state
        stmt = select(CrisisStateORM).where(CrisisStateORM.brand == brand)
        res = await session.execute(stmt)
        state = res.scalars().one_or_none()

        now_dt = datetime.now(timezone.utc)
        if not state:
            state = CrisisStateORM(brand=brand, consecutive_windows=0, last_score=0.0, last_severity=None, last_evaluated_at=now_dt)
            session.add(state)
            await session.flush()

        # determine if this window counts toward consecutive windows
        threshold_for_alert = 0.4
        is_alerting = score >= threshold_for_alert
        if is_alerting:
            state.consecutive_windows = (state.consecutive_windows or 0) + 1
        else:
            state.consecutive_windows = 0

        state.last_score = float(score)
        state.last_severity = severity
        state.last_evaluated_at = now_dt
        await session.flush()

        # if consecutive_windows reached required and severity >= warning, create alert
        if state.consecutive_windows >= self.cfg.get("hysteresis_windows_required", 2) and severity != "ok":
            alert = CrisisAlertORM(
                brand=brand,
                platform=None,
                score=float(score),
                severity=severity,
                reason=", ".join(reasons[:3]) if reasons else None,
                window_from=datetime.fromtimestamp(from_ts, tz=timezone.utc),
                window_to=now,
                payload=payload,
            )
            session.add(alert)
            await session.flush()

        report = CrisisReport(
            brand=brand,
            score=float(score),
            severity=severity,
            reasons=reasons,
            summary=summary,
            window_from=datetime.fromtimestamp(from_ts, tz=timezone.utc),
            window_to=now,
            payload=payload,
        )
        return report

    async def evaluate_all_brands(self, session: AsyncSession, window_seconds: int = 3600, limit: int = 200) -> List[CrisisReport]:
        # derive brands to evaluate from reputation tracker (available brands)
        try:
            # InMemoryPersistence exposes keys; RedisPersistence uses keys pattern; use rt.get_trending_brands to sample brands
            trending = await self.rt.get_trending_brands(limit=limit, window_seconds=window_seconds)
            brands = [t["brand"] for t in trending]
        except Exception:
            brands = []

        reports: List[CrisisReport] = []
        for brand in brands:
            try:
                r = await self.evaluate_brand(brand, session, window_seconds=window_seconds)
                reports.append(r)
            except Exception:
                # continue evaluating other brands even if one fails
                continue
        return reports
