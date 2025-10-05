#!/usr/bin/env python3
"""
CrisisAnalyzer

Analyzes social media mentions, follower metrics, and sentiment data to produce a crisis score.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Dict, Optional

from dataclasses import dataclass
from sqlalchemy.ext.asyncio import AsyncSession

from ..reputation_monitor.reputation_tracker import ReputationTracker
from linkshield.services.depends import get_ai_service
from linkshield.models.social_protection import CrisisAlertORM, CrisisStateORM

@dataclass
class CrisisScore:
    brand: str
    score: float
    severity: str
    reasons: List[str]
    summary: Optional[str]
    timestamp: datetime


class CrisisAnalyzer:
    def __init__(self, reputation_tracker: ReputationTracker, ai_service=None, config: Optional[Dict] = None):
        self.rt = reputation_tracker
        self.ai = ai_service or get_ai_service()
        self.config = config or {}
        self.cfg = {
            "min_mentions": 5,
            "weights": {"volume": 0.30, "sentiment": 0.25, "keywords": 0.20, "emotion": 0.10, "amplification": 0.10, "cross_platform": 0.05},
            "crisis_keywords": ["scandal", "breach", "lawsuit", "fraud", "hack", "recall", "explosion", "death", "arrest", "investigation"],
            **(self.config or {}),
        }

    async def analyze(self, brand: str, session: AsyncSession, window_seconds: int = 3600) -> CrisisScore:
        now = datetime.now(timezone.utc)
        from_ts = (now.timestamp() - window_seconds)

        metrics = await self.rt.get_brand_metrics(brand, window_seconds=window_seconds)
        if not metrics or metrics.mention_count < self.cfg["min_mentions"]:
            return CrisisScore(brand, 0.0, "ok", [], None, now)

        mentions = await self.rt.persistence.range(brand, from_ts, now.timestamp())
        texts = [m.get("text_snippet", "") for m in mentions]
        metas = [m.get("metadata", {}) for m in mentions]

        vol_score = max(0.0, min(1.0, (metrics.trend_score or 0.0) / 5.0))
        sentiment_score = max(0.0, min(1.0, (0.5 - metrics.avg_sentiment) * 2.0 if metrics.avg_sentiment is not None else 0.0))
        kw_count = sum(1 for t in texts if any(k in (t or "").lower() for k in self.cfg["crisis_keywords"]))
        kw_ratio = kw_count / max(1, len(texts))
        emotion_count = sum(1 for m in metas if m.get("sentiment_emotion") in ("anger", "fear", "disgust"))
        emotion_ratio = emotion_count / max(1, len(texts))
        verified_count = sum(1 for m in metas if m.get("author_verified") or m.get("metadata", {}).get("author_verified"))
        amp_ratio = verified_count / max(1, len(texts))

        w = self.cfg["weights"]
        score = vol_score * w["volume"] + sentiment_score * w["sentiment"] + kw_ratio * w["keywords"] + emotion_ratio * w["emotion"] + amp_ratio * w["amplification"]

        severity = "ok"
        if score >= 0.85: severity = "critical"
        elif score >= 0.65: severity = "high"
        elif score >= 0.4: severity = "warning"

        reasons = []
        if vol_score > 0.3: reasons.append("volume_spike")
        if sentiment_score > 0.25: reasons.append("negative_sentiment")
        if kw_ratio > 0.05: reasons.append("crisis_keywords")
        if emotion_ratio > 0.05: reasons.append("high_negative_emotion")
        if amp_ratio > 0.1: reasons.append("amplified_by_verified")

        summary = None
        try:
            if self.ai and texts:
                sample = "\n".join(texts[:10])
                ai_resp = await self.ai.classify(f"Summarize and label severity for these mentions: {sample}")
                if isinstance(ai_resp, dict):
                    summary = ai_resp.get("summary") or ai_resp.get("label")
        except Exception:
            summary = None

        return CrisisScore(brand, score, severity, reasons, summary, now)
