#!/usr/bin/env python3
"""
Crisis Detector core implementation

Evaluates brands using signals from ReputationTracker, Mention metadata, and
optional AI enrichment. Persists CrisisAlertORM and CrisisStateORM entries and
returns a CrisisReport dataclass.
"""
from __future__ import annotations

import logging
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

logger = logging.getLogger(__name__)


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
            if self.ai and texts and len(texts) > 0:
                sample = "\n".join(texts[:10])
                prompt = f"Analyze these social media mentions for crisis indicators and provide a brief summary (max 200 words):\n\n{sample}"
                # Use the AI service's analyze_content method
                ai_result = await self.ai.analyze_content(sample, url="")
                if isinstance(ai_result, dict):
                    # Extract summary from AI analysis
                    summary = ai_result.get("summary", f"Crisis detected with {len(texts)} mentions")
                    if not summary and "analysis" in ai_result:
                        summary = ai_result["analysis"][:200]
        except Exception as e:
            logger.warning(f"AI summary generation failed: {str(e)}")
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
            state = CrisisStateORM(
                brand=brand,
                consecutive_high_windows=0,
                last_severity=None,
                last_alert_at=None
            )
            session.add(state)
            await session.flush()

        # determine if this window counts toward consecutive windows
        threshold_for_alert = 0.4
        is_alerting = score >= threshold_for_alert
        
        # Implement cooldown logic - don't increment if we're in cooldown period
        cooldown_seconds = self.cfg.get("cooldown_seconds", 900)
        in_cooldown = False
        if state.last_alert_at:
            time_since_last_alert = (now_dt - state.last_alert_at).total_seconds()
            in_cooldown = time_since_last_alert < cooldown_seconds
        
        if is_alerting and not in_cooldown:
            state.consecutive_high_windows = (state.consecutive_high_windows or 0) + 1
        elif not is_alerting:
            # Reset counter when score drops below threshold
            state.consecutive_high_windows = 0

        state.last_severity = severity
        await session.flush()

        # if consecutive_windows reached required and severity >= warning, create alert
        hysteresis_required = self.cfg.get("hysteresis_windows_required", 2)
        should_create_alert = (
            state.consecutive_high_windows >= hysteresis_required 
            and severity != "ok" 
            and not in_cooldown
        )
        
        if should_create_alert:
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
            # Update last_alert_at to start cooldown period
            state.last_alert_at = now_dt
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
        """
        Evaluate all brands for crisis indicators.
        
        Args:
            session: Database session
            window_seconds: Time window for analysis
            limit: Maximum number of brands to evaluate
            
        Returns:
            List of crisis reports for all evaluated brands
        """
        # derive brands to evaluate from reputation tracker (available brands)
        try:
            # InMemoryPersistence exposes keys; RedisPersistence uses keys pattern; use rt.get_trending_brands to sample brands
            trending = await self.rt.get_trending_brands(limit=limit, window_seconds=window_seconds)
            brands = [t["brand"] for t in trending]
        except Exception as e:
            logger.warning(f"Failed to get trending brands: {str(e)}")
            brands = []

        reports: List[CrisisReport] = []
        for brand in brands:
            try:
                r = await self.evaluate_brand(brand, session, window_seconds=window_seconds)
                reports.append(r)
            except Exception as e:
                # continue evaluating other brands even if one fails
                logger.error(f"Failed to evaluate brand {brand}: {str(e)}")
                continue
        return reports

    async def get_crisis_alerts(
        self,
        session: AsyncSession,
        brand: Optional[str] = None,
        severity: Optional[str] = None,
        resolved: bool = False,
        limit: int = 100
    ) -> List[CrisisAlertORM]:
        """
        Retrieve crisis alerts from the database.
        
        Args:
            session: Database session
            brand: Optional brand filter
            severity: Optional severity filter (ok, warning, high, critical)
            resolved: Whether to include only resolved alerts
            limit: Maximum number of alerts to return
            
        Returns:
            List of crisis alerts matching the filters
        """
        stmt = select(CrisisAlertORM)
        
        if brand:
            stmt = stmt.where(CrisisAlertORM.brand == brand)
        
        if severity:
            stmt = stmt.where(CrisisAlertORM.severity == severity)
        
        stmt = stmt.where(CrisisAlertORM.resolved == resolved)
        
        # Order by creation time, most recent first
        stmt = stmt.order_by(CrisisAlertORM.created_at.desc())
        stmt = stmt.limit(limit)
        
        result = await session.execute(stmt)
        alerts = result.scalars().all()
        
        return list(alerts)

    async def get_crisis_history(
        self,
        session: AsyncSession,
        brand: str,
        days: int = 30
    ) -> List[CrisisAlertORM]:
        """
        Get historical crisis data for a brand.
        
        Args:
            session: Database session
            brand: Brand name
            days: Number of days of history to retrieve
            
        Returns:
            List of crisis alerts for the brand
        """
        from datetime import timedelta
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        stmt = select(CrisisAlertORM).where(
            CrisisAlertORM.brand == brand,
            CrisisAlertORM.created_at >= cutoff_date
        ).order_by(CrisisAlertORM.created_at.desc())
        
        result = await session.execute(stmt)
        alerts = result.scalars().all()
        
        return list(alerts)

    async def update_alert_status(
        self,
        session: AsyncSession,
        alert_id: str,
        resolved: bool = True
    ) -> Optional[CrisisAlertORM]:
        """
        Update the resolution status of a crisis alert.
        
        Args:
            session: Database session
            alert_id: Alert ID (UUID as string)
            resolved: Whether the alert is resolved
            
        Returns:
            Updated alert or None if not found
        """
        from uuid import UUID
        
        try:
            alert_uuid = UUID(alert_id)
        except ValueError:
            logger.error(f"Invalid alert ID format: {alert_id}")
            return None
        
        stmt = select(CrisisAlertORM).where(CrisisAlertORM.id == alert_uuid)
        result = await session.execute(stmt)
        alert = result.scalars().one_or_none()
        
        if alert:
            alert.resolved = resolved
            if resolved:
                alert.resolved_at = datetime.now(timezone.utc)
            else:
                alert.resolved_at = None
            await session.flush()
        
        return alert
