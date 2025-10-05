#!/usr/bin/env python3
"""
AlertGenerator

Generates and persists crisis alerts based on analysis scores from CrisisAnalyzer.
"""
from __future__ import annotations
from typing import Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone

from linkshield.models.social_protection import CrisisAlertORM
from .crisis_analyzer import CrisisScore


class AlertGenerator:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    async def generate_alert(self, score: CrisisScore, session: AsyncSession) -> CrisisAlertORM:
        if score.severity == "ok":
            return None
        now = datetime.now(timezone.utc)
        alert = CrisisAlertORM(
            brand=score.brand,
            platform=None,
            score=score.score,
            severity=score.severity,
            reason=", ".join(score.reasons[:3]) if score.reasons else None,
            window_from=score.timestamp,
            window_to=now,
            payload={
                "summary": score.summary,
            },
        )
        session.add(alert)
        await session.flush()
        return alert
