#!/usr/bin/env python3
"""
EscalationMonitor

Monitors consecutive alert windows and triggers escalation if thresholds are exceeded.
"""
from __future__ import annotations
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
from typing import Optional

from linkshield.models.social_protection import CrisisStateORM

class EscalationMonitor:
    def __init__(self, hysteresis_windows: int = 2):
        self.hysteresis_windows = hysteresis_windows

    async def evaluate_state(self, brand: str, session: AsyncSession) -> Optional[CrisisStateORM]:
        res = await session.execute(
            f"SELECT * FROM sp_crisis_state WHERE brand = :brand", {"brand": brand}
        )
        state = res.scalar_one_or_none()
        if state and state.consecutive_windows >= self.hysteresis_windows:
            return state
        return None
