#!/usr/bin/env python3
"""
FollowerAuthenticator

Fetches followers for a profile via platform adapters, persists follower records,
and runs heuristic + AI-based authenticity checks.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel

from src.models.social_protection import FollowerORM, ProfileAuditORM

try:
    from src.services.depends import get_ai_service
    from src.services.ai_service import AIService
except Exception:
    AIService = None
    def get_ai_service():
        return None


class FollowerAuthResult(BaseModel):
    platform: str
    handle: str
    total_followers_scanned: int
    suspicious_count: int
    authenticity_score: float  # 0..1 where 1 is fully authentic


class FollowerAuthenticator:
    def __init__(self, ai_service: Optional[AIService] = None, sample_limit: int = 500):
        self.ai_service = ai_service or get_ai_service()
        self.sample_limit = sample_limit

    @staticmethod
    def _is_suspicious_account(follower: Dict[str, Any]) -> bool:
        # heuristic checks
        if not follower:
            return True
        # missing avatar
        if not follower.get("profile_picture"):
            return True
        # very low followers and following counts often bot-like
        followers = int(follower.get("followers_count") or 0)
        following = int(follower.get("following_count") or 0)
        if followers == 0 and following > 100:
            return True
        # username with many digits
        uname = (follower.get("username") or "").lower()
        digits = sum(c.isdigit() for c in uname)
        if len(uname) >= 6 and digits / len(uname) > 0.5:
            return True
        return False

    async def scan_and_persist(self, platform: str, handle: str, adapter, db_session) -> FollowerAuthResult:
        # fetch profile to get internal id
        profile = await adapter.get_profile(handle)
        if not profile:
            return FollowerAuthResult(platform=platform, handle=handle, total_followers_scanned=0, suspicious_count=0, authenticity_score=0.0)

        # adapter must implement get_followers(profile, limit)
        followers = []
        try:
            followers = await adapter.get_followers(profile, limit=self.sample_limit)
        except Exception:
            # adapter may not support follower enumeration; treat as empty
            followers = []

        suspicious = 0
        tasks = []
        now = datetime.now(timezone.utc)

        # batch persistence
        for f in followers:
            try:
                platform_id = f.get("id") or f.get("platform_id") or f.get("user_id")
                username = f.get("username") or f.get("handle") or str(platform_id)
                is_susp = self._is_suspicious_account(f)
                if is_susp:
                    suspicious += 1

                # optional AI classification
                if self.ai_service:
                    try:
                        prompt = f"Classify whether this follower is likely a bot or fake account: {f}"
                        ai_resp = await self.ai_service.classify(prompt)
                        if isinstance(ai_resp, dict) and ai_resp.get("is_bot"):
                            is_susp = True
                    except Exception:
                        pass

                # upsert follower
                orm = None
                try:
                    # try naive upsert with query (sync/async compatibility)
                    orm = db_session.query(FollowerORM).filter_by(profile_id=profile.get("id"), platform_id=platform_id).one_or_none()
                except Exception:
                    orm = None

                if orm:
                    orm.username = username
                    orm.is_suspicious = is_susp
                    orm.metadata = f
                    orm.updated_at = now
                    db_session.add(orm)
                else:
                    # find or create profile audit
                    profile_orm = db_session.query(ProfileAuditORM).filter_by(platform=platform, handle=handle).one_or_none()
                    if not profile_orm:
                        profile_orm = ProfileAuditORM(platform=platform, handle=handle, profile_raw=profile)
                        db_session.add(profile_orm)
                        try:
                            db_session.commit()
                        except Exception:
                            db_session.flush()
                    follower_orm = FollowerORM(
                        profile_id=profile_orm.id,
                        username=username,
                        platform_id=platform_id,
                        is_suspicious=is_susp,
                        metadata=f,
                    )
                    db_session.add(follower_orm)
            except Exception:
                # continue processing other followers
                continue

        # commit once
        try:
            db_session.commit()
        except Exception:
            try:
                db_session.flush()
            except Exception:
                pass

        total = len(followers)
        authenticity_score = 1.0 - (suspicious / total) if total else 0.0
        return FollowerAuthResult(platform=platform, handle=handle, total_followers_scanned=total, suspicious_count=suspicious, authenticity_score=authenticity_score)
