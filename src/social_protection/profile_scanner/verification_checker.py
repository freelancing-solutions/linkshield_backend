#!/usr/bin/env python3
"""
VerificationChecker

Checks platform-specific verification flags and normalizes them for storage and
reporting.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel

from src.models.social_protection import ProfileAuditORM


class VerificationResult(BaseModel):
    platform: str
    handle: str
    verified: bool
    verification_type: Optional[str]
    raw: Dict[str, Any]


class VerificationChecker:
    def __init__(self):
        pass

    async def check_and_persist(self, platform: str, handle: str, adapter, db_session) -> VerificationResult:
        """Fetch profile metadata (or use provided) and persist verification status.

        Returns VerificationResult and upserts ProfileAuditORM. This is a best-effort
        operation and will not raise for adapter errors.
        """
        profile = None
        try:
            profile = await adapter.get_profile(handle)
        except Exception:
            profile = None

        verified = False
        vtype = None
        raw = profile or {}

        # adapter may expose a field
        if raw.get("verified") is not None:
            verified = bool(raw.get("verified"))
            vtype = raw.get("verification_type") or raw.get("verified_type")

        # platform-specific heuristics
        # Twitter/X: 'verified_type' or 'is_blue_verified'
        if not verified and raw.get("is_blue_verified"):
            verified = True
            vtype = "blue"

        # Instagram: 'is_verified'
        if not verified and raw.get("is_verified"):
            verified = True
            vtype = vtype or "instagram_verified"

        # Persist into ProfileAuditORM
        try:
            profile_orm = db_session.query(ProfileAuditORM).filter_by(platform=platform, handle=handle).one_or_none()
            if profile_orm:
                profile_orm.verified = verified
                profile_orm.profile_raw = raw
                db_session.add(profile_orm)
            else:
                profile_orm = ProfileAuditORM(platform=platform, handle=handle, verified=verified, profile_raw=raw)
                db_session.add(profile_orm)
            try:
                db_session.commit()
            except Exception:
                db_session.flush()
        except Exception:
            pass

        return VerificationResult(platform=platform, handle=handle, verified=verified, verification_type=vtype, raw=raw)
