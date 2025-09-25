#!/usr/bin/env python3
"""
ProfileAnalyzer

Fetches profile metadata via platform adapters, runs heuristic checks and
optionally calls AIService for enrichment, then persists a ProfileAuditORM.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from src.models.social_protection import ProfileAuditORM

try:
    from src.services.depends import get_ai_service
    from src.services.ai_service import AIService
except Exception:  # pragma: no cover - optional integration
    AIService = None
    def get_ai_service():
        return None


class ProfileAuditResult(BaseModel):
    platform: str
    handle: str
    account_age_days: Optional[int]
    profile_completeness: Optional[int]
    suspicious_signals: List[str]
    verified: bool
    raw: Dict[str, Any]


class ProfileAnalyzer:
    def __init__(self, ai_service: Optional[AIService] = None):
        self.ai_service = ai_service or get_ai_service()

    @staticmethod
    def _compute_completeness(profile: Dict[str, Any]) -> int:
        # simple heuristic: presence of profile_picture, bio, link, location
        score = 0
        if profile.get("profile_picture"):
            score += 30
        if profile.get("bio"):
            score += 30
        if profile.get("url"):
            score += 20
        if profile.get("location"):
            score += 10
        if profile.get("display_name"):
            score += 10
        return min(100, score)

    @staticmethod
    def _detect_suspicious(profile: Dict[str, Any]) -> List[str]:
        signals = []
        username = (profile.get("handle") or profile.get("username") or "").lower()
        bio = (profile.get("bio") or "").lower()

        # suspicious: lots of urls in bio
        if bio.count("http") >= 2:
            signals.append("multiple_external_links_in_bio")

        # suspicious: username with many numbers or gibberish
        digits = sum(c.isdigit() for c in username)
        if digits / max(1, len(username)) > 0.3 and len(username) > 6:
            signals.append("numeric_username_high_ratio")

        # suspicious: newly created account
        created_at = profile.get("created_at")
        if created_at:
            try:
                dt = datetime.fromisoformat(created_at)
                age_days = (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)).days
                if age_days < 7:
                    signals.append("very_new_account")
            except Exception:
                # ignore parse errors
                pass

        # suspicious: default avatar placeholder
        if not profile.get("profile_picture"):
            signals.append("no_profile_picture")

        return signals

    async def analyze_and_persist(self, platform: str, handle: str, adapter, db_session) -> ProfileAuditResult:
        """Fetch profile via adapter, analyze it, persist ProfileAuditORM and return result.

        db_session: a SQLAlchemy session (sync or async) - this method will try to
        add/commit but prefers when callers manage transactions. If your app uses
        a session-manager that automatically commits, you can pass that session.
        """
        profile = await adapter.get_profile(handle)
        raw = profile or {}

        completeness = self._compute_completeness(raw)
        signals = self._detect_suspicious(raw)

        verified = False
        if raw.get("verified") is not None:
            verified = bool(raw.get("verified"))

        account_age = None
        if raw.get("created_at"):
            try:
                dt = datetime.fromisoformat(raw.get("created_at"))
                account_age = (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)).days
            except Exception:
                account_age = None

        # Optional AI enrichment
        if self.ai_service:
            try:
                prompt = f"Analyze this social profile for suspicious signals: {raw}"
                ai_resp = await self.ai_service.classify(prompt)
                # Expect ai_resp to be dict-like with keys 'suspicious' and 'notes'
                if isinstance(ai_resp, dict):
                    if ai_resp.get("suspicious"):
                        signals.append("ai_flagged_suspicious")
                        # attach ai notes to raw
                        raw.setdefault("ai", {}).update(ai_resp)
            except Exception:
                # non-fatal
                pass

        # Persist
        orm = None
        try:
            # Upsert logic: attempt to find existing by platform+handle
            existing = None
            try:
                # support sync and async sessions
                existing = (await db_session.execute("SELECT id FROM sp_profile_audits WHERE platform=:p AND handle=:h", {"p": platform, "h": handle})).scalar_one_or_none()
            except Exception:
                existing = None

            if existing:
                # naive update path
                orm = db_session.query(ProfileAuditORM).filter_by(platform=platform, handle=handle).one_or_none()
                if orm:
                    orm.profile_raw = raw
                    orm.profile_completeness = completeness
                    orm.suspicious_signals = signals
                    orm.verified = verified
                    orm.account_age_days = account_age
                    orm.updated_at = datetime.utcnow()
                    db_session.add(orm)
                    try:
                        db_session.commit()
                    except Exception:
                        db_session.flush()
            else:
                orm = ProfileAuditORM(
                    platform=platform,
                    handle=handle,
                    platform_id=raw.get("id") or raw.get("platform_id"),
                    account_created_at=raw.get("created_at"),
                    account_age_days=account_age,
                    profile_completeness=completeness,
                    verified=verified,
                    suspicious_signals=signals,
                    profile_raw=raw,
                )
                db_session.add(orm)
                try:
                    db_session.commit()
                except Exception:
                    db_session.flush()
        except Exception:
            # best-effort persistence; do not crash analyzer
            orm = None

        result = ProfileAuditResult(
            platform=platform,
            handle=handle,
            account_age_days=account_age,
            profile_completeness=completeness,
            suspicious_signals=signals,
            verified=verified,
            raw=raw,
        )
        return result
