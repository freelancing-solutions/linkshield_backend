# src/social_protection/profile_analyzer.py

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from linkshield.social_protection.registry import registry
from linkshield.services.depends import get_ai_service
from linkshield.models.social_protection import ProfileAuditORM
from linkshield.social_protection.data_models.social_profile_models import (
    ProfileAuditResult,
    SuspiciousActivity,
)

class ProfileAnalyzer:
    def __init__(self):
        self.ai_service = get_ai_service()

    async def analyze_profile(
        self, platform: str, handle: str, session: AsyncSession
    ) -> ProfileAuditResult:
        """
        Analyze a social media profile, persist results, and return structured audit.
        """
        adapter = registry.get_adapter(platform)
        if not adapter:
            raise ValueError(f"No adapter registered for platform {platform}")

        # Fetch raw profile data
        profile_data = await adapter.fetch_profile(handle)

        suspicious_flags: list[SuspiciousActivity] = []

        # Heuristic checks
        account_age_days = (
            (datetime.now(timezone.utc) - profile_data.created_at).days
            if profile_data.created_at
            else None
        )
        if account_age_days is not None and account_age_days < 30:
            suspicious_flags.append(
                SuspiciousActivity(type="new_account", details="Account younger than 30 days")
            )

        if profile_data.followers_count and profile_data.following_count:
            ratio = profile_data.followers_count / max(1, profile_data.following_count)
            if ratio > 50 or ratio < 0.01:
                suspicious_flags.append(
                    SuspiciousActivity(type="imbalance", details="Suspicious follower/following ratio")
                )

        if not profile_data.bio or len(profile_data.bio.strip()) < 5:
            suspicious_flags.append(
                SuspiciousActivity(type="incomplete_bio", details="Bio appears empty or too short")
            )

        # Optional AI-based anomaly detection
        if self.ai_service:
            ai_result = await self.ai_service.classify(
                text=profile_data.bio or "",
                task="profile_suspiciousness"
            )
            if ai_result and ai_result.get("suspicious"):
                suspicious_flags.append(
                    SuspiciousActivity(type="ai_flagged", details="AI flagged suspicious content")
                )

        # Build Pydantic result
        audit_result = ProfileAuditResult(
            platform=platform,
            handle=handle,
            account_age_days=account_age_days,
            followers_count=profile_data.followers_count,
            following_count=profile_data.following_count,
            verified=profile_data.verified,
            suspicious_flags=suspicious_flags,
            analyzed_at=datetime.now(timezone.utc),
        )

        # Persist to DB
        audit_record = ProfileAuditORM(
            platform=platform,
            handle=handle,
            account_age_days=account_age_days,
            followers_count=profile_data.followers_count,
            following_count=profile_data.following_count,
            verified=profile_data.verified,
            suspicious_flags=[f.type for f in suspicious_flags],
            analyzed_at=audit_result.analyzed_at,
        )
        await session.merge(audit_record)

        return audit_result
