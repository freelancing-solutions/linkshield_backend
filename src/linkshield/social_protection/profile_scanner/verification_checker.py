# src/social_protection/verification_checker.py

from sqlalchemy.ext.asyncio import AsyncSession

from linkshield.social_protection.registry import registry
from linkshield.models.social_protection import ProfileAuditORM
from linkshield.social_protection.data_models.social_profile_models import VerificationResult

class VerificationChecker:
    async def check_verification(
        self,
        platform: str,
        handle: str,
        session: AsyncSession
    ) -> VerificationResult:
        """
        Check verification status of a profile, persist, and return result.
        """
        adapter = registry.get_adapter(platform)
        if not adapter:
            raise ValueError(f"No adapter registered for platform {platform}")

        profile_data = await adapter.fetch_profile(handle)

        result = VerificationResult(
            platform=platform,
            handle=handle,
            verified=profile_data.verified,
        )

        # Update existing audit record
        audit_record = ProfileAuditORM(
            platform=platform,
            handle=handle,
            verified=profile_data.verified,
        )
        await session.merge(audit_record)

        return result
