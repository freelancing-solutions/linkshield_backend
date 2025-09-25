# src/social_protection/follower_authenticator.py

from typing import List
from sqlalchemy.ext.asyncio import AsyncSession

from src.social_protection.registry import registry
from src.services.depends import get_ai_service
from src.models.social_protection import FollowerORM
from src.social_protection.data_models.social_profile_models import (
    FollowerAuthResult,
    FollowerCheck,
)

class FollowerAuthenticator:
    def __init__(self):
        self.ai_service = get_ai_service()

    async def analyze_followers(
        self,
        platform: str,
        handle: str,
        session: AsyncSession,
        limit: int = 100
    ) -> FollowerAuthResult:
        """
        Fetch followers, analyze authenticity, persist to DB, and return result.
        """
        adapter = registry.get_adapter(platform)
        if not adapter:
            raise ValueError(f"No adapter registered for platform {platform}")

        followers = await adapter.fetch_followers(handle, limit=limit)

        checks: List[FollowerCheck] = []

        for f in followers:
            suspicion_score = 0.0

            # Heuristics
            if f.followers_count == 0:
                suspicion_score += 0.3
            if f.bio is None or len(f.bio.strip()) < 5:
                suspicion_score += 0.2
            if f.posts_count == 0:
                suspicion_score += 0.2

            # AI enrichment
            if self.ai_service:
                ai_result = await self.ai_service.classify(
                    text=f.bio or "",
                    task="follower_authenticity"
                )
                if ai_result and "score" in ai_result:
                    suspicion_score = max(suspicion_score, ai_result["score"])

            # Build Pydantic
            check = FollowerCheck(
                id=f.id,
                username=f.username,
                followers_count=f.followers_count,
                posts_count=f.posts_count,
                suspicion_score=suspicion_score
            )
            checks.append(check)

            # Persist ORM
            follower_record = FollowerORM(
                platform=platform,
                handle=handle,
                follower_id=f.id,
                username=f.username,
                followers_count=f.followers_count,
                posts_count=f.posts_count,
                suspicion_score=suspicion_score,
            )
            await session.merge(follower_record)

        return FollowerAuthResult(
            platform=platform,
            handle=handle,
            checks=checks,
        )
