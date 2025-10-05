
from typing import Optional
from fastapi import Depends, HTTPException
from linkshield.authentication.auth_service import AuthService
from linkshield.config.database import AsyncSession, get_db_session, get_db
from linkshield.services.admin_service import AdminService
from linkshield.services.ai_service import AIService
from linkshield.services.ai_analysis_service import AIAnalysisService
from linkshield.services.email_service import EmailService
from linkshield.services.security_service import SecurityService
from linkshield.services.subscription_service import SubscriptionService
from linkshield.services.url_analysis_service import URLAnalysisService
from linkshield.services.quick_analysis_service import QuickAnalysisService
from linkshield.social_protection.services import ExtensionDataProcessor, SocialScanService
from linkshield.social_protection.content_analyzer import (
    ContentRiskAnalyzer, LinkPenaltyDetector, SpamPatternDetector, CommunityNotesAnalyzer
)
from linkshield.social_protection.algorithm_health import (
    VisibilityScorer, EngagementAnalyzer, PenaltyDetector, ShadowBanDetector
)
from linkshield.models import User

async def get_email_service():
    """
    Get EmailService instance without database session dependency.
    """
    return EmailService()

async def get_security_service() -> SecurityService:
    """
    Get SecurityService instance without database session dependency.
    """
    return SecurityService()

async def get_auth_service(
    security_service: SecurityService = Depends(get_security_service)
    ) -> AuthService:
    """
    Get AuthService instance without database session dependency.
    """
    return AuthService(security_service=security_service)

async def get_admin_service() -> AdminService:
    """
    Get AdminService instance without database session dependency.
    Pure business logic service for data processing and validation.
    """
    return AdminService()

async def get_rate_limits(user: Optional[User], db: AsyncSession = Depends(get_db_session), security_service: SecurityService = Depends(get_security_service)) -> None:
    """
    Check rate limits for user.
    """   
    identifier = str(user.id) if user else "anonymous"
    
    # Check API request rate limit
    is_allowed, limit_info = security_service.check_rate_limit(identifier, "api_requests", "127.0.0.1")
    if not is_allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {limit_info['retry_after']:.0f} seconds",
            headers={"Retry-After": str(int(limit_info['retry_after']))}
        )

async def get_ai_service() -> AIService:
    """
    Get AIService instance (pure business logic, no database dependency).
    """
    return AIService()

async def get_ai_analysis_service() -> AIAnalysisService:
    """
    Get AI analysis service instance (pure business logic, no database dependency).
    """
    return AIAnalysisService()

async def get_url_analysis_service(ai_service: AIService = Depends(get_ai_service)) -> URLAnalysisService:
    """
    Get URL analysis service instance (pure business logic, no database dependency).
    """
    return URLAnalysisService(ai_service=ai_service)

async def get_extension_data_processor() -> ExtensionDataProcessor:
    """
    Get ExtensionDataProcessor instance for processing browser extension data.
    """
    return ExtensionDataProcessor()

async def get_social_scan_service(ai_service: AIService = Depends(get_ai_service)) -> SocialScanService:
    """
    Get SocialScanService instance for social media profile scanning.
    """
    return SocialScanService(ai_service=ai_service)

async def get_quick_analysis_service(
    ai_service: AIService = Depends(get_ai_service)
) -> QuickAnalysisService:
    """
    Get QuickAnalysisService instance for fast bot responses.
    """
    return QuickAnalysisService(ai_service=ai_service)

# Social Protection Content Analyzer Services

async def get_content_risk_analyzer(ai_service: AIService = Depends(get_ai_service)) -> ContentRiskAnalyzer:
    """
    Get ContentRiskAnalyzer instance for content risk assessment.
    """
    return ContentRiskAnalyzer(ai_service=ai_service)

async def get_link_penalty_detector(ai_service: AIService = Depends(get_ai_service)) -> LinkPenaltyDetector:
    """
    Get LinkPenaltyDetector instance for link penalty detection.
    """
    return LinkPenaltyDetector(ai_service=ai_service)

async def get_spam_pattern_detector(ai_service: AIService = Depends(get_ai_service)) -> SpamPatternDetector:
    """
    Get SpamPatternDetector instance for spam pattern detection.
    """
    return SpamPatternDetector(ai_service=ai_service)

async def get_community_notes_analyzer(ai_service: AIService = Depends(get_ai_service)) -> CommunityNotesAnalyzer:
    """
    Get CommunityNotesAnalyzer instance for community notes analysis.
    """
    return CommunityNotesAnalyzer(ai_service=ai_service)

# Social Protection Algorithm Health Services

async def get_visibility_scorer(ai_service: AIService = Depends(get_ai_service)) -> VisibilityScorer:
    """
    Get VisibilityScorer instance for visibility analysis.
    """
    return VisibilityScorer(ai_service=ai_service)

async def get_engagement_analyzer(ai_service: AIService = Depends(get_ai_service)) -> EngagementAnalyzer:
    """
    Get EngagementAnalyzer instance for engagement analysis.
    """
    return EngagementAnalyzer(ai_service=ai_service)

async def get_penalty_detector(ai_service: AIService = Depends(get_ai_service)) -> PenaltyDetector:
    """
    Get PenaltyDetector instance for penalty detection.
    """
    return PenaltyDetector(ai_service=ai_service)

async def get_shadow_ban_detector(ai_service: AIService = Depends(get_ai_service)) -> ShadowBanDetector:
    """
    Get ShadowBanDetector instance for shadow ban detection.
    """
    return ShadowBanDetector(ai_service=ai_service)

def get_subscription_service(db: AsyncSession = Depends(get_db)) -> SubscriptionService:
    """Dependency to get SubscriptionService instance."""
    return SubscriptionService(db)
