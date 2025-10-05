from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks
from src.authentication import auth_service
from src.authentication.auth_service import AuthService
from src.config.database import AsyncSession, get_db_session
from src.controllers import URLCheckController, ReportController, HealthController, UserController, AdminController, AIAnalysisController, DashboardController
from src.controllers.bot_controller import BotController
from src.controllers.subscription_controller import SubscriptionController
from src.services.subscription_service import SubscriptionService
from src.social_protection.controllers import SocialProtectionController
from src.social_protection.controllers.user_controller import UserController as SocialUserController
from src.social_protection.controllers.bot_controller import BotController as SocialBotController
from src.social_protection.controllers.extension_controller import ExtensionController
from src.social_protection.services import ExtensionDataProcessor, SocialScanService
from src.social_protection.content_analyzer import (
    ContentRiskAnalyzer, LinkPenaltyDetector, SpamPatternDetector, CommunityNotesAnalyzer
)
from src.social_protection.algorithm_health import (
    VisibilityScorer, EngagementAnalyzer, PenaltyDetector, ShadowBanDetector
)

from src.services.admin_service import AdminService
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.services.url_analysis_service import URLAnalysisService
from src.services.ai_analysis_service import AIAnalysisService
from src.services.ai_service import AIService
from src.services.depends import get_security_service, get_auth_service, get_url_analysis_service, \
    get_ai_analysis_service, get_ai_service, get_email_service, get_admin_service, get_extension_data_processor, \
    get_social_scan_service, get_quick_analysis_service, get_content_risk_analyzer, get_link_penalty_detector, \
    get_spam_pattern_detector, get_community_notes_analyzer, get_visibility_scorer, get_engagement_analyzer, \
    get_penalty_detector, get_shadow_ban_detector, get_subscription_service


async def get_health_controller() -> HealthController:
    """
    Get health controller instance (no dependencies).
    """
    return HealthController()

async def get_user_controller(
    security_service: SecurityService = Depends(get_security_service), 
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service)) -> UserController:
    """
    Get user controller instance with required dependencies.
    """
    return UserController(
        security_service=security_service, 
        auth_service=auth_service,
        email_service=email_service)

async def get_admin_controller(
    security_service: SecurityService = Depends(get_security_service), 
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    admin_service: AdminService = Depends(get_admin_service)) -> AdminController:
    """
    Get admin controller instance with required dependencies.
    """
    return AdminController(
        security_service=security_service, 
        auth_service=auth_service,
        email_service=email_service,
        admin_service=admin_service)

async def get_url_check_controller(
    security_service: SecurityService = Depends(get_security_service), 
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    url_analysis_service: URLAnalysisService = Depends(get_url_analysis_service)) -> URLCheckController:
    """
    Get URL check controller instance with required dependencies.
    """
    return URLCheckController(
        security_service=security_service, 
        auth_service=auth_service,
        email_service=email_service,
        url_analysis_service=url_analysis_service)

async def get_report_controller(
    security_service: SecurityService = Depends(get_security_service), 
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service)) -> ReportController:
    """
    Get report controller instance with required dependencies.
    """
    return ReportController(
        security_service=security_service, 
        auth_service=auth_service,
        email_service=email_service)

async def get_ai_analysis_controller(
    security_service: SecurityService = Depends(get_security_service), 
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service)) -> AIAnalysisController:
    """
    Get AI analysis controller instance with required dependencies.
    """
    return AIAnalysisController(
        security_service=security_service, 
        auth_service=auth_service,
        email_service=email_service,
        ai_analysis_service=ai_analysis_service)

async def get_dashboard_controller(
    security_service: SecurityService = Depends(get_security_service), 
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service)) -> DashboardController:
    """
    Get dashboard controller instance with required dependencies.
    """
    return DashboardController(
        security_service=security_service, 
        auth_service=auth_service,
        email_service=email_service)

async def get_social_protection_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    extension_data_processor: ExtensionDataProcessor = Depends(get_extension_data_processor),
    social_scan_service: SocialScanService = Depends(get_social_scan_service)
) -> SocialProtectionController:
    """
    Get social protection controller instance with required dependencies.
    """
    return SocialProtectionController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
        extension_data_processor=extension_data_processor,
        social_scan_service=social_scan_service
    )

async def get_bot_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    quick_analysis_service = Depends(get_quick_analysis_service)
) -> BotController:
    """
    Get bot controller instance with required dependencies.
    """
    return BotController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
        quick_analysis_service=quick_analysis_service
    )

# Social Protection Controllers

async def get_social_user_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    social_scan_service: SocialScanService = Depends(get_social_scan_service),
    content_risk_analyzer: ContentRiskAnalyzer = Depends(get_content_risk_analyzer),
    link_penalty_detector: LinkPenaltyDetector = Depends(get_link_penalty_detector),
    spam_pattern_detector: SpamPatternDetector = Depends(get_spam_pattern_detector),
    community_notes_analyzer: CommunityNotesAnalyzer = Depends(get_community_notes_analyzer),
    visibility_scorer: VisibilityScorer = Depends(get_visibility_scorer),
    engagement_analyzer: EngagementAnalyzer = Depends(get_engagement_analyzer),
    penalty_detector: PenaltyDetector = Depends(get_penalty_detector),
    shadow_ban_detector: ShadowBanDetector = Depends(get_shadow_ban_detector)
) -> SocialUserController:
    """
    Get social protection user controller instance with required dependencies.
    """
    return SocialUserController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
        social_scan_service=social_scan_service,
        content_risk_analyzer=content_risk_analyzer,
        link_penalty_detector=link_penalty_detector,
        spam_pattern_detector=spam_pattern_detector,
        community_notes_analyzer=community_notes_analyzer,
        visibility_scorer=visibility_scorer,
        engagement_analyzer=engagement_analyzer,
        penalty_detector=penalty_detector,
        shadow_ban_detector=shadow_ban_detector
    )

async def get_social_bot_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    social_scan_service: SocialScanService = Depends(get_social_scan_service),
    content_risk_analyzer: ContentRiskAnalyzer = Depends(get_content_risk_analyzer),
    link_penalty_detector: LinkPenaltyDetector = Depends(get_link_penalty_detector),
    spam_pattern_detector: SpamPatternDetector = Depends(get_spam_pattern_detector),
    community_notes_analyzer: CommunityNotesAnalyzer = Depends(get_community_notes_analyzer),
    visibility_scorer: VisibilityScorer = Depends(get_visibility_scorer),
    engagement_analyzer: EngagementAnalyzer = Depends(get_engagement_analyzer),
    penalty_detector: PenaltyDetector = Depends(get_penalty_detector),
    shadow_ban_detector: ShadowBanDetector = Depends(get_shadow_ban_detector)
) -> SocialBotController:
    """
    Get social protection bot controller instance with required dependencies.
    """
    return SocialBotController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
        social_scan_service=social_scan_service,
        content_risk_analyzer=content_risk_analyzer,
        link_penalty_detector=link_penalty_detector,
        spam_pattern_detector=spam_pattern_detector,
        community_notes_analyzer=community_notes_analyzer,
        visibility_scorer=visibility_scorer,
        engagement_analyzer=engagement_analyzer,
        penalty_detector=penalty_detector,
        shadow_ban_detector=shadow_ban_detector
    )

async def get_extension_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    social_scan_service: SocialScanService = Depends(get_social_scan_service),
    content_risk_analyzer: ContentRiskAnalyzer = Depends(get_content_risk_analyzer),
    link_penalty_detector: LinkPenaltyDetector = Depends(get_link_penalty_detector),
    spam_pattern_detector: SpamPatternDetector = Depends(get_spam_pattern_detector),
    community_notes_analyzer: CommunityNotesAnalyzer = Depends(get_community_notes_analyzer),
    visibility_scorer: VisibilityScorer = Depends(get_visibility_scorer),
    engagement_analyzer: EngagementAnalyzer = Depends(get_engagement_analyzer),
    penalty_detector: PenaltyDetector = Depends(get_penalty_detector),
    shadow_ban_detector: ShadowBanDetector = Depends(get_shadow_ban_detector)
) -> ExtensionController:
    """
    Get extension controller instance with required dependencies.
    """
    return ExtensionController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
        social_scan_service=social_scan_service,
        content_risk_analyzer=content_risk_analyzer,
        link_penalty_detector=link_penalty_detector,
        spam_pattern_detector=spam_pattern_detector,
        community_notes_analyzer=community_notes_analyzer,
        visibility_scorer=visibility_scorer,
        engagement_analyzer=engagement_analyzer,
        penalty_detector=penalty_detector,
        shadow_ban_detector=shadow_ban_detector
    )



async def get_subscription_controller(
        subscription_service: SubscriptionService = Depends(get_subscription_service),
        security_service: SecurityService  = Depends(get_security_service),
        auth_service: AuthService  =Depends(get_auth_service),
        email_service:EmailService = Depends(get_email_service)) -> SubscriptionController:
    """Dependency to get SubscriptionController instance."""
    return SubscriptionController(subscription_service=subscription_service, security_service=security_service,
                                  auth_service=auth_service, email_service=email_service)
