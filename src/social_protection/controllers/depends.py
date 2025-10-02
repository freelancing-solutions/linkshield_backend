#!/usr/bin/env python3
"""
Social Protection Controllers Dependencies

Dependency injection for social protection controllers.
"""

from fastapi import Depends

from src.services.depends import (
    get_security_service, get_auth_service, get_email_service,
    get_extension_data_processor, get_social_scan_service
)
from src.services.security_service import SecurityService
from src.services.email_service import EmailService
from src.authentication.auth_service import AuthService
from src.social_protection.services import ExtensionDataProcessor, SocialScanService
from src.social_protection.content_analyzer.depends import (
    get_content_risk_analyzer, get_link_penalty_detector,
    get_spam_pattern_detector, get_community_notes_analyzer
)
from src.social_protection.content_analyzer import (
    ContentRiskAnalyzer, LinkPenaltyDetector, SpamPatternDetector, CommunityNotesAnalyzer
)
from src.social_protection.algorithm_health.depends import (
    get_visibility_scorer, get_engagement_analyzer,
    get_penalty_detector, get_shadow_ban_detector
)
from src.social_protection.algorithm_health import (
    VisibilityScorer, EngagementAnalyzer, PenaltyDetector, ShadowBanDetector
)
from src.social_protection.controllers.user_controller import UserController
from src.social_protection.controllers.bot_controller import BotController
from src.social_protection.controllers.extension_controller import ExtensionController


async def get_user_controller(
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
) -> UserController:
    """
    Get social protection user controller instance with all dependencies.
    
    Args:
        security_service: Security service for authentication and authorization
        auth_service: Authentication service for user management
        email_service: Email service for notifications
        social_scan_service: Service for social media profile scanning
        content_risk_analyzer: Analyzer for content risk assessment
        link_penalty_detector: Detector for link penalties
        spam_pattern_detector: Detector for spam patterns
        community_notes_analyzer: Analyzer for community notes
        visibility_scorer: Scorer for content visibility
        engagement_analyzer: Analyzer for engagement patterns
        penalty_detector: Detector for algorithmic penalties
        shadow_ban_detector: Detector for shadow bans
        
    Returns:
        UserController: Configured controller instance
    """
    return UserController(
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


async def get_bot_controller(
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
) -> BotController:
    """
    Get social protection bot controller instance with all dependencies.
    
    Args:
        security_service: Security service for authentication and authorization
        auth_service: Authentication service for user management
        email_service: Email service for notifications
        social_scan_service: Service for social media profile scanning
        content_risk_analyzer: Analyzer for content risk assessment
        link_penalty_detector: Detector for link penalties
        spam_pattern_detector: Detector for spam patterns
        community_notes_analyzer: Analyzer for community notes
        visibility_scorer: Scorer for content visibility
        engagement_analyzer: Analyzer for engagement patterns
        penalty_detector: Detector for algorithmic penalties
        shadow_ban_detector: Detector for shadow bans
        
    Returns:
        BotController: Configured controller instance
    """
    return BotController(
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
    Get social protection extension controller instance with all dependencies.
    
    Args:
        security_service: Security service for authentication and authorization
        auth_service: Authentication service for user management
        email_service: Email service for notifications
        social_scan_service: Service for social media profile scanning
        content_risk_analyzer: Analyzer for content risk assessment
        link_penalty_detector: Detector for link penalties
        spam_pattern_detector: Detector for spam patterns
        community_notes_analyzer: Analyzer for community notes
        visibility_scorer: Scorer for content visibility
        engagement_analyzer: Analyzer for engagement patterns
        penalty_detector: Detector for algorithmic penalties
        shadow_ban_detector: Detector for shadow bans
        
    Returns:
        ExtensionController: Configured controller instance
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