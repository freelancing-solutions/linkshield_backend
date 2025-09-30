"""
Bot Controller for Social Protection

This controller provides a specialized facade for bot integration and quick analysis services,
focusing on automated monitoring, API integrations, and rapid content assessment.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from src.authentication.auth_service import AuthService
from src.controllers.base_controller import BaseController
from src.models.user import User, UserRole
from src.models.project import Project
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.social_protection.types import PlatformType, RiskLevel, ScanStatus
from src.social_protection.data_models import ContentRiskAssessment, ContentType
from src.social_protection.services import SocialScanService
from src.social_protection.content_analyzer import (
    ContentRiskAnalyzer, LinkPenaltyDetector, SpamPatternDetector, CommunityNotesAnalyzer
)
from src.social_protection.algorithm_health import (
    VisibilityScorer, EngagementAnalyzer, PenaltyDetector, ShadowBanDetector
)
from src.utils import utc_datetime
import logging
import asyncio
from enum import Enum

logger = logging.getLogger(__name__)


class BotAnalysisType(Enum):
    """Types of bot analysis available"""
    QUICK_SCAN = "quick_scan"
    CONTENT_RISK = "content_risk"
    LINK_SAFETY = "link_safety"
    SPAM_DETECTION = "spam_detection"
    ALGORITHM_HEALTH = "algorithm_health"
    COMPREHENSIVE = "comprehensive"


class BotResponseFormat(Enum):
    """Response formats for bot integration"""
    JSON = "json"
    MINIMAL = "minimal"
    DETAILED = "detailed"
    WEBHOOK = "webhook"


class BotController(BaseController):
    """
    Specialized controller for bot integration and quick analysis services.
    
    This controller provides optimized endpoints for automated systems, bots,
    and third-party integrations that need fast, reliable social protection analysis.
    """
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        social_scan_service: SocialScanService,
        content_risk_analyzer: ContentRiskAnalyzer,
        link_penalty_detector: LinkPenaltyDetector,
        spam_pattern_detector: SpamPatternDetector,
        community_notes_analyzer: CommunityNotesAnalyzer,
        visibility_scorer: VisibilityScorer,
        engagement_analyzer: EngagementAnalyzer,
        penalty_detector: PenaltyDetector,
        shadow_ban_detector: ShadowBanDetector
    ):
        """Initialize bot controller with all required services"""
        super().__init__(security_service, auth_service, email_service)
        
        # Core services
        self.social_scan_service = social_scan_service
        
        # Content analyzer services
        self.content_risk_analyzer = content_risk_analyzer
        self.link_penalty_detector = link_penalty_detector
        self.spam_pattern_detector = spam_pattern_detector
        self.community_notes_analyzer = community_notes_analyzer
        
        # Algorithm health services
        self.visibility_scorer = visibility_scorer
        self.engagement_analyzer = engagement_analyzer
        self.penalty_detector = penalty_detector
        self.shadow_ban_detector = shadow_ban_detector
        
        # Bot-specific rate limits (higher for automated systems)
        self.max_bot_requests_per_minute = 100
        self.max_bot_requests_per_hour = 2000
        self.max_batch_size = 50
        
        # Cache for frequent bot requests
        self._analysis_cache = {}
        self._cache_ttl = 300  # 5 minutes