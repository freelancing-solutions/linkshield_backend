"""Social Protection Data Models

This module contains Pydantic models for social protection functionality,
including profile scanning, content risk assessment, extension integration,
and real-time assessment data structures.

These models ensure type safety and data validation across the social
protection domain layer.
"""

# Profile scanning models
from .social_profile_models import (
    ProfileVerificationStatus,
    FollowerAuthenticityLevel,
    SocialProfileInfo,
    FollowerAnalysis,
    ProfileRiskFactor,
    ProfileSecurityAssessment,
    ProfileScanRequest,
    ProfileScanResult,
    BulkProfileScanRequest,
    BulkProfileScanResult,
    ProfileMonitoringConfig,
    ProfileMonitoringAlert
)

# Content risk assessment models
from .content_risk_models import (
    ContentType,
    ContentModerationStatus,
    PolicyViolationType,
    ContentInfo,
    ContentRiskFactor,
    SpamAnalysis,
    LinkPenaltyAnalysis,
    SentimentAnalysis,
    ContentRiskAssessment,
    ContentAnalysisRequest,
    ContentAnalysisResult,
    BulkContentAnalysisRequest,
    BulkContentAnalysisResult,
    ContentMonitoringConfig,
    ContentMonitoringAlert
)

# Extension integration models  
from .extension_models import (
    ExtensionAction,
    ScanTrigger,
    ExtensionStatus,
    BrowserInfo,
    PageContext,
    ExtensionScanPayload,
    RealTimeAssessment,
    ExtensionResponse,
    FeedMonitoringData,
    LinkSafetyCheck,
    ExtensionSettings,
    ExtensionAnalytics,
    ExtensionHealthCheck,
    BatchExtensionRequest,
    BatchExtensionResponse
)

# Real-time assessment models
from .assessment_models import (
    AlgorithmHealthStatus,
    VisibilityTrend,
    PenaltyType,
    CrisisType,
    CrisisSeverity,
    EngagementMetrics,
    VisibilityMetrics,
    AlgorithmHealthAssessment,
    ReputationMetrics,
    MentionData,
    ReputationAssessment,
    CrisisIndicator,
    CrisisAssessment,
    ComprehensiveAssessment,
    AssessmentHistory
)

# Telegram platform models
from .telegram_models import (
    TelegramEntityType,
    TelegramChannelType,
    TelegramMessageType,
    TelegramProfileData,
    TelegramMessageData,
    TelegramRiskFactors,
    TelegramAnalysisRequest,
    TelegramAnalysisResponse,
    TelegramContentAnalysisRequest,
    TelegramContentAnalysisResponse,
    TelegramBotAnalysis,
    TelegramChannelMetrics
)

# Discord platform models
from .discord_models import (
    DiscordEntityType,
    DiscordChannelType,
    DiscordServerFeature,
    DiscordVerificationLevel,
    DiscordContentFilterLevel,
    DiscordProfileData,
    DiscordMessageData,
    DiscordRiskFactors,
    DiscordAnalysisRequest,
    DiscordAnalysisResponse,
    DiscordServerAnalysis,
    DiscordBotAnalysis,
    DiscordContentAnalysisRequest,
    DiscordContentAnalysisResponse,
    DiscordRaidDetection,
    DiscordCommunityMetrics
)

__all__ = [
    # Profile scanning
    "ProfileVerificationStatus",
    "FollowerAuthenticityLevel", 
    "SocialProfileInfo",
    "FollowerAnalysis",
    "ProfileRiskFactor",
    "ProfileSecurityAssessment",
    "ProfileScanRequest",
    "ProfileScanResult",
    "BulkProfileScanRequest",
    "BulkProfileScanResult",
    "ProfileMonitoringConfig",
    "ProfileMonitoringAlert",
    
    # Content risk assessment
    "ContentType",
    "ContentModerationStatus",
    "PolicyViolationType",
    "ContentInfo",
    "ContentRiskFactor",
    "SpamAnalysis",
    "LinkPenaltyAnalysis",
    "SentimentAnalysis",
    "ContentRiskAssessment",
    "ContentAnalysisRequest",
    "ContentAnalysisResult",
    "BulkContentAnalysisRequest",
    "BulkContentAnalysisResult",
    "ContentMonitoringConfig",
    "ContentMonitoringAlert",
    
    # Extension integration
    "ExtensionAction",
    "ScanTrigger",
    "ExtensionStatus",
    "BrowserInfo",
    "PageContext",
    "ExtensionScanPayload",
    "RealTimeAssessment",
    "ExtensionResponse",
    "FeedMonitoringData",
    "LinkSafetyCheck",
    "ExtensionSettings",
    "ExtensionAnalytics",
    "ExtensionHealthCheck",
    "BatchExtensionRequest",
    "BatchExtensionResponse",
    
    # Real-time assessment
    "AlgorithmHealthStatus",
    "VisibilityTrend",
    "PenaltyType",
    "CrisisType",
    "CrisisSeverity",
    "EngagementMetrics",
    "VisibilityMetrics",
    "AlgorithmHealthAssessment",
    "ReputationMetrics",
    "MentionData",
    "ReputationAssessment",
    "CrisisIndicator",
    "CrisisAssessment",
    "ComprehensiveAssessment",
    "AssessmentHistory",
    
    # Telegram platform models
    "TelegramEntityType",
    "TelegramChannelType",
    "TelegramMessageType",
    "TelegramProfileData",
    "TelegramMessageData",
    "TelegramRiskFactors",
    "TelegramAnalysisRequest",
    "TelegramAnalysisResponse",
    "TelegramContentAnalysisRequest",
    "TelegramContentAnalysisResponse",
    "TelegramBotAnalysis",
    "TelegramChannelMetrics",
    
    # Discord platform models
    "DiscordEntityType",
    "DiscordChannelType",
    "DiscordServerFeature",
    "DiscordVerificationLevel",
    "DiscordContentFilterLevel",
    "DiscordProfileData",
    "DiscordMessageData",
    "DiscordRiskFactors",
    "DiscordAnalysisRequest",
    "DiscordAnalysisResponse",
    "DiscordServerAnalysis",
    "DiscordBotAnalysis",
    "DiscordContentAnalysisRequest",
    "DiscordContentAnalysisResponse",
    "DiscordRaidDetection",
    "DiscordCommunityMetrics"
]