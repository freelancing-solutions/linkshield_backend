"""
Discord-specific Data Models

This module defines data structures for Discord platform analysis including:
- Server and user profile information
- Message and content data
- Risk assessment models
- Analysis request/response structures
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator
from enum import Enum

from ..types import PlatformType, RiskLevel, ScanStatus, ContentType


class DiscordEntityType(Enum):
    """Types of Discord entities that can be analyzed."""
    USER = "user"
    SERVER = "server"
    CHANNEL = "channel"
    BOT = "bot"
    ROLE = "role"


class DiscordChannelType(Enum):
    """Types of Discord channels."""
    TEXT = "text"
    VOICE = "voice"
    CATEGORY = "category"
    NEWS = "news"
    STORE = "store"
    THREAD = "thread"
    STAGE_VOICE = "stage_voice"
    FORUM = "forum"


class DiscordServerFeature(Enum):
    """Discord server features and boosts."""
    ANIMATED_ICON = "animated_icon"
    BANNER = "banner"
    COMMERCE = "commerce"
    COMMUNITY = "community"
    DISCOVERABLE = "discoverable"
    FEATURABLE = "featurable"
    INVITE_SPLASH = "invite_splash"
    MEMBER_VERIFICATION_GATE = "member_verification_gate"
    NEWS = "news"
    PARTNERED = "partnered"
    PREVIEW_ENABLED = "preview_enabled"
    VANITY_URL = "vanity_url"
    VERIFIED = "verified"
    VIP_REGIONS = "vip_regions"
    WELCOME_SCREEN_ENABLED = "welcome_screen_enabled"


class DiscordVerificationLevel(Enum):
    """Discord server verification levels."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4


class DiscordContentFilterLevel(Enum):
    """Discord explicit content filter levels."""
    DISABLED = 0
    MEMBERS_WITHOUT_ROLES = 1
    ALL_MEMBERS = 2


class DiscordProfileData(BaseModel):
    """Discord user/server profile data structure."""
    
    # Basic identification
    id: str = Field(..., description="Discord user/server ID")
    username: Optional[str] = Field(None, description="Username")
    discriminator: Optional[str] = Field(None, description="User discriminator (legacy)")
    global_name: Optional[str] = Field(None, description="Global display name")
    
    # Entity type and verification
    entity_type: DiscordEntityType = Field(..., description="Type of Discord entity")
    is_bot: bool = Field(False, description="Whether this is a bot account")
    is_system: bool = Field(False, description="Whether this is a system account")
    is_verified: bool = Field(False, description="Bot verification status")
    
    # User-specific data
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    banner_url: Optional[str] = Field(None, description="Banner image URL")
    accent_color: Optional[int] = Field(None, description="Profile accent color")
    
    # Server-specific data (when analyzing servers)
    server_name: Optional[str] = Field(None, description="Server name")
    server_description: Optional[str] = Field(None, description="Server description")
    icon_url: Optional[str] = Field(None, description="Server icon URL")
    splash_url: Optional[str] = Field(None, description="Server splash URL")
    
    # Server configuration
    verification_level: Optional[DiscordVerificationLevel] = Field(None, description="Server verification level")
    content_filter_level: Optional[DiscordContentFilterLevel] = Field(None, description="Content filter level")
    features: List[DiscordServerFeature] = Field(default_factory=list, description="Server features")
    
    # Membership and activity
    member_count: Optional[int] = Field(None, description="Server member count")
    online_count: Optional[int] = Field(None, description="Online members count")
    boost_level: Optional[int] = Field(None, description="Server boost level")
    boost_count: Optional[int] = Field(None, description="Number of boosts")
    
    # Timestamps
    created_at: Optional[datetime] = Field(None, description="Account/server creation date")
    joined_at: Optional[datetime] = Field(None, description="User join date (for server analysis)")
    
    # Permissions and roles
    permissions: List[str] = Field(default_factory=list, description="User permissions")
    roles: List[Dict[str, Any]] = Field(default_factory=list, description="User roles")
    
    # Activity and presence
    status: Optional[str] = Field(None, description="User status")
    activity: Optional[Dict[str, Any]] = Field(None, description="Current activity")
    
    # Privacy and security
    mfa_enabled: bool = Field(False, description="Multi-factor authentication enabled")
    email_verified: bool = Field(False, description="Email verification status")
    phone_verified: bool = Field(False, description="Phone verification status")
    
    class Config:
        use_enum_values = True


class DiscordMessageData(BaseModel):
    """Discord message data structure."""
    
    # Message identification
    message_id: str = Field(..., description="Unique message ID")
    channel_id: str = Field(..., description="Channel ID where message was sent")
    server_id: Optional[str] = Field(None, description="Server ID (if in server)")
    
    # Message content
    content: Optional[str] = Field(None, description="Message text content")
    clean_content: Optional[str] = Field(None, description="Message content without mentions")
    
    # Author information
    author_id: str = Field(..., description="Message author ID")
    author_username: Optional[str] = Field(None, description="Author username")
    author_display_name: Optional[str] = Field(None, description="Author display name")
    author_is_bot: bool = Field(False, description="Whether author is a bot")
    
    # Message properties
    is_pinned: bool = Field(False, description="Whether message is pinned")
    is_tts: bool = Field(False, description="Whether message is text-to-speech")
    is_system: bool = Field(False, description="Whether message is system message")
    
    # Embeds and attachments
    embeds: List[Dict[str, Any]] = Field(default_factory=list, description="Message embeds")
    attachments: List[Dict[str, Any]] = Field(default_factory=list, description="Message attachments")
    
    # Reactions and interactions
    reactions: List[Dict[str, Any]] = Field(default_factory=list, description="Message reactions")
    
    # References and replies
    is_reply: bool = Field(False, description="Whether message is a reply")
    referenced_message_id: Optional[str] = Field(None, description="Referenced message ID")
    
    # Mentions
    user_mentions: List[str] = Field(default_factory=list, description="Mentioned user IDs")
    role_mentions: List[str] = Field(default_factory=list, description="Mentioned role IDs")
    channel_mentions: List[str] = Field(default_factory=list, description="Mentioned channel IDs")
    everyone_mention: bool = Field(False, description="Whether @everyone was mentioned")
    
    # Timestamps
    timestamp: datetime = Field(..., description="Message timestamp")
    edited_timestamp: Optional[datetime] = Field(None, description="Last edit timestamp")
    
    # Thread information (if applicable)
    thread_id: Optional[str] = Field(None, description="Thread ID if message is in thread")
    
    class Config:
        use_enum_values = True


class DiscordRiskFactors(BaseModel):
    """Discord-specific risk factors assessment."""
    
    # User and bot risks
    bot_detection_score: float = Field(0.0, ge=0.0, le=1.0, description="Bot detection probability")
    fake_account_probability: float = Field(0.0, ge=0.0, le=1.0, description="Fake account probability")
    malicious_bot_indicators: List[str] = Field(default_factory=list, description="Malicious bot indicators")
    
    # Server security risks
    server_security_score: float = Field(1.0, ge=0.0, le=1.0, description="Server security score")
    moderation_effectiveness: float = Field(0.5, ge=0.0, le=1.0, description="Moderation effectiveness score")
    raid_vulnerability: float = Field(0.0, ge=0.0, le=1.0, description="Raid attack vulnerability")
    
    # Content risks
    spam_score: float = Field(0.0, ge=0.0, le=1.0, description="Spam content probability")
    harassment_score: float = Field(0.0, ge=0.0, le=1.0, description="Harassment content score")
    nsfw_violation_score: float = Field(0.0, ge=0.0, le=1.0, description="NSFW violation score")
    
    # Phishing and scam risks
    phishing_probability: float = Field(0.0, ge=0.0, le=1.0, description="Phishing attempt probability")
    scam_indicators: List[str] = Field(default_factory=list, description="Scam pattern indicators")
    malicious_link_count: int = Field(0, ge=0, description="Number of malicious links detected")
    
    # Privacy and doxxing risks
    doxxing_risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Doxxing risk assessment")
    personal_info_exposure: List[str] = Field(default_factory=list, description="Types of personal info exposed")
    
    # Community health risks
    toxicity_score: float = Field(0.0, ge=0.0, le=1.0, description="Community toxicity score")
    harassment_patterns: List[str] = Field(default_factory=list, description="Harassment patterns detected")
    
    # Coordinated attack risks
    coordinated_attack_probability: float = Field(0.0, ge=0.0, le=1.0, description="Coordinated attack probability")
    mass_reporting_indicators: List[str] = Field(default_factory=list, description="Mass reporting indicators")


class DiscordAnalysisRequest(BaseModel):
    """Request model for Discord analysis."""
    
    # Target identification
    target_url: Optional[str] = Field(None, description="Discord invite URL to analyze")
    server_id: Optional[str] = Field(None, description="Server ID to analyze")
    user_id: Optional[str] = Field(None, description="User ID to analyze")
    
    # Analysis configuration
    analysis_type: str = Field("comprehensive", description="Type of analysis to perform")
    include_message_analysis: bool = Field(True, description="Whether to analyze messages")
    include_member_analysis: bool = Field(False, description="Whether to analyze members")
    include_role_analysis: bool = Field(True, description="Whether to analyze roles and permissions")
    
    # Scope and timeframe
    timeframe_days: int = Field(30, ge=1, le=365, description="Analysis timeframe in days")
    max_messages: int = Field(100, ge=1, le=1000, description="Maximum messages to analyze")
    max_channels: int = Field(10, ge=1, le=50, description="Maximum channels to analyze")
    
    # Additional options
    deep_security_scan: bool = Field(False, description="Perform deep security scan")
    check_invite_links: bool = Field(True, description="Check server invite links")
    analyze_bots: bool = Field(True, description="Analyze bot accounts")
    
    @validator('target_url')
    def validate_discord_url(cls, v):
        """Validate that the URL is a valid Discord URL."""
        if v and not v.startswith(('https://discord.gg/', 'https://discord.com/invite/', 'discord.gg/')):
            raise ValueError('Invalid Discord invite URL format')
        return v


class DiscordAnalysisResponse(BaseModel):
    """Response model for Discord analysis."""
    
    # Analysis metadata
    analysis_id: str = Field(..., description="Unique analysis ID")
    target_identifier: str = Field(..., description="Analyzed Discord identifier")
    analysis_timestamp: datetime = Field(..., description="Analysis completion timestamp")
    
    # Target information
    profile_data: DiscordProfileData = Field(..., description="Profile/server data")
    entity_type: DiscordEntityType = Field(..., description="Type of analyzed entity")
    
    # Risk assessment
    overall_risk_level: RiskLevel = Field(..., description="Overall risk level")
    overall_risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall risk score")
    risk_factors: DiscordRiskFactors = Field(..., description="Detailed risk factors")
    
    # Analysis results
    message_analysis: Optional[Dict[str, Any]] = Field(None, description="Message analysis results")
    member_analysis: Optional[Dict[str, Any]] = Field(None, description="Member analysis results")
    channel_analysis: Optional[Dict[str, Any]] = Field(None, description="Channel analysis results")
    
    # Security findings
    security_issues: List[Dict[str, Any]] = Field(default_factory=list, description="Security issues found")
    moderation_gaps: List[str] = Field(default_factory=list, description="Moderation gaps identified")
    
    # Recommendations and alerts
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    alerts: List[str] = Field(default_factory=list, description="Security alerts")
    immediate_actions: List[str] = Field(default_factory=list, description="Immediate actions needed")
    
    # Confidence and reliability
    confidence_score: float = Field(0.8, ge=0.0, le=1.0, description="Analysis confidence score")
    data_completeness: float = Field(0.8, ge=0.0, le=1.0, description="Data completeness score")
    
    # Additional insights
    related_servers: List[Dict[str, Any]] = Field(default_factory=list, description="Related servers found")
    bot_analysis: List[Dict[str, Any]] = Field(default_factory=list, description="Bot analysis results")
    
    class Config:
        use_enum_values = True


class DiscordServerAnalysis(BaseModel):
    """Specialized analysis for Discord servers."""
    
    # Server identification
    server_id: str = Field(..., description="Server ID")
    server_name: str = Field(..., description="Server name")
    
    # Server configuration analysis
    security_configuration: Dict[str, Any] = Field(default_factory=dict, description="Security configuration analysis")
    moderation_setup: Dict[str, Any] = Field(default_factory=dict, description="Moderation setup analysis")
    
    # Member analysis
    member_statistics: Dict[str, Any] = Field(default_factory=dict, description="Member statistics")
    suspicious_members: List[Dict[str, Any]] = Field(default_factory=list, description="Suspicious members identified")
    
    # Channel analysis
    channel_security: Dict[str, Any] = Field(default_factory=dict, description="Channel security analysis")
    permission_analysis: Dict[str, Any] = Field(default_factory=dict, description="Permission structure analysis")
    
    # Activity patterns
    activity_patterns: Dict[str, Any] = Field(default_factory=dict, description="Server activity patterns")
    growth_analysis: Dict[str, Any] = Field(default_factory=dict, description="Server growth analysis")
    
    # Risk assessment
    raid_protection_score: float = Field(0.5, ge=0.0, le=1.0, description="Raid protection effectiveness")
    community_health_score: float = Field(0.5, ge=0.0, le=1.0, description="Community health score")
    
    # Compliance and guidelines
    tos_compliance_score: float = Field(0.8, ge=0.0, le=1.0, description="Terms of Service compliance")
    community_guidelines_adherence: float = Field(0.8, ge=0.0, le=1.0, description="Community guidelines adherence")


class DiscordBotAnalysis(BaseModel):
    """Specialized analysis for Discord bots."""
    
    # Bot identification
    bot_id: str = Field(..., description="Bot user ID")
    bot_name: str = Field(..., description="Bot name")
    
    # Bot characteristics
    is_verified: bool = Field(False, description="Bot verification status")
    is_public: bool = Field(True, description="Whether bot can be invited by anyone")
    requires_code_grant: bool = Field(False, description="Whether bot requires code grant")
    
    # Permissions analysis
    requested_permissions: List[str] = Field(default_factory=list, description="Permissions requested by bot")
    dangerous_permissions: List[str] = Field(default_factory=list, description="Dangerous permissions identified")
    
    # Functionality analysis
    command_analysis: Dict[str, Any] = Field(default_factory=dict, description="Bot command analysis")
    interaction_patterns: Dict[str, Any] = Field(default_factory=dict, description="Bot interaction patterns")
    
    # Security assessment
    bot_security_score: float = Field(0.5, ge=0.0, le=1.0, description="Bot security score")
    malicious_indicators: List[str] = Field(default_factory=list, description="Malicious behavior indicators")
    
    # Privacy and data handling
    data_collection_practices: List[str] = Field(default_factory=list, description="Data collection practices")
    privacy_concerns: List[str] = Field(default_factory=list, description="Privacy concerns identified")


class DiscordContentAnalysisRequest(BaseModel):
    """Request model for Discord content analysis."""
    
    # Content identification
    server_id: Optional[str] = Field(None, description="Server ID")
    channel_id: str = Field(..., description="Channel ID")
    message_ids: List[str] = Field(..., description="Message IDs to analyze")
    
    # Analysis options
    analyze_attachments: bool = Field(True, description="Analyze message attachments")
    analyze_embeds: bool = Field(True, description="Analyze message embeds")
    analyze_reactions: bool = Field(True, description="Analyze message reactions")
    
    # Context and scope
    include_context: bool = Field(True, description="Include surrounding message context")
    context_range: int = Field(5, ge=0, le=20, description="Number of context messages")
    
    # Deep analysis options
    sentiment_analysis: bool = Field(True, description="Perform sentiment analysis")
    toxicity_detection: bool = Field(True, description="Detect toxic content")
    threat_assessment: bool = Field(True, description="Assess threat level")


class DiscordContentAnalysisResponse(BaseModel):
    """Response model for Discord content analysis."""
    
    # Analysis metadata
    analysis_id: str = Field(..., description="Unique analysis ID")
    server_id: Optional[str] = Field(None, description="Server ID")
    channel_id: str = Field(..., description="Channel ID")
    analysis_timestamp: datetime = Field(..., description="Analysis timestamp")
    
    # Content data
    messages_analyzed: List[DiscordMessageData] = Field(..., description="Analyzed message data")
    
    # Risk assessment
    content_risk_level: RiskLevel = Field(..., description="Content risk level")
    content_risk_score: float = Field(..., ge=0.0, le=1.0, description="Content risk score")
    
    # Content analysis results
    toxicity_analysis: Dict[str, Any] = Field(default_factory=dict, description="Toxicity analysis results")
    harassment_detection: Dict[str, Any] = Field(default_factory=dict, description="Harassment detection results")
    spam_detection: Dict[str, Any] = Field(default_factory=dict, description="Spam detection results")
    
    # Threat assessment
    threat_indicators: List[Dict[str, Any]] = Field(default_factory=list, description="Threat indicators found")
    doxxing_risks: List[Dict[str, Any]] = Field(default_factory=list, description="Doxxing risks identified")
    
    # Media and link analysis
    attachment_analysis: Dict[str, Any] = Field(default_factory=dict, description="Attachment analysis results")
    link_analysis: Dict[str, Any] = Field(default_factory=dict, description="Link analysis results")
    
    # Recommendations
    content_recommendations: List[str] = Field(default_factory=list, description="Content-specific recommendations")
    moderation_suggestions: List[str] = Field(default_factory=list, description="Moderation suggestions")
    
    class Config:
        use_enum_values = True


class DiscordRaidDetection(BaseModel):
    """Raid detection and analysis for Discord servers."""
    
    # Detection metadata
    detection_id: str = Field(..., description="Unique detection ID")
    server_id: str = Field(..., description="Target server ID")
    detection_timestamp: datetime = Field(..., description="Detection timestamp")
    
    # Raid characteristics
    raid_type: str = Field(..., description="Type of raid detected")
    severity_level: RiskLevel = Field(..., description="Raid severity level")
    
    # Attack patterns
    join_rate_anomaly: float = Field(0.0, description="Join rate anomaly score")
    message_spam_rate: float = Field(0.0, description="Message spam rate")
    coordinated_behavior_score: float = Field(0.0, description="Coordinated behavior score")
    
    # Participant analysis
    suspected_raiders: List[str] = Field(default_factory=list, description="Suspected raider user IDs")
    bot_participation: bool = Field(False, description="Bot participation detected")
    
    # Impact assessment
    channels_affected: List[str] = Field(default_factory=list, description="Affected channel IDs")
    members_impacted: int = Field(0, description="Number of members impacted")
    
    # Mitigation recommendations
    immediate_actions: List[str] = Field(default_factory=list, description="Immediate mitigation actions")
    prevention_measures: List[str] = Field(default_factory=list, description="Future prevention measures")


class DiscordCommunityMetrics(BaseModel):
    """Community health and engagement metrics for Discord servers."""
    
    # Basic metrics
    total_members: int = Field(0, description="Total member count")
    active_members: int = Field(0, description="Active members (last 30 days)")
    online_members: int = Field(0, description="Currently online members")
    
    # Growth metrics
    member_growth_rate: float = Field(0.0, description="Member growth rate")
    retention_rate: float = Field(0.0, description="Member retention rate")
    churn_rate: float = Field(0.0, description="Member churn rate")
    
    # Engagement metrics
    messages_per_day: float = Field(0.0, description="Average messages per day")
    active_channels_ratio: float = Field(0.0, description="Ratio of active channels")
    engagement_score: float = Field(0.0, description="Overall engagement score")
    
    # Community health indicators
    toxicity_level: float = Field(0.0, ge=0.0, le=1.0, description="Community toxicity level")
    moderation_effectiveness: float = Field(0.5, ge=0.0, le=1.0, description="Moderation effectiveness")
    community_satisfaction: float = Field(0.5, ge=0.0, le=1.0, description="Community satisfaction score")
    
    # Activity patterns
    peak_activity_hours: List[int] = Field(default_factory=list, description="Peak activity hours")
    most_active_channels: List[str] = Field(default_factory=list, description="Most active channel IDs")
    
    # Quality metrics
    content_quality_score: float = Field(0.5, ge=0.0, le=1.0, description="Content quality score")
    discussion_depth_score: float = Field(0.5, ge=0.0, le=1.0, description="Discussion depth score")