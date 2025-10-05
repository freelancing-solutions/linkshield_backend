"""
Telegram-specific Data Models

This module defines data structures for Telegram platform analysis including:
- Profile and channel information
- Message and content data
- Risk assessment models
- Analysis request/response structures
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator
from enum import Enum

from ..types import PlatformType, RiskLevel, ScanStatus, ContentType


class TelegramEntityType(Enum):
    """Types of Telegram entities that can be analyzed."""
    USER = "user"
    CHANNEL = "channel"
    GROUP = "group"
    SUPERGROUP = "supergroup"
    BOT = "bot"


class TelegramChannelType(Enum):
    """Types of Telegram channels."""
    PUBLIC = "public"
    PRIVATE = "private"
    BROADCAST = "broadcast"
    DISCUSSION = "discussion"


class TelegramMessageType(Enum):
    """Types of Telegram messages."""
    TEXT = "text"
    PHOTO = "photo"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    STICKER = "sticker"
    VOICE = "voice"
    VIDEO_NOTE = "video_note"
    CONTACT = "contact"
    LOCATION = "location"
    POLL = "poll"
    FORWARDED = "forwarded"


class TelegramProfileData(BaseModel):
    """Telegram profile/channel data structure."""
    
    # Basic identification
    id: str = Field(..., description="Telegram user/channel ID")
    username: Optional[str] = Field(None, description="Username (without @)")
    title: Optional[str] = Field(None, description="Channel/group title")
    first_name: Optional[str] = Field(None, description="User first name")
    last_name: Optional[str] = Field(None, description="User last name")
    
    # Entity type and verification
    entity_type: TelegramEntityType = Field(..., description="Type of Telegram entity")
    is_verified: bool = Field(False, description="Official verification status")
    is_scam: bool = Field(False, description="Marked as scam by Telegram")
    is_fake: bool = Field(False, description="Marked as fake by Telegram")
    is_bot: bool = Field(False, description="Whether this is a bot account")
    
    # Channel/Group specific data
    channel_type: Optional[TelegramChannelType] = Field(None, description="Channel type if applicable")
    member_count: Optional[int] = Field(None, description="Number of members/subscribers")
    admin_count: Optional[int] = Field(None, description="Number of administrators")
    
    # Profile information
    bio: Optional[str] = Field(None, description="Profile bio/description")
    photo_url: Optional[str] = Field(None, description="Profile photo URL")
    
    # Activity metrics
    last_seen: Optional[datetime] = Field(None, description="Last seen timestamp")
    created_date: Optional[datetime] = Field(None, description="Account creation date")
    
    # Privacy and security settings
    phone_number_visible: bool = Field(False, description="Phone number visibility")
    profile_photo_visible: bool = Field(True, description="Profile photo visibility")
    forward_privacy: str = Field("everyone", description="Message forwarding privacy setting")
    
    # Additional metadata
    language_code: Optional[str] = Field(None, description="User language code")
    premium_user: bool = Field(False, description="Telegram Premium subscriber")
    
    class Config:
        use_enum_values = True


class TelegramMessageData(BaseModel):
    """Telegram message data structure."""
    
    # Message identification
    message_id: int = Field(..., description="Unique message ID")
    chat_id: str = Field(..., description="Chat/channel ID where message was sent")
    
    # Message content
    text: Optional[str] = Field(None, description="Message text content")
    message_type: TelegramMessageType = Field(..., description="Type of message")
    
    # Sender information
    sender_id: Optional[str] = Field(None, description="Sender user ID")
    sender_username: Optional[str] = Field(None, description="Sender username")
    sender_first_name: Optional[str] = Field(None, description="Sender first name")
    
    # Forwarding information
    is_forwarded: bool = Field(False, description="Whether message is forwarded")
    forward_from_id: Optional[str] = Field(None, description="Original sender ID if forwarded")
    forward_from_chat_id: Optional[str] = Field(None, description="Original chat ID if forwarded")
    forward_count: int = Field(0, description="Number of times message was forwarded")
    
    # Media and attachments
    media_urls: List[str] = Field(default_factory=list, description="URLs of attached media")
    file_names: List[str] = Field(default_factory=list, description="Names of attached files")
    sticker_set: Optional[str] = Field(None, description="Sticker set name if sticker message")
    
    # Links and entities
    urls: List[str] = Field(default_factory=list, description="URLs found in message")
    mentions: List[str] = Field(default_factory=list, description="User mentions in message")
    hashtags: List[str] = Field(default_factory=list, description="Hashtags in message")
    
    # Engagement metrics
    views: Optional[int] = Field(None, description="Number of views (channels only)")
    reactions: Dict[str, int] = Field(default_factory=dict, description="Reaction counts")
    
    # Timestamps
    timestamp: datetime = Field(..., description="Message timestamp")
    edit_timestamp: Optional[datetime] = Field(None, description="Last edit timestamp")
    
    # Message properties
    is_reply: bool = Field(False, description="Whether message is a reply")
    reply_to_message_id: Optional[int] = Field(None, description="ID of message being replied to")
    is_pinned: bool = Field(False, description="Whether message is pinned")
    
    class Config:
        use_enum_values = True


class TelegramRiskFactors(BaseModel):
    """Telegram-specific risk factors assessment."""
    
    # Bot and automation risks
    bot_detection_score: float = Field(0.0, ge=0.0, le=1.0, description="Bot detection probability")
    automation_indicators: List[str] = Field(default_factory=list, description="Automation indicators found")
    
    # Subscriber and engagement risks
    fake_subscriber_ratio: float = Field(0.0, ge=0.0, le=1.0, description="Estimated fake subscriber ratio")
    engagement_authenticity: float = Field(1.0, ge=0.0, le=1.0, description="Engagement authenticity score")
    
    # Content and communication risks
    spam_score: float = Field(0.0, ge=0.0, le=1.0, description="Spam content probability")
    scam_indicators: List[str] = Field(default_factory=list, description="Scam pattern indicators")
    malicious_link_count: int = Field(0, ge=0, description="Number of malicious links detected")
    
    # Forward chain analysis
    forward_manipulation_score: float = Field(0.0, ge=0.0, le=1.0, description="Forward chain manipulation score")
    viral_spread_pattern: str = Field("normal", description="Viral spread pattern analysis")
    
    # Channel authenticity (for channels/groups)
    channel_authenticity_score: float = Field(1.0, ge=0.0, le=1.0, description="Channel authenticity score")
    verification_trust_score: float = Field(0.5, ge=0.0, le=1.0, description="Verification trust score")
    
    # Privacy and security concerns
    privacy_risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Privacy risk assessment")
    data_harvesting_indicators: List[str] = Field(default_factory=list, description="Data harvesting indicators")


class TelegramAnalysisRequest(BaseModel):
    """Request model for Telegram analysis."""
    
    # Target identification
    target_url: str = Field(..., description="Telegram URL to analyze")
    target_username: Optional[str] = Field(None, description="Username to analyze")
    target_id: Optional[str] = Field(None, description="Telegram ID to analyze")
    
    # Analysis configuration
    analysis_type: str = Field("comprehensive", description="Type of analysis to perform")
    include_content_analysis: bool = Field(True, description="Whether to analyze content")
    include_member_analysis: bool = Field(False, description="Whether to analyze members (groups/channels)")
    
    # Timeframe and scope
    timeframe_days: int = Field(30, ge=1, le=365, description="Analysis timeframe in days")
    max_messages: int = Field(100, ge=1, le=1000, description="Maximum messages to analyze")
    
    # Additional options
    deep_scan: bool = Field(False, description="Perform deep security scan")
    check_related_entities: bool = Field(True, description="Check related channels/groups")
    
    @validator('target_url')
    def validate_telegram_url(cls, v):
        """Validate that the URL is a valid Telegram URL."""
        if not v.startswith(('https://t.me/', 'https://telegram.me/', 'tg://')):
            raise ValueError('Invalid Telegram URL format')
        return v


class TelegramAnalysisResponse(BaseModel):
    """Response model for Telegram analysis."""
    
    # Analysis metadata
    analysis_id: str = Field(..., description="Unique analysis ID")
    target_url: str = Field(..., description="Analyzed Telegram URL")
    analysis_timestamp: datetime = Field(..., description="Analysis completion timestamp")
    
    # Target information
    profile_data: TelegramProfileData = Field(..., description="Profile/channel data")
    entity_type: TelegramEntityType = Field(..., description="Type of analyzed entity")
    
    # Risk assessment
    overall_risk_level: RiskLevel = Field(..., description="Overall risk level")
    overall_risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall risk score")
    risk_factors: TelegramRiskFactors = Field(..., description="Detailed risk factors")
    
    # Content analysis results
    content_analysis: Optional[Dict[str, Any]] = Field(None, description="Content analysis results")
    message_count_analyzed: int = Field(0, description="Number of messages analyzed")
    
    # Recommendations and alerts
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    alerts: List[str] = Field(default_factory=list, description="Security alerts")
    
    # Confidence and reliability
    confidence_score: float = Field(0.8, ge=0.0, le=1.0, description="Analysis confidence score")
    data_completeness: float = Field(0.8, ge=0.0, le=1.0, description="Data completeness score")
    
    # Additional insights
    related_entities: List[Dict[str, Any]] = Field(default_factory=list, description="Related entities found")
    historical_data: Optional[Dict[str, Any]] = Field(None, description="Historical analysis data")
    
    class Config:
        use_enum_values = True


class TelegramContentAnalysisRequest(BaseModel):
    """Request model for Telegram content analysis."""
    
    # Content identification
    chat_id: str = Field(..., description="Chat/channel ID")
    message_ids: List[int] = Field(..., description="Message IDs to analyze")
    
    # Analysis options
    analyze_media: bool = Field(True, description="Analyze media content")
    analyze_links: bool = Field(True, description="Analyze embedded links")
    analyze_forwards: bool = Field(True, description="Analyze forward chains")
    
    # Context information
    context_messages: int = Field(5, ge=0, le=20, description="Number of context messages to include")
    include_sender_analysis: bool = Field(True, description="Include sender profile analysis")


class TelegramContentAnalysisResponse(BaseModel):
    """Response model for Telegram content analysis."""
    
    # Analysis metadata
    analysis_id: str = Field(..., description="Unique analysis ID")
    chat_id: str = Field(..., description="Analyzed chat/channel ID")
    analysis_timestamp: datetime = Field(..., description="Analysis timestamp")
    
    # Content data
    messages_analyzed: List[TelegramMessageData] = Field(..., description="Analyzed message data")
    
    # Risk assessment
    content_risk_level: RiskLevel = Field(..., description="Content risk level")
    content_risk_score: float = Field(..., ge=0.0, le=1.0, description="Content risk score")
    
    # Specific risk findings
    spam_detection: Dict[str, Any] = Field(default_factory=dict, description="Spam detection results")
    malicious_links: List[Dict[str, Any]] = Field(default_factory=list, description="Malicious links found")
    scam_indicators: List[Dict[str, Any]] = Field(default_factory=list, description="Scam indicators found")
    
    # Forward chain analysis
    forward_analysis: Dict[str, Any] = Field(default_factory=dict, description="Forward chain analysis")
    viral_patterns: List[str] = Field(default_factory=list, description="Viral spread patterns detected")
    
    # Media analysis
    media_analysis: Dict[str, Any] = Field(default_factory=dict, description="Media content analysis")
    
    # Recommendations
    content_recommendations: List[str] = Field(default_factory=list, description="Content-specific recommendations")
    moderation_actions: List[str] = Field(default_factory=list, description="Suggested moderation actions")
    
    class Config:
        use_enum_values = True


class TelegramBotAnalysis(BaseModel):
    """Specialized analysis for Telegram bots."""
    
    # Bot identification
    bot_id: str = Field(..., description="Bot user ID")
    bot_username: str = Field(..., description="Bot username")
    
    # Bot characteristics
    is_inline_bot: bool = Field(False, description="Whether bot supports inline queries")
    supports_groups: bool = Field(True, description="Whether bot can be added to groups")
    privacy_mode: bool = Field(True, description="Bot privacy mode setting")
    
    # Functionality analysis
    command_list: List[str] = Field(default_factory=list, description="Available bot commands")
    permissions_requested: List[str] = Field(default_factory=list, description="Permissions requested by bot")
    
    # Security assessment
    bot_security_score: float = Field(0.5, ge=0.0, le=1.0, description="Bot security score")
    malicious_behavior_indicators: List[str] = Field(default_factory=list, description="Malicious behavior indicators")
    
    # Usage patterns
    interaction_patterns: Dict[str, Any] = Field(default_factory=dict, description="Bot interaction patterns")
    user_data_collection: List[str] = Field(default_factory=list, description="Types of user data collected")


class TelegramChannelMetrics(BaseModel):
    """Metrics and analytics for Telegram channels."""
    
    # Basic metrics
    subscriber_count: int = Field(0, description="Current subscriber count")
    active_members: int = Field(0, description="Active members count")
    
    # Growth metrics
    growth_rate_daily: float = Field(0.0, description="Daily growth rate")
    growth_rate_weekly: float = Field(0.0, description="Weekly growth rate")
    growth_rate_monthly: float = Field(0.0, description="Monthly growth rate")
    
    # Engagement metrics
    average_views_per_post: float = Field(0.0, description="Average views per post")
    engagement_rate: float = Field(0.0, description="Overall engagement rate")
    
    # Content metrics
    posting_frequency: float = Field(0.0, description="Posts per day")
    content_diversity_score: float = Field(0.0, description="Content diversity score")
    
    # Quality indicators
    subscriber_authenticity_score: float = Field(1.0, ge=0.0, le=1.0, description="Subscriber authenticity score")
    content_quality_score: float = Field(0.5, ge=0.0, le=1.0, description="Content quality score")
    
    # Temporal analysis
    peak_activity_hours: List[int] = Field(default_factory=list, description="Peak activity hours")
    activity_consistency_score: float = Field(0.5, ge=0.0, le=1.0, description="Activity consistency score")