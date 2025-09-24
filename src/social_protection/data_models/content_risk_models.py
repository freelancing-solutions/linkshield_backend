"""
Content Risk Assessment Data Models

This module defines Pydantic models for social media content risk assessment,
policy compliance analysis, and content security evaluation.

Used for validating and serializing content analysis data across
different platform adapters and content analysis services.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, validator

from ..platform_adapters.base_adapter import PlatformType, RiskLevel


class ContentType(str, Enum):
    """Social media content types."""
    POST = "post"
    STORY = "story"
    VIDEO = "video"
    IMAGE = "image"
    ARTICLE = "article"
    LIVE_STREAM = "live_stream"
    POLL = "poll"
    EVENT = "event"
    ADVERTISEMENT = "advertisement"
    COMMENT = "comment"
    DIRECT_MESSAGE = "direct_message"


class ContentModerationStatus(str, Enum):
    """Content moderation status."""
    APPROVED = "approved"
    PENDING = "pending"
    FLAGGED = "flagged"
    REMOVED = "removed"
    RESTRICTED = "restricted"
    APPEALED = "appealed"


class PolicyViolationType(str, Enum):
    """Types of policy violations."""
    SPAM = "spam"
    HARASSMENT = "harassment"
    HATE_SPEECH = "hate_speech"
    MISINFORMATION = "misinformation"
    COPYRIGHT = "copyright"
    ADULT_CONTENT = "adult_content"
    VIOLENCE = "violence"
    SELF_HARM = "self_harm"
    ILLEGAL_ACTIVITY = "illegal_activity"
    IMPERSONATION = "impersonation"
    FAKE_ENGAGEMENT = "fake_engagement"
    SCAM = "scam"


class ContentInfo(BaseModel):
    """Basic social media content information."""
    
    content_id: str = Field(..., description="Platform-specific content identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    content_type: ContentType = Field(..., description="Type of content")
    author_id: str = Field(..., description="Content author identifier")
    author_username: str = Field(..., description="Content author username")
    
    # Content details
    text_content: Optional[str] = Field(None, description="Text content")
    media_urls: List[str] = Field(default_factory=list, description="Media file URLs")
    hashtags: List[str] = Field(default_factory=list, description="Content hashtags")
    mentions: List[str] = Field(default_factory=list, description="User mentions")
    links: List[str] = Field(default_factory=list, description="External links")
    
    # Engagement metrics
    likes_count: int = Field(0, description="Number of likes")
    shares_count: int = Field(0, description="Number of shares")
    comments_count: int = Field(0, description="Number of comments")
    views_count: int = Field(0, description="Number of views")
    
    # Timestamps
    created_at: Optional[datetime] = Field(None, description="Content creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Content last update timestamp")
    
    # Moderation status
    moderation_status: ContentModerationStatus = Field(
        ContentModerationStatus.APPROVED,
        description="Content moderation status"
    )
    
    class Config:
        use_enum_values = True


class ContentRiskFactor(BaseModel):
    """Individual content risk factor assessment."""
    
    factor_name: str = Field(..., description="Risk factor identifier")
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Risk score for this factor")
    risk_level: RiskLevel = Field(RiskLevel.LOW, description="Risk level classification")
    description: str = Field("", description="Risk factor description")
    
    # Risk details
    indicators: List[str] = Field(default_factory=list, description="Specific risk indicators")
    evidence: List[str] = Field(default_factory=list, description="Evidence supporting the assessment")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence in assessment")
    
    # Policy implications
    policy_violations: List[PolicyViolationType] = Field(
        default_factory=list,
        description="Potential policy violations"
    )
    
    class Config:
        use_enum_values = True


class SpamAnalysis(BaseModel):
    """Spam detection and analysis results."""
    
    spam_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall spam probability score")
    spam_indicators: List[str] = Field(default_factory=list, description="Detected spam indicators")
    
    # Spam pattern analysis
    repetitive_content: bool = Field(False, description="Repetitive content detected")
    excessive_hashtags: bool = Field(False, description="Excessive hashtag usage")
    suspicious_links: bool = Field(False, description="Suspicious external links")
    fake_engagement_patterns: bool = Field(False, description="Fake engagement patterns")
    
    # Content quality metrics
    content_quality_score: float = Field(0.0, ge=0.0, le=1.0, description="Content quality assessment")
    originality_score: float = Field(0.0, ge=0.0, le=1.0, description="Content originality score")
    
    @validator('spam_score', 'content_quality_score', 'originality_score')
    def validate_scores(cls, v):
        """Validate score values are between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError('Score must be between 0.0 and 1.0')
        return v


class LinkPenaltyAnalysis(BaseModel):
    """Link penalty and safety analysis."""
    
    total_links: int = Field(0, description="Total number of links in content")
    safe_links: int = Field(0, description="Number of safe links")
    suspicious_links: int = Field(0, description="Number of suspicious links")
    malicious_links: int = Field(0, description="Number of malicious links")
    
    # Link analysis details
    link_safety_score: float = Field(1.0, ge=0.0, le=1.0, description="Overall link safety score")
    penalty_risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Link penalty risk score")
    
    # Detailed link assessments
    link_assessments: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Individual link safety assessments"
    )
    
    # Recommendations
    flagged_domains: List[str] = Field(default_factory=list, description="Flagged domains")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended actions")


class SentimentAnalysis(BaseModel):
    """Content sentiment analysis results."""
    
    overall_sentiment: str = Field("neutral", description="Overall sentiment: positive, negative, neutral")
    sentiment_score: float = Field(0.0, ge=-1.0, le=1.0, description="Sentiment score (-1 to 1)")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Sentiment analysis confidence")
    
    # Detailed sentiment breakdown
    positive_indicators: List[str] = Field(default_factory=list, description="Positive sentiment indicators")
    negative_indicators: List[str] = Field(default_factory=list, description="Negative sentiment indicators")
    neutral_indicators: List[str] = Field(default_factory=list, description="Neutral sentiment indicators")
    
    # Emotional analysis
    emotions_detected: Dict[str, float] = Field(
        default_factory=dict,
        description="Detected emotions with confidence scores"
    )
    
    @validator('sentiment_score')
    def validate_sentiment_score(cls, v):
        """Validate sentiment score is between -1 and 1."""
        if not -1.0 <= v <= 1.0:
            raise ValueError('Sentiment score must be between -1.0 and 1.0')
        return v


class ContentRiskAssessment(BaseModel):
    """Comprehensive content risk assessment."""
    
    content_id: str = Field(..., description="Content identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    assessment_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Assessment timestamp")
    
    # Overall risk metrics
    overall_risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall content risk score")
    overall_risk_level: RiskLevel = Field(RiskLevel.LOW, description="Overall risk level")
    
    # Risk factor assessments
    risk_factors: Dict[str, ContentRiskFactor] = Field(
        default_factory=dict,
        description="Individual risk factor assessments"
    )
    
    # Specialized analyses
    spam_analysis: Optional[SpamAnalysis] = Field(None, description="Spam detection analysis")
    link_penalty_analysis: Optional[LinkPenaltyAnalysis] = Field(None, description="Link penalty analysis")
    sentiment_analysis: Optional[SentimentAnalysis] = Field(None, description="Sentiment analysis")
    
    # Policy compliance
    policy_violations: List[PolicyViolationType] = Field(
        default_factory=list,
        description="Detected policy violations"
    )
    compliance_score: float = Field(1.0, ge=0.0, le=1.0, description="Policy compliance score")
    
    # Recommendations
    recommendations: List[str] = Field(default_factory=list, description="Content improvement recommendations")
    action_items: List[str] = Field(default_factory=list, description="Required action items")
    
    class Config:
        use_enum_values = True


class ContentAnalysisRequest(BaseModel):
    """Request model for content analysis."""
    
    platform: PlatformType = Field(..., description="Target social media platform")
    content_identifier: str = Field(..., description="Content ID or URL to analyze")
    analysis_options: Dict[str, Any] = Field(default_factory=dict, description="Analysis configuration options")
    
    # Analysis scope
    include_spam_analysis: bool = Field(True, description="Include spam detection")
    include_link_analysis: bool = Field(True, description="Include link safety analysis")
    include_sentiment_analysis: bool = Field(True, description="Include sentiment analysis")
    include_policy_check: bool = Field(True, description="Include policy compliance check")
    
    # Analysis depth
    analysis_depth: str = Field("standard", description="Analysis depth: basic, standard, comprehensive")
    
    class Config:
        use_enum_values = True


class ContentAnalysisResult(BaseModel):
    """Complete content analysis result."""
    
    analysis_id: str = Field(..., description="Unique analysis identifier")
    request: ContentAnalysisRequest = Field(..., description="Original analysis request")
    content_info: ContentInfo = Field(..., description="Basic content information")
    risk_assessment: ContentRiskAssessment = Field(..., description="Risk assessment results")
    
    # Analysis metadata
    analysis_started_at: datetime = Field(default_factory=datetime.utcnow, description="Analysis start timestamp")
    analysis_completed_at: Optional[datetime] = Field(None, description="Analysis completion timestamp")
    analysis_duration_seconds: Optional[float] = Field(None, description="Analysis duration in seconds")
    analysis_status: str = Field("completed", description="Analysis status")
    
    class Config:
        use_enum_values = True


class BulkContentAnalysisRequest(BaseModel):
    """Request model for bulk content analysis."""
    
    platform: PlatformType = Field(..., description="Target social media platform")
    content_identifiers: List[str] = Field(..., description="List of content IDs or URLs to analyze")
    analysis_options: Dict[str, Any] = Field(default_factory=dict, description="Analysis configuration options")
    batch_size: int = Field(10, ge=1, le=100, description="Batch processing size")
    priority: str = Field("normal", description="Analysis priority: low, normal, high")
    
    @validator('content_identifiers')
    def validate_content_list(cls, v):
        """Validate content identifiers list."""
        if not v:
            raise ValueError('Content identifiers list cannot be empty')
        if len(v) > 1000:
            raise ValueError('Cannot analyze more than 1000 content items in a single request')
        return v
    
    class Config:
        use_enum_values = True


class BulkContentAnalysisResult(BaseModel):
    """Bulk content analysis result."""
    
    batch_id: str = Field(..., description="Unique batch identifier")
    request: BulkContentAnalysisRequest = Field(..., description="Original bulk analysis request")
    
    # Analysis results
    successful_analyses: List[ContentAnalysisResult] = Field(
        default_factory=list,
        description="Successful analysis results"
    )
    failed_analyses: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Failed analysis details"
    )
    
    # Batch statistics
    total_requested: int = Field(0, description="Total content items requested")
    total_successful: int = Field(0, description="Total successful analyses")
    total_failed: int = Field(0, description="Total failed analyses")
    
    # Risk summary
    high_risk_content: int = Field(0, description="Number of high-risk content items")
    medium_risk_content: int = Field(0, description="Number of medium-risk content items")
    low_risk_content: int = Field(0, description="Number of low-risk content items")
    
    # Batch metadata
    batch_started_at: datetime = Field(default_factory=datetime.utcnow, description="Batch start timestamp")
    batch_completed_at: Optional[datetime] = Field(None, description="Batch completion timestamp")
    batch_duration_seconds: Optional[float] = Field(None, description="Batch duration in seconds")
    
    class Config:
        use_enum_values = True


class ContentMonitoringConfig(BaseModel):
    """Configuration for ongoing content monitoring."""
    
    account_id: str = Field(..., description="Account to monitor")
    platform: PlatformType = Field(..., description="Social media platform")
    monitoring_frequency: str = Field("hourly", description="Monitoring frequency: hourly, daily, weekly")
    content_types: List[ContentType] = Field(default_factory=list, description="Content types to monitor")
    
    # Alert configurations
    alert_thresholds: Dict[str, float] = Field(default_factory=dict, description="Alert threshold configurations")
    notification_channels: List[str] = Field(default_factory=list, description="Notification delivery channels")
    
    # Monitoring scope
    monitor_new_content: bool = Field(True, description="Monitor new content")
    monitor_content_changes: bool = Field(True, description="Monitor content modifications")
    monitor_engagement_patterns: bool = Field(True, description="Monitor engagement patterns")
    
    active: bool = Field(True, description="Monitoring active status")
    
    class Config:
        use_enum_values = True


class ContentMonitoringAlert(BaseModel):
    """Content monitoring alert."""
    
    alert_id: str = Field(..., description="Unique alert identifier")
    content_id: str = Field(..., description="Content identifier that triggered alert")
    account_id: str = Field(..., description="Account identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    
    # Alert details
    alert_type: str = Field(..., description="Type of alert triggered")
    risk_level: RiskLevel = Field(..., description="Alert risk level")
    alert_message: str = Field(..., description="Alert message")
    alert_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Alert timestamp")
    
    # Alert context
    trigger_data: Dict[str, Any] = Field(default_factory=dict, description="Data that triggered the alert")
    content_snapshot: Optional[ContentInfo] = Field(None, description="Content snapshot at alert time")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended response actions")
    
    # Alert status
    acknowledged: bool = Field(False, description="Alert acknowledgment status")
    resolved: bool = Field(False, description="Alert resolution status")
    resolution_notes: Optional[str] = Field(None, description="Alert resolution notes")
    
    class Config:
        use_enum_values = True