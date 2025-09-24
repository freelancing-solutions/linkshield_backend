"""
Social Protection Assessment Data Models

This module defines Pydantic models for comprehensive social protection assessments,
including algorithm health monitoring, reputation tracking, and crisis detection.

Used for validating and serializing assessment data across different
social protection services and monitoring systems.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, validator

from ..platform_adapters.base_adapter import PlatformType, RiskLevel


class AlgorithmHealthStatus(str, Enum):
    """Algorithm health status levels."""
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class VisibilityTrend(str, Enum):
    """Visibility trend directions."""
    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"
    VOLATILE = "volatile"
    UNKNOWN = "unknown"


class PenaltyType(str, Enum):
    """Types of algorithmic penalties."""
    SHADOW_BAN = "shadow_ban"
    REACH_LIMITATION = "reach_limitation"
    ENGAGEMENT_THROTTLING = "engagement_throttling"
    CONTENT_SUPPRESSION = "content_suppression"
    SEARCH_VISIBILITY_REDUCTION = "search_visibility_reduction"
    RECOMMENDATION_EXCLUSION = "recommendation_exclusion"
    MONETIZATION_RESTRICTION = "monetization_restriction"


class CrisisType(str, Enum):
    """Types of social media crises."""
    REPUTATION_ATTACK = "reputation_attack"
    VIRAL_NEGATIVE_CONTENT = "viral_negative_content"
    COORDINATED_HARASSMENT = "coordinated_harassment"
    MISINFORMATION_SPREAD = "misinformation_spread"
    ACCOUNT_COMPROMISE = "account_compromise"
    MASS_REPORTING = "mass_reporting"
    ALGORITHMIC_PENALTY = "algorithmic_penalty"
    BRAND_IMPERSONATION = "brand_impersonation"


class CrisisSeverity(str, Enum):
    """Crisis severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class EngagementMetrics(BaseModel):
    """Social media engagement metrics."""
    
    # Basic engagement
    likes: int = Field(0, description="Number of likes")
    shares: int = Field(0, description="Number of shares")
    comments: int = Field(0, description="Number of comments")
    views: int = Field(0, description="Number of views")
    saves: int = Field(0, description="Number of saves/bookmarks")
    
    # Advanced engagement
    reach: int = Field(0, description="Content reach")
    impressions: int = Field(0, description="Content impressions")
    click_through_rate: float = Field(0.0, ge=0.0, le=1.0, description="Click-through rate")
    engagement_rate: float = Field(0.0, ge=0.0, le=1.0, description="Overall engagement rate")
    
    # Time-based metrics
    engagement_velocity: float = Field(0.0, description="Engagement velocity (engagements per hour)")
    peak_engagement_time: Optional[datetime] = Field(None, description="Peak engagement timestamp")
    
    # Quality metrics
    positive_sentiment_ratio: float = Field(0.0, ge=0.0, le=1.0, description="Positive sentiment ratio")
    authentic_engagement_ratio: float = Field(1.0, ge=0.0, le=1.0, description="Authentic engagement ratio")
    
    @validator('click_through_rate', 'engagement_rate', 'positive_sentiment_ratio', 'authentic_engagement_ratio')
    def validate_ratios(cls, v):
        """Validate ratio values are between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError('Ratio must be between 0.0 and 1.0')
        return v


class VisibilityMetrics(BaseModel):
    """Content visibility and reach metrics."""
    
    # Visibility scores
    overall_visibility_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall visibility score")
    organic_reach_score: float = Field(0.0, ge=0.0, le=1.0, description="Organic reach score")
    search_visibility_score: float = Field(0.0, ge=0.0, le=1.0, description="Search visibility score")
    recommendation_score: float = Field(0.0, ge=0.0, le=1.0, description="Recommendation algorithm score")
    
    # Trend analysis
    visibility_trend: VisibilityTrend = Field(VisibilityTrend.UNKNOWN, description="Visibility trend direction")
    trend_confidence: float = Field(0.0, ge=0.0, le=1.0, description="Trend analysis confidence")
    
    # Comparative metrics
    industry_percentile: Optional[float] = Field(None, ge=0.0, le=100.0, description="Industry percentile ranking")
    competitor_comparison: Dict[str, float] = Field(
        default_factory=dict,
        description="Comparison with competitors"
    )
    
    # Historical data
    visibility_history: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Historical visibility data points"
    )
    
    class Config:
        use_enum_values = True


class AlgorithmHealthAssessment(BaseModel):
    """Comprehensive algorithm health assessment."""
    
    account_id: str = Field(..., description="Account identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    assessment_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Assessment timestamp")
    
    # Overall health
    health_status: AlgorithmHealthStatus = Field(..., description="Overall algorithm health status")
    health_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall health score")
    
    # Detailed metrics
    engagement_metrics: EngagementMetrics = Field(..., description="Engagement metrics")
    visibility_metrics: VisibilityMetrics = Field(..., description="Visibility metrics")
    
    # Penalty detection
    detected_penalties: List[PenaltyType] = Field(default_factory=list, description="Detected penalties")
    penalty_confidence: Dict[PenaltyType, float] = Field(
        default_factory=dict,
        description="Confidence scores for detected penalties"
    )
    shadow_ban_probability: float = Field(0.0, ge=0.0, le=1.0, description="Shadow ban probability")
    
    # Performance indicators
    content_performance_decline: bool = Field(False, description="Content performance decline detected")
    engagement_drop_percentage: float = Field(0.0, description="Engagement drop percentage")
    reach_limitation_detected: bool = Field(False, description="Reach limitation detected")
    
    # Recommendations
    improvement_recommendations: List[str] = Field(
        default_factory=list,
        description="Algorithm health improvement recommendations"
    )
    risk_mitigation_actions: List[str] = Field(
        default_factory=list,
        description="Risk mitigation actions"
    )
    
    class Config:
        use_enum_values = True


class ReputationMetrics(BaseModel):
    """Brand and reputation monitoring metrics."""
    
    # Overall reputation
    reputation_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall reputation score")
    sentiment_score: float = Field(0.0, ge=-1.0, le=1.0, description="Overall sentiment score")
    brand_health_score: float = Field(0.0, ge=0.0, le=1.0, description="Brand health score")
    
    # Mention analysis
    total_mentions: int = Field(0, description="Total mentions in monitoring period")
    positive_mentions: int = Field(0, description="Positive mentions")
    negative_mentions: int = Field(0, description="Negative mentions")
    neutral_mentions: int = Field(0, description="Neutral mentions")
    
    # Engagement with mentions
    mention_engagement_rate: float = Field(0.0, ge=0.0, le=1.0, description="Mention engagement rate")
    response_rate: float = Field(0.0, ge=0.0, le=1.0, description="Response rate to mentions")
    average_response_time_hours: float = Field(0.0, description="Average response time in hours")
    
    # Influence metrics
    influencer_mentions: int = Field(0, description="Mentions by influencers")
    viral_content_count: int = Field(0, description="Viral content mentioning brand")
    share_of_voice: float = Field(0.0, ge=0.0, le=1.0, description="Share of voice in industry")
    
    # Risk indicators
    reputation_risk_factors: List[str] = Field(default_factory=list, description="Reputation risk factors")
    trending_negative_topics: List[str] = Field(default_factory=list, description="Trending negative topics")
    
    @validator('sentiment_score')
    def validate_sentiment_score(cls, v):
        """Validate sentiment score is between -1 and 1."""
        if not -1.0 <= v <= 1.0:
            raise ValueError('Sentiment score must be between -1.0 and 1.0')
        return v


class MentionData(BaseModel):
    """Individual mention data."""
    
    mention_id: str = Field(..., description="Unique mention identifier")
    platform: PlatformType = Field(..., description="Platform where mention occurred")
    author_id: str = Field(..., description="Mention author identifier")
    author_username: str = Field(..., description="Mention author username")
    
    # Mention content
    content: str = Field(..., description="Mention content")
    mention_type: str = Field("direct", description="Type of mention: direct, indirect, hashtag")
    context: str = Field("", description="Mention context")
    
    # Metrics
    sentiment: str = Field("neutral", description="Mention sentiment: positive, negative, neutral")
    sentiment_score: float = Field(0.0, ge=-1.0, le=1.0, description="Sentiment score")
    influence_score: float = Field(0.0, ge=0.0, le=1.0, description="Author influence score")
    reach: int = Field(0, description="Mention reach")
    engagement: int = Field(0, description="Mention engagement")
    
    # Timestamps
    created_at: datetime = Field(..., description="Mention creation timestamp")
    detected_at: datetime = Field(default_factory=datetime.utcnow, description="Detection timestamp")
    
    # Response tracking
    responded: bool = Field(False, description="Whether mention was responded to")
    response_time_hours: Optional[float] = Field(None, description="Response time in hours")
    response_quality_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Response quality score")
    
    class Config:
        use_enum_values = True


class ReputationAssessment(BaseModel):
    """Comprehensive reputation assessment."""
    
    brand_id: str = Field(..., description="Brand identifier")
    assessment_period_days: int = Field(7, description="Assessment period in days")
    assessment_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Assessment timestamp")
    
    # Overall assessment
    reputation_metrics: ReputationMetrics = Field(..., description="Reputation metrics")
    
    # Detailed mention analysis
    mentions: List[MentionData] = Field(default_factory=list, description="Individual mentions")
    mention_summary: Dict[str, Any] = Field(default_factory=dict, description="Mention summary statistics")
    
    # Trend analysis
    reputation_trend: str = Field("stable", description="Reputation trend: improving, stable, declining")
    trend_confidence: float = Field(0.0, ge=0.0, le=1.0, description="Trend confidence")
    
    # Competitive analysis
    competitor_comparison: Dict[str, float] = Field(
        default_factory=dict,
        description="Reputation comparison with competitors"
    )
    
    # Risk assessment
    reputation_risks: List[str] = Field(default_factory=list, description="Identified reputation risks")
    crisis_probability: float = Field(0.0, ge=0.0, le=1.0, description="Crisis probability score")
    
    # Recommendations
    reputation_recommendations: List[str] = Field(
        default_factory=list,
        description="Reputation improvement recommendations"
    )
    
    class Config:
        use_enum_values = True


class CrisisIndicator(BaseModel):
    """Individual crisis indicator."""
    
    indicator_id: str = Field(..., description="Unique indicator identifier")
    indicator_type: str = Field(..., description="Type of crisis indicator")
    severity: CrisisSeverity = Field(..., description="Indicator severity")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Indicator confidence")
    
    # Indicator details
    description: str = Field(..., description="Indicator description")
    evidence: List[str] = Field(default_factory=list, description="Supporting evidence")
    affected_platforms: List[PlatformType] = Field(default_factory=list, description="Affected platforms")
    
    # Metrics
    impact_score: float = Field(0.0, ge=0.0, le=1.0, description="Potential impact score")
    urgency_score: float = Field(0.0, ge=0.0, le=1.0, description="Urgency score")
    spread_velocity: float = Field(0.0, description="Crisis spread velocity")
    
    # Timeline
    first_detected: datetime = Field(default_factory=datetime.utcnow, description="First detection timestamp")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    estimated_peak: Optional[datetime] = Field(None, description="Estimated crisis peak time")
    
    class Config:
        use_enum_values = True


class CrisisAssessment(BaseModel):
    """Comprehensive crisis detection and assessment."""
    
    assessment_id: str = Field(..., description="Unique assessment identifier")
    account_id: str = Field(..., description="Account identifier")
    crisis_type: CrisisType = Field(..., description="Type of crisis detected")
    severity: CrisisSeverity = Field(..., description="Crisis severity level")
    
    # Crisis metrics
    crisis_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall crisis score")
    impact_assessment: float = Field(0.0, ge=0.0, le=1.0, description="Potential impact assessment")
    containment_difficulty: float = Field(0.0, ge=0.0, le=1.0, description="Containment difficulty score")
    
    # Crisis indicators
    indicators: List[CrisisIndicator] = Field(default_factory=list, description="Crisis indicators")
    trigger_events: List[str] = Field(default_factory=list, description="Events that triggered the crisis")
    
    # Affected areas
    affected_platforms: List[PlatformType] = Field(default_factory=list, description="Affected platforms")
    affected_content: List[str] = Field(default_factory=list, description="Affected content identifiers")
    stakeholder_impact: Dict[str, str] = Field(default_factory=dict, description="Stakeholder impact assessment")
    
    # Timeline and progression
    crisis_start: datetime = Field(default_factory=datetime.utcnow, description="Crisis start timestamp")
    detection_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Detection timestamp")
    estimated_duration: Optional[timedelta] = Field(None, description="Estimated crisis duration")
    progression_stage: str = Field("emerging", description="Crisis progression stage")
    
    # Response planning
    immediate_actions: List[str] = Field(default_factory=list, description="Immediate response actions")
    escalation_triggers: List[str] = Field(default_factory=list, description="Escalation triggers")
    communication_plan: Dict[str, Any] = Field(default_factory=dict, description="Crisis communication plan")
    
    # Monitoring
    monitoring_frequency: str = Field("continuous", description="Monitoring frequency during crisis")
    key_metrics_to_track: List[str] = Field(default_factory=list, description="Key metrics to monitor")
    
    class Config:
        use_enum_values = True


class ComprehensiveAssessment(BaseModel):
    """Complete social protection assessment combining all modules."""
    
    assessment_id: str = Field(..., description="Unique comprehensive assessment identifier")
    account_id: str = Field(..., description="Account identifier")
    platforms: List[PlatformType] = Field(..., description="Assessed platforms")
    assessment_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Assessment timestamp")
    
    # Individual assessments
    algorithm_health: Optional[AlgorithmHealthAssessment] = Field(
        None,
        description="Algorithm health assessment"
    )
    reputation_assessment: Optional[ReputationAssessment] = Field(
        None,
        description="Reputation assessment"
    )
    crisis_assessment: Optional[CrisisAssessment] = Field(
        None,
        description="Crisis assessment"
    )
    
    # Overall metrics
    overall_risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall risk score")
    overall_risk_level: RiskLevel = Field(RiskLevel.LOW, description="Overall risk level")
    health_score: float = Field(1.0, ge=0.0, le=1.0, description="Overall health score")
    
    # Consolidated recommendations
    priority_actions: List[str] = Field(default_factory=list, description="Priority action items")
    strategic_recommendations: List[str] = Field(
        default_factory=list,
        description="Strategic recommendations"
    )
    monitoring_recommendations: List[str] = Field(
        default_factory=list,
        description="Monitoring recommendations"
    )
    
    # Assessment metadata
    assessment_duration_seconds: float = Field(0.0, description="Assessment duration in seconds")
    data_sources: List[str] = Field(default_factory=list, description="Data sources used")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall assessment confidence")
    
    class Config:
        use_enum_values = True


class AssessmentHistory(BaseModel):
    """Historical assessment tracking."""
    
    account_id: str = Field(..., description="Account identifier")
    assessment_history: List[ComprehensiveAssessment] = Field(
        default_factory=list,
        description="Historical assessments"
    )
    
    # Trend analysis
    risk_trend: str = Field("stable", description="Risk trend over time")
    health_trend: str = Field("stable", description="Health trend over time")
    improvement_areas: List[str] = Field(default_factory=list, description="Areas showing improvement")
    concern_areas: List[str] = Field(default_factory=list, description="Areas of concern")
    
    # Statistics
    total_assessments: int = Field(0, description="Total number of assessments")
    average_risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Average risk score")
    risk_score_variance: float = Field(0.0, description="Risk score variance")
    
    # Metadata
    tracking_start_date: datetime = Field(default_factory=datetime.utcnow, description="Tracking start date")
    last_assessment_date: Optional[datetime] = Field(None, description="Last assessment date")
    
    class Config:
        use_enum_values = True