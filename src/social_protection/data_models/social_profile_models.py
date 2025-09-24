"""
Social Profile Data Models

This module defines Pydantic models for social media profile scanning,
risk assessment, and security analysis data structures.

Used for validating and serializing social protection profile data
across different platform adapters and services.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, validator

from ..platform_adapters.base_adapter import PlatformType, RiskLevel


class ProfileVerificationStatus(str, Enum):
    """Profile verification status across platforms."""
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    PENDING = "pending"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


class FollowerAuthenticityLevel(str, Enum):
    """Follower authenticity assessment levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SUSPICIOUS = "suspicious"


class SocialProfileInfo(BaseModel):
    """Basic social media profile information."""
    
    user_id: str = Field(..., description="Platform-specific user identifier")
    username: str = Field(..., description="Profile username or handle")
    display_name: Optional[str] = Field(None, description="Profile display name")
    bio: Optional[str] = Field(None, description="Profile biography/description")
    profile_image_url: Optional[str] = Field(None, description="Profile image URL")
    follower_count: int = Field(0, description="Number of followers")
    following_count: int = Field(0, description="Number of accounts following")
    post_count: int = Field(0, description="Total number of posts")
    verification_status: ProfileVerificationStatus = Field(
        ProfileVerificationStatus.UNKNOWN,
        description="Profile verification status"
    )
    account_created_date: Optional[datetime] = Field(None, description="Account creation date")
    last_activity_date: Optional[datetime] = Field(None, description="Last activity timestamp")
    platform: PlatformType = Field(..., description="Social media platform")
    
    class Config:
        use_enum_values = True


class FollowerAnalysis(BaseModel):
    """Follower authenticity and quality analysis."""
    
    total_followers: int = Field(0, description="Total follower count")
    authentic_followers: int = Field(0, description="Estimated authentic followers")
    suspicious_followers: int = Field(0, description="Suspicious/fake followers detected")
    authenticity_score: float = Field(0.0, ge=0.0, le=1.0, description="Follower authenticity score")
    authenticity_level: FollowerAuthenticityLevel = Field(
        FollowerAuthenticityLevel.MEDIUM,
        description="Overall authenticity assessment"
    )
    bot_indicators: List[str] = Field(default_factory=list, description="Bot detection indicators")
    engagement_quality: float = Field(0.0, ge=0.0, le=1.0, description="Engagement quality score")
    follower_growth_pattern: str = Field("normal", description="Follower growth pattern analysis")
    
    @validator('authenticity_score', 'engagement_quality')
    def validate_scores(cls, v):
        """Validate score values are between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError('Score must be between 0.0 and 1.0')
        return v


class ProfileRiskFactor(BaseModel):
    """Individual risk factor assessment."""
    
    factor_name: str = Field(..., description="Risk factor identifier")
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Risk score for this factor")
    risk_level: RiskLevel = Field(RiskLevel.LOW, description="Risk level classification")
    description: str = Field("", description="Risk factor description")
    indicators: List[str] = Field(default_factory=list, description="Specific risk indicators")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence in assessment")
    
    class Config:
        use_enum_values = True


class ProfileSecurityAssessment(BaseModel):
    """Comprehensive profile security assessment."""
    
    profile_id: str = Field(..., description="Profile identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    assessment_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Assessment timestamp")
    overall_risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall risk score")
    overall_risk_level: RiskLevel = Field(RiskLevel.LOW, description="Overall risk level")
    
    # Risk factor assessments
    risk_factors: Dict[str, ProfileRiskFactor] = Field(
        default_factory=dict,
        description="Individual risk factor assessments"
    )
    
    # Follower analysis
    follower_analysis: Optional[FollowerAnalysis] = Field(None, description="Follower authenticity analysis")
    
    # Profile completeness and authenticity
    profile_completeness_score: float = Field(0.0, ge=0.0, le=1.0, description="Profile completeness score")
    authenticity_indicators: List[str] = Field(default_factory=list, description="Profile authenticity indicators")
    
    # Security recommendations
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    action_items: List[str] = Field(default_factory=list, description="Recommended action items")
    
    class Config:
        use_enum_values = True


class ProfileScanRequest(BaseModel):
    """Request model for profile scanning."""
    
    platform: PlatformType = Field(..., description="Target social media platform")
    profile_identifier: str = Field(..., description="Profile username or ID to scan")
    scan_options: Dict[str, Any] = Field(default_factory=dict, description="Platform-specific scan options")
    include_followers: bool = Field(True, description="Include follower analysis")
    include_content_analysis: bool = Field(False, description="Include recent content analysis")
    depth_level: str = Field("standard", description="Scan depth level: basic, standard, comprehensive")
    
    class Config:
        use_enum_values = True


class ProfileScanResult(BaseModel):
    """Complete profile scan result."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    request: ProfileScanRequest = Field(..., description="Original scan request")
    profile_info: SocialProfileInfo = Field(..., description="Basic profile information")
    security_assessment: ProfileSecurityAssessment = Field(..., description="Security assessment results")
    
    # Scan metadata
    scan_started_at: datetime = Field(default_factory=datetime.utcnow, description="Scan start timestamp")
    scan_completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")
    scan_duration_seconds: Optional[float] = Field(None, description="Scan duration in seconds")
    scan_status: str = Field("completed", description="Scan status")
    
    # Additional analysis results
    content_analysis_summary: Optional[Dict[str, Any]] = Field(None, description="Content analysis summary")
    network_analysis: Optional[Dict[str, Any]] = Field(None, description="Network connection analysis")
    
    class Config:
        use_enum_values = True


class BulkProfileScanRequest(BaseModel):
    """Request model for bulk profile scanning."""
    
    platform: PlatformType = Field(..., description="Target social media platform")
    profile_identifiers: List[str] = Field(..., description="List of profile usernames or IDs to scan")
    scan_options: Dict[str, Any] = Field(default_factory=dict, description="Platform-specific scan options")
    batch_size: int = Field(10, ge=1, le=100, description="Batch processing size")
    priority: str = Field("normal", description="Scan priority: low, normal, high")
    
    @validator('profile_identifiers')
    def validate_profile_list(cls, v):
        """Validate profile identifiers list."""
        if not v:
            raise ValueError('Profile identifiers list cannot be empty')
        if len(v) > 1000:
            raise ValueError('Cannot scan more than 1000 profiles in a single request')
        return v
    
    class Config:
        use_enum_values = True


class BulkProfileScanResult(BaseModel):
    """Bulk profile scan result."""
    
    batch_id: str = Field(..., description="Unique batch identifier")
    request: BulkProfileScanRequest = Field(..., description="Original bulk scan request")
    
    # Scan results
    successful_scans: List[ProfileScanResult] = Field(default_factory=list, description="Successful scan results")
    failed_scans: List[Dict[str, Any]] = Field(default_factory=list, description="Failed scan details")
    
    # Batch statistics
    total_requested: int = Field(0, description="Total profiles requested")
    total_successful: int = Field(0, description="Total successful scans")
    total_failed: int = Field(0, description="Total failed scans")
    
    # Batch metadata
    batch_started_at: datetime = Field(default_factory=datetime.utcnow, description="Batch start timestamp")
    batch_completed_at: Optional[datetime] = Field(None, description="Batch completion timestamp")
    batch_duration_seconds: Optional[float] = Field(None, description="Batch duration in seconds")
    
    class Config:
        use_enum_values = True


class ProfileMonitoringConfig(BaseModel):
    """Configuration for ongoing profile monitoring."""
    
    profile_id: str = Field(..., description="Profile to monitor")
    platform: PlatformType = Field(..., description="Social media platform")
    monitoring_frequency: str = Field("daily", description="Monitoring frequency: hourly, daily, weekly")
    alert_thresholds: Dict[str, float] = Field(default_factory=dict, description="Alert threshold configurations")
    notification_channels: List[str] = Field(default_factory=list, description="Notification delivery channels")
    active: bool = Field(True, description="Monitoring active status")
    
    class Config:
        use_enum_values = True


class ProfileMonitoringAlert(BaseModel):
    """Profile monitoring alert."""
    
    alert_id: str = Field(..., description="Unique alert identifier")
    profile_id: str = Field(..., description="Monitored profile identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    alert_type: str = Field(..., description="Type of alert triggered")
    risk_level: RiskLevel = Field(..., description="Alert risk level")
    alert_message: str = Field(..., description="Alert message")
    alert_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Alert timestamp")
    
    # Alert details
    trigger_data: Dict[str, Any] = Field(default_factory=dict, description="Data that triggered the alert")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended response actions")
    
    # Alert status
    acknowledged: bool = Field(False, description="Alert acknowledgment status")
    resolved: bool = Field(False, description="Alert resolution status")
    
    class Config:
        use_enum_values = True