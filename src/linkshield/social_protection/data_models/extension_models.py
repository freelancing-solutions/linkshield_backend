"""
Browser Extension Integration Data Models

This module defines Pydantic models for browser extension integration,
real-time social media scanning, and extension-backend communication.

Used for validating and serializing data exchanged between the LinkShield
browser extension and the social protection backend services.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field, validator

from ..types import PlatformType, RiskLevel


class ExtensionAction(str, Enum):
    """Browser extension action types."""
    SCAN_PROFILE = "scan_profile"
    ANALYZE_CONTENT = "analyze_content"
    CHECK_LINKS = "check_links"
    MONITOR_FEED = "monitor_feed"
    ASSESS_ALGORITHM = "assess_algorithm"
    DETECT_CRISIS = "detect_crisis"
    GET_RECOMMENDATIONS = "get_recommendations"
    UPDATE_SETTINGS = "update_settings"


class ScanTrigger(str, Enum):
    """Scan trigger sources."""
    USER_INITIATED = "user_initiated"
    AUTOMATIC = "automatic"
    SCHEDULED = "scheduled"
    REAL_TIME = "real_time"
    ALERT_TRIGGERED = "alert_triggered"


class ExtensionStatus(str, Enum):
    """Extension operation status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SCANNING = "scanning"
    ERROR = "error"
    UPDATING = "updating"
    OFFLINE = "offline"


class BrowserInfo(BaseModel):
    """Browser and extension information."""
    
    browser_name: str = Field(..., description="Browser name (Chrome, Firefox, etc.)")
    browser_version: str = Field(..., description="Browser version")
    extension_version: str = Field(..., description="LinkShield extension version")
    user_agent: str = Field(..., description="Browser user agent string")
    
    # Extension capabilities
    supported_platforms: List[PlatformType] = Field(
        default_factory=list,
        description="Supported social media platforms"
    )
    features_enabled: List[str] = Field(default_factory=list, description="Enabled extension features")
    
    class Config:
        use_enum_values = True


class PageContext(BaseModel):
    """Current page context information."""
    
    url: str = Field(..., description="Current page URL")
    domain: str = Field(..., description="Page domain")
    platform: Optional[PlatformType] = Field(None, description="Detected social media platform")
    page_type: str = Field("unknown", description="Type of page (profile, feed, post, etc.)")
    
    # Page metadata
    title: Optional[str] = Field(None, description="Page title")
    language: Optional[str] = Field(None, description="Page language")
    
    # User context
    logged_in: bool = Field(False, description="User logged in status")
    user_id: Optional[str] = Field(None, description="Current user ID if logged in")
    username: Optional[str] = Field(None, description="Current username if logged in")
    
    class Config:
        use_enum_values = True


class ExtensionScanPayload(BaseModel):
    """Payload for extension-initiated scans."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    action: ExtensionAction = Field(..., description="Requested action")
    trigger: ScanTrigger = Field(..., description="Scan trigger source")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Scan request timestamp")
    
    # Context information
    browser_info: BrowserInfo = Field(..., description="Browser and extension information")
    page_context: PageContext = Field(..., description="Current page context")
    
    # Scan parameters
    target_identifier: str = Field(..., description="Target to scan (profile URL, content ID, etc.)")
    scan_options: Dict[str, Any] = Field(default_factory=dict, description="Scan configuration options")
    
    # User preferences
    user_settings: Dict[str, Any] = Field(default_factory=dict, description="User preference settings")
    privacy_level: str = Field("standard", description="Privacy level: minimal, standard, comprehensive")
    
    class Config:
        use_enum_values = True


class RealTimeAssessment(BaseModel):
    """Real-time risk assessment result."""
    
    assessment_id: str = Field(..., description="Unique assessment identifier")
    target_identifier: str = Field(..., description="Assessed target identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    assessment_type: str = Field(..., description="Type of assessment performed")
    
    # Risk assessment
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall risk score")
    risk_level: RiskLevel = Field(RiskLevel.LOW, description="Risk level classification")
    risk_factors: List[str] = Field(default_factory=list, description="Identified risk factors")
    
    # Assessment details
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Assessment confidence")
    assessment_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Assessment timestamp")
    processing_time_ms: int = Field(0, description="Processing time in milliseconds")
    
    # Recommendations
    immediate_actions: List[str] = Field(default_factory=list, description="Immediate recommended actions")
    warnings: List[str] = Field(default_factory=list, description="Warning messages")
    suggestions: List[str] = Field(default_factory=list, description="Improvement suggestions")
    
    class Config:
        use_enum_values = True


class ExtensionResponse(BaseModel):
    """Response from backend to extension."""
    
    response_id: str = Field(..., description="Unique response identifier")
    scan_id: str = Field(..., description="Original scan identifier")
    status: str = Field("success", description="Response status: success, error, partial")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")
    
    # Response data
    assessment: Optional[RealTimeAssessment] = Field(None, description="Risk assessment result")
    data: Dict[str, Any] = Field(default_factory=dict, description="Additional response data")
    
    # Error handling
    error_message: Optional[str] = Field(None, description="Error message if status is error")
    error_code: Optional[str] = Field(None, description="Error code for debugging")
    
    # Performance metrics
    processing_time_ms: int = Field(0, description="Total processing time in milliseconds")
    cache_hit: bool = Field(False, description="Whether result was served from cache")
    
    class Config:
        use_enum_values = True


class FeedMonitoringData(BaseModel):
    """Data for real-time feed monitoring."""
    
    feed_url: str = Field(..., description="Feed URL being monitored")
    platform: PlatformType = Field(..., description="Social media platform")
    monitoring_started: datetime = Field(default_factory=datetime.utcnow, description="Monitoring start time")
    
    # Feed content
    posts_detected: int = Field(0, description="Number of posts detected")
    high_risk_posts: int = Field(0, description="Number of high-risk posts")
    medium_risk_posts: int = Field(0, description="Number of medium-risk posts")
    
    # Risk patterns
    risk_patterns: List[str] = Field(default_factory=list, description="Detected risk patterns")
    trending_risks: List[str] = Field(default_factory=list, description="Trending risk factors")
    
    # Monitoring statistics
    scan_frequency_seconds: int = Field(30, description="Scan frequency in seconds")
    last_scan_timestamp: Optional[datetime] = Field(None, description="Last scan timestamp")
    
    class Config:
        use_enum_values = True


class LinkSafetyCheck(BaseModel):
    """Link safety check result."""
    
    url: str = Field(..., description="Checked URL")
    safety_score: float = Field(1.0, ge=0.0, le=1.0, description="Link safety score")
    risk_level: RiskLevel = Field(RiskLevel.LOW, description="Link risk level")
    
    # Safety analysis
    is_safe: bool = Field(True, description="Overall safety status")
    risk_categories: List[str] = Field(default_factory=list, description="Identified risk categories")
    warnings: List[str] = Field(default_factory=list, description="Safety warnings")
    
    # Link metadata
    domain_reputation: float = Field(1.0, ge=0.0, le=1.0, description="Domain reputation score")
    ssl_status: bool = Field(True, description="SSL certificate status")
    redirect_chain: List[str] = Field(default_factory=list, description="URL redirect chain")
    
    # Check metadata
    check_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Check timestamp")
    check_source: str = Field("linkshield", description="Safety check source")
    
    class Config:
        use_enum_values = True


class ExtensionSettings(BaseModel):
    """Extension user settings and preferences."""
    
    user_id: str = Field(..., description="User identifier")
    
    # General settings
    auto_scan_enabled: bool = Field(True, description="Automatic scanning enabled")
    real_time_monitoring: bool = Field(True, description="Real-time monitoring enabled")
    notification_level: str = Field("medium", description="Notification level: low, medium, high")
    
    # Platform-specific settings
    platform_settings: Dict[PlatformType, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Platform-specific configuration"
    )
    
    # Privacy settings
    data_sharing_level: str = Field("anonymous", description="Data sharing level")
    analytics_enabled: bool = Field(True, description="Analytics collection enabled")
    
    # Alert preferences
    alert_types: List[str] = Field(default_factory=list, description="Enabled alert types")
    alert_frequency: str = Field("immediate", description="Alert frequency: immediate, hourly, daily")
    
    # Advanced settings
    scan_depth: str = Field("standard", description="Scan depth: basic, standard, comprehensive")
    cache_duration_minutes: int = Field(30, description="Result cache duration in minutes")
    
    # Settings metadata
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Settings last updated")
    version: str = Field("1.0", description="Settings schema version")
    
    class Config:
        use_enum_values = True


class ExtensionAnalytics(BaseModel):
    """Extension usage analytics data."""
    
    user_id: str = Field(..., description="User identifier (anonymized)")
    session_id: str = Field(..., description="Session identifier")
    
    # Usage statistics
    scans_performed: int = Field(0, description="Number of scans performed")
    platforms_used: List[PlatformType] = Field(default_factory=list, description="Platforms used")
    features_used: List[str] = Field(default_factory=list, description="Features used")
    
    # Performance metrics
    average_scan_time_ms: float = Field(0.0, description="Average scan time in milliseconds")
    cache_hit_rate: float = Field(0.0, ge=0.0, le=1.0, description="Cache hit rate")
    error_rate: float = Field(0.0, ge=0.0, le=1.0, description="Error rate")
    
    # Risk detection statistics
    high_risk_detections: int = Field(0, description="High-risk detections")
    medium_risk_detections: int = Field(0, description="Medium-risk detections")
    false_positive_reports: int = Field(0, description="User-reported false positives")
    
    # Session metadata
    session_start: datetime = Field(default_factory=datetime.utcnow, description="Session start time")
    session_duration_minutes: int = Field(0, description="Session duration in minutes")
    browser_info: Optional[BrowserInfo] = Field(None, description="Browser information")
    
    class Config:
        use_enum_values = True


class ExtensionHealthCheck(BaseModel):
    """Extension health and status check."""
    
    extension_id: str = Field(..., description="Extension identifier")
    status: ExtensionStatus = Field(..., description="Extension status")
    version: str = Field(..., description="Extension version")
    
    # Health metrics
    uptime_minutes: int = Field(0, description="Extension uptime in minutes")
    memory_usage_mb: float = Field(0.0, description="Memory usage in MB")
    cpu_usage_percent: float = Field(0.0, description="CPU usage percentage")
    
    # Connectivity
    backend_connectivity: bool = Field(True, description="Backend connectivity status")
    api_response_time_ms: int = Field(0, description="API response time in milliseconds")
    last_successful_scan: Optional[datetime] = Field(None, description="Last successful scan timestamp")
    
    # Error tracking
    recent_errors: List[str] = Field(default_factory=list, description="Recent error messages")
    error_count_24h: int = Field(0, description="Error count in last 24 hours")
    
    # Feature status
    features_operational: Dict[str, bool] = Field(
        default_factory=dict,
        description="Feature operational status"
    )
    
    # Check metadata
    check_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")
    check_source: str = Field("extension", description="Health check source")
    
    class Config:
        use_enum_values = True


class BatchExtensionRequest(BaseModel):
    """Batch request from extension for multiple operations."""
    
    batch_id: str = Field(..., description="Unique batch identifier")
    requests: List[ExtensionScanPayload] = Field(..., description="List of scan requests")
    batch_options: Dict[str, Any] = Field(default_factory=dict, description="Batch processing options")
    
    # Batch configuration
    max_concurrent: int = Field(5, ge=1, le=20, description="Maximum concurrent operations")
    timeout_seconds: int = Field(30, ge=5, le=300, description="Batch timeout in seconds")
    priority: str = Field("normal", description="Batch priority: low, normal, high")
    
    @validator('requests')
    def validate_requests(cls, v):
        """Validate batch requests."""
        if not v:
            raise ValueError('Batch requests cannot be empty')
        if len(v) > 100:
            raise ValueError('Cannot process more than 100 requests in a single batch')
        return v
    
    class Config:
        use_enum_values = True


class BatchExtensionResponse(BaseModel):
    """Batch response to extension."""
    
    batch_id: str = Field(..., description="Batch identifier")
    responses: List[ExtensionResponse] = Field(default_factory=list, description="Individual responses")
    
    # Batch statistics
    total_requests: int = Field(0, description="Total requests in batch")
    successful_responses: int = Field(0, description="Successful responses")
    failed_responses: int = Field(0, description="Failed responses")
    
    # Batch metadata
    batch_started: datetime = Field(default_factory=datetime.utcnow, description="Batch start time")
    batch_completed: Optional[datetime] = Field(None, description="Batch completion time")
    processing_time_ms: int = Field(0, description="Total processing time in milliseconds")
    
    class Config:
        use_enum_values = True