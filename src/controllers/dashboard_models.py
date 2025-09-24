#!/usr/bin/env python3
"""
Dashboard API models for LinkShield.

Pydantic models for dashboard controller to avoid circular imports and forward reference issues.
"""
import uuid
from datetime import datetime
from typing import List, Optional, Dict,Union, Any as AnyType
from pydantic import BaseModel, Field, EmailStr


class DashboardOverviewResponse(BaseModel):
    """Dashboard overview response model."""
    total_projects: int
    active_projects: int
    total_scans: int
    total_alerts: int
    recent_projects: List[Dict[str, AnyType]]
    recent_alerts: List[Dict[str, AnyType]]
    subscription_status: Dict[str, AnyType]
    social_protection: Optional[Dict[str, AnyType]] = None  # Social protection overview data


class SocialProtectionOverviewResponse(BaseModel):
    """Social protection overview response model."""
    total_social_scans: int
    active_monitoring: int
    risk_assessments_today: int
    high_risk_alerts: int
    platform_coverage: Dict[str, int]  # Platform -> scan count
    recent_assessments: List[Dict[str, AnyType]]
    protection_health_score: float  # 0-100 overall protection health
    
    class Config:
        from_attributes = True


class ProtectionHealthResponse(BaseModel):
    """Protection health metrics response model."""
    overall_score: float  # 0-100 combined protection score
    url_safety_score: float  # Existing URL safety metrics
    social_protection_score: float  # New social media protection metrics
    risk_breakdown: Dict[str, float]  # Risk category -> score
    trending: str  # "improving", "stable", "declining"
    last_updated: datetime
    recommendations: List[str]  # Action items for improvement
    
    class Config:
        from_attributes = True


class ProjectResponse(BaseModel):
    """Project response model."""
    id: uuid.UUID
    name: str
    description: Optional[str]
    website_url: str
    domain: str
    is_active: bool
    monitoring_enabled: bool
    settings: Optional[Dict[str, AnyType]]
    member_count: int
    created_at: datetime
    updated_at: datetime
    last_scan_at: Optional[datetime]

    class Config:
        from_attributes = True




class ProjectCreateRequest(BaseModel):
    """Project creation request model."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    website_url: str = Field(..., max_length=500)
    settings: Optional[Dict[str, Union[str, int, bool]]] = None

    class Config:
        from_attributes = True



class ProjectUpdateRequest(BaseModel):
    """Project update request model."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    website_url: Optional[str] = Field(None, max_length=500)
    settings: Optional[Dict[str, AnyType]] = None
    is_active: Optional[bool] = None
    
    class Config:
        from_attributes = True


class MemberResponse(BaseModel):
    """Project member response model."""
    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    joined_at: Optional[datetime]
    invited_at: datetime

    class Config:
        from_attributes = True


class MemberInviteRequest(BaseModel):
    """Member invitation request model."""
    email: EmailStr
    role: str = Field(..., description="Project role: owner, admin, editor, viewer")
    
    class Config:
        from_attributes = True


class MonitoringConfigResponse(BaseModel):
    """Monitoring configuration response model."""
    id: uuid.UUID
    project_id: uuid.UUID
    scan_frequency_minutes: int
    scan_depth_limit: int
    max_links_per_scan: int
    exclude_patterns: Optional[List[str]]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertResponse(BaseModel):
    """Project alert response model."""
    id: uuid.UUID
    project_id: uuid.UUID
    alert_type: str
    title: str
    description: Optional[str]
    severity: str
    is_resolved: bool
    created_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class AlertInstanceResponse(BaseModel):
    """Alert instance response model."""
    id: uuid.UUID
    project_id: uuid.UUID
    project_alert_id: Optional[uuid.UUID]
    user_id: Optional[uuid.UUID]
    alert_type: str
    severity: str
    title: str
    description: Optional[str]
    context_data: Optional[Dict[str, AnyType]]
    affected_urls: Optional[List[str]]
    status: str
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    notification_sent: bool
    notification_sent_at: Optional[datetime]
    notification_channel: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertCreateRequest(BaseModel):
    """Alert creation request model."""
    alert_type: str
    severity: str = Field(default="medium", description="Alert severity: low, medium, high, critical")
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    context_data: Optional[Dict[str, AnyType]] = None
    affected_urls: Optional[List[str]] = None
    
    class Config:
        from_attributes = True


class AlertUpdateRequest(BaseModel):
    """Alert update request model."""
    status: Optional[str] = Field(None, description="Alert status: active, acknowledged, resolved, dismissed")
    severity: Optional[str] = Field(None, description="Alert severity: low, medium, high, critical")
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    
    class Config:
        from_attributes = True


class AnalyticsResponse(BaseModel):
    """Analytics response model."""
    date_range: Dict[str, datetime]
    total_scans: int
    total_alerts: int
    avg_scan_duration: float
    top_issues: List[Dict[str, AnyType]]
    usage_trends: Dict[str, List[Dict[str, AnyType]]]
    subscription_usage: Dict[str, AnyType]


class ActivityLogResponse(BaseModel):
    """Activity log response model."""
    id: uuid.UUID
    user_id: uuid.UUID
    user_email: str
    user_full_name: Optional[str]
    project_id: uuid.UUID
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    details: Optional[Dict[str, AnyType]]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# Rebuild all models to resolve forward reference issues
DashboardOverviewResponse.model_rebuild()
ProjectResponse.model_rebuild()
ProjectCreateRequest.model_rebuild()
ProjectUpdateRequest.model_rebuild()
MemberResponse.model_rebuild()
MemberInviteRequest.model_rebuild()
MonitoringConfigResponse.model_rebuild()
AlertResponse.model_rebuild()
AlertInstanceResponse.model_rebuild()
AlertCreateRequest.model_rebuild()
AlertUpdateRequest.model_rebuild()
AnalyticsResponse.model_rebuild()
ActivityLogResponse.model_rebuild()
