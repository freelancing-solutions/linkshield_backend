"""
Social Protection User Routes

API routes for user-facing social protection operations including account
protection, settings, analytics, and monitoring.
"""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession

from linkshield.authentication.dependencies import get_current_user
from linkshield.config.database import get_db
from linkshield.models.user import User
from linkshield.social_protection.controllers.user_controller import UserController
from linkshield.social_protection.controllers.depends import get_user_controller
from linkshield.social_protection.types import PlatformType
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/social-protection/user", tags=["Social Protection - User"])


# Request/Response Models
class ProtectionSettingsUpdate(BaseModel):
    """Model for updating protection settings"""
    auto_scan_enabled: Optional[bool] = None
    notification_preferences: Optional[dict] = None
    risk_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    platform_settings: Optional[dict] = None


class PlatformScanRequest(BaseModel):
    """Model for initiating platform scan"""
    platform: PlatformType
    profile_url: str
    scan_options: Optional[dict] = Field(default_factory=dict)
    project_id: Optional[UUID] = None


class ContentAnalysisRequest(BaseModel):
    """Model for content analysis"""
    content: str
    platform: PlatformType
    content_type: str = "post"
    metadata: Optional[dict] = Field(default_factory=dict)


class AlgorithmHealthRequest(BaseModel):
    """Model for algorithm health check"""
    platform: PlatformType
    profile_identifier: str
    metrics_window_days: int = Field(default=30, ge=1, le=90)


@router.get("/settings")
async def get_protection_settings(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    controller: UserController = Depends(get_user_controller)
):
    """
    Get user's social protection settings
    
    Returns current protection configuration including auto-scan settings,
    notification preferences, and platform-specific settings.
    """
    return await controller.get_user_protection_settings(user=current_user, db=db)


@router.put("/settings")
async def update_protection_settings(
    settings: ProtectionSettingsUpdate,
    current_user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Update user's social protection settings
    
    Allows users to configure auto-scan behavior, notification preferences,
    risk thresholds, and platform-specific settings.
    """
    return await controller.update_user_protection_settings(
        current_user,
        settings.dict(exclude_unset=True),
        db
    )


@router.get("/analytics")
async def get_protection_analytics(
    time_range: str = "30d",
    include_details: bool = False,
    current_user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get user's protection analytics
    
    Returns analytics including threats detected, scans performed,
    risk assessments, and platform-specific metrics.
    
    Query Parameters:
    - time_range: Time range for analytics (7d, 30d, 90d)
    - include_details: Include detailed breakdown
    """
    return await controller.get_user_protection_analytics(
        current_user,
        time_range=time_range,
        include_details=include_details,
        db=db
    )


@router.post("/scan")
async def initiate_platform_scan(
    scan_request: PlatformScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Initiate a comprehensive platform scan
    
    Starts a full scan of the specified social media profile including
    content analysis, algorithm health check, and risk assessment.
    """
    return await controller.initiate_user_platform_scan(
        current_user,
        scan_request.platform,
        scan_request.profile_url,
        scan_request.scan_options,
        scan_request.project_id,
        background_tasks,
        db
    )


@router.post("/analyze")
async def analyze_content(
    analysis_request: ContentAnalysisRequest,
    current_user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Analyze content for risks and issues
    
    Performs comprehensive content analysis including risk assessment,
    spam detection, link safety, and community notes analysis.
    """
    return await controller.analyze_user_content(
        current_user,
        analysis_request.content,
        analysis_request.platform,
        analysis_request.content_type,
        analysis_request.metadata
    )


@router.get("/algorithm-health")
async def get_algorithm_health(
    platform: PlatformType,
    profile_identifier: str,
    metrics_window_days: int = 30,
    current_user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get algorithm health analysis
    
    Returns comprehensive algorithm health metrics including visibility score,
    engagement analysis, penalty detection, and shadow ban indicators.
    
    Query Parameters:
    - platform: Social media platform
    - profile_identifier: Profile username or ID
    - metrics_window_days: Time window for metrics (1-90 days)
    """
    return await controller.get_user_algorithm_health(
        current_user,
        platform,
        profile_identifier,
        metrics_window_days,
        db
    )


@router.get("/scans")
async def get_user_scans(
    platform: Optional[PlatformType] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get user's scan history
    
    Returns list of previous scans with optional filtering by platform and status.
    
    Query Parameters:
    - platform: Filter by platform
    - status: Filter by scan status (pending, in_progress, completed, failed)
    - limit: Maximum number of results (1-100)
    - offset: Pagination offset
    """
    # This would call a method on the controller to retrieve scan history
    # For now, return a placeholder response
    return {
        "success": True,
        "scans": [],
        "pagination": {
            "total": 0,
            "limit": limit,
            "offset": offset
        }
    }


@router.get("/scans/{scan_id}")
async def get_scan_details(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed scan results
    
    Returns comprehensive results for a specific scan including all
    analysis components and recommendations.
    """
    # This would call a method on the controller to retrieve scan details
    # For now, return a placeholder response
    return {
        "success": True,
        "scan_id": str(scan_id),
        "status": "completed",
        "results": {}
    }


@router.get("/dashboard")
async def get_user_dashboard(
    current_user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get user dashboard summary
    
    Returns a comprehensive dashboard view including recent activity,
    current threats, protection status, and quick stats.
    """
    # This would aggregate data from multiple sources
    return {
        "success": True,
        "dashboard": {
            "protection_status": "active",
            "recent_threats": 0,
            "active_scans": 0,
            "total_scans": 0,
            "platforms_monitored": []
        }
    }
