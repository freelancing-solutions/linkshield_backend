#!/usr/bin/env python3
"""
Dashboard routes for LinkShield.

FastAPI router for dashboard functionality.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Dict, Any as AnyType

from fastapi import APIRouter, Depends, Query, status, HTTPException

from src.controllers.dashboard_controller import DashboardController
from src.controllers.dashboard_models import (
    DashboardOverviewResponse,
    ProjectResponse,
    ProjectCreateRequest,
    ProjectUpdateRequest,
    MemberResponse,
    MemberInviteRequest,
    MonitoringConfigResponse,
    AlertResponse,
    AlertInstanceResponse,
    AlertCreateRequest,
    AlertUpdateRequest,
    AnalyticsResponse,
    ActivityLogResponse,
    SocialProtectionOverviewResponse,
    ProtectionHealthResponse,
)

from src.controllers.depends import get_dashboard_controller
from src.authentication.dependencies import get_current_user
from src.models.user import User


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# ------------------------------------------------------------------
# Dashboard Overview Endpoints
# ------------------------------------------------------------------
@router.get(
    "/overview",
    response_model=DashboardOverviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Get dashboard overview",
    description="Get comprehensive dashboard overview including statistics and recent activity",
)
async def get_dashboard_overview(
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> DashboardOverviewResponse:
    """Get dashboard overview for the current user."""
    return await controller.get_dashboard_overview(user=current_user)


# ------------------------------------------------------------------
# Project Management Endpoints
# ------------------------------------------------------------------
@router.get(
    "/projects",
    response_model=Dict[str, AnyType],
    status_code=status.HTTP_200_OK,
    summary="List projects",
    description="List user's projects with pagination and filtering",
)
async def list_projects(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    search: str = Query(None, description="Search term for project name/domain"),
    status_filter: str = Query(None, description="Filter by project status (active/inactive)"),
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> Dict[str, AnyType]:
    """List user's projects with pagination and filtering."""
    return await controller.list_projects(
        user=current_user,
        page=page,
        limit=limit,
        search=search,
        status_filter=status_filter,
    )


@router.post(
    "/projects",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create project",
    description="Create a new project with default monitoring configuration",
)
async def create_project(
    request_model: ProjectCreateRequest,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> ProjectResponse:
    """Create a new project with monitoring configuration."""
    return await controller.create_project(
        user=current_user,
        request_model=request_model,
    )


@router.get(
    "/projects/{project_id}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Get project",
    description="Get project details with access control",
)
async def get_project(
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> ProjectResponse:
    """Get project details."""
    return await controller.get_project(
        user=current_user,
        project_id=project_id,
    )

@router.patch(
    "/projects/{project_id}",
    response_model=ProjectResponse,
    status_code=status.HTTP_200_OK,
    summary="Update project",
    description="Update project settings with permission checks",
)
async def update_project(
    project_id: uuid.UUID,
    request_model: ProjectUpdateRequest,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> ProjectResponse:
    """Update project settings."""
    return await controller.update_project(
        user=current_user,
        project_id=project_id,
        request_model=request_model,
    )


@router.delete(
    "/projects/{project_id}",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Delete project",
    description="Delete project (soft delete) with cleanup",
)
async def delete_project(
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> None:
    await controller.delete_project(user=current_user, project_id=project_id)
    return None


# ------------------------------------------------------------------
# Monitoring Control Endpoints
# ------------------------------------------------------------------
@router.post(
    "/projects/{project_id}/monitoring/{enabled}",
    response_model=MonitoringConfigResponse,
    status_code=status.HTTP_200_OK,
    summary="Toggle monitoring",
    description="Enable or disable project monitoring",
)
async def toggle_monitoring(
    project_id: uuid.UUID,
    enabled: bool,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> MonitoringConfigResponse:
    """Enable or disable project monitoring."""
    return await controller.toggle_monitoring(
        user=current_user,
        project_id=project_id,
        enabled=enabled,
    )


# ------------------------------------------------------------------
# Team Management Endpoints
# ------------------------------------------------------------------
@router.get(
    "/projects/{project_id}/members",
    response_model=List[MemberResponse],
    status_code=status.HTTP_200_OK,
    summary="List project members",
    description="List all team members for a project",
)
async def list_project_members(
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> List[MemberResponse]:
    """List project team members."""
    return await controller.list_project_members(
        user=current_user,
        project_id=project_id,
    )


@router.post(
    "/projects/{project_id}/members/invite",
    response_model=MemberResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Invite team member",
    description="Invite a new team member to the project",
)
async def invite_member(
    project_id: uuid.UUID,
    request_model: MemberInviteRequest,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> MemberResponse:
    """Invite a team member to the project."""
    return await controller.invite_member(
        user=current_user,
        project_id=project_id,
        request_model=request_model,
    )


# ------------------------------------------------------------------
# Analytics Endpoints (Placeholder)
# ------------------------------------------------------------------
@router.get(
    "/analytics",
    response_model=AnalyticsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get analytics",
    description="Get dashboard analytics and usage statistics",
)
async def get_analytics(
    date_from: str = Query(None, description="Start date (ISO format, e.g., 2024-01-01)"),
    date_to: str = Query(None, description="End date (ISO format, e.g., 2024-01-31)"),
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> AnalyticsResponse:
    """Get dashboard analytics."""
    # Parse date parameters if provided
    from_date = None
    to_date = None
    
    if date_from:
        try:
            from_date = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid date_from format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)"
            )
    
    if date_to:
        try:
            to_date = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid date_to format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)"
            )
    
    return await controller.get_analytics(
        user=current_user,
        date_from=from_date,
        date_to=to_date,
    )


@router.get(
    "/projects/{project_id}/activity-logs",
    response_model=List[ActivityLogResponse],
    status_code=status.HTTP_200_OK,
    summary="Get activity logs",
    description="Get activity logs for a specific project",
)
async def get_activity_logs(
    project_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=200, description="Maximum number of logs to return"),
    offset: int = Query(0, ge=0, description="Number of logs to skip"),
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> List[ActivityLogResponse]:
    """Get activity logs for a specific project."""
    return await controller.get_activity_logs(
        user=current_user,
        project_id=project_id,
        limit=limit,
        offset=offset,
    )


# ------------------------------------------------------------------
# Alert Management Endpoints
# ------------------------------------------------------------------
@router.get(
    "/projects/{project_id}/alerts",
    response_model=List[AlertInstanceResponse],
    status_code=status.HTTP_200_OK,
    summary="List project alerts",
    description="List alerts for a specific project with filtering options",
)
async def list_project_alerts(
    project_id: uuid.UUID,
    status: str = Query(None, description="Filter by alert status (active, acknowledged, resolved, dismissed)"),
    severity: str = Query(None, description="Filter by severity (low, medium, high, critical)"),
    limit: int = Query(50, ge=1, le=100, description="Number of alerts to return"),
    offset: int = Query(0, ge=0, description="Number of alerts to skip"),
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> List[AlertInstanceResponse]:
    """List project alerts."""
    return await controller.get_project_alerts(
        user=current_user,
        project_id=project_id,
        status=status,
        severity=severity,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/projects/{project_id}/alerts",
    response_model=AlertInstanceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create alert",
    description="Create a new alert for the project",
)
async def create_alert(
    project_id: uuid.UUID,
    request_model: AlertCreateRequest,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> AlertInstanceResponse:
    """Create a new alert."""
    return await controller.create_alert(
        user=current_user,
        project_id=project_id,
        request_model=request_model,
    )


@router.get(
    "/projects/{project_id}/alerts/{alert_id}",
    response_model=AlertInstanceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get alert",
    description="Get details of a specific alert",
)
async def get_alert(
    project_id: uuid.UUID,
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> AlertInstanceResponse:
    """Get alert details."""
    return await controller.get_alert(
        user=current_user,
        project_id=project_id,
        alert_id=alert_id,
    )


@router.patch(
    "/projects/{project_id}/alerts/{alert_id}",
    response_model=AlertInstanceResponse,
    status_code=status.HTTP_200_OK,
    summary="Update alert",
    description="Update alert details and status",
)
async def update_alert(
    project_id: uuid.UUID,
    alert_id: uuid.UUID,
    request_model: AlertUpdateRequest,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> AlertInstanceResponse:
    """Update an alert."""
    return await controller.update_alert(
        user=current_user,
        project_id=project_id,
        alert_id=alert_id,
        request_model=request_model,
    )


@router.post(
    "/projects/{project_id}/alerts/{alert_id}/acknowledge",
    response_model=AlertInstanceResponse,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge alert",
    description="Mark an alert as acknowledged",
)
async def acknowledge_alert(
    project_id: uuid.UUID,
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> AlertInstanceResponse:
    """Acknowledge an alert."""
    return await controller.acknowledge_alert(
        user=current_user,
        project_id=project_id,
        alert_id=alert_id,
    )


@router.post(
    "/projects/{project_id}/alerts/{alert_id}/resolve",
    response_model=AlertInstanceResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve alert",
    description="Mark an alert as resolved",
)
async def resolve_alert(
    project_id: uuid.UUID,
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> AlertInstanceResponse:
    """Resolve an alert."""
    return await controller.resolve_alert(
        user=current_user,
        project_id=project_id,
        alert_id=alert_id,
    )


@router.post(
    "/projects/{project_id}/alerts/{alert_id}/dismiss",
    response_model=AlertInstanceResponse,
    status_code=status.HTTP_200_OK,
    summary="Dismiss alert",
    description="Mark an alert as dismissed",
)
async def dismiss_alert(
    project_id: uuid.UUID,
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> AlertInstanceResponse:
    """Dismiss an alert."""
    return await controller.dismiss_alert(
        user=current_user,
        project_id=project_id,
        alert_id=alert_id,
    )


@router.get(
    "/projects/{project_id}/alerts/stats",
    response_model=Dict[str, AnyType],
    status_code=status.HTTP_200_OK,
    summary="Get alert statistics",
    description="Get alert statistics for the project",
)
async def get_alert_statistics(
    project_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> Dict[str, AnyType]:
    """Get alert statistics."""
    return await controller.get_alert_statistics(
        user=current_user,
        project_id=project_id,
    )


@router.patch(
    "/alerts/{alert_id}/resolve",
    response_model=AlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve alert",
    description="Mark an alert as resolved",
)
async def resolve_alert(
    alert_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> AlertResponse:
    """Mark an alert as resolved."""
    # This is a placeholder implementation
    # In a real implementation, this would update the alert status
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Alert resolution not yet implemented"
    )


# ------------------------------------------------------------------
# Social Protection Dashboard Endpoints
# ------------------------------------------------------------------
@router.get(
    "/social-protection/overview",
    response_model=SocialProtectionOverviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Get social protection overview",
    description="Get comprehensive social protection overview including scans, assessments, and metrics",
)
async def get_social_protection_overview(
    project_id: uuid.UUID = Query(None, description="Optional project ID to filter by"),
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> SocialProtectionOverviewResponse:
    """Get social protection overview for the user or specific project."""
    return await controller.get_social_protection_overview(
        user=current_user,
        project_id=project_id,
    )


@router.get(
    "/protection-health",
    response_model=ProtectionHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Get protection health metrics",
    description="Get comprehensive protection health combining URL safety and social protection",
)
async def get_protection_health(
    project_id: uuid.UUID = Query(None, description="Optional project ID to filter by"),
    current_user: User = Depends(get_current_user),
    controller: DashboardController = Depends(get_dashboard_controller),
) -> ProtectionHealthResponse:
    """Get comprehensive protection health metrics."""
    return await controller.get_protection_health(
        user=current_user,
        project_id=project_id,
    )