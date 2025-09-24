#!/usr/bin/env python3
"""
Dashboard controller for LinkShield.

All business logic + Pydantic response models for dashboard functionality.
Public methods return typed models and use keyword-only arguments.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any as AnyType

from fastapi import HTTPException, status
from sqlalchemy import and_, select, update, func as sql_func
from sqlalchemy.exc import IntegrityError

from src.controllers.base_controller import BaseController
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
from src.models.project import Project, ProjectMember, MonitoringConfig, ProjectAlert, ProjectRole, AlertInstance, AlertType, AlertChannel
from src.models.subscription import SubscriptionPlan, UserSubscription
from src.models.user import User
from src.models.activity_log import ActivityLog, ActivityLogManager
from src.services.email_service import EmailService, EmailRequest
from src.services.security_service import SecurityService
from src.services.advanced_rate_limiter import rate_limit
from src.authentication.auth_service import AuthService
from src.utils import utc_datetime
from src.config import settings


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _to_project_response(project: Project) -> ProjectResponse:
    """Convert Project model to ProjectResponse."""
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        website_url=project.website_url,
        domain=project.domain,
        is_active=project.is_active,
        monitoring_enabled=project.monitoring_enabled,
        settings=project.settings,
        member_count=project.get_member_count(),
        created_at=project.created_at,
        updated_at=project.updated_at,
        last_scan_at=project.last_scan_at,
    )


def _to_member_response(member: ProjectMember) -> MemberResponse:
    """Convert ProjectMember model to MemberResponse."""
    return MemberResponse(
        id=member.id,
        user_id=member.user_id,
        email=member.user.email,
        full_name=member.user.get_full_name(),
        role=member.role.value,
        is_active=member.is_active,
        joined_at=member.joined_at,
        invited_at=member.invited_at,
    )


def _to_alert_response(alert: ProjectAlert) -> AlertResponse:
    """Convert ProjectAlert model to AlertResponse."""
    return AlertResponse(
        id=alert.id,
        project_id=alert.project_id,
        alert_type=alert.alert_type.value,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        is_resolved=alert.is_resolved,
        created_at=alert.created_at,
        resolved_at=alert.resolved_at,
    )


def _to_alert_instance_response(alert: AlertInstance) -> AlertInstanceResponse:
    """Convert AlertInstance to AlertInstanceResponse."""
    return AlertInstanceResponse(
        id=alert.id,
        project_id=alert.project_id,
        project_alert_id=alert.project_alert_id,
        user_id=alert.user_id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        context_data=alert.context_data,
        affected_urls=alert.affected_urls,
        status=alert.status,
        acknowledged_at=alert.acknowledged_at,
        resolved_at=alert.resolved_at,
        notification_sent=alert.notification_sent,
        notification_sent_at=alert.notification_sent_at,
        notification_channel=alert.notification_channel,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


# ------------------------------------------------------------------
# Controller
# ------------------------------------------------------------------
class DashboardController(BaseController):
    def __init__(
        self,
        *,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
    ) -> None:
        super().__init__(security_service, auth_service, email_service)

        self.project_creation_rate_limit = 10
        self.member_invitation_rate_limit = 20

    # --------------------------------------------------------------
    # Dashboard Overview Methods
    # --------------------------------------------------------------
    async def get_dashboard_overview(
        self,
        *,
        user: User,
    ) -> DashboardOverviewResponse:
        """
        Get comprehensive dashboard overview for the user.
        
        Args:
            user: Current authenticated user
            
        Returns:
            DashboardOverviewResponse with user statistics and activity
        """
        try:
            async with self.get_db_session() as session:
                # Get user's projects
                stmt = select(Project).where(Project.user_id == user.id)
                result = await session.execute(stmt)
                projects = result.scalars().all()
                
                # Get user's active subscription
                subscription_stmt = select(UserSubscription).where(
                    and_(
                        UserSubscription.user_id == user.id,
                        UserSubscription.status.in_(["active", "trial"])
                    )
                )
                sub_result = await session.execute(subscription_stmt)
                subscription = sub_result.scalar_one_or_none()
                
                # Get recent alerts
                project_ids = [p.id for p in projects]
                if project_ids:
                    alert_stmt = select(ProjectAlert).where(
                        ProjectAlert.project_id.in_(project_ids)
                    ).order_by(ProjectAlert.created_at.desc()).limit(10)
                    alert_result = await session.execute(alert_stmt)
                    recent_alerts = alert_result.scalars().all()
                else:
                    recent_alerts = []
                
                # Calculate statistics
                total_projects = len(projects)
                active_projects = len([p for p in projects if p.is_active and p.monitoring_enabled])
                recent_alerts_count = len(recent_alerts)
                
                # Get subscription status
                subscription_status = "none"
                if subscription:
                    subscription_status = subscription.status.value
                
                # Calculate usage stats
                usage_stats = await self._calculate_usage_stats(user, session)
                
                # Get recent activity
                recent_activity = await self._get_recent_activity(user, session)
                
                # Get monitoring summary
                monitoring_summary = await self._get_monitoring_summary(projects, session)
                
                # Get social protection overview (optional)
                social_protection = None
                try:
                    social_protection = await self.get_social_protection_overview(user=user)
                except Exception as e:
                    self.logger.warning(f"Failed to get social protection overview: {e}")
                
                return DashboardOverviewResponse(
                    total_projects=total_projects,
                    active_projects=active_projects,
                    recent_alerts=recent_alerts_count,
                    subscription_status=subscription_status,
                    usage_stats=usage_stats,
                    recent_activity=recent_activity,
                    monitoring_summary=monitoring_summary,
                    social_protection=social_protection,
                )
                
        except Exception as e:
            self.logger.error(f"Error getting dashboard overview: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve dashboard overview"
            )

    # --------------------------------------------------------------
    # Project Management Methods
    # --------------------------------------------------------------
    async def list_projects(
        self,
        *,
        user: User,
        page: int = 1,
        limit: int = 20,
        search: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> Dict[str, AnyType]:
        """
        List user's projects with pagination and filtering.
        
        Args:
            user: Current authenticated user
            page: Page number (1-based)
            limit: Items per page
            search: Search term for project name/domain
            status_filter: Filter by project status
            
        Returns:
            Dict with projects list and pagination info
        """
        try:
            async with self.get_db_session() as session:
                # Build query
                stmt = select(Project).where(Project.user_id == user.id)
                
                # Apply filters
                if search:
                    stmt = stmt.where(
                        Project.name.ilike(f"%{search}%") |
                        Project.domain.ilike(f"%{search}%")
                    )
                
                if status_filter:
                    if status_filter == "active":
                        stmt = stmt.where(Project.is_active == True)
                    elif status_filter == "inactive":
                        stmt = stmt.where(Project.is_active == False)
                
                # Get total count
                count_stmt = select(sql_func.count()).select_from(stmt.subquery())
                count_result = await session.execute(count_stmt)
                total = count_result.scalar()
                
                # Apply pagination
                offset = (page - 1) * limit
                stmt = stmt.order_by(Project.created_at.desc()).offset(offset).limit(limit)
                
                result = await session.execute(stmt)
                projects = result.scalars().all()
                
                # Convert to response models
                project_responses = [_to_project_response(p) for p in projects]
                
                return {
                    "projects": project_responses,
                    "pagination": {
                        "page": page,
                        "limit": limit,
                        "total": total,
                        "pages": (total + limit - 1) // limit,
                    }
                }
                
        except Exception as e:
            self.logger.error(f"Error listing projects: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve projects"
            )

    @rate_limit("project_creation")
    async def create_project(
        self,
        *,
        user: User,
        request_model: ProjectCreateRequest,
    ) -> ProjectResponse:
        """
        Create a new project with monitoring configuration.
        
        Args:
            user: Current authenticated user
            request_model: Project creation data
            
        Returns:
            ProjectResponse for the created project
        """
        try:
            # Check subscription limits
            if not await self.can_create_project(user):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Project limit reached for your subscription plan"
                )
            
            async with self.get_db_session() as session:
                # Extract domain from URL
                from urllib.parse import urlparse
                parsed_url = urlparse(request_model.website_url)
                domain = parsed_url.netloc or parsed_url.path
                
                # Create project
                project = Project(
                    user_id=user.id,
                    name=request_model.name,
                    description=request_model.description,
                    website_url=request_model.website_url,
                    domain=domain,
                    settings=request_model.settings or {},
                )
                
                session.add(project)
                await session.flush()
                
                # Create default monitoring configuration
                monitoring_config = MonitoringConfig(
                    project_id=project.id,
                    scan_frequency_minutes=1440,  # 24 hours default
                    scan_depth_limit=3,
                    max_links_per_scan=100,
                    exclude_patterns=[],
                    is_active=True,
                )
                
                session.add(monitoring_config)
                await session.commit()
                
                # Log activity
                await self._log_project_activity(
                    project.id, user.id, "project_created", 
                    {"name": project.name, "domain": domain},
                    resource_type="project",
                    resource_id=str(project.id)
                )
                
                return _to_project_response(project)
                
        except IntegrityError as e:
            self.logger.error(f"Error creating project: {e}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Project with this domain already exists"
            )
        except Exception as e:
            self.logger.error(f"Error creating project: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create project"
            )

    async def get_project(
        self,
        *,
        user: User,
        project_id: uuid.UUID,
    ) -> ProjectResponse:
        """
        Get project details with access control.
        
        Args:
            user: Current authenticated user
            project_id: Project ID
            
        Returns:
            ProjectResponse for the project
        """
        try:
            async with self.get_db_session() as session:
                # Get project with access check
                stmt = select(Project).where(Project.id == project_id)
                result = await session.execute(stmt)
                project = result.scalar_one_or_none()
                
                if not project:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Project not found"
                    )
                
                # Check access
                if not project.can_user_access(user.id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this project"
                    )
                
                return _to_project_response(project)
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error getting project: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve project"
            )

    @rate_limit("project_modification")
    async def update_project(
        self,
        *,
        user: User,
        project_id: uuid.UUID,
        request_model: ProjectUpdateRequest,
    ) -> ProjectResponse:
        """
        Update project settings with permission checks.
        
        Args:
            user: Current authenticated user
            project_id: Project ID
            request_model: Update data
            
        Returns:
            ProjectResponse for the updated project
        """
        try:
            async with self.get_db_session() as session:
                # Get project with access check
                stmt = select(Project).where(Project.id == project_id)
                result = await session.execute(stmt)
                project = result.scalar_one_or_none()
                
                if not project:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Project not found"
                    )
                
                # Check permissions (owner or admin)
                user_role = project.get_user_role(user.id)
                if not user_role or user_role not in [ProjectRole.OWNER, ProjectRole.ADMIN]:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions to update project"
                    )
                
                # Update fields
                update_data = request_model.dict(exclude_unset=True)
                for field, value in update_data.items():
                    setattr(project, field, value)
                
                await session.commit()
                
                # Log activity
                await self._log_project_activity(
                    project.id, user.id, "project_updated", 
                    {"updated_fields": list(update_data.keys())},
                    resource_type="project",
                    resource_id=str(project.id)
                )
                
                return _to_project_response(project)
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error updating project: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update project"
            )

    @rate_limit("project_modification")
    async def delete_project(
        self,
        *,
        user: User,
        project_id: uuid.UUID,
    ) -> None:
        """
        Delete project (soft delete) with cleanup.
        
        Args:
            user: Current authenticated user
            project_id: Project ID
            
        Returns:
            None on success
        """
        try:
            async with self.get_db_session() as session:
                # Get project with access check
                stmt = select(Project).where(Project.id == project_id)
                result = await session.execute(stmt)
                project = result.scalar_one_or_none()
                
                if not project:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Project not found"
                    )
                
                # Check ownership
                if not project.is_owner(user.id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Only project owner can delete project"
                    )
                
                # Soft delete by setting is_active to False
                project.is_active = False
                
                # Disable monitoring
                if project.monitoring_config:
                    project.monitoring_config.is_active = False
                
                await session.commit()
                
                # Log activity
                await self._log_project_activity(
                    project.id, user.id, "project_deleted", 
                    {"name": project.name},
                    resource_type="project",
                    resource_id=str(project.id)
                )
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error deleting project: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete project"
            )

    async def toggle_monitoring(
        self,
        *,
        user: User,
        project_id: uuid.UUID,
        enabled: bool,
    ) -> MonitoringConfigResponse:
        """
        Enable/disable project monitoring.
        
        Args:
            user: Current authenticated user
            project_id: Project ID
            enabled: Whether to enable monitoring
            
        Returns:
            MonitoringConfigResponse for the updated config
        """
        try:
            async with self.get_db_session() as session:
                # Get project with access check
                stmt = select(Project).where(Project.id == project_id)
                result = await session.execute(stmt)
                project = result.scalar_one_or_none()
                
                if not project:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Project not found"
                    )
                
                # Check access
                if not project.can_user_access(user.id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this project"
                    )
                
                # Get or create monitoring config
                if not project.monitoring_config:
                    config = MonitoringConfig(
                        project_id=project.id,
                        scan_frequency_minutes=1440,
                        scan_depth_limit=3,
                        max_links_per_scan=100,
                        exclude_patterns=[],
                        is_active=enabled,
                    )
                    session.add(config)
                else:
                    project.monitoring_config.is_active = enabled
                
                await session.commit()
                
                # Log activity
                action = "monitoring_enabled" if enabled else "monitoring_disabled"
                await self._log_project_activity(
                    project.id, user.id, action,
                    {"previous_state": not enabled},
                    resource_type="config",
                    resource_id=str(project.monitoring_config.id)
                )
                
                return MonitoringConfigResponse(
                    id=project.monitoring_config.id,
                    project_id=project.monitoring_config.project_id,
                    scan_frequency_minutes=project.monitoring_config.scan_frequency_minutes,
                    scan_depth_limit=project.monitoring_config.scan_depth_limit,
                    max_links_per_scan=project.monitoring_config.max_links_per_scan,
                    exclude_patterns=project.monitoring_config.exclude_patterns,
                    is_active=project.monitoring_config.is_active,
                    created_at=project.monitoring_config.created_at,
                    updated_at=project.monitoring_config.updated_at,
                )
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error toggling monitoring: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to toggle monitoring"
            )

    # --------------------------------------------------------------
    # Team Management Methods
    # --------------------------------------------------------------
    async def list_project_members(
        self,
        *,
        user: User,
        project_id: uuid.UUID,
    ) -> List[MemberResponse]:
        """
        List project team members.
        
        Args:
            user: Current authenticated user
            project_id: Project ID
            
        Returns:
            List of MemberResponse objects
        """
        try:
            async with self.get_db_session() as session:
                # Get project with access check
                stmt = select(Project).where(Project.id == project_id)
                result = await session.execute(stmt)
                project = result.scalar_one_or_none()
                
                if not project:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Project not found"
                    )
                
                # Check access
                if not project.can_user_access(user.id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this project"
                    )
                
                # Get members
                member_stmt = select(ProjectMember).where(
                    ProjectMember.project_id == project_id,
                    ProjectMember.is_active == True
                ).order_by(ProjectMember.created_at.desc())
                
                member_result = await session.execute(member_stmt)
                members = member_result.scalars().all()
                
                return [_to_member_response(member) for member in members]
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error listing project members: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve project members"
            )

    async def invite_member(
        self,
        *,
        user: User,
        project_id: uuid.UUID,
        request_model: MemberInviteRequest,
    ) -> MemberResponse:
        """
        Invite a team member to the project.
        
        Args:
            user: Current authenticated user (inviter)
            project_id: Project ID
            request_model: Invitation data
            
        Returns:
            MemberResponse for the invited member
        """
        try:
            # Check invitation rate limit
            if not await self.check_rate_limit(str(user.id), "member_invitation", self.member_invitation_rate_limit):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Member invitation rate limit exceeded"
                )
            
            async with self.get_db_session() as session:
                # Get project with access check
                stmt = select(Project).where(Project.id == project_id)
                result = await session.execute(stmt)
                project = result.scalar_one_or_none()
                
                if not project:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Project not found"
                    )
                
                # Check permissions (owner or admin)
                user_role = project.get_user_role(user.id)
                if not user_role or user_role not in [ProjectRole.OWNER, ProjectRole.ADMIN]:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions to invite members"
                    )
                
                # Check subscription limits
                current_member_count = project.get_member_count()
                if subscription := await self._get_user_subscription(user, session):
                    if not subscription.plan.can_add_team_member(current_member_count):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Team member limit reached for your subscription plan"
                        )
                
                # Check if user already exists
                invitee_stmt = select(User).where(User.email == request_model.email.lower())
                invitee_result = await session.execute(invitee_stmt)
                invitee = invitee_result.scalar_one_or_none()
                
                if invitee and any(m.user_id == invitee.id for m in project.members):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="User is already a member of this project"
                    )
                
                # Create invitation token
                invitation_token = self.security_service.generate_secure_token()
                
                # Create project member (pending invitation)
                member = ProjectMember(
                    project_id=project_id,
                    user_id=invitee.id if invitee else uuid.uuid4(),  # Temporary ID if user doesn't exist
                    invited_by=user.id,
                    role=ProjectRole(request_model.role),
                    invitation_token=invitation_token,
                    is_active=False,  # Pending until accepted
                )
                
                session.add(member)
                await session.commit()
                
                # Send invitation email
                await self._send_invitation_email(
                    project, request_model.email, user, request_model.role
                )
                
                # Log activity
                await self._log_project_activity(
                    project.id, user.id, "member_invited", 
                    {"email": request_model.email, "role": request_model.role},
                    resource_type="member",
                    resource_id=str(member.id)
                )
                
                return _to_member_response(member)
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error inviting member: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to invite team member"
            )

    # --------------------------------------------------------------
    # Analytics Methods
    # --------------------------------------------------------------
    async def get_analytics(
        self,
        *,
        user: User,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ) -> AnalyticsResponse:
        """
        Get comprehensive analytics for the user's projects.
        
        Args:
            user: Current authenticated user
            date_from: Start date for analytics (optional)
            date_to: End date for analytics (optional)
            
        Returns:
            AnalyticsResponse with detailed analytics data
        """
        try:
            async with self.get_db_session() as session:
                # Set default date range if not provided
                if not date_to:
                    date_to = datetime.now(timezone.utc)
                if not date_from:
                    date_from = date_to - timedelta(days=30)  # Default 30 days
                
                # Get user's projects
                project_stmt = select(Project).where(Project.user_id == user.id)
                result = await session.execute(project_stmt)
                projects = result.scalars().all()
                
                if not projects:
                    return AnalyticsResponse(
                        date_range={"from": date_from, "to": date_to},
                        total_scans=0,
                        total_alerts=0,
                        avg_scan_duration=0.0,
                        top_issues=[],
                        usage_trends={},
                        subscription_usage={},
                    )
                
                project_ids = [p.id for p in projects]
                
                # Get total scans (URL checks) in date range
                scan_stmt = select(sql_func.count(URLCheck.id)).where(
                    and_(
                        URLCheck.user_id == user.id,
                        URLCheck.created_at >= date_from,
                        URLCheck.created_at <= date_to
                    )
                )
                scan_result = await session.execute(scan_stmt)
                total_scans = scan_result.scalar() or 0
                
                # Get total alerts in date range
                alert_stmt = select(sql_func.count(AlertInstance.id)).where(
                    and_(
                        AlertInstance.project_id.in_(project_ids),
                        AlertInstance.created_at >= date_from,
                        AlertInstance.created_at <= date_to
                    )
                )
                alert_result = await session.execute(alert_stmt)
                total_alerts = alert_result.scalar() or 0
                
                # Get average scan duration
                avg_duration_stmt = select(sql_func.avg(URLCheck.duration)).where(
                    and_(
                        URLCheck.user_id == user.id,
                        URLCheck.duration.is_not(None),
                        URLCheck.created_at >= date_from,
                        URLCheck.created_at <= date_to
                    )
                )
                avg_result = await session.execute(avg_duration_stmt)
                avg_scan_duration = float(avg_result.scalar() or 0.0)
                
                # Get top issues (most common alert types)
                top_issues_stmt = select(
                    AlertInstance.alert_type,
                    sql_func.count(AlertInstance.id).label('count')
                ).where(
                    and_(
                        AlertInstance.project_id.in_(project_ids),
                        AlertInstance.created_at >= date_from,
                        AlertInstance.created_at <= date_to
                    )
                ).group_by(AlertInstance.alert_type).order_by(sql_func.count(AlertInstance.id).desc()).limit(5)
                
                top_issues_result = await session.execute(top_issues_stmt)
                top_issues = [
                    {"issue": row.alert_type, "count": row.count}
                    for row in top_issues_result
                ]
                
                # Get usage trends (scans per day)
                trends_stmt = select(
                    sql_func.date_trunc('day', URLCheck.created_at).label('day'),
                    sql_func.count(URLCheck.id).label('count')
                ).where(
                    and_(
                        URLCheck.user_id == user.id,
                        URLCheck.created_at >= date_from,
                        URLCheck.created_at <= date_to
                    )
                ).group_by(sql_func.date_trunc('day', URLCheck.created_at)).order_by('day')
                
                trends_result = await session.execute(trends_stmt)
                usage_trends = {
                    "scans_per_day": [
                        {"date": row.day.isoformat(), "count": row.count}
                        for row in trends_result
                    ]
                }
                
                # Get subscription usage
                subscription = await self._get_user_subscription(user, session)
                subscription_usage = {}
                
                if subscription:
                    # Get current project count
                    project_count_stmt = select(sql_func.count(Project.id)).where(Project.user_id == user.id)
                    project_count_result = await session.execute(project_count_stmt)
                    project_count = project_count_result.scalar()
                    
                    subscription_usage = {
                        "plan_name": subscription.plan.name,
                        "daily_checks_used": subscription.daily_checks_used,
                        "daily_checks_limit": subscription.plan.daily_check_limit,
                        "monthly_checks_used": subscription.monthly_checks_used,
                        "monthly_checks_limit": subscription.plan.monthly_check_limit,
                        "projects_used": project_count,
                        "projects_limit": subscription.plan.max_projects,
                        "alerts_used": total_alerts,
                        "alerts_limit": subscription.plan.max_alerts_per_project,
                    }
                
                return AnalyticsResponse(
                    date_range={"from": date_from, "to": date_to},
                    total_scans=total_scans,
                    total_alerts=total_alerts,
                    avg_scan_duration=round(avg_scan_duration, 2),
                    top_issues=top_issues,
                    usage_trends=usage_trends,
                    subscription_usage=subscription_usage,
                )
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error getting analytics: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve analytics"
            )

    # --------------------------------------------------------------
    # Utility Methods
    # --------------------------------------------------------------
    async def _calculate_usage_stats(
        self,
        user: User,
        session: AnyType,
    ) -> Dict[str, AnyType]:
        """Calculate current usage statistics."""
        # Get subscription
        subscription_stmt = select(UserSubscription).where(
            UserSubscription.user_id == user.id,
            UserSubscription.status.in_(["active", "trial"])
        )
        sub_result = await session.execute(subscription_stmt)
        subscription = sub_result.scalar_one_or_none()
        
        if not subscription:
            return {
                "daily_checks_used": 0,
                "daily_checks_limit": 0,
                "monthly_checks_used": 0,
                "monthly_checks_limit": 0,
                "projects_used": 0,
                "projects_limit": 1,
            }
        
        # Get project count
        project_stmt = select(sql_func.count(Project.id)).where(Project.user_id == user.id)
        project_result = await session.execute(project_stmt)
        project_count = project_result.scalar()
        
        return {
            "daily_checks_used": subscription.daily_checks_used,
            "daily_checks_limit": subscription.plan.daily_check_limit,
            "monthly_checks_used": subscription.monthly_checks_used,
            "monthly_checks_limit": subscription.plan.monthly_check_limit,
            "projects_used": project_count,
            "projects_limit": subscription.plan.max_projects,
        }

    async def _get_recent_activity(
        self,
        user: User,
        session: AnyType,
    ) -> List[Dict[str, AnyType]]:
        """Get recent project activity."""
        # This is a simplified implementation
        # In a real implementation, you might have a dedicated activity log table
        
        # Get recent projects
        project_stmt = select(Project).where(Project.user_id == user.id).order_by(Project.updated_at.desc()).limit(5)
        project_result = await session.execute(project_stmt)
        recent_projects = project_result.scalars().all()
        
        activity = []
        for project in recent_projects:
            activity.append({
                "type": "project_updated",
                "project_name": project.name,
                "timestamp": project.updated_at.isoformat(),
                "description": f"Project '{project.name}' was updated",
            })
        
        return activity

    async def _get_monitoring_summary(
        self,
        projects: List[Project],
        session: AnyType,
    ) -> Dict[str, AnyType]:
        """Get monitoring summary for projects."""
        total_projects = len(projects)
        monitored_projects = len([p for p in projects if p.monitoring_enabled])
        
        # Get recent alerts count (last 7 days)
        if projects:
            project_ids = [p.id for p in projects]
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            
            alert_stmt = select(sql_func.count(ProjectAlert.id)).where(
                and_(
                    ProjectAlert.project_id.in_(project_ids),
                    ProjectAlert.created_at >= seven_days_ago
                )
            )
            alert_result = await session.execute(alert_stmt)
            recent_alerts = alert_result.scalar()
        else:
            recent_alerts = 0
        
        return {
            "total_projects": total_projects,
            "monitored_projects": monitored_projects,
            "recent_alerts": recent_alerts,
            "last_scan_summary": "No recent scans" if total_projects == 0 else f"{monitored_projects} projects monitored",
        }

    async def _get_user_subscription(
        self,
        user: User,
        session: AnyType,
    ) -> Optional[UserSubscription]:
        """Get user's active subscription."""
        subscription_stmt = select(UserSubscription).where(
            UserSubscription.user_id == user.id,
            UserSubscription.status.in_(["active", "trial"])
        )
        sub_result = await session.execute(subscription_stmt)
        return sub_result.scalar_one_or_none()

    async def _log_project_activity(
        self,
        project_id: uuid.UUID,
        user_id: uuid.UUID,
        action: str,
        details: Optional[Dict[str, AnyType]] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Log project activity with proper ActivityLog model.
        
        Args:
            project_id: Project UUID
            user_id: User UUID
            action: Activity action type
            details: Additional details as dictionary
            resource_type: Type of resource affected (e.g., 'alert', 'member', 'config')
            resource_id: ID of the affected resource
            ip_address: IP address of the user
            user_agent: User agent string
        """
        try:
            async with self.get_db_session() as session:
                # Validate action type
                if not ActivityLogManager.is_valid_action(action):
                    self.logger.warning(f"Unknown activity action: {action}")
                
                # Create activity log entry
                activity_log = ActivityLog(
                    user_id=user_id,
                    project_id=project_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    details=details,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                
                session.add(activity_log)
                await session.commit()
                
                self.logger.info(f"Activity logged: {project_id} - {user_id} - {action}")
                
        except Exception as e:
            self.logger.error(f"Failed to log activity: {e}")
            # Don't raise the exception to avoid breaking the main operation

    async def _send_invitation_email(
        self,
        project: Project,
        invitee_email: str,
        inviter: User,
        role: str,
    ) -> None:
        """Send project invitation email."""
        # This would integrate with the email service
        self.logger.info(f"Sending invitation email to {invitee_email} for project {project.name} with role {role}")

    async def create_alert(
        self,
        *,
        user: User,
        project_id: uuid.UUID,
        alert_request: AlertCreateRequest,
    ) -> AlertInstanceResponse:
        """
        Create a new alert instance with email notification.
        
        Args:
            user: Current authenticated user
            project_id: Project ID
            alert_request: Alert creation data
            
        Returns:
            AlertInstanceResponse for the created alert
        """
        try:
            async with self.get_db_session() as session:
                # Get project with access check
                stmt = select(Project).where(Project.id == project_id)
                result = await session.execute(stmt)
                project = result.scalar_one_or_none()
                
                if not project:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Project not found"
                    )
                
                # Check access
                if not project.can_user_access(user.id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this project"
                    )
                
                # Create alert instance
                alert_instance = AlertInstance(
                    project_id=project.id,
                    user_id=user.id,
                    alert_type=alert_request.alert_type,
                    severity=alert_request.severity,
                    title=alert_request.title,
                    description=alert_request.description,
                    context_data=alert_request.context_data,
                    affected_urls=alert_request.affected_urls,
                    status="active"
                )
                
                session.add(alert_instance)
                await session.commit()
                await session.refresh(alert_instance)
                
                # Log activity
                await self._log_project_activity(
                    project.id, user.id, "alert_created", 
                    {"title": alert_instance.title, "severity": alert_instance.severity},
                    resource_type="alert",
                    resource_id=str(alert_instance.id)
                )
                
                # Send email notification (don't wait for it to complete)
                import asyncio
                asyncio.create_task(self._send_alert_notification(
                    alert_instance=alert_instance,
                    project=project,
                    user=user
                ))
                
                return _to_alert_instance_response(alert_instance)
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error creating alert: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create alert"
            )

    async def _send_alert_notification(
        self,
        *,
        alert_instance: AlertInstance,
        project: Project,
        user: User,
    ) -> None:
        """Send email notification for alert creation."""
        try:
            subject = f"LinkShield Alert: {alert_instance.title}"
            body = f"""
            Hello {user.get_full_name() or user.email},
            
            A new alert has been created for your project '{project.name}':
            
            Title: {alert_instance.title}
            Severity: {alert_instance.severity.upper()}
            Type: {alert_instance.alert_type}
            {f'Description: {alert_instance.description}' if alert_instance.description else ''}
            {f'Affected URLs: {", ".join(alert_instance.affected_urls)}' if alert_instance.affected_urls else ''}
            
            Please log in to your dashboard to review and take action.
            
            Best regards,
            LinkShield Team
            """
            
            await self.email_service.send_email(
                to_email=user.email,
                subject=subject,
                body=body.strip()
            )
            
            # Update notification status
            alert_instance.notification_sent = True
            alert_instance.notification_sent_at = utc_datetime()
            
            async with self.get_db_session() as session:
                session.add(alert_instance)
                await session.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to send alert notification: {e}")

    async def can_create_project(self, user: User) -> bool:
        """Check if user can create another project based on subscription limits."""
        try:
            async with self.get_db_session() as session:
                # Get subscription
                subscription = await self._get_user_subscription(user, session)
                if not subscription:
                    return False
                
                # Get current project count
                project_stmt = select(sql_func.count(Project.id)).where(Project.user_id == user.id)
                project_result = await session.execute(project_stmt)
                current_count = project_result.scalar()
                
                return subscription.plan.can_create_project(current_count)
                
        except Exception as e:
            self.logger.error(f"Error checking project creation limits: {e}")
            return False

    @rate_limit("api_authenticated")
    async def get_activity_logs(
        self,
        *,
        user: User,
        project_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ActivityLogResponse]:
        """
        Get activity logs for a project.
        
        Args:
            user: Current authenticated user
            project_id: Project ID
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            
        Returns:
            List of ActivityLogResponse objects
        """
        try:
            async with self.get_db_session() as session:
                # Get project with access check
                stmt = select(Project).where(Project.id == project_id)
                result = await session.execute(stmt)
                project = result.scalar_one_or_none()
                
                if not project:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Project not found"
                    )
                
                # Check access
                if not project.can_user_access(user.id):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this project"
                    )
                
                # Get activity logs with user information
                logs_stmt = (
                    select(ActivityLog, User)
                    .join(User, ActivityLog.user_id == User.id)
                    .where(ActivityLog.project_id == project_id)
                    .order_by(ActivityLog.created_at.desc())
                    .limit(limit)
                    .offset(offset)
                )
                
                logs_result = await session.execute(logs_stmt)
                logs_with_users = logs_result.all()
                
                # Convert to response models
                responses = []
                for activity_log, user_obj in logs_with_users:
                    response = ActivityLogResponse(
                        id=activity_log.id,
                        user_id=activity_log.user_id,
                        user_email=user_obj.email,
                        user_full_name=user_obj.get_full_name(),
                        project_id=activity_log.project_id,
                        action=activity_log.action,
                        resource_type=activity_log.resource_type,
                        resource_id=activity_log.resource_id,
                        details=activity_log.details,
                        ip_address=activity_log.ip_address,
                        user_agent=activity_log.user_agent,
                        created_at=activity_log.created_at
                    )
                    responses.append(response)
                
                return responses
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error retrieving activity logs: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve activity logs"
            )

    # --------------------------------------------------------------
    # Social Protection Methods
    # --------------------------------------------------------------
    async def get_social_protection_overview(
        self,
        *,
        user: User,
        project_id: Optional[uuid.UUID] = None,
    ) -> SocialProtectionOverviewResponse:
        """
        Get social protection overview for the user or specific project.
        
        Args:
            user: Current authenticated user
            project_id: Optional project ID to filter by
            
        Returns:
            SocialProtectionOverviewResponse with social protection metrics
        """
        try:
            async with self.get_db_session() as session:
                from src.models.social_protection import SocialProfileScan, ContentRiskAssessment
                
                # Build base query for user's data
                scan_stmt = select(SocialProfileScan).where(SocialProfileScan.user_id == user.id)
                assessment_stmt = select(ContentRiskAssessment).where(ContentRiskAssessment.user_id == user.id)
                
                # Filter by project if specified
                if project_id:
                    scan_stmt = scan_stmt.where(SocialProfileScan.project_id == project_id)
                    assessment_stmt = assessment_stmt.where(ContentRiskAssessment.project_id == project_id)
                
                # Get social scans
                scan_result = await session.execute(scan_stmt)
                scans = scan_result.scalars().all()
                
                # Get risk assessments
                assessment_result = await session.execute(assessment_stmt)
                assessments = assessment_result.scalars().all()
                
                # Calculate metrics
                total_social_scans = len(scans)
                active_monitoring = len([s for s in scans if s.status == "IN_PROGRESS"])
                
                # Risk assessments from today
                today = datetime.utcnow().date()
                risk_assessments_today = len([
                    a for a in assessments 
                    if a.created_at.date() == today
                ])
                
                # High risk alerts
                high_risk_alerts = len([
                    a for a in assessments 
                    if a.risk_level in ["HIGH", "CRITICAL"]
                ])
                
                # Platform coverage
                platform_coverage = {}
                for scan in scans:
                    platform = scan.platform.value
                    platform_coverage[platform] = platform_coverage.get(platform, 0) + 1
                
                # Recent assessments (last 10)
                recent_assessments = sorted(assessments, key=lambda x: x.created_at, reverse=True)[:10]
                recent_assessments_data = [
                    {
                        "id": str(a.id),
                        "content_type": a.content_type.value,
                        "risk_level": a.risk_level.value if a.risk_level else "UNKNOWN",
                        "confidence_score": a.confidence_score,
                        "created_at": a.created_at.isoformat(),
                    }
                    for a in recent_assessments
                ]
                
                # Calculate protection health score (0-100)
                protection_health_score = self._calculate_protection_health_score(scans, assessments)
                
                return SocialProtectionOverviewResponse(
                    total_social_scans=total_social_scans,
                    active_monitoring=active_monitoring,
                    risk_assessments_today=risk_assessments_today,
                    high_risk_alerts=high_risk_alerts,
                    platform_coverage=platform_coverage,
                    recent_assessments=recent_assessments_data,
                    protection_health_score=protection_health_score,
                )
                
        except Exception as e:
            self.logger.error(f"Error getting social protection overview: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve social protection overview"
            )

    async def get_protection_health(
        self,
        *,
        user: User,
        project_id: Optional[uuid.UUID] = None,
    ) -> ProtectionHealthResponse:
        """
        Get comprehensive protection health metrics combining URL safety and social protection.
        
        Args:
            user: Current authenticated user
            project_id: Optional project ID to filter by
            
        Returns:
            ProtectionHealthResponse with combined protection metrics
        """
        try:
            async with self.get_db_session() as session:
                from src.models.social_protection import SocialProfileScan, ContentRiskAssessment
                from src.models.url_check import URLCheck
                
                # Get URL safety data
                url_stmt = select(URLCheck).where(URLCheck.user_id == user.id)
                if project_id:
                    url_stmt = url_stmt.where(URLCheck.project_id == project_id)
                
                url_result = await session.execute(url_stmt)
                url_checks = url_result.scalars().all()
                
                # Get social protection data
                scan_stmt = select(SocialProfileScan).where(SocialProfileScan.user_id == user.id)
                assessment_stmt = select(ContentRiskAssessment).where(ContentRiskAssessment.user_id == user.id)
                
                if project_id:
                    scan_stmt = scan_stmt.where(SocialProfileScan.project_id == project_id)
                    assessment_stmt = assessment_stmt.where(ContentRiskAssessment.project_id == project_id)
                
                scan_result = await session.execute(scan_stmt)
                scans = scan_result.scalars().all()
                
                assessment_result = await session.execute(assessment_stmt)
                assessments = assessment_result.scalars().all()
                
                # Calculate URL safety score
                url_safety_score = self._calculate_url_safety_score(url_checks)
                
                # Calculate social protection score
                social_protection_score = self._calculate_protection_health_score(scans, assessments)
                
                # Calculate overall score (weighted average)
                overall_score = (url_safety_score * 0.6) + (social_protection_score * 0.4)
                
                # Risk breakdown
                risk_breakdown = {
                    "url_threats": self._calculate_url_threat_score(url_checks),
                    "social_risks": self._calculate_social_risk_score(assessments),
                    "reputation_health": self._calculate_reputation_score(scans, assessments),
                    "monitoring_coverage": self._calculate_coverage_score(scans, url_checks),
                }
                
                # Determine trending
                trending = self._calculate_trending(user, session)
                
                # Generate recommendations
                recommendations = self._generate_protection_recommendations(
                    url_checks, scans, assessments, overall_score
                )
                
                return ProtectionHealthResponse(
                    overall_score=round(overall_score, 2),
                    url_safety_score=round(url_safety_score, 2),
                    social_protection_score=round(social_protection_score, 2),
                    risk_breakdown={k: round(v, 2) for k, v in risk_breakdown.items()},
                    trending=trending,
                    last_updated=datetime.utcnow(),
                    recommendations=recommendations,
                )
                
        except Exception as e:
            self.logger.error(f"Error getting protection health: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve protection health"
            )

    def _calculate_protection_health_score(self, scans, assessments) -> float:
        """Calculate protection health score based on scans and assessments."""
        if not scans and not assessments:
            return 100.0  # No data means no known risks
        
        # Base score
        score = 100.0
        
        # Deduct points for high-risk assessments
        high_risk_count = len([a for a in assessments if a.risk_level in ["HIGH", "CRITICAL"]])
        score -= min(high_risk_count * 10, 50)  # Max 50 point deduction
        
        # Deduct points for failed scans
        failed_scans = len([s for s in scans if s.status == "FAILED"])
        score -= min(failed_scans * 5, 25)  # Max 25 point deduction
        
        # Bonus for recent successful scans
        recent_successful = len([
            s for s in scans 
            if s.status == "COMPLETED" and 
            (datetime.utcnow() - s.completed_at).days <= 7
        ])
        score += min(recent_successful * 2, 10)  # Max 10 point bonus
        
        return max(0.0, min(100.0, score))

    def _calculate_url_safety_score(self, url_checks) -> float:
        """Calculate URL safety score based on URL checks."""
        if not url_checks:
            return 100.0
        
        # Simple scoring based on threat detection
        total_checks = len(url_checks)
        threat_checks = len([u for u in url_checks if u.is_threat])
        
        if total_checks == 0:
            return 100.0
        
        safety_ratio = (total_checks - threat_checks) / total_checks
        return safety_ratio * 100.0

    def _calculate_url_threat_score(self, url_checks) -> float:
        """Calculate URL threat score based on detected threats."""
        if not url_checks:
            return 100.0  # No checks means no known threats
        
        # Calculate threat ratio
        total_checks = len(url_checks)
        threat_checks = len([u for u in url_checks if u.is_threat])
        
        if total_checks == 0:
            return 100.0
        
        # Invert the ratio so higher threats = lower score
        threat_ratio = threat_checks / total_checks
        return max(0.0, 100.0 - (threat_ratio * 100))

    def _calculate_social_risk_score(self, assessments) -> float:
        """Calculate social risk score."""
        if not assessments:
            return 100.0
        
        risk_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "VERY_LOW": 0}
        total_risk = sum(risk_weights.get(a.risk_level.value if a.risk_level else "LOW", 1) for a in assessments)
        max_possible_risk = len(assessments) * 25
        
        if max_possible_risk == 0:
            return 100.0
        
        return max(0.0, 100.0 - (total_risk / max_possible_risk * 100))

    def _calculate_reputation_score(self, scans, assessments) -> float:
        """Calculate reputation health score."""
        # Simplified reputation scoring
        if not scans and not assessments:
            return 100.0
        
        # Base on recent activity and risk levels
        recent_high_risk = len([
            a for a in assessments 
            if a.risk_level in ["HIGH", "CRITICAL"] and 
            (datetime.utcnow() - a.created_at).days <= 30
        ])
        
        return max(0.0, 100.0 - (recent_high_risk * 10))

    def _calculate_coverage_score(self, scans, url_checks) -> float:
        """Calculate monitoring coverage score."""
        # Simple coverage based on activity
        total_activity = len(scans) + len(url_checks)
        if total_activity == 0:
            return 0.0
        
        # Score based on recent activity
        recent_activity = len([
            s for s in scans 
            if (datetime.utcnow() - s.created_at).days <= 30
        ]) + len([
            u for u in url_checks 
            if (datetime.utcnow() - u.created_at).days <= 30
        ])
        
        return min(100.0, (recent_activity / max(1, total_activity)) * 100)

    def _calculate_trending(self, user, session) -> str:
        """Calculate trending direction for protection health."""
        # Simplified trending calculation
        # In a real implementation, this would compare recent metrics to historical data
        return "stable"

    def _generate_protection_recommendations(self, url_checks, scans, assessments, overall_score) -> List[str]:
        """Generate actionable recommendations based on protection data."""
        recommendations = []
        
        if overall_score < 70:
            recommendations.append("Your protection score is below optimal. Consider increasing monitoring frequency.")
        
        if not scans:
            recommendations.append("Enable social media monitoring to protect your online reputation.")
        
        high_risk_assessments = [a for a in assessments if a.risk_level in ["HIGH", "CRITICAL"]]
        if high_risk_assessments:
            recommendations.append(f"Address {len(high_risk_assessments)} high-risk content issues immediately.")
        
        if not url_checks:
            recommendations.append("Start monitoring your website URLs for security threats.")
        
        failed_scans = [s for s in scans if s.status == "FAILED"]
        if failed_scans:
            recommendations.append("Review and retry failed social media scans.")
        
        if len(recommendations) == 0:
            recommendations.append("Your protection setup looks good! Continue regular monitoring.")
        
        return recommendations[:5]  # Limit to 5 recommendations