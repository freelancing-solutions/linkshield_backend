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
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import and_, select, update, func as sql_func
from sqlalchemy.exc import IntegrityError

from src.controllers.base_controller import BaseController
from src.models.project import Project, ProjectMember, MonitoringConfig, ProjectAlert, ProjectRole
from src.models.subscription import SubscriptionPlan, UserSubscription
from src.models.user import User
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.utils import utc_datetime


# ------------------------------------------------------------------
# Pydantic response models (live close to business logic)
# ------------------------------------------------------------------
class DashboardOverviewResponse(BaseModel):
    """Dashboard overview response model."""
    total_projects: int
    active_projects: int
    recent_alerts: int
    subscription_status: str
    usage_stats: Dict[str, AnyType]
    recent_activity: List[Dict[str, AnyType]]
    monitoring_summary: Dict[str, AnyType]


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
    settings: Optional[Dict[str, AnyType]] = None


class ProjectUpdateRequest(BaseModel):
    """Project update request model."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    website_url: Optional[str] = Field(None, max_length=500)
    settings: Optional[Dict[str, AnyType]] = None
    is_active: Optional[bool] = None


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


class AnalyticsResponse(BaseModel):
    """Analytics response model."""
    date_range: Dict[str, datetime]
    total_scans: int
    total_alerts: int
    avg_scan_duration: float
    top_issues: List[Dict[str, AnyType]]
    usage_trends: Dict[str, List[Dict[str, AnyType]]]
    subscription_usage: Dict[str, AnyType]


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
                
                return DashboardOverviewResponse(
                    total_projects=total_projects,
                    active_projects=active_projects,
                    recent_alerts=recent_alerts_count,
                    subscription_status=subscription_status,
                    usage_stats=usage_stats,
                    recent_activity=recent_activity,
                    monitoring_summary=monitoring_summary,
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
                    {"name": project.name, "domain": domain}
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
                    {"updated_fields": list(update_data.keys())}
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
                    {"name": project.name}
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
                await self._log_project_activity(project.id, user.id, action)
                
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
                    {"email": request_model.email, "role": request_model.role}
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
    ) -> None:
        """Log project activity."""
        # In a real implementation, this would write to an activity log table
        self.logger.info(f"Project activity: {project_id} - {user_id} - {action} - {details}")

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