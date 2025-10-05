#!/usr/bin/env python3
"""
LinkShield Backend Admin Routes

Admin dashboard endpoints for system management, user administration,
configuration management, and monitoring.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPBearer
from loguru import logger
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession


from linkshield.config.database import get_db_session, AsyncSession
from linkshield.controllers.admin_controller import AdminController
from linkshield.controllers.depends import get_admin_controller
from linkshield.authentication.dependencies import get_admin_user
from linkshield.models.user import User

# Security scheme for JWT tokens
security = HTTPBearer()

# Create router with admin prefix
router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


# Request/Response Models

class ConfigurationUpdateRequest(BaseModel):
    """Request model for configuration updates."""
    key: str = Field(..., min_length=1, max_length=100, description="Configuration key")
    value: str = Field(..., max_length=1000, description="Configuration value")
    
    @field_validator('key')
    def validate_key(cls, v):
        """Validate configuration key format."""
        if not v.replace('_', '').replace('.', '').isalnum():
            raise ValueError('Key must contain only alphanumeric characters, underscores, and dots')
        return v.lower()


class UserStatusUpdateRequest(BaseModel):
    """Request model for user status updates."""
    status: str = Field(..., description="New user status")
    
    @field_validator('status')
    def validate_status(cls, v):
        """Validate user status."""
        valid_statuses = ["active", "inactive", "suspended", "pending_verification"]
        if v not in valid_statuses:
            raise ValueError(f'Status must be one of: {valid_statuses}')
        return v


class AdminResponse(BaseModel):
    """Standard admin response model."""
    success: bool
    data: Dict[str, Any]
    message: Optional[str] = None
    timestamp: datetime


# Dashboard Statistics Endpoints

@router.get("/dashboard/statistics", response_model=AdminResponse)
async def get_dashboard_statistics(
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Get comprehensive dashboard statistics.
    
    Returns system overview including user counts, URL analysis stats,
    threat detection metrics, and system performance indicators.
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} requested dashboard statistics")
        result = await controller.get_dashboard_statistics()
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get dashboard statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard statistics"
        )


@router.get("/dashboard/traffic", response_model=AdminResponse)
async def get_traffic_analytics(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Get traffic analytics for the specified period.
    
    Returns API usage patterns, request volumes, response times,
    and geographic distribution of requests.
    
    **Parameters:**
    - **days**: Number of days to analyze (1-365)
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} requested traffic analytics for {days} days")
        result = await controller.get_traffic_analytics(days)
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get traffic analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve traffic analytics"
        )


@router.get("/dashboard/threats", response_model=AdminResponse)
async def get_threat_intelligence(
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Get threat intelligence summary.
    
    Returns recent threat detections, malware categories,
    blocked domains, and security incident trends.
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} requested threat intelligence")
        result = await controller.get_threat_intelligence()
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get threat intelligence: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve threat intelligence"
        )


@router.get("/dashboard/users", response_model=AdminResponse)
async def get_user_analytics(
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Get user analytics and behavior insights.
    
    Returns user registration trends, subscription distribution,
    activity patterns, and engagement metrics.
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} requested user analytics")
        result = await controller.get_user_analytics()
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user analytics"
        )


# Configuration Management Endpoints

@router.get("/config", response_model=AdminResponse)
async def get_configuration(
    category: Optional[str] = Query(None, description="Configuration category filter"),
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Get system configuration settings.
    
    Returns current configuration values organized by category.
    Sensitive values are masked for security.
    
    **Parameters:**
    - **category**: Optional category filter (security, rate_limiting, ai_services, external_apis, system, notifications)
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} requested configuration (category: {category})")
        result = await controller.get_configuration(category)
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve configuration"
        )


@router.put("/config", response_model=AdminResponse)
async def update_configuration(
    request: ConfigurationUpdateRequest,
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Update a configuration setting.
    
    Updates the specified configuration key with a new value.
    Changes are logged for audit purposes and may require service restart.
    
    **Request Body:**
    - **key**: Configuration key to update
    - **value**: New configuration value
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} updating configuration key: {request.key}")
        result = await controller.update_configuration(
            key=request.key,
            value=request.value,
            current_user=current_user
        )
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update configuration"
        )


# User Management Endpoints

@router.get("/users", response_model=AdminResponse)
async def get_users(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
    role: Optional[str] = Query(None, description="Filter by user role"),
    status: Optional[str] = Query(None, description="Filter by user status"),
    subscription: Optional[str] = Query(None, description="Filter by subscription plan"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search term for email, username, or name"),
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Get paginated list of users with optional filters.
    
    Returns user information including profile data, subscription status,
    activity metrics, and account status.
    
    **Parameters:**
    - **page**: Page number (default: 1)
    - **limit**: Items per page (1-100, default: 50)
    - **role**: Filter by user role (admin, super_admin, user, moderator)
    - **status**: Filter by user status (active, inactive, suspended, pending_verification)
    - **subscription**: Filter by subscription plan (free, basic, pro, enterprise)
    - **is_active**: Filter by active status (true/false)
    - **search**: Search term for email, username, or name
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} requested users list (page: {page}, limit: {limit})")
        result = await controller.get_users(
            page=page,
            limit=limit,
            role=role,
            status=status,
            subscription=subscription,
            is_active=is_active,
            search=search
        )
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )


@router.put("/users/{user_id}/status", response_model=AdminResponse)
async def update_user_status(
    user_id: str,
    request: UserStatusUpdateRequest,
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Update user status (activate, deactivate, suspend).
    
    Changes user account status and logs the action for audit purposes.
    Status changes may affect user access and API functionality.
    
    **Parameters:**
    - **user_id**: UUID of the user to update
    
    **Request Body:**
    - **status**: New user status (active, inactive, suspended, pending_verification)
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} updating user {user_id} status to {request.status}")
        result = await controller.update_user_status(
            user_id=user_id,
            status=request.status,
            current_user=current_user
        )
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user status"
        )


# System Management Endpoints

@router.get("/system/health", response_model=AdminResponse)
async def get_system_health(
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Get current system health status.
    
    Returns comprehensive system health information including
    database connectivity, external service status, resource usage,
    and performance metrics.
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} requested system health")
        result = await controller.get_system_health()
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get system health: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system health"
        )


@router.get("/system/logs", response_model=AdminResponse)
async def get_system_logs(
    level: str = Query("INFO", description="Log level filter"),
    limit: int = Query(100, ge=1, le=1000, description="Number of log entries"),
    controller: AdminController = Depends(get_admin_controller),
    current_user: User = Depends(get_admin_user)
) -> AdminResponse:
    """
    Get recent system logs.
    
    Returns recent log entries filtered by level and limited by count.
    Useful for debugging and monitoring system behavior.
    
    **Parameters:**
    - **level**: Log level filter (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - **limit**: Number of log entries to return (1-1000, default: 100)
    
    **Requires:** Admin or Super Admin role
    """
    try:
        logger.info(f"Admin {current_user.email} requested system logs (level: {level}, limit: {limit})")
        result = await controller.get_system_logs(level=level, limit=limit)
        return AdminResponse(**result)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get system logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system logs"
        )


# Health check for admin routes
@router.get("/health")
async def admin_health_check():
    """
    Admin routes health check.
    
    Simple endpoint to verify admin routes are accessible.
    Does not require authentication.
    """
    return {
        "status": "healthy",
        "service": "admin-routes",
        "timestamp": datetime.now(timezone.utc),
        "version": "1.0.0"
    }