#!/usr/bin/env python3
"""
LinkShield Backend Admin Controller

Controller for handling admin dashboard business logic including statistics,
configuration management, user administration, and system monitoring.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from fastapi import HTTPException
from loguru import logger

from src.controllers.base_controller import BaseController
from src.services.admin_service import AdminService, AdminServiceError, ConfigurationError
from src.models.user import User


class AdminController(BaseController):
    """
    Controller for admin dashboard operations.
    
    Handles system statistics, configuration management, user administration,
    and system health monitoring for administrative users.
    """
    
    def __init__(self, admin_service: AdminService):
        """
        Initialize the admin controller.
        
        Args:
            admin_service: Admin service instance
        """
        super().__init__()
        self.admin_service = admin_service
    
    # Dashboard Statistics Methods
    
    async def get_dashboard_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive dashboard statistics.
        
        Returns:
            Dict containing dashboard statistics
        """
        try:
            self.logger.info("Fetching dashboard statistics")
            
            statistics = await self.admin_service.get_system_statistics()
            
            self.logger.info("Dashboard statistics retrieved successfully")
            return {
                "success": True,
                "data": statistics,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get dashboard statistics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve dashboard statistics: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error getting dashboard statistics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def get_traffic_analytics(self, days: int = 30) -> Dict[str, Any]:
        """
        Get traffic analytics for the specified period.
        
        Args:
            days: Number of days to analyze (default: 30)
            
        Returns:
            Dict containing traffic analytics
        """
        try:
            # Validate days parameter
            if days < 1 or days > 365:
                raise HTTPException(
                    status_code=400,
                    detail="Days parameter must be between 1 and 365"
                )
            
            self.logger.info(f"Fetching traffic analytics for {days} days")
            
            analytics = await self.admin_service.get_traffic_analytics(days)
            
            self.logger.info("Traffic analytics retrieved successfully")
            return {
                "success": True,
                "data": analytics,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get traffic analytics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve traffic analytics: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting traffic analytics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def get_threat_intelligence(self) -> Dict[str, Any]:
        """
        Get threat intelligence summary.
        
        Returns:
            Dict containing threat intelligence data
        """
        try:
            self.logger.info("Fetching threat intelligence")
            
            intelligence = await self.admin_service.get_threat_intelligence()
            
            self.logger.info("Threat intelligence retrieved successfully")
            return {
                "success": True,
                "data": intelligence,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get threat intelligence: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve threat intelligence: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error getting threat intelligence: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def get_user_analytics(self) -> Dict[str, Any]:
        """
        Get user analytics and behavior insights.
        
        Returns:
            Dict containing user analytics
        """
        try:
            self.logger.info("Fetching user analytics")
            
            analytics = await self.admin_service.get_user_analytics()
            
            self.logger.info("User analytics retrieved successfully")
            return {
                "success": True,
                "data": analytics,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get user analytics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve user analytics: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error getting user analytics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    # Configuration Management Methods
    
    async def get_configuration(self, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Get system configuration settings.
        
        Args:
            category: Optional category filter
            
        Returns:
            Dict containing configuration settings
        """
        try:
            self.logger.info(f"Fetching configuration (category: {category})")
            
            # Validate category if provided
            if category:
                valid_categories = ["security", "rate_limiting", "ai_services", "external_apis", "system", "notifications"]
                if category not in valid_categories:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid category. Must be one of: {valid_categories}"
                    )
            
            configuration = await self.admin_service.get_configuration(category)
            
            self.logger.info("Configuration retrieved successfully")
            return {
                "success": True,
                "data": {
                    "category": category,
                    "settings": configuration
                },
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get configuration: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve configuration: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting configuration: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def update_configuration(self, key: str, value: str, current_user: User) -> Dict[str, Any]:
        """
        Update a configuration setting.
        
        Args:
            key: Configuration key
            value: New value
            current_user: Current admin user
            
        Returns:
            Dict containing updated configuration
        """
        try:
            self.logger.info(f"Updating configuration key: {key}")
            
            # Validate inputs
            if not key or not key.strip():
                raise HTTPException(
                    status_code=400,
                    detail="Configuration key cannot be empty"
                )
            
            if value is None:
                raise HTTPException(
                    status_code=400,
                    detail="Configuration value cannot be null"
                )
            
            updated_config = await self.admin_service.update_configuration(
                key=key.strip(),
                value=value,
                user_id=current_user.id
            )
            
            self.logger.info(f"Configuration key '{key}' updated successfully")
            return {
                "success": True,
                "data": updated_config,
                "message": f"Configuration '{key}' updated successfully",
                "timestamp": datetime.now(timezone.utc)
            }
        
        except ConfigurationError as e:
            self.logger.warning(f"Configuration validation error: {e}")
            raise self._create_http_exception(
                status_code=400,
                detail=str(e)
            )
        except AdminServiceError as e:
            self.logger.error(f"Failed to update configuration: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to update configuration: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error updating configuration: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    # User Management Methods
    
    async def get_users(self, page: int = 1, limit: int = 50, 
                       role: Optional[str] = None, status: Optional[str] = None,
                       subscription: Optional[str] = None, is_active: Optional[bool] = None,
                       search: Optional[str] = None) -> Dict[str, Any]:
        """
        Get paginated list of users with optional filters.
        
        Args:
            page: Page number (default: 1)
            limit: Items per page (default: 50)
            role: Filter by user role
            status: Filter by user status
            subscription: Filter by subscription plan
            is_active: Filter by active status
            search: Search term for email, username, or name
            
        Returns:
            Dict containing paginated user data
        """
        try:
            # Validate pagination parameters
            if page < 1:
                raise HTTPException(status_code=400, detail="Page must be >= 1")
            if limit < 1 or limit > 100:
                raise HTTPException(status_code=400, detail="Limit must be between 1 and 100")
            
            # Validate filter parameters
            if role and role not in ["admin", "super_admin", "user", "moderator"]:
                raise HTTPException(status_code=400, detail="Invalid role filter")
            if status and status not in ["active", "inactive", "suspended", "pending_verification"]:
                raise HTTPException(status_code=400, detail="Invalid status filter")
            if subscription and subscription not in ["free", "basic", "pro", "enterprise"]:
                raise HTTPException(status_code=400, detail="Invalid subscription filter")
            
            self.logger.info(f"Fetching users (page: {page}, limit: {limit})")
            
            # Build filters
            filters = {}
            if role:
                filters['role'] = role
            if status:
                filters['status'] = status
            if subscription:
                filters['subscription'] = subscription
            if is_active is not None:
                filters['is_active'] = is_active
            if search:
                filters['search'] = search.strip()
            
            users_data = await self.admin_service.get_users(page, limit, filters)
            
            self.logger.info("Users retrieved successfully")
            return {
                "success": True,
                "data": users_data,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get users: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve users: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting users: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def update_user_status(self, user_id: str, status: str, current_user: User) -> Dict[str, Any]:
        """
        Update user status (activate, deactivate, suspend).
        
        Args:
            user_id: User ID to update
            status: New status
            current_user: Current admin user
            
        Returns:
            Dict containing updated user data
        """
        try:
            # Validate user_id
            try:
                user_uuid = uuid.UUID(user_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid user ID format")
            
            # Validate status
            valid_statuses = ["active", "inactive", "suspended", "pending_verification"]
            if status not in valid_statuses:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status. Must be one of: {valid_statuses}"
                )
            
            # Prevent self-modification
            if user_uuid == current_user.id:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot modify your own user status"
                )
            
            self.logger.info(f"Updating user {user_id} status to {status}")
            
            updated_user = await self.admin_service.update_user_status(
                user_id=user_uuid,
                status=status,
                admin_user_id=current_user.id
            )
            
            self.logger.info(f"User {user_id} status updated successfully")
            return {
                "success": True,
                "data": updated_user,
                "message": f"User status updated to {status}",
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to update user status: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to update user status: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error updating user status: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    # System Management Methods
    
    async def get_system_health(self) -> Dict[str, Any]:
        """
        Get current system health status.
        
        Returns:
            Dict containing system health data
        """
        try:
            self.logger.info("Fetching system health")
            
            health_data = await self.admin_service.get_system_health()
            
            self.logger.info("System health retrieved successfully")
            return {
                "success": True,
                "data": health_data,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get system health: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve system health: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error getting system health: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def get_system_logs(self, level: str = "INFO", limit: int = 100) -> Dict[str, Any]:
        """
        Get recent system logs.
        
        Args:
            level: Log level filter (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            limit: Number of log entries to return
            
        Returns:
            Dict containing system logs
        """
        try:
            # Validate parameters
            valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            if level.upper() not in valid_levels:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid log level. Must be one of: {valid_levels}"
                )
            
            if limit < 1 or limit > 1000:
                raise HTTPException(
                    status_code=400,
                    detail="Limit must be between 1 and 1000"
                )
            
            self.logger.info(f"Fetching system logs (level: {level}, limit: {limit})")
            
            # This is a placeholder implementation
            # In a real system, you would read from log files or a logging service
            logs = [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": "INFO",
                    "message": "System logs endpoint accessed",
                    "module": "admin_controller"
                }
            ]
            
            return {
                "success": True,
                "data": {
                    "logs": logs,
                    "level": level.upper(),
                    "count": len(logs)
                },
                "timestamp": datetime.now(timezone.utc)
            }
        
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting system logs: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )