#!/usr/bin/env python3
"""
LinkShield Backend Admin Controller

Controller for handling admin dashboard business logic including statistics,
configuration management, user administration, and system monitoring.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from fastapi import HTTPException, BackgroundTasks
from loguru import logger

from src.controllers.base_controller import BaseController
from src.services.admin_service import AdminService, AdminServiceError, ConfigurationError
from src.services.webhook_service import get_webhook_service
from src.services.task_tracking_service import get_task_tracking_service
from src.models.user import User
from src.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority


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
    
    # Async Background Task Methods
    
    async def _export_users_async(
        self,
        task_id: str,
        page: int,
        limit: int,
        filters: Dict[str, Any],
        callback_url: Optional[str] = None
    ) -> None:
        """
        Export users data asynchronously in the background.
        
        Args:
            task_id: ID of the background task
            page: Page number for pagination
            limit: Items per page
            filters: User filters to apply
            callback_url: Optional webhook URL for completion notification
        """
        task_tracking_service = get_task_tracking_service()
        webhook_service = get_webhook_service()
        
        try:
            # Get database session
            db = await self.get_db_session()
            
            # Update task status to running
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                progress=10
            )
            
            self.logger.info(f"Starting async user export (task: {task_id})")
            
            # Fetch all user data (potentially large dataset)
            users_data = await self.admin_service.get_users(page, limit, filters)
            
            # Update progress
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                progress=50
            )
            
            # Process and format data for export
            export_data = {
                "users": users_data.get('users', []),
                "total": users_data.get('total', 0),
                "page": page,
                "limit": limit,
                "filters": filters,
                "exported_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Update progress
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                progress=90
            )
            
            # Complete task
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.COMPLETED,
                progress=100,
                result=export_data
            )
            
            # Send webhook notification if callback URL provided
            if callback_url:
                await webhook_service.send_webhook(
                    url=callback_url,
                    event_type="ADMIN_USER_EXPORT_COMPLETED",
                    data={
                        "task_id": task_id,
                        "status": "completed",
                        "total_users": export_data["total"],
                        "export_data": export_data
                    }
                )
            
            self.logger.info(f"User export completed successfully (task: {task_id})")
            
        except Exception as e:
            self.logger.error(f"User export failed (task: {task_id}): {str(e)}")
            
            # Update task status to failed
            try:
                db = await self.get_db_session()
                await task_tracking_service.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.FAILED,
                    error_message=str(e)
                )
                
                # Send failure webhook notification
                if callback_url:
                    await webhook_service.send_webhook(
                        url=callback_url,
                        event_type="ADMIN_USER_EXPORT_FAILED",
                        data={
                            "task_id": task_id,
                            "status": "failed",
                            "error": str(e)
                        }
                    )
            except Exception as webhook_error:
                self.logger.error(f"Failed to send failure notification (task: {task_id}): {webhook_error}")
    
    async def _export_logs_async(
        self,
        task_id: str,
        level: str,
        limit: int,
        callback_url: Optional[str] = None
    ) -> None:
        """
        Export system logs asynchronously in the background.
        
        Args:
            task_id: ID of the background task
            level: Log level filter
            limit: Number of log entries to export
            callback_url: Optional webhook URL for completion notification
        """
        task_tracking_service = get_task_tracking_service()
        webhook_service = get_webhook_service()
        
        try:
            # Get database session
            db = await self.get_db_session()
            
            # Update task status to running
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                progress=10
            )
            
            self.logger.info(f"Starting async log export (task: {task_id})")
            
            # Simulate log processing (in real implementation, read from log files/service)
            # This would involve reading from actual log files or a logging service
            logs = []
            for i in range(min(limit, 1000)):  # Simulate processing logs
                logs.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": level,
                    "message": f"Log entry {i+1}",
                    "module": "system",
                    "request_id": str(uuid.uuid4())
                })
                
                # Update progress periodically
                if i % 100 == 0:
                    progress = min(10 + (i / limit) * 80, 90)
                    await task_tracking_service.update_task_status(
                        db=db,
                        task_id=task_id,
                        status=TaskStatus.RUNNING,
                        progress=int(progress)
                    )
            
            # Prepare export data
            export_data = {
                "logs": logs,
                "level": level,
                "count": len(logs),
                "exported_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Complete task
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.COMPLETED,
                progress=100,
                result=export_data
            )
            
            # Send webhook notification if callback URL provided
            if callback_url:
                await webhook_service.send_webhook(
                    url=callback_url,
                    event_type="ADMIN_LOG_EXPORT_COMPLETED",
                    data={
                        "task_id": task_id,
                        "status": "completed",
                        "log_count": len(logs),
                        "export_data": export_data
                    }
                )
            
            self.logger.info(f"Log export completed successfully (task: {task_id})")
            
        except Exception as e:
            self.logger.error(f"Log export failed (task: {task_id}): {str(e)}")
            
            # Update task status to failed
            try:
                db = await self.get_db_session()
                await task_tracking_service.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.FAILED,
                    error_message=str(e)
                )
                
                # Send failure webhook notification
                if callback_url:
                    await webhook_service.send_webhook(
                        url=callback_url,
                        event_type="ADMIN_LOG_EXPORT_FAILED",
                        data={
                            "task_id": task_id,
                            "status": "failed",
                            "error": str(e)
                        }
                    )
            except Exception as webhook_error:
                self.logger.error(f"Failed to send failure notification (task: {task_id}): {webhook_error}")
    
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
                       search: Optional[str] = None, background_tasks: Optional[BackgroundTasks] = None,
                       callback_url: Optional[str] = None) -> Dict[str, Any]:
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
            background_tasks: FastAPI background tasks for async processing
            callback_url: Optional webhook URL for completion notification
            
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
            
            # Check if this should be processed asynchronously for large datasets
            should_process_async = (
                background_tasks is not None and 
                (users_data.get('total', 0) > 1000 or callback_url is not None)
            )
            
            if should_process_async:
                # Create background task for async processing
                task_tracking_service = get_task_tracking_service()
                db = await self.get_db_session()
                
                task = await task_tracking_service.create_task(
                    db=db,
                    task_type=TaskType.ADMIN_USER_EXPORT,
                    priority=TaskPriority.MEDIUM,
                    user_id=None,  # Admin operation
                    metadata={
                        "page": page,
                        "limit": limit,
                        "filters": filters,
                        "total_users": users_data.get('total', 0),
                        "callback_url": callback_url
                    }
                )
                
                # Add background task for async processing
                background_tasks.add_task(
                    self._export_users_async,
                    task_id=str(task.id),
                    page=page,
                    limit=limit,
                    filters=filters,
                    callback_url=callback_url
                )
                
                self.logger.info(f"Large user dataset queued for async processing (task: {task.id})")
                return {
                    "success": True,
                    "task_id": str(task.id),
                    "status": "processing",
                    "message": "User data export queued for processing",
                    "timestamp": datetime.now(timezone.utc)
                }

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
    
    async def get_system_logs(self, level: str = "INFO", limit: int = 100,
                             background_tasks: Optional[BackgroundTasks] = None,
                             callback_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Get recent system logs.
        
        Args:
            level: Log level filter (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            limit: Number of log entries to return
            background_tasks: FastAPI background tasks for async processing
            callback_url: Optional webhook URL for completion notification
            
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
            
            # Check if this should be processed asynchronously for large log requests
            should_process_async = (
                background_tasks is not None and 
                (limit > 500 or callback_url is not None)
            )
            
            if should_process_async:
                # Create background task for async log processing
                task_tracking_service = get_task_tracking_service()
                db = await self.get_db_session()
                
                task = await task_tracking_service.create_task(
                    db=db,
                    task_type=TaskType.ADMIN_LOG_EXPORT,
                    priority=TaskPriority.LOW,
                    user_id=None,  # Admin operation
                    metadata={
                        "level": level.upper(),
                        "limit": limit,
                        "callback_url": callback_url
                    }
                )
                
                # Add background task for async processing
                background_tasks.add_task(
                    self._export_logs_async,
                    task_id=str(task.id),
                    level=level.upper(),
                    limit=limit,
                    callback_url=callback_url
                )
                
                self.logger.info(f"Large log export queued for async processing (task: {task.id})")
                return {
                    "success": True,
                    "task_id": str(task.id),
                    "status": "processing",
                    "message": "System logs export queued for processing",
                    "timestamp": datetime.now(timezone.utc)
                }
            
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