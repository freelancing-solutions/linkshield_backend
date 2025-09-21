"""Base controller class providing common functionality for all controllers.

This module defines the BaseController class that serves as the foundation for all
controller classes in the application. It provides common dependency injection patterns,
error handling utilities, logging, validation helpers, and response formatting.
"""

from typing import Dict, Any, Optional, List, Union
from abc import ABC
from datetime import datetime, timedelta
import logging
import uuid

from fastapi import HTTPException, status, Request, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from pydantic import ValidationError

from src.database.session import get_db_session
from src.config.settings import get_settings
from src.services.security_service import SecurityService
from src.services.auth_service import AuthService
from src.services.email_service import EmailService
from src.services.webhook_service import get_webhook_service
from src.services.task_tracking_service import get_task_tracking_service
from src.models.user import User
from src.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority


class BaseController(ABC):
    """Base controller class with common functionality.
    
    This class provides:
    - Dependency injection for common services
    - Standard error handling and logging
    - Common validation helpers
    - Response formatting utilities
    - Rate limiting and authentication helpers
    """
    
    def __init__(
        self,
        get_db_session: Optional[AsyncSession] = None,
        security_service: Optional[SecurityService] = None,
        auth_service: Optional[AuthService] = None,
        email_service: Optional[EmailService] = None
    ):
        """Initialize base controller with common dependencies.
        
        Args:
            db_session: Database session for data operations
            security_service: Security service for validation and checks
            auth_service: Authentication service for user operations
        """
        self.get_db_session = get_db_session if get_db_session else get_db_session
        self.email_service = email_service or EmailService(db_session=self.get_db_session)
        self.security_service = security_service or SecurityService(db_session=self.get_db_session)
        self.auth_service = auth_service or AuthService(db_session=self.get_db_session, email_service=self.email_service, security_service=self.security_service)
        self.settings = get_settings()
        self.logger = logging.getLogger(self.__class__.__name__)
    
   
    def log_operation(
        self,
        operation: str,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        level: str = "info"
    ) -> None:
        """Log controller operations with structured data.
        
        Args:
            operation: Description of the operation being performed
            user_id: ID of the user performing the operation
            details: Additional operation details
            level: Log level (debug, info, warning, error)
        """
        log_data = {
            "operation": operation,
            "controller": self.__class__.__name__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "details": details or {}
        }
        
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"Controller operation: {operation}", extra=log_data)
    
    def handle_database_error(self, error: SQLAlchemyError, operation: str) -> HTTPException:
        """Handle database errors with appropriate HTTP responses.
        
        Args:
            error: SQLAlchemy error that occurred
            operation: Description of the operation that failed
            
        Returns:
            HTTPException: Appropriate HTTP exception for the error
        """
        self.logger.error(
            f"Database error during {operation}: {str(error)}",
            extra={"error_type": type(error).__name__, "operation": operation}
        )
        
        # Map specific database errors to HTTP status codes
        if "duplicate key" in str(error).lower():
            return HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Resource already exists: {operation}"
            )
        elif "foreign key" in str(error).lower():
            return HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid reference in {operation}"
            )
        else:
            return HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error during {operation}"
            )
    
    def handle_validation_error(self, error: ValidationError, operation: str) -> HTTPException:
        """Handle validation errors with detailed error messages.
        
        Args:
            error: Pydantic validation error
            operation: Description of the operation that failed
            
        Returns:
            HTTPException: HTTP 422 exception with validation details
        """
        self.logger.warning(
            f"Validation error during {operation}: {str(error)}",
            extra={"validation_errors": error.errors(), "operation": operation}
        )
        
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": f"Validation failed for {operation}",
                "errors": error.errors()
            }
        )
    
    def validate_user_access(
        self,
        user_id: int,
        resource_user_id: int,
        is_admin: bool = False,
        operation: str = "access resource"
    ) -> None:
        """Validate user access to resources.
        
        Args:
            user_id: ID of the requesting user
            resource_user_id: ID of the user who owns the resource
            is_admin: Whether the requesting user is an admin
            operation: Description of the operation being attempted
            
        Raises:
            HTTPException: If access is denied
        """
        if user_id != resource_user_id and not is_admin:
            self.log_operation(
                f"Access denied: {operation}",
                user_id=user_id,
                details={"resource_user_id": resource_user_id},
                level="warning"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: cannot {operation}"
            )
    
    def validate_pagination(
        self,
        skip: int,
        limit: int,
        max_limit: int = 100
    ) -> tuple[int, int]:
        """Validate and normalize pagination parameters.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            max_limit: Maximum allowed limit value
            
        Returns:
            tuple: Validated (skip, limit) values
            
        Raises:
            HTTPException: If pagination parameters are invalid
        """
        if skip < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Skip parameter must be non-negative"
            )
        
        if limit <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Limit parameter must be positive"
            )
        
        if limit > max_limit:
            limit = max_limit
        
        return skip, limit
    
    def format_success_response(
        self,
        data: Any,
        message: str = "Operation successful",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Format successful response with consistent structure.
        
        Args:
            data: Response data
            message: Success message
            metadata: Additional metadata (pagination, counts, etc.)
            
        Returns:
            Dict: Formatted response structure
        """
        response = {
            "success": True,
            "message": message,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if metadata:
            response["metadata"] = metadata
        
        return response
    
    def format_error_response(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Format error response with consistent structure.
        
        Args:
            message: Error message
            error_code: Optional error code for client handling
            details: Additional error details
            
        Returns:
            Dict: Formatted error response structure
        """
        response = {
            "success": False,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if error_code:
            response["error_code"] = error_code
        
        if details:
            response["details"] = details
        
        return response
    
    async def check_rate_limit(
        self,
        user_id: int,
        operation: str,
        limit: int,
        window_seconds: int = 3600
    ) -> bool:
        """Check if user has exceeded rate limit for operation.
        
        Args:
            user_id: ID of the user
            operation: Operation being rate limited
            limit: Maximum number of operations allowed
            window_seconds: Time window in seconds
            
        Returns:
            bool: True if within rate limit, False if exceeded
        """
        try:
            return await self.security_service.check_rate_limit(
                f"user:{user_id}:{operation}",
                limit,
                window_seconds
            )
        except Exception as e:
            self.logger.error(f"Rate limit check failed: {str(e)}")
            # Fail open - allow operation if rate limit check fails
            return True
    
    def validate_required_fields(
        self,
        data: Dict[str, Any],
        required_fields: List[str],
        operation: str
    ) -> None:
        """Validate that required fields are present and not empty.
        
        Args:
            data: Data dictionary to validate
            required_fields: List of required field names
            operation: Description of the operation for error messages
            
        Raises:
            HTTPException: If required fields are missing or empty
        """
        missing_fields = []
        empty_fields = []
        
        for field in required_fields:
            if field not in data:
                missing_fields.append(field)
            elif not data[field] or (isinstance(data[field], str) and not data[field].strip()):
                empty_fields.append(field)
        
        if missing_fields or empty_fields:
            error_details = {}
            if missing_fields:
                error_details["missing_fields"] = missing_fields
            if empty_fields:
                error_details["empty_fields"] = empty_fields
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": f"Required fields validation failed for {operation}",
                    "errors": error_details
                }
            )
    
    async def cleanup_resources(self) -> None:
        """Clean up controller resources (database connections, etc.).
        
        This method should be called when the controller is no longer needed
        to ensure proper resource cleanup.
        """
        if self.db_session:
            try:
                await self.db_session.close()
            except Exception as e:
                self.logger.error(f"Error closing database session: {str(e)}")
            finally:
                self.db_session = None

    # Background Task and Webhook Methods
    
    async def create_background_task(
        self,
        task_type: TaskType,
        task_data: Dict[str, Any],
        user_id: Optional[int] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        callback_url: Optional[str] = None,
        depends_on: Optional[List[str]] = None
    ) -> str:
        """Create a new background task for tracking.
        
        Args:
            task_type: Type of the task
            task_data: Task-specific data
            user_id: ID of the user who initiated the task
            priority: Task priority level
            callback_url: Optional webhook URL for completion notification
            depends_on: List of task IDs this task depends on
            
        Returns:
            str: Task ID
            
        Raises:
            HTTPException: If task creation fails
        """
        try:
            task_tracking_service = get_task_tracking_service()
            db = await self.get_db_session()
            
            task_id = str(uuid.uuid4())
            
            task = BackgroundTask(
                id=task_id,
                task_type=task_type,
                status=TaskStatus.PENDING,
                priority=priority,
                user_id=user_id,
                task_data=task_data,
                callback_url=callback_url,
                depends_on=depends_on or [],
                created_at=datetime.utcnow()
            )
            
            await task_tracking_service.create_task(db=db, task=task)
            
            self.logger.info(f"Created background task {task_id} of type {task_type.value}")
            return task_id
            
        except Exception as e:
            self.logger.error(f"Failed to create background task: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create background task"
            )
    
    async def update_task_progress(
        self,
        task_id: str,
        progress: int,
        status: Optional[TaskStatus] = None,
        result_data: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Update background task progress and status.
        
        Args:
            task_id: ID of the task to update
            progress: Progress percentage (0-100)
            status: New task status
            result_data: Task result data
            error_message: Error message if task failed
            
        Raises:
            HTTPException: If task update fails
        """
        try:
            task_tracking_service = get_task_tracking_service()
            db = await self.get_db_session()
            
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=status or TaskStatus.RUNNING,
                progress=progress,
                result_data=result_data,
                error_message=error_message
            )
            
            self.logger.info(f"Updated task {task_id} progress to {progress}%")
            
        except Exception as e:
            self.logger.error(f"Failed to update task progress: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update task progress"
            )
    
    async def complete_task_with_webhook(
        self,
        task_id: str,
        result_data: Dict[str, Any],
        callback_url: Optional[str] = None
    ) -> None:
        """Complete a background task and send webhook notification.
        
        Args:
            task_id: ID of the task to complete
            result_data: Task result data
            callback_url: Optional webhook URL override
            
        Raises:
            HTTPException: If task completion fails
        """
        try:
            task_tracking_service = get_task_tracking_service()
            webhook_service = get_webhook_service()
            db = await self.get_db_session()
            
            # Update task status to completed
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.COMPLETED,
                progress=100,
                result_data=result_data
            )
            
            # Get task details for webhook
            task = await task_tracking_service.get_task(db=db, task_id=task_id)
            if not task:
                self.logger.error(f"Task {task_id} not found for webhook notification")
                return
            
            # Send webhook notification if callback URL is provided
            webhook_url = callback_url or task.callback_url
            if webhook_url:
                webhook_payload = {
                    "task_id": task_id,
                    "task_type": task.task_type.value,
                    "status": "completed",
                    "result": result_data,
                    "completed_at": datetime.utcnow().isoformat()
                }
                
                await webhook_service.send_webhook(
                    url=webhook_url,
                    payload=webhook_payload,
                    event_type="task.completed"
                )
            
            self.logger.info(f"Completed task {task_id} with webhook notification")
            
        except Exception as e:
            self.logger.error(f"Failed to complete task with webhook: {str(e)}")
            # Don't raise exception here to avoid breaking the main process
    
    async def fail_task_with_webhook(
        self,
        task_id: str,
        error_message: str,
        callback_url: Optional[str] = None
    ) -> None:
        """Mark a background task as failed and send webhook notification.
        
        Args:
            task_id: ID of the task to fail
            error_message: Error message describing the failure
            callback_url: Optional webhook URL override
            
        Raises:
            HTTPException: If task failure handling fails
        """
        try:
            task_tracking_service = get_task_tracking_service()
            webhook_service = get_webhook_service()
            db = await self.get_db_session()
            
            # Update task status to failed
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.FAILED,
                error_message=error_message
            )
            
            # Get task details for webhook
            task = await task_tracking_service.get_task(db=db, task_id=task_id)
            if not task:
                self.logger.error(f"Task {task_id} not found for webhook notification")
                return
            
            # Send webhook notification if callback URL is provided
            webhook_url = callback_url or task.callback_url
            if webhook_url:
                webhook_payload = {
                    "task_id": task_id,
                    "task_type": task.task_type.value,
                    "status": "failed",
                    "error": error_message,
                    "failed_at": datetime.utcnow().isoformat()
                }
                
                await webhook_service.send_webhook(
                    url=webhook_url,
                    payload=webhook_payload,
                    event_type="task.failed"
                )
            
            self.logger.info(f"Failed task {task_id} with webhook notification")
            
        except Exception as e:
            self.logger.error(f"Failed to handle task failure with webhook: {str(e)}")
            # Don't raise exception here to avoid breaking the main process
    
    async def add_background_task_with_tracking(
        self,
        background_tasks: BackgroundTasks,
        task_func: callable,
        task_type: TaskType,
        task_data: Dict[str, Any],
        user_id: Optional[int] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        callback_url: Optional[str] = None,
        *args,
        **kwargs
    ) -> str:
        """Add a background task with automatic tracking and webhook support.
        
        Args:
            background_tasks: FastAPI BackgroundTasks instance
            task_func: Function to execute in background
            task_type: Type of the task
            task_data: Task-specific data
            user_id: ID of the user who initiated the task
            priority: Task priority level
            callback_url: Optional webhook URL for completion notification
            *args: Additional positional arguments for task_func
            **kwargs: Additional keyword arguments for task_func
            
        Returns:
            str: Task ID
            
        Raises:
            HTTPException: If task creation fails
        """
        try:
            # Create task record
            task_id = await self.create_background_task(
                task_type=task_type,
                task_data=task_data,
                user_id=user_id,
                priority=priority,
                callback_url=callback_url
            )
            
            # Add to FastAPI background tasks
            background_tasks.add_task(
                task_func,
                task_id,
                *args,
                **kwargs
            )
            
            self.logger.info(f"Added background task {task_id} to execution queue")
            return task_id
            
        except Exception as e:
            self.logger.error(f"Failed to add background task with tracking: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add background task"
            )