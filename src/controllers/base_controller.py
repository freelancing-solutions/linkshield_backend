"""Base controller class providing common functionality for all controllers.

This module defines the BaseController class that serves as the foundation for all
controller classes in the application. It provides common dependency injection patterns,
error handling utilities, logging, validation helpers, and response formatting.
"""

from typing import Dict, Any, Optional, List, Union
from abc import ABC
from datetime import datetime, timedelta, timezone
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import HTTPException, status, Request, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from pydantic import ValidationError

from src.config.database import get_db
from src.config.settings import get_settings
from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.services.email_service import EmailService
from .webhook_controller import WebhookController
from src.models.user import User
from src.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority
from ..utils import utc_datetime


class BaseController(WebhookController):
    """Base controller class with common functionality.
    
    This class provides common functionality for all controllers including:
    - Database session management
    - Authentication and authorization
    - Logging and error handling
    - Webhook and background task management (inherited from WebhookController)
    
    All controllers should inherit from this class to ensure consistent
    behavior across the application.
    """
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService
    ):
        """Initialize the base controller.
        
        Args:
            security_service: Service for security operations
            auth_service: Service for authentication operations
            email_service: Service for email operations
        """
        # Initialize parent WebhookController
        super().__init__()
        
        # Initialize services
        self.security_service = security_service
        self.auth_service = auth_service
        self.email_service = email_service
        
        # Initialize settings and logger
        self.settings = get_settings()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @asynccontextmanager
    async def get_db_session(self) -> AsyncSession:
        """Async context manager for database session management.
        
        Provides proper session lifecycle management with automatic
        commit/rollback and cleanup.
        
        Yields:
            AsyncSession: Database session for operations
            
        Example:
            async with self.get_db_session() as session:
                result = await session.query(User).all()
        """
        session = await get_db()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
   
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
            "timestamp": utc_datetime()
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
            is_allowed, limit_info = self.security_service.check_rate_limit(
                identifier=f"user:{user_id}:{operation}",
                limit_type=operation,
                ip_address="127.0.0.1"  # Default IP for internal operations
            )
            return is_allowed
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
        """Clean up controller resources.
        
        This method should be called when the controller is no longer needed
        to ensure proper resource cleanup. Database sessions are now managed
        by the context manager, so no manual cleanup is needed.
        """
        # Database sessions are now managed by context manager
        # No manual cleanup needed
        pass

    # Additional controller-specific methods can be added here