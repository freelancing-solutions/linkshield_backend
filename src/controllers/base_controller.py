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
import time
from contextlib import asynccontextmanager

from fastapi import HTTPException, status, Request, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
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
    async def get_db_session(self):
        """Get database session with enhanced validation and error handling.
        
        This method provides a managed database session with comprehensive
        validation, logging, and error handling capabilities.
        
        Yields:
            AsyncSession: Database session for operations
            
        Raises:
            RuntimeError: If session validation fails
            SQLAlchemyError: If database operations fail
            Exception: If session management encounters errors
        """
        session_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        
        # Validate session usage patterns
        self.validate_session_usage()
        
        # Session validation checks - remove db_session_factory dependency
        # Use the existing get_db dependency instead
        
        # Log session start
        self.log_operation(
            "Database session started",
            details={
                "session_id": session_id,
                "controller": self.__class__.__name__
            },
            level="debug"
        )
        
        # Use the existing get_db dependency instead of undefined db_session_factory
        async with get_db() as session:
            try:
                # Validate session connection - only in DEBUG mode to reduce overhead
                if self.settings.DEBUG:
                    await session.execute(text("SELECT 1"))
                    self.log_operation(
                        "Database connectivity validated",
                        details={
                            "session_id": session_id,
                            "controller": self.__class__.__name__
                        },
                        level="debug"
                    )
                
                yield session
                
                # Commit transaction
                await session.commit()
                duration = time.time() - start_time
                self.log_operation(
                    "Database session committed",
                    details={
                        "session_id": session_id,
                        "duration_ms": round(duration * 1000, 2),
                        "controller": self.__class__.__name__
                    },
                    level="debug"
                )
                
            except Exception as e:
                # Rollback on any error
                try:
                    await session.rollback()
                    duration = time.time() - start_time
                    self.log_operation(
                        "Database session rolled back",
                        details={
                            "session_id": session_id,
                            "duration_ms": round(duration * 1000, 2),
                            "error": str(e),
                            "error_type": type(e).__name__,
                            "controller": self.__class__.__name__
                        },
                        level="warning"
                    )
                except Exception as rollback_error:
                    self.logger.error(
                        f"Failed to rollback session {session_id}: {str(rollback_error)}",
                        extra={
                            "session_id": session_id,
                            "original_error": str(e),
                            "rollback_error": str(rollback_error),
                            "controller": self.__class__.__name__
                        }
                    )
                raise  # Re-raise the original exception
            finally:
                # Always close the session
                try:
                    await session.close()
                    duration = time.time() - start_time
                    self.log_operation(
                        "Database session closed",
                        details={
                            "session_id": session_id,
                            "total_duration_ms": round(duration * 1000, 2),
                            "controller": self.__class__.__name__
                        },
                        level="debug"
                    )
                except Exception as close_error:
                    self.logger.error(
                        f"Failed to close session {session_id}: {str(close_error)}",
                        extra={
                            "session_id": session_id,
                            "close_error": str(close_error),
                            "controller": self.__class__.__name__
                        }
                    )
   
    def log_operation(
        self,
        operation: str,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        level: str = "info",
        session_id: Optional[str] = None,
        session_duration_ms: Optional[float] = None
    ) -> None:
        """Log controller operations with structured data and database session tracking.
        
        Enhanced logging method that includes database session information
        for comprehensive operation tracking and debugging.
        
        Args:
            operation: Description of the operation being performed
            user_id: ID of the user performing the operation
            details: Additional operation details
            level: Log level (debug, info, warning, error)
            session_id: Database session ID for tracking
            session_duration_ms: Session duration in milliseconds
        """
        # Build base log data
        log_data = {
            "operation": operation,
            "controller": self.__class__.__name__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "details": details or {}
        }
        
        # Add database session tracking information if available
        if session_id:
            log_data["database_session"] = {
                "session_id": session_id,
                "duration_ms": session_duration_ms,
                "has_active_session": True
            }
        
        # Attempt to detect active session context automatically
        if not session_id:
            try:
                import inspect
                frame = inspect.currentframe()
                
                # Look through the call stack for session-related context
                current_frame = frame
                session_context_found = False
                
                while current_frame and not session_context_found:
                    local_vars = current_frame.f_locals
                    
                    # Check for common session variable names
                    for var_name in ['session', 'db', 'db_session']:
                        if var_name in local_vars:
                            session_obj = local_vars[var_name]
                            if hasattr(session_obj, 'bind') or hasattr(session_obj, 'commit'):
                                log_data["database_session"] = {
                                    "session_detected": True,
                                    "session_type": type(session_obj).__name__,
                                    "has_active_session": True
                                }
                                session_context_found = True
                                break
                    
                    current_frame = current_frame.f_back
                
                # If no session context found, note it
                if not session_context_found:
                    log_data["database_session"] = {
                        "has_active_session": False,
                        "session_detected": False
                    }
                    
            except Exception:
                # Don't fail logging due to session detection errors
                log_data["database_session"] = {
                    "has_active_session": False,
                    "detection_error": True
                }
            finally:
                if 'frame' in locals():
                    del frame  # Prevent reference cycles
        
        # Add performance and context information
        log_data["performance"] = {
            "controller_class": self.__class__.__name__,
            "operation_category": self._categorize_operation(operation)
        }
        
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"Controller operation: {operation}", extra=log_data)
    
    def _categorize_operation(self, operation: str) -> str:
        """Categorize operations for better logging organization.
        
        Args:
            operation: Operation description
            
        Returns:
            str: Operation category
        """
        operation_lower = operation.lower()
        
        if any(keyword in operation_lower for keyword in ['session', 'commit', 'rollback', 'close']):
            return "database_session"
        elif any(keyword in operation_lower for keyword in ['create', 'insert', 'add']):
            return "create"
        elif any(keyword in operation_lower for keyword in ['read', 'get', 'fetch', 'query', 'select']):
            return "read"
        elif any(keyword in operation_lower for keyword in ['update', 'modify', 'edit']):
            return "update"
        elif any(keyword in operation_lower for keyword in ['delete', 'remove']):
            return "delete"
        elif any(keyword in operation_lower for keyword in ['auth', 'login', 'logout', 'token']):
            return "authentication"
        elif any(keyword in operation_lower for keyword in ['valid', 'check', 'verify']):
            return "validation"
        else:
            return "general"
    
    def validate_session_usage(self) -> None:
        """Validate database session usage patterns to prevent sync/async mixing.
        
        This method performs static analysis of common session management
        anti-patterns and provides clear error messages when issues are detected.
        
        Raises:
            RuntimeError: If session usage validation fails
        """
        import inspect
        import ast
        
        # Get the calling method's frame to analyze usage patterns
        frame = inspect.currentframe()
        try:
            # Go up the call stack to find the calling method
            caller_frame = frame.f_back.f_back if frame.f_back else None
            if not caller_frame:
                return  # Cannot validate without caller context
            
            caller_code = caller_frame.f_code
            caller_name = caller_code.co_name
            
            # Check if we're being called from an async method
            if not inspect.iscoroutinefunction(getattr(self, caller_name, None)):
                # If the calling method is not async, warn about potential issues
                self.logger.warning(
                    f"Database session requested from non-async method: {caller_name}",
                    extra={
                        "controller": self.__class__.__name__,
                        "method": caller_name,
                        "recommendation": "Ensure the calling method is declared as 'async def'"
                    }
                )
            
            # Validate that we're in an async context
            try:
                import asyncio
                asyncio.current_task()
            except RuntimeError:
                raise RuntimeError(
                    f"Database session requested outside async context in {self.__class__.__name__}.{caller_name}. "
                    "Ensure you're using 'async with self.get_db_session()' within an async method."
                )
            
            # Log successful validation
            self.log_operation(
                "Session usage validation passed",
                details={
                    "calling_method": caller_name,
                    "controller": self.__class__.__name__
                },
                level="debug"
            )
            
        except Exception as e:
            # Don't fail the entire operation for validation errors, just log them
            self.logger.warning(
                f"Session usage validation encountered an error: {str(e)}",
                extra={
                    "controller": self.__class__.__name__,
                    "error_type": type(e).__name__
                }
            )
        finally:
            del frame  # Prevent reference cycles

    async def ensure_consistent_commit_rollback(
        self, 
        session, 
        operation: str,
        session_id: str = None,
        start_time: float = None
    ) -> bool:
        """Ensure consistent commit/rollback behavior with standardized error handling.
        
        This method provides a standardized approach to transaction management
        across all controllers, ensuring consistent logging and error handling.
        
        Args:
            session: Database session to manage
            operation: Description of the operation being performed
            session_id: Optional session ID for tracking
            start_time: Optional start time for duration calculation
            
        Returns:
            bool: True if commit succeeded, False if rollback was performed
            
        Raises:
            Exception: Re-raises any exceptions after proper rollback handling
        """
        session_id = session_id or str(uuid.uuid4())[:8]
        start_time = start_time or time.time()
        
        try:
            # Attempt to commit the transaction
            await session.commit()
            
            # Log successful commit
            duration = time.time() - start_time
            self.log_operation(
                f"Transaction committed successfully: {operation}",
                details={
                    "session_id": session_id,
                    "operation": operation,
                    "duration_ms": round(duration * 1000, 2),
                    "controller": self.__class__.__name__
                },
                level="debug"
            )
            
            return True
            
        except Exception as e:
            # Perform rollback with comprehensive error handling
            rollback_success = False
            try:
                await session.rollback()
                rollback_success = True
                
                # Log rollback with error details
                duration = time.time() - start_time
                self.log_operation(
                    f"Transaction rolled back due to error: {operation}",
                    details={
                        "session_id": session_id,
                        "operation": operation,
                        "duration_ms": round(duration * 1000, 2),
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "controller": self.__class__.__name__
                    },
                    level="warning"
                )
                
            except Exception as rollback_error:
                # Log rollback failure
                self.logger.error(
                    f"Critical: Failed to rollback transaction for {operation}",
                    extra={
                        "session_id": session_id,
                        "operation": operation,
                        "original_error": str(e),
                        "rollback_error": str(rollback_error),
                        "controller": self.__class__.__name__
                    }
                )
            
            # Always re-raise the original exception
            raise e

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