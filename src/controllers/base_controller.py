"""Base controller class providing common functionality for all controllers."""

from typing import Dict, Any, Optional, List, Union, AsyncGenerator, Callable
from datetime import datetime, timezone
import logging
import uuid
import time
from contextlib import asynccontextmanager
from functools import wraps

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
from pydantic import ValidationError

from src.config.database import get_db, get_db_session
from src.config.settings import get_settings
from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.services.email_service import EmailService
from .webhook_controller import WebhookController
from src.utils import utc_datetime


class BaseController(WebhookController):
    """Base controller class with common functionality."""

    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService
    ):
        """Initialize the base controller."""
        # Initialize parent WebhookController
        super().__init__()

        # Set self as the session provider for WebhookController
        self.set_session_provider(self)

        # Initialize services
        self.security_service = security_service
        self.auth_service = auth_service
        self.email_service = email_service

        # Initialize settings and logger
        self.settings = get_settings()
        self.logger = logging.getLogger(self.__class__.__name__)

    @asynccontextmanager
    async def get_db_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session with enhanced validation and error handling."""
        session_id = str(uuid.uuid4())[:8]
        start_time = time.time()

        # Validate session usage patterns
        self.validate_session_usage()

        # Log session start
        self.log_operation(
            "Database session started",
            details={
                "session_id": session_id,
                "controller": self.__class__.__name__
            },
            level="debug"
        )

        # Use the existing get_db dependency
        async for session in get_db_session():
            try:
                # Validate session connection - only in DEBUG mode
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
                # Session is automatically closed by the dependency
                duration = time.time() - start_time
                self.log_operation(
                    "Database session completed",
                    details={
                        "session_id": session_id,
                        "total_duration_ms": round(duration * 1000, 2),
                        "controller": self.__class__.__name__
                    },
                    level="debug"
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
        """Log controller operations with structured data."""
        log_data = {
            "operation": operation,
            "controller": self.__class__.__name__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "details": details or {}
        }

        if session_id:
            log_data["database_session"] = {
                "session_id": session_id,
                "duration_ms": session_duration_ms,
                "has_active_session": True
            }

        log_data["performance"] = {
            "controller_class": self.__class__.__name__,
            "operation_category": self._categorize_operation(operation)
        }

        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"Controller operation: {operation}", extra=log_data)

    def _categorize_operation(self, operation: str) -> str:
        """Categorize operations for better logging organization."""
        operation_lower = operation.lower()

        categories = {
            "database_session": ['session', 'commit', 'rollback', 'close'],
            "create": ['create', 'insert', 'add'],
            "read": ['read', 'get', 'fetch', 'query', 'select'],
            "update": ['update', 'modify', 'edit'],
            "delete": ['delete', 'remove'],
            "authentication": ['auth', 'login', 'logout', 'token'],
            "validation": ['valid', 'check', 'verify']
        }

        for category, keywords in categories.items():
            if any(keyword in operation_lower for keyword in keywords):
                return category

        return "general"

    def validate_session_usage(self) -> None:
        """Validate database session usage patterns."""
        import inspect

        frame = inspect.currentframe()
        try:
            caller_frame = frame.f_back.f_back if frame.f_back else None
            if not caller_frame:
                return

            caller_code = caller_frame.f_code
            caller_name = caller_code.co_name

            # Check if we're being called from an async method
            if not inspect.iscoroutinefunction(getattr(self, caller_name, None)):
                self.logger.warning(
                    f"Database session requested from non-async method: {caller_name}",
                    extra={
                        "controller": self.__class__.__name__,
                        "method": caller_name,
                        "recommendation": "Ensure the calling method is declared as 'async def'"
                    }
                )

            # Validate async context
            try:
                import asyncio
                asyncio.current_task()
            except RuntimeError:
                raise RuntimeError(
                    f"Database session requested outside async context in {self.__class__.__name__}.{caller_name}. "
                    "Ensure you're using 'async with self.get_db_session()' within an async method."
                )

            self.log_operation(
                "Session usage validation passed",
                details={
                    "calling_method": caller_name,
                    "controller": self.__class__.__name__
                },
                level="debug"
            )

        except Exception as e:
            self.logger.warning(
                f"Session usage validation encountered an error: {str(e)}",
                extra={
                    "controller": self.__class__.__name__,
                    "error_type": type(e).__name__
                }
            )
        finally:
            del frame

    def handle_database_error(self, error: Exception, operation: str) -> HTTPException:
        """Handle database errors with appropriate HTTP responses."""
        self.logger.error(
            f"Database error during {operation}: {str(error)}",
            extra={"error_type": type(error).__name__, "operation": operation}
        )

        error_str = str(error).lower()

        if "duplicate key" in error_str:
            return HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Resource already exists: {operation}"
            )
        elif "foreign key" in error_str:
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
        """Handle validation errors with detailed error messages."""
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
        """Validate user access to resources."""
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
        """Validate and normalize pagination parameters."""
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
        """Format successful response with consistent structure."""
        response = {
            "success": True,
            "message": message,
            "data": data,
            "timestamp": utc_datetime().isoformat()
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
        """Format error response with consistent structure."""
        response = {
            "success": False,
            "message": message,
            "timestamp": utc_datetime().isoformat()
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
        """Check if user has exceeded rate limit for operation."""
        try:
            is_allowed, _ = self.security_service.check_rate_limit(
                identifier=f"user:{user_id}:{operation}",
                limit_type=operation,
                ip_address="127.0.0.1"
            )
            return is_allowed
        except Exception as e:
            self.logger.error(f"Rate limit check failed: {str(e)}")
            return True  # Fail open

    def validate_required_fields(
        self,
        data: Dict[str, Any],
        required_fields: List[str],
        operation: str
    ) -> None:
        """Validate that required fields are present and not empty."""
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
        """Clean up controller resources."""
        pass  # Sessions managed by context manager

    # Enhanced Error Handling Methods

    def handle_error(
        self,
        error: Exception,
        operation: str,
        user_id: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> HTTPException:
        """
        Centralized error handling with appropriate HTTP responses.
        
        Maps various exception types to appropriate HTTP status codes and messages.
        Logs errors with context for debugging and monitoring.
        
        Args:
            error: The exception that occurred
            operation: Description of the operation that failed
            user_id: Optional user ID for logging
            context: Optional additional context for logging
            
        Returns:
            HTTPException with appropriate status code and detail
        """
        # Log the error with context
        self.log_operation(
            f"Error during {operation}",
            user_id=user_id,
            details={
                "error_type": type(error).__name__,
                "error_message": str(error),
                "context": context or {},
                "operation": operation
            },
            level="error"
        )

        # Handle validation errors (400)
        if isinstance(error, ValidationError):
            return HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": f"Validation failed for {operation}",
                    "errors": error.errors()
                }
            )

        # Handle database errors
        if isinstance(error, SQLAlchemyError):
            return self.handle_database_error(error, operation)

        # Handle HTTP exceptions (pass through)
        if isinstance(error, HTTPException):
            return error

        # Handle generic exceptions (500)
        self.logger.critical(
            f"Unexpected error during {operation}: {str(error)}",
            exc_info=True,
            extra={
                "user_id": user_id,
                "operation": operation,
                "context": context or {}
            }
        )

        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during {operation}"
        )

    def handle_authentication_error(
        self,
        message: str = "Authentication failed",
        details: Optional[Dict[str, Any]] = None
    ) -> HTTPException:
        """
        Handle authentication errors (401).
        
        Args:
            message: Error message
            details: Optional additional details
            
        Returns:
            HTTPException with 401 status
        """
        self.logger.warning(
            f"Authentication error: {message}",
            extra={"details": details or {}}
        )

        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": message, "details": details} if details else message,
            headers={"WWW-Authenticate": "Bearer"}
        )

    def handle_authorization_error(
        self,
        message: str = "Access denied",
        required_permission: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> HTTPException:
        """
        Handle authorization errors (403).
        
        Args:
            message: Error message
            required_permission: Optional permission that was required
            details: Optional additional details
            
        Returns:
            HTTPException with 403 status
        """
        log_details = details or {}
        if required_permission:
            log_details["required_permission"] = required_permission

        self.logger.warning(
            f"Authorization error: {message}",
            extra={"details": log_details}
        )

        response_detail = {"message": message}
        if required_permission:
            response_detail["required_permission"] = required_permission
        if details:
            response_detail["details"] = details

        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=response_detail
        )

    def handle_not_found_error(
        self,
        resource: str,
        identifier: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> HTTPException:
        """
        Handle resource not found errors (404).
        
        Args:
            resource: Type of resource that was not found
            identifier: Optional identifier of the resource
            details: Optional additional details
            
        Returns:
            HTTPException with 404 status
        """
        message = f"{resource} not found"
        if identifier:
            message += f": {identifier}"

        self.logger.info(
            f"Resource not found: {message}",
            extra={"resource": resource, "identifier": identifier, "details": details or {}}
        )

        response_detail = {"message": message, "resource": resource}
        if identifier:
            response_detail["identifier"] = identifier
        if details:
            response_detail["details"] = details

        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=response_detail
        )

    def handle_conflict_error(
        self,
        message: str,
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> HTTPException:
        """
        Handle resource conflict errors (409).
        
        Args:
            message: Error message
            resource: Optional resource type
            details: Optional additional details
            
        Returns:
            HTTPException with 409 status
        """
        self.logger.warning(
            f"Conflict error: {message}",
            extra={"resource": resource, "details": details or {}}
        )

        response_detail = {"message": message}
        if resource:
            response_detail["resource"] = resource
        if details:
            response_detail["details"] = details

        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=response_detail
        )

    def handle_rate_limit_error(
        self,
        retry_after: int,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        message: str = "Rate limit exceeded"
    ) -> HTTPException:
        """
        Handle rate limit errors (429).
        
        Args:
            retry_after: Seconds until retry is allowed
            limit: Optional rate limit value
            window: Optional time window in seconds
            message: Error message
            
        Returns:
            HTTPException with 429 status and Retry-After header
        """
        self.logger.warning(
            f"Rate limit exceeded: {message}",
            extra={
                "retry_after": retry_after,
                "limit": limit,
                "window": window
            }
        )

        response_detail = {
            "message": message,
            "retry_after": retry_after
        }
        if limit:
            response_detail["limit"] = limit
        if window:
            response_detail["window"] = window

        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=response_detail,
            headers={"Retry-After": str(retry_after)}
        )

    def handle_service_unavailable_error(
        self,
        service: str,
        message: Optional[str] = None,
        retry_after: Optional[int] = None
    ) -> HTTPException:
        """
        Handle service unavailable errors (503).
        
        Args:
            service: Name of the unavailable service
            message: Optional custom message
            retry_after: Optional seconds until retry
            
        Returns:
            HTTPException with 503 status
        """
        default_message = f"Service temporarily unavailable: {service}"
        final_message = message or default_message

        self.logger.error(
            f"Service unavailable: {service}",
            extra={"service": service, "message": final_message}
        )

        response_detail = {
            "message": final_message,
            "service": service
        }

        headers = {}
        if retry_after:
            response_detail["retry_after"] = retry_after
            headers["Retry-After"] = str(retry_after)

        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=response_detail,
            headers=headers if headers else None
        )

    async def execute_with_error_handling(
        self,
        operation: Callable,
        operation_name: str,
        user_id: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Execute an operation with comprehensive error handling.
        
        Wraps an operation with try-catch and maps exceptions to appropriate
        HTTP responses. Useful for controller methods.
        
        Args:
            operation: Async callable to execute
            operation_name: Name of the operation for logging
            user_id: Optional user ID for logging
            context: Optional context for logging
            
        Returns:
            Result of the operation
            
        Raises:
            HTTPException: Mapped from caught exceptions
        """
        try:
            self.log_operation(
                f"Starting {operation_name}",
                user_id=user_id,
                details=context or {},
                level="debug"
            )

            result = await operation()

            self.log_operation(
                f"Completed {operation_name}",
                user_id=user_id,
                details=context or {},
                level="debug"
            )

            return result

        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise

        except Exception as e:
            # Handle and convert to HTTP exception
            raise self.handle_error(e, operation_name, user_id, context)