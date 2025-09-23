"""Base controller class providing common functionality for all controllers."""

from typing import Dict, Any, Optional, List, Union, AsyncGenerator
from datetime import datetime, timezone
import logging
import uuid
import time
from contextlib import asynccontextmanager

from fastapi import HTTPException, status
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
        async for session in get_db():
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