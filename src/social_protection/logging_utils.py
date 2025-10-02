#!/usr/bin/env python3
"""
Social Protection Structured Logging Utilities

Provides structured logging helpers for consistent, contextual logging
across all social protection services.
"""

from typing import Any, Dict, Optional
from uuid import UUID
from loguru import logger
from datetime import datetime, timezone


class StructuredLogger:
    """
    Wrapper for loguru logger that adds structured context to all log messages.
    
    This ensures consistent logging format across all social protection services
    with relevant context fields for debugging and monitoring.
    """
    
    def __init__(self, service_name: str):
        """
        Initialize structured logger for a service.
        
        Args:
            service_name: Name of the service (e.g., "SocialScanService")
        """
        self.service_name = service_name
        self.logger = logger.bind(service=service_name)
    
    def _build_context(
        self,
        message: str,
        user_id: Optional[UUID] = None,
        platform: Optional[str] = None,
        operation: Optional[str] = None,
        duration_ms: Optional[float] = None,
        **extra_fields
    ) -> Dict[str, Any]:
        """Build structured context dictionary."""
        context = {
            "service": self.service_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        if user_id:
            context["user_id"] = str(user_id)
        if platform:
            context["platform"] = platform
        if operation:
            context["operation"] = operation
        if duration_ms is not None:
            context["duration_ms"] = duration_ms
        
        # Add any extra fields
        context.update(extra_fields)
        
        return context
    
    def info(
        self,
        message: str,
        user_id: Optional[UUID] = None,
        platform: Optional[str] = None,
        operation: Optional[str] = None,
        duration_ms: Optional[float] = None,
        **extra_fields
    ):
        """Log info level message with structured context."""
        context = self._build_context(
            message, user_id, platform, operation, duration_ms, **extra_fields
        )
        self.logger.bind(**context).info(message)
    
    def warning(
        self,
        message: str,
        user_id: Optional[UUID] = None,
        platform: Optional[str] = None,
        operation: Optional[str] = None,
        duration_ms: Optional[float] = None,
        **extra_fields
    ):
        """Log warning level message with structured context."""
        context = self._build_context(
            message, user_id, platform, operation, duration_ms, **extra_fields
        )
        self.logger.bind(**context).warning(message)
    
    def error(
        self,
        message: str,
        error: Optional[Exception] = None,
        user_id: Optional[UUID] = None,
        platform: Optional[str] = None,
        operation: Optional[str] = None,
        duration_ms: Optional[float] = None,
        **extra_fields
    ):
        """Log error level message with structured context."""
        context = self._build_context(
            message, user_id, platform, operation, duration_ms, **extra_fields
        )
        
        if error:
            context["error_type"] = type(error).__name__
            context["error_message"] = str(error)
        
        self.logger.bind(**context).error(message, exc_info=error is not None)
    
    def debug(
        self,
        message: str,
        user_id: Optional[UUID] = None,
        platform: Optional[str] = None,
        operation: Optional[str] = None,
        duration_ms: Optional[float] = None,
        **extra_fields
    ):
        """Log debug level message with structured context."""
        context = self._build_context(
            message, user_id, platform, operation, duration_ms, **extra_fields
        )
        self.logger.bind(**context).debug(message)
    
    def critical(
        self,
        message: str,
        error: Optional[Exception] = None,
        user_id: Optional[UUID] = None,
        platform: Optional[str] = None,
        operation: Optional[str] = None,
        **extra_fields
    ):
        """Log critical level message with structured context."""
        context = self._build_context(
            message, user_id, platform, operation, **extra_fields
        )
        
        if error:
            context["error_type"] = type(error).__name__
            context["error_message"] = str(error)
        
        self.logger.bind(**context).critical(message, exc_info=error is not None)


def get_logger(service_name: str) -> StructuredLogger:
    """
    Get a structured logger instance for a service.
    
    Args:
        service_name: Name of the service
        
    Returns:
        StructuredLogger instance
    """
    return StructuredLogger(service_name)
