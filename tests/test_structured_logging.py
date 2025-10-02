#!/usr/bin/env python3
"""
Tests for Social Protection Structured Logging

Verifies that structured logging utilities work correctly and provide
consistent context across all log messages.
"""

import pytest
from uuid import uuid4
from src.social_protection.logging_utils import get_logger, StructuredLogger


class TestStructuredLogger:
    """Test structured logging functionality."""
    
    def test_get_logger_returns_structured_logger(self):
        """Test that get_logger returns a StructuredLogger instance."""
        logger = get_logger("TestService")
        assert isinstance(logger, StructuredLogger)
        assert logger.service_name == "TestService"
    
    def test_logger_info_with_context(self):
        """Test info logging with structured context."""
        logger = get_logger("TestService")
        user_id = uuid4()
        
        # Should not raise any exceptions
        logger.info(
            "Test message",
            user_id=user_id,
            platform="twitter",
            operation="test_operation",
            duration_ms=123.45
        )
    
    def test_logger_error_with_exception(self):
        """Test error logging with exception context."""
        logger = get_logger("TestService")
        user_id = uuid4()
        
        try:
            raise ValueError("Test error")
        except ValueError as e:
            # Should not raise any exceptions
            logger.error(
                "Error occurred",
                error=e,
                user_id=user_id,
                platform="twitter",
                operation="test_operation"
            )
    
    def test_logger_warning_with_context(self):
        """Test warning logging with structured context."""
        logger = get_logger("TestService")
        
        # Should not raise any exceptions
        logger.warning(
            "Warning message",
            platform="twitter",
            operation="test_operation",
            custom_field="custom_value"
        )
    
    def test_logger_debug_with_context(self):
        """Test debug logging with structured context."""
        logger = get_logger("TestService")
        
        # Should not raise any exceptions
        logger.debug(
            "Debug message",
            platform="twitter",
            operation="test_operation"
        )
    
    def test_logger_critical_with_exception(self):
        """Test critical logging with exception context."""
        logger = get_logger("TestService")
        
        try:
            raise RuntimeError("Critical error")
        except RuntimeError as e:
            # Should not raise any exceptions
            logger.critical(
                "Critical error occurred",
                error=e,
                operation="test_operation"
            )
    
    def test_build_context_includes_all_fields(self):
        """Test that context builder includes all provided fields."""
        logger = get_logger("TestService")
        user_id = uuid4()
        
        context = logger._build_context(
            "Test message",
            user_id=user_id,
            platform="twitter",
            operation="test_op",
            duration_ms=100.0,
            custom_field="custom_value"
        )
        
        assert context["service"] == "TestService"
        assert context["user_id"] == str(user_id)
        assert context["platform"] == "twitter"
        assert context["operation"] == "test_op"
        assert context["duration_ms"] == 100.0
        assert context["custom_field"] == "custom_value"
        assert "timestamp" in context
    
    def test_multiple_loggers_have_different_service_names(self):
        """Test that different loggers have different service names."""
        logger1 = get_logger("Service1")
        logger2 = get_logger("Service2")
        
        assert logger1.service_name == "Service1"
        assert logger2.service_name == "Service2"
        assert logger1.service_name != logger2.service_name


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
