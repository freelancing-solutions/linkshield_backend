"""
Unit tests for bot error handling system.

Tests comprehensive error handling across all bot components including
command parsing, platform API interactions, BotController communication,
and response formatting with appropriate fallbacks and user guidance.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from typing import Dict, Any

from linkshield.bots.error_handler import (
    BotErrorHandler, BotError, ErrorCategory, ErrorSeverity,
    bot_error_handler
)
from linkshield.bots.models import (
    BotCommand, BotResponse, FormattedResponse,
    CommandType, ResponseType, DeliveryMethod, PlatformType
)


class TestBotError:
    """Test BotError exception class."""
    
    def test_bot_error_initialization(self):
        """Test BotError initialization with all parameters."""
        error = BotError(
            message="Test error",
            category=ErrorCategory.COMMAND_PARSING,
            severity=ErrorSeverity.HIGH,
            platform=PlatformType.TWITTER,
            user_id="test_user",
            command_type=CommandType.ANALYZE_ACCOUNT,
            original_error=ValueError("Original error"),
            context={"test": "context"}
        )
        
        assert error.message == "Test error"
        assert error.category == ErrorCategory.COMMAND_PARSING
        assert error.severity == ErrorSeverity.HIGH
        assert error.platform == PlatformType.TWITTER
        assert error.user_id == "test_user"
        assert error.command_type == CommandType.ANALYZE_ACCOUNT
        assert isinstance(error.original_error, ValueError)
        assert error.context == {"test": "context"}
        assert error.error_id.startswith("bot_error_")
        assert isinstance(error.timestamp, datetime)
    
    def test_bot_error_minimal_initialization(self):
        """Test BotError initialization with minimal parameters."""
        error = BotError("Minimal error")
        
        assert error.message == "Minimal error"
        assert error.category == ErrorCategory.UNKNOWN
        assert error.severity == ErrorSeverity.MEDIUM
        assert error.platform is None
        assert error.user_id is None
        assert error.command_type is None
        assert error.original_error is None
        assert error.context == {}
    
    def test_bot_error_to_dict(self):
        """Test BotError to_dict conversion."""
        original_error = ValueError("Original error")
        error = BotError(
            message="Test error",
            category=ErrorCategory.PLATFORM_API,
            severity=ErrorSeverity.CRITICAL,
            platform="telegram",
            user_id="123456",
            command_type=CommandType.CHECK_COMPLIANCE,
            original_error=original_error,
            context={"operation": "send_message"}
        )
        
        error_dict = error.to_dict()
        
        assert error_dict["message"] == "Test error"
        assert error_dict["category"] == "platform_api"
        assert error_dict["severity"] == "critical"
        assert error_dict["platform"] == "telegram"
        assert error_dict["user_id"] == "123456"
        assert error_dict["command_type"] == "check_compliance"
        assert error_dict["original_error"] == "Original error"
        assert error_dict["context"] == {"operation": "send_message"}
        assert "error_id" in error_dict
        assert "timestamp" in error_dict


class TestBotErrorHandler:
    """Test BotErrorHandler class."""
    
    @pytest.fixture
    def error_handler(self):
        """Create a fresh error handler for each test."""
        return BotErrorHandler()
    
    @pytest.fixture
    def sample_command(self):
        """Create a sample bot command for testing."""
        return BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=PlatformType.TWITTER,
            user_id="test_user",
            parameters={"account_identifier": "testuser"},
            metadata={"original_command": "@bot analyze @testuser"}
        )
    
    @pytest.fixture
    def sample_bot_response(self):
        """Create a sample bot response for testing."""
        return BotResponse.success_response(
            data={"risk_level": "medium", "risk_score": 65},
            response_type=ResponseType.ANALYSIS_RESULT
        )


class TestCommandParsingErrorHandling:
    """Test command parsing error handling."""
    
    @pytest.fixture
    def error_handler(self):
        return BotErrorHandler()
    
    @pytest.mark.asyncio
    async def test_handle_command_parsing_error_basic(self, error_handler):
        """Test basic command parsing error handling."""
        parsing_error = ValueError("Invalid command syntax")
        
        response = await error_handler.handle_command_parsing_error(
            error=parsing_error,
            platform=PlatformType.TWITTER,
            raw_command="@bot invalid command",
            user_id="test_user"
        )
        
        assert isinstance(response, BotResponse)
        assert not response.success
        assert response.response_type == ResponseType.ERROR
        assert "command format" in response.error_message.lower()
        assert "error_id" in response.data
        assert response.data["category"] == "command_parsing"
        assert response.data["severity"] == "medium"
    
    @pytest.mark.asyncio
    async def test_handle_command_parsing_error_with_guidance(self, error_handler):
        """Test command parsing error with platform-specific guidance."""
        parsing_error = SyntaxError("Command syntax error")
        
        response = await error_handler.handle_command_parsing_error(
            error=parsing_error,
            platform="telegram",
            raw_command="/invalid_command",
            user_id="telegram_user"
        )
        
        assert not response.success
        assert "telegram commands start with /" in response.error_message.lower()
        assert "/analyze_account" in response.error_message
        assert response.data["guidance_provided"] is True
    
    @pytest.mark.asyncio
    async def test_handle_command_parsing_error_no_command(self, error_handler):
        """Test command parsing error with no raw command."""
        parsing_error = ValueError("No command provided")
        
        response = await error_handler.handle_command_parsing_error(
            error=parsing_error,
            platform="discord",
            raw_command=None,
            user_id="discord_user"
        )
        
        assert not response.success
        assert response.data["severity"] == "high"  # Higher severity for no command
    
    @pytest.mark.asyncio
    async def test_handle_command_parsing_error_fallback(self, error_handler):
        """Test command parsing error handler fallback when it fails."""
        parsing_error = ValueError("Test error")
        
        # Mock the _log_error method to raise an exception
        with patch.object(error_handler, '_log_error', side_effect=Exception("Log error")):
            response = await error_handler.handle_command_parsing_error(
                error=parsing_error,
                platform=PlatformType.TWITTER,
                raw_command="@bot test",
                user_id="test_user"
            )
        
        assert not response.success
        assert "command parsing failed" in response.error_message.lower()
        assert response.data.get("fallback_response") is True


class TestPlatformAPIErrorHandling:
    """Test platform API error handling."""
    
    @pytest.fixture
    def error_handler(self):
        return BotErrorHandler()
    
    @pytest.mark.asyncio
    async def test_handle_platform_api_error_rate_limit(self, error_handler):
        """Test handling of rate limit errors."""
        rate_limit_error = Exception("Rate limit exceeded (429)")
        
        response = await error_handler.handle_platform_api_error(
            error=rate_limit_error,
            platform=PlatformType.TWITTER,
            operation="send_tweet",
            user_id="test_user",
            retry_count=0
        )
        
        assert not response.success
        assert response.data["category"] == "platform_api"
        assert response.data["severity"] == "medium"
        assert "rate limit" in response.error_message.lower()
        assert response.data["operation"] == "send_tweet"
    
    @pytest.mark.asyncio
    async def test_handle_platform_api_error_with_retry(self, error_handler):
        """Test platform API error with retry logic."""
        network_error = Exception("Connection timeout")
        
        response = await error_handler.handle_platform_api_error(
            error=network_error,
            platform="telegram",
            operation="send_message",
            user_id="test_user",
            retry_count=0
        )
        
        # Should indicate retry is in progress for retryable errors
        assert not response.success
        assert response.data.get("retry_in_progress") is True
        assert response.data["retry_count"] == 1
    
    @pytest.mark.asyncio
    async def test_handle_platform_api_error_auth_failure(self, error_handler):
        """Test handling of authentication errors."""
        auth_error = Exception("Authentication failed (401)")
        
        response = await error_handler.handle_platform_api_error(
            error=auth_error,
            platform="discord",
            operation="send_interaction_response",
            user_id="test_user",
            retry_count=0
        )
        
        assert not response.success
        assert response.data["severity"] == "high"  # Auth errors are high severity
        assert response.data.get("retry_in_progress") is not True  # No retry for auth errors
    
    @pytest.mark.asyncio
    async def test_handle_platform_api_error_max_retries(self, error_handler):
        """Test platform API error after max retries."""
        network_error = Exception("Connection timeout")
        
        response = await error_handler.handle_platform_api_error(
            error=network_error,
            platform=PlatformType.TWITTER,
            operation="send_tweet",
            user_id="test_user",
            retry_count=3  # Max retries exceeded
        )
        
        assert not response.success
        assert response.data.get("retry_in_progress") is not True
        assert response.data["retry_attempted"] is True
        assert response.data["severity"] == "high"  # Higher severity after max retries


class TestBotControllerErrorHandling:
    """Test BotController error handling."""
    
    @pytest.fixture
    def error_handler(self):
        return BotErrorHandler()
    
    @pytest.fixture
    def sample_command(self):
        return BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=PlatformType.TWITTER,
            user_id="test_user",
            parameters={"account_identifier": "testuser"}
        )
    
    @pytest.mark.asyncio
    async def test_handle_bot_controller_error_with_degradation(self, error_handler, sample_command):
        """Test BotController error with graceful degradation."""
        controller_error = Exception("Database connection failed")
        
        response = await error_handler.handle_bot_controller_error(
            error=controller_error,
            command=sample_command,
            operation="analyze_account_safety"
        )
        
        # Should return degraded response for account analysis
        assert response.success  # Degraded response is still successful
        assert response.data["degraded_response"] is True
        assert response.data["risk_level"] == "unknown"
        assert "error_id" in response.data
        assert len(response.data["recommendations"]) > 0
    
    @pytest.mark.asyncio
    async def test_handle_bot_controller_error_compliance_degradation(self, error_handler):
        """Test BotController error with compliance check degradation."""
        compliance_command = BotCommand(
            command_type=CommandType.CHECK_COMPLIANCE,
            platform="telegram",
            user_id="test_user",
            parameters={"content": "Test content to check"}
        )
        
        controller_error = Exception("Analysis service timeout")
        
        response = await error_handler.handle_bot_controller_error(
            error=controller_error,
            command=compliance_command,
            operation="check_content_compliance"
        )
        
        assert response.success
        assert response.data["degraded_response"] is True
        assert response.data["is_compliant"] is True  # Conservative degradation
        assert "Test content" in response.data["content_preview"]
    
    @pytest.mark.asyncio
    async def test_handle_bot_controller_error_followers_degradation(self, error_handler):
        """Test BotController error with follower analysis degradation."""
        followers_command = BotCommand(
            command_type=CommandType.ANALYZE_FOLLOWERS,
            platform="discord",
            user_id="test_user",
            parameters={}
        )
        
        controller_error = Exception("Service unavailable")
        
        response = await error_handler.handle_bot_controller_error(
            error=controller_error,
            command=followers_command,
            operation="analyze_verified_followers"
        )
        
        assert response.success
        assert response.data["degraded_response"] is True
        assert response.data["verified_followers_count"] == 0
        assert "temporarily unavailable" in response.data["networking_opportunities"][0]
    
    @pytest.mark.asyncio
    async def test_handle_bot_controller_error_no_degradation(self, error_handler):
        """Test BotController error when degradation fails."""
        sample_command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=PlatformType.TWITTER,
            user_id="test_user",
            parameters={"account_identifier": "testuser"}
        )
        
        controller_error = Exception("Critical system failure")
        
        # Mock graceful degradation to fail
        with patch.object(error_handler, '_attempt_graceful_degradation', return_value=None):
            response = await error_handler.handle_bot_controller_error(
                error=controller_error,
                command=sample_command,
                operation="analyze_account_safety"
            )
        
        assert not response.success
        assert response.data["category"] == "bot_controller"
        assert response.data["degradation_attempted"] is True


class TestResponseFormattingErrorHandling:
    """Test response formatting error handling."""
    
    @pytest.fixture
    def error_handler(self):
        return BotErrorHandler()
    
    @pytest.fixture
    def sample_bot_response(self):
        return BotResponse.success_response(
            data={"risk_level": "medium", "risk_score": 65},
            response_type=ResponseType.ANALYSIS_RESULT
        )
    
    @pytest.mark.asyncio
    async def test_handle_response_formatting_error_success_response(self, error_handler, sample_bot_response):
        """Test formatting error handling for successful response."""
        formatting_error = Exception("JSON serialization failed")
        
        formatted_response = await error_handler.handle_response_formatting_error(
            error=formatting_error,
            bot_response=sample_bot_response,
            platform=PlatformType.TWITTER,
            delivery_method=DeliveryMethod.EMBED
        )
        
        assert isinstance(formatted_response, FormattedResponse)
        assert formatted_response.platform == PlatformType.TWITTER
        assert formatted_response.delivery_method == DeliveryMethod.MESSAGE  # Fallback
        assert "operation completed successfully" in formatted_response.response_data["text"].lower()
        assert "fallback_text" in formatted_response.formatting_applied
    
    @pytest.mark.asyncio
    async def test_handle_response_formatting_error_error_response(self, error_handler):
        """Test formatting error handling for error response."""
        error_response = BotResponse.error_response(
            error_message="Original error message",
            response_type=ResponseType.ERROR
        )
        
        formatting_error = Exception("Formatting failed")
        
        formatted_response = await error_handler.handle_response_formatting_error(
            error=formatting_error,
            bot_response=error_response,
            platform="telegram",
            delivery_method=DeliveryMethod.INLINE_KEYBOARD
        )
        
        assert "original error message" in formatted_response.response_data["text"].lower()
        assert "error_recovery" in formatted_response.formatting_applied
    
    @pytest.mark.asyncio
    async def test_handle_response_formatting_error_emergency_fallback(self, error_handler, sample_bot_response):
        """Test emergency fallback when formatting error handler fails."""
        formatting_error = Exception("Critical formatting error")
        
        # Mock the fallback creation to fail
        with patch.object(error_handler, '_create_fallback_formatted_response', side_effect=Exception("Fallback failed")):
            formatted_response = await error_handler.handle_response_formatting_error(
                error=formatting_error,
                bot_response=sample_bot_response,
                platform="discord",
                delivery_method=DeliveryMethod.EMBED
            )
        
        assert "system error occurred" in formatted_response.response_data["text"].lower()
        assert "emergency_fallback" in formatted_response.formatting_applied


class TestErrorAnalysisAndSeverity:
    """Test error analysis and severity determination."""
    
    @pytest.fixture
    def error_handler(self):
        return BotErrorHandler()
    
    def test_determine_parsing_error_severity(self, error_handler):
        """Test parsing error severity determination."""
        # Test validation error
        validation_error = ValueError("Validation failed")
        severity = error_handler._determine_parsing_error_severity(validation_error, "@bot test")
        assert severity == ErrorSeverity.MEDIUM
        
        # Test syntax error
        syntax_error = SyntaxError("Invalid syntax")
        severity = error_handler._determine_parsing_error_severity(syntax_error, "/invalid")
        assert severity == ErrorSeverity.MEDIUM
        
        # Test timeout error
        timeout_error = TimeoutError("Command timeout")
        severity = error_handler._determine_parsing_error_severity(timeout_error, "@bot analyze")
        assert severity == ErrorSeverity.HIGH
        
        # Test no command
        no_command_severity = error_handler._determine_parsing_error_severity(ValueError("No command"), None)
        assert no_command_severity == ErrorSeverity.HIGH
    
    def test_analyze_api_error(self, error_handler):
        """Test API error analysis for severity and retry logic."""
        # Test rate limit error
        rate_limit_error = Exception("Rate limit exceeded (429)")
        severity, should_retry = error_handler._analyze_api_error(rate_limit_error, 0)
        assert severity == ErrorSeverity.MEDIUM
        assert should_retry is False
        
        # Test authentication error
        auth_error = Exception("Authentication failed (401)")
        severity, should_retry = error_handler._analyze_api_error(auth_error, 0)
        assert severity == ErrorSeverity.HIGH
        assert should_retry is False
        
        # Test network error (retryable)
        network_error = Exception("Connection timeout")
        severity, should_retry = error_handler._analyze_api_error(network_error, 0)
        assert severity == ErrorSeverity.MEDIUM
        assert should_retry is True
        
        # Test network error after retries
        severity, should_retry = error_handler._analyze_api_error(network_error, 2)
        assert severity == ErrorSeverity.HIGH
        assert should_retry is False
        
        # Test server error
        server_error = Exception("Internal server error (500)")
        severity, should_retry = error_handler._analyze_api_error(server_error, 0)
        assert severity == ErrorSeverity.MEDIUM
        assert should_retry is True
        
        # Test client error
        client_error = Exception("Bad request (400)")
        severity, should_retry = error_handler._analyze_api_error(client_error, 0)
        assert severity == ErrorSeverity.MEDIUM
        assert should_retry is False
    
    def test_determine_controller_error_severity(self, error_handler):
        """Test BotController error severity determination."""
        # Test timeout error
        timeout_error = Exception("Operation timeout")
        severity = error_handler._determine_controller_error_severity(timeout_error, "analyze")
        assert severity == ErrorSeverity.MEDIUM
        
        # Test database error
        db_error = Exception("Database connection failed")
        severity = error_handler._determine_controller_error_severity(db_error, "query")
        assert severity == ErrorSeverity.HIGH
        
        # Test validation error
        validation_error = Exception("Input validation failed")
        severity = error_handler._determine_controller_error_severity(validation_error, "validate")
        assert severity == ErrorSeverity.MEDIUM
        
        # Test permission error
        permission_error = Exception("Permission denied")
        severity = error_handler._determine_controller_error_severity(permission_error, "access")
        assert severity == ErrorSeverity.HIGH
    
    def test_determine_formatting_error_severity(self, error_handler):
        """Test response formatting error severity determination."""
        # Test encoding error
        encoding_error = Exception("Unicode encoding error")
        severity = error_handler._determine_formatting_error_severity(encoding_error, DeliveryMethod.MESSAGE)
        assert severity == ErrorSeverity.MEDIUM
        
        # Test length error
        length_error = Exception("Message too long")
        severity = error_handler._determine_formatting_error_severity(length_error, DeliveryMethod.EMBED)
        assert severity == ErrorSeverity.LOW
        
        # Test JSON error
        json_error = Exception("JSON serialization failed")
        severity = error_handler._determine_formatting_error_severity(json_error, DeliveryMethod.REPLY)
        assert severity == ErrorSeverity.MEDIUM


class TestErrorGuidanceGeneration:
    """Test error guidance generation."""
    
    @pytest.fixture
    def error_handler(self):
        return BotErrorHandler()
    
    def test_generate_parsing_guidance_twitter(self, error_handler):
        """Test parsing guidance generation for Twitter."""
        guidance = error_handler._generate_parsing_guidance("@bot invalid", PlatformType.TWITTER)
        assert "twitter commands should mention @bot" in guidance.lower()
        assert "@bot analyze @username" in guidance
    
    def test_generate_parsing_guidance_telegram(self, error_handler):
        """Test parsing guidance generation for Telegram."""
        guidance = error_handler._generate_parsing_guidance("/invalid", "telegram")
        assert "telegram commands start with /" in guidance.lower()
        assert "/analyze_account @username" in guidance
    
    def test_generate_parsing_guidance_discord(self, error_handler):
        """Test parsing guidance generation for Discord."""
        guidance = error_handler._generate_parsing_guidance("/invalid", "discord")
        assert "discord slash commands" in guidance.lower()
        assert "/analyze_account user:@username" in guidance
    
    def test_generate_parsing_guidance_no_command(self, error_handler):
        """Test parsing guidance when no command provided."""
        guidance = error_handler._generate_parsing_guidance(None, PlatformType.TWITTER)
        assert "use /help to see available commands" in guidance.lower()
    
    def test_generate_platform_guidance_rate_limits(self, error_handler):
        """Test platform-specific guidance for rate limits."""
        rate_limit_error = Exception("Rate limit exceeded")
        
        # Twitter rate limit guidance
        guidance = error_handler._generate_platform_guidance(PlatformType.TWITTER, "send_tweet", rate_limit_error)
        assert "15 minutes" in guidance
        
        # Telegram rate limit guidance
        guidance = error_handler._generate_platform_guidance("telegram", "send_message", rate_limit_error)
        assert "1 minute" in guidance
        
        # Discord rate limit guidance
        guidance = error_handler._generate_platform_guidance("discord", "send_interaction", rate_limit_error)
        assert "few seconds" in guidance
    
    def test_generate_command_guidance(self, error_handler):
        """Test command-specific guidance generation."""
        # Account analysis guidance
        account_command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=PlatformType.TWITTER,
            user_id="test",
            parameters={"account_identifier": "testuser"}
        )
        guidance = error_handler._generate_command_guidance(account_command, Exception("Error"))
        assert "account username is correct" in guidance.lower()
        
        # Compliance check guidance
        compliance_command = BotCommand(
            command_type=CommandType.CHECK_COMPLIANCE,
            platform="telegram",
            user_id="test",
            parameters={"content": "test content"}
        )
        guidance = error_handler._generate_command_guidance(compliance_command, Exception("Error"))
        assert "shorter content" in guidance.lower()
        
        # Follower analysis guidance
        followers_command = BotCommand(
            command_type=CommandType.ANALYZE_FOLLOWERS,
            platform="discord",
            user_id="test",
            parameters={}
        )
        guidance = error_handler._generate_command_guidance(followers_command, Exception("Error"))
        assert "account access" in guidance.lower()


class TestErrorStatisticsAndMonitoring:
    """Test error statistics and monitoring functionality."""
    
    @pytest.fixture
    def error_handler(self):
        return BotErrorHandler()
    
    def test_track_error(self, error_handler):
        """Test error tracking functionality."""
        initial_count = len(error_handler.recent_errors)
        
        bot_error = BotError(
            message="Test error",
            category=ErrorCategory.COMMAND_PARSING,
            severity=ErrorSeverity.MEDIUM
        )
        
        error_handler._track_error(bot_error)
        
        assert len(error_handler.recent_errors) == initial_count + 1
        assert error_handler.recent_errors[-1] == bot_error
        
        error_key = f"{ErrorCategory.COMMAND_PARSING.value}:{ErrorSeverity.MEDIUM.value}"
        assert error_key in error_handler.error_counts
        assert error_handler.error_counts[error_key] >= 1
    
    def test_get_error_statistics(self, error_handler):
        """Test error statistics generation."""
        # Add some test errors
        for i in range(5):
            bot_error = BotError(
                message=f"Test error {i}",
                category=ErrorCategory.PLATFORM_API,
                severity=ErrorSeverity.HIGH if i % 2 == 0 else ErrorSeverity.MEDIUM
            )
            error_handler._track_error(bot_error)
        
        stats = error_handler.get_error_statistics()
        
        assert "total_errors" in stats
        assert "error_counts_by_category" in stats
        assert "recent_errors" in stats
        assert "error_rate_by_severity" in stats
        
        assert stats["total_errors"] >= 5
        assert len(stats["recent_errors"]) <= 10  # Limited to last 10
        assert ErrorSeverity.HIGH.value in stats["error_rate_by_severity"]
        assert ErrorSeverity.MEDIUM.value in stats["error_rate_by_severity"]
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, error_handler):
        """Test health check when system is healthy."""
        # Add some low/medium severity errors
        for i in range(3):
            bot_error = BotError(
                message=f"Minor error {i}",
                category=ErrorCategory.RESPONSE_FORMATTING,
                severity=ErrorSeverity.LOW
            )
            error_handler._track_error(bot_error)
        
        health = await error_handler.health_check()
        
        assert health["status"] == "healthy"
        assert health["error_handler_operational"] is True
        assert "recent_critical_errors" in health
        assert "recent_high_errors" in health
        assert "total_tracked_errors" in health
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, error_handler):
        """Test health check when health check itself fails."""
        # Mock the health check to fail
        with patch.object(error_handler, 'recent_errors', side_effect=Exception("Health check failed")):
            health = await error_handler.health_check()
        
        assert health["status"] == "unhealthy"
        assert health["error_handler_operational"] is False
        assert "error" in health


class TestGlobalErrorHandlerInstance:
    """Test the global error handler instance."""
    
    def test_global_instance_exists(self):
        """Test that global error handler instance exists."""
        assert bot_error_handler is not None
        assert isinstance(bot_error_handler, BotErrorHandler)
    
    @pytest.mark.asyncio
    async def test_global_instance_functionality(self):
        """Test that global error handler instance is functional."""
        parsing_error = ValueError("Test parsing error")
        
        response = await bot_error_handler.handle_command_parsing_error(
            error=parsing_error,
            platform=PlatformType.TWITTER,
            raw_command="@bot test",
            user_id="global_test_user"
        )
        
        assert isinstance(response, BotResponse)
        assert not response.success
        assert response.response_type == ResponseType.ERROR


if __name__ == "__main__":
    pytest.main([__file__])