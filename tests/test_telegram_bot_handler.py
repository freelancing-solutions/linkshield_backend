"""
Unit tests for TelegramBotHandler.

Tests command parsing, response formatting, and Telegram Bot API integration
for the social media bot service.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
from typing import Dict, Any

from linkshield.bots.handlers.telegram_bot_handler import TelegramBotHandler
from linkshield.bots.models import (
    BotCommand, BotResponse, CommandType, ResponseType, 
    DeliveryMethod, FormattedResponse
)


class TestTelegramBotHandler:
    """Test cases for TelegramBotHandler."""
    
    @pytest.fixture
    def handler(self):
        """Create TelegramBotHandler instance for testing."""
        with patch('src.bots.handlers.telegram_bot_handler.settings') as mock_settings:
            mock_settings.TELEGRAM_BOT_TOKEN = "test_token"
            handler = TelegramBotHandler()
            handler.is_initialized = True
            handler.http_session = AsyncMock()
            return handler
    
    @pytest.fixture
    def sample_message_data(self):
        """Sample Telegram message data."""
        return {
            "message_id": 123,
            "from": {
                "id": 12345,
                "username": "testuser",
                "first_name": "Test"
            },
            "chat": {
                "id": 67890,
                "type": "private"
            },
            "date": 1234567890,
            "text": "/analyze_account @elonmusk"
        }
    
    @pytest.fixture
    def sample_bot_response(self):
        """Sample BotResponse for testing."""
        return BotResponse.success_response(
            data={
                "risk_level": "medium",
                "risk_score": 65,
                "account_identifier": "elonmusk",
                "recommendations": [
                    "Monitor account activity",
                    "Check recent posts for policy violations"
                ],
                "threats_detected": ["Suspicious engagement patterns"]
            },
            response_type=ResponseType.ANALYSIS_RESULT
        )


class TestCommandParsing:
    """Test command parsing functionality."""
    
    @pytest.mark.asyncio
    async def test_parse_analyze_account_command(self, handler, sample_message_data):
        """Test parsing analyze_account command."""
        sample_message_data["text"] = "/analyze_account @elonmusk"
        
        command = await handler.parse_command(sample_message_data)
        
        assert command is not None
        assert command.command_type == CommandType.ANALYZE_ACCOUNT
        assert command.platform == "telegram"
        assert command.user_id == "12345"
        assert command.parameters["account_identifier"] == "elonmusk"
        assert command.metadata["username"] == "testuser"
        assert command.metadata["chat_id"] == 67890
    
    @pytest.mark.asyncio
    async def test_parse_check_compliance_command(self, handler, sample_message_data):
        """Test parsing check_compliance command."""
        sample_message_data["text"] = "/check_compliance This is test content to check"
        
        command = await handler.parse_command(sample_message_data)
        
        assert command is not None
        assert command.command_type == CommandType.CHECK_COMPLIANCE
        assert command.platform == "telegram"
        assert command.user_id == "12345"
        assert command.parameters["content"] == "This is test content to check"
    
    @pytest.mark.asyncio
    async def test_parse_analyze_followers_command(self, handler, sample_message_data):
        """Test parsing analyze_followers command."""
        sample_message_data["text"] = "/analyze_followers"
        
        command = await handler.parse_command(sample_message_data)
        
        assert command is not None
        assert command.command_type == CommandType.ANALYZE_FOLLOWERS
        assert command.platform == "telegram"
        assert command.user_id == "12345"
        assert len(command.parameters) == 0  # No parameters for follower analysis
    
    @pytest.mark.asyncio
    async def test_parse_invalid_command(self, handler, sample_message_data):
        """Test parsing invalid command returns None."""
        sample_message_data["text"] = "/invalid_command"
        
        command = await handler.parse_command(sample_message_data)
        
        assert command is None
    
    @pytest.mark.asyncio
    async def test_parse_non_command_message(self, handler, sample_message_data):
        """Test parsing non-command message returns None."""
        sample_message_data["text"] = "This is just a regular message"
        
        command = await handler.parse_command(sample_message_data)
        
        assert command is None
    
    @pytest.mark.asyncio
    async def test_parse_command_with_missing_data(self, handler):
        """Test parsing command with missing required data."""
        incomplete_data = {
            "text": "/analyze_account @test"
            # Missing 'from' field
        }
        
        command = await handler.parse_command(incomplete_data)
        
        assert command is None
    
    @pytest.mark.asyncio
    async def test_parse_command_alternative_syntax(self, handler, sample_message_data):
        """Test parsing commands with alternative syntax."""
        # Test alternative command names
        sample_message_data["text"] = "/check_account @testuser"
        
        command = await handler.parse_command(sample_message_data)
        
        assert command is not None
        assert command.command_type == CommandType.ANALYZE_ACCOUNT
        assert command.parameters["account_identifier"] == "testuser"


class TestResponseFormatting:
    """Test response formatting functionality."""
    
    @pytest.mark.asyncio
    async def test_format_account_analysis_response(self, handler, sample_bot_response):
        """Test formatting account analysis response."""
        formatted = await handler.format_response(sample_bot_response)
        
        assert isinstance(formatted, FormattedResponse)
        assert formatted.platform == "telegram"
        assert formatted.delivery_method == DeliveryMethod.MESSAGE
        assert "telegram_markdown" in formatted.formatting_applied
        
        response_text = formatted.response_data["text"]
        assert "Account Safety Analysis" in response_text
        assert "elonmusk" in response_text
        assert "Medium" in response_text
        assert "65/100" in response_text
        assert "Monitor account activity" in response_text
    
    @pytest.mark.asyncio
    async def test_format_compliance_check_response(self, handler):
        """Test formatting compliance check response."""
        compliance_response = BotResponse.success_response(
            data={
                "is_compliant": False,
                "compliance_score": 45,
                "violations": [
                    {"severity": "high", "description": "Hate speech detected"},
                    {"severity": "medium", "description": "Spam indicators found"}
                ],
                "remediation_suggestions": [
                    "Remove offensive language",
                    "Reduce promotional content"
                ]
            },
            response_type=ResponseType.COMPLIANCE_CHECK
        )
        
        formatted = await handler.format_response(compliance_response)
        
        assert isinstance(formatted, FormattedResponse)
        response_text = formatted.response_data["text"]
        assert "Content Compliance Check" in response_text
        assert "Issues Found" in response_text
        assert "45/100" in response_text
        assert "Hate speech detected" in response_text
        assert "Remove offensive language" in response_text
    
    @pytest.mark.asyncio
    async def test_format_follower_analysis_response(self, handler):
        """Test formatting follower analysis response."""
        follower_response = BotResponse.success_response(
            data={
                "verified_followers_count": 1250,
                "total_followers": 10000,
                "high_value_followers": 85,
                "follower_categories": {
                    "influencers": 45,
                    "businesses": 120,
                    "media": 25
                },
                "networking_opportunities": [
                    "Connect with tech influencers",
                    "Engage with business leaders"
                ]
            },
            response_type=ResponseType.FOLLOWER_ANALYSIS
        )
        
        formatted = await handler.format_response(follower_response)
        
        assert isinstance(formatted, FormattedResponse)
        response_text = formatted.response_data["text"]
        assert "Verified Followers Analysis" in response_text
        assert "1,250" in response_text
        assert "12.5%" in response_text  # Verification rate
        assert "85" in response_text  # High-value followers
        assert "Connect with tech influencers" in response_text
    
    @pytest.mark.asyncio
    async def test_format_error_response(self, handler):
        """Test formatting error response."""
        error_response = BotResponse.error_response(
            error_message="Account not found or private",
            response_type=ResponseType.ERROR
        )
        
        formatted = await handler.format_response(error_response)
        
        assert isinstance(formatted, FormattedResponse)
        response_text = formatted.response_data["text"]
        assert "Error" in response_text
        assert "Account not found or private" in response_text
        assert "try again" in response_text.lower()
    
    @pytest.mark.asyncio
    async def test_format_response_with_markdown(self, handler, sample_bot_response):
        """Test that responses use Markdown formatting."""
        formatted = await handler.format_response(sample_bot_response)
        
        assert formatted.response_data["parse_mode"] == "Markdown"
        response_text = formatted.response_data["text"]
        # Check for Markdown formatting
        assert "*" in response_text  # Bold text
        assert "`" in response_text  # Code formatting


class TestMessageHandling:
    """Test message handling functionality."""
    
    @pytest.mark.asyncio
    async def test_handle_webhook_with_message(self, handler):
        """Test handling webhook with message."""
        webhook_payload = {
            "update_id": 123456,
            "message": {
                "message_id": 789,
                "from": {"id": 12345, "username": "testuser"},
                "chat": {"id": 67890, "type": "private"},
                "text": "Hello bot"
            }
        }
        
        with patch.object(handler, '_handle_message') as mock_handle:
            mock_handle.return_value = {"type": "message", "action": "processed"}
            
            result = await handler.handle_webhook(webhook_payload)
            
            mock_handle.assert_called_once_with(webhook_payload["message"])
            assert result["type"] == "message"
    
    @pytest.mark.asyncio
    async def test_handle_webhook_with_callback_query(self, handler):
        """Test handling webhook with callback query."""
        webhook_payload = {
            "update_id": 123456,
            "callback_query": {
                "id": "callback123",
                "from": {"id": 12345, "username": "testuser"},
                "data": "test_callback"
            }
        }
        
        with patch.object(handler, '_handle_callback_query') as mock_handle:
            mock_handle.return_value = {"type": "callback_query", "action": "processed"}
            
            result = await handler.handle_webhook(webhook_payload)
            
            mock_handle.assert_called_once_with(webhook_payload["callback_query"])
            assert result["type"] == "callback_query"
    
    @pytest.mark.asyncio
    async def test_send_response_success(self, handler):
        """Test successful response sending."""
        formatted_response = FormattedResponse(
            platform="telegram",
            response_data={
                "text": "Test message",
                "parse_mode": "Markdown"
            },
            delivery_method=DeliveryMethod.MESSAGE,
            formatting_applied=["telegram_markdown"]
        )
        
        with patch.object(handler, '_send_message') as mock_send:
            mock_send.return_value = {"message_id": 123}
            
            success = await handler.send_response(formatted_response, 67890)
            
            assert success is True
            mock_send.assert_called_once_with(67890, "Test message", "Markdown")
    
    @pytest.mark.asyncio
    async def test_send_response_with_keyboard(self, handler):
        """Test sending response with inline keyboard."""
        formatted_response = FormattedResponse(
            platform="telegram",
            response_data={
                "text": "Choose an option",
                "reply_markup": {"inline_keyboard": []}
            },
            delivery_method=DeliveryMethod.INLINE_KEYBOARD,
            formatting_applied=["telegram_keyboard"]
        )
        
        with patch.object(handler, '_send_message_with_keyboard') as mock_send:
            mock_send.return_value = True
            
            success = await handler.send_response(formatted_response, 67890)
            
            assert success is True
            mock_send.assert_called_once_with(67890, formatted_response.response_data)


class TestIntegration:
    """Test integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_command_flow(self, handler):
        """Test complete command processing flow."""
        message_data = {
            "message_id": 123,
            "from": {"id": 12345, "username": "testuser"},
            "chat": {"id": 67890, "type": "private"},
            "text": "/analyze_account @testaccount"
        }
        
        # Mock the gateway response
        mock_bot_response = BotResponse.success_response(
            data={
                "risk_level": "low",
                "risk_score": 25,
                "account_identifier": "testaccount"
            },
            response_type=ResponseType.ANALYSIS_RESULT
        )
        
        with patch('src.bots.handlers.telegram_bot_handler.bot_gateway') as mock_gateway:
            mock_gateway.route_command.return_value = mock_bot_response
            
            with patch.object(handler, '_send_message') as mock_send:
                mock_send.return_value = {"message_id": 456}
                
                with patch.object(handler, '_delete_message') as mock_delete:
                    result = await handler._handle_standardized_command(message_data)
                    
                    # Verify command was routed to gateway
                    mock_gateway.route_command.assert_called_once()
                    
                    # Verify response was sent
                    assert mock_send.call_count >= 1
                    
                    # Verify result
                    assert result["type"] == "command"
                    assert result["command_type"] == "analyze_account"
                    assert result["success"] is True
    
    @pytest.mark.asyncio
    async def test_error_handling_in_command_processing(self, handler):
        """Test error handling during command processing."""
        message_data = {
            "message_id": 123,
            "from": {"id": 12345, "username": "testuser"},
            "chat": {"id": 67890, "type": "private"},
            "text": "/analyze_account @testaccount"
        }
        
        with patch('src.bots.handlers.telegram_bot_handler.bot_gateway') as mock_gateway:
            # Simulate gateway error
            mock_gateway.route_command.side_effect = Exception("Gateway error")
            
            with patch.object(handler, '_send_message') as mock_send:
                mock_send.return_value = {"message_id": 456}
                
                result = await handler._handle_standardized_command(message_data)
                
                # Verify error was handled
                assert "error" in result
                
                # Verify error message was sent to user
                error_calls = [call for call in mock_send.call_args_list 
                             if "error occurred" in str(call).lower()]
                assert len(error_calls) > 0


class TestHelperMethods:
    """Test helper methods."""
    
    @pytest.mark.asyncio
    async def test_help_command_formatting(self, handler):
        """Test help command response formatting."""
        result = await handler._handle_help_command(67890, "testuser")
        
        assert result["type"] == "command"
        assert result["command"] == "help"
        assert result["action"] == "help_sent"
        assert result["user"] == "testuser"
    
    @pytest.mark.asyncio
    async def test_api_connection_test(self, handler):
        """Test API connection testing."""
        # Mock successful API response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "ok": True,
            "result": {"username": "test_bot"}
        }
        
        handler.http_session.get.return_value.__aenter__.return_value = mock_response
        
        # Should not raise exception
        await handler._test_api_connection()
        
        handler.http_session.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initialization_without_token(self):
        """Test initialization without bot token."""
        with patch('src.bots.handlers.telegram_bot_handler.settings') as mock_settings:
            mock_settings.TELEGRAM_BOT_TOKEN = None
            
            handler = TelegramBotHandler()
            await handler.initialize()
            
            # Should handle missing token gracefully
            assert not handler.is_initialized
    
    @pytest.mark.asyncio
    async def test_shutdown_cleanup(self, handler):
        """Test proper cleanup during shutdown."""
        handler.http_session = AsyncMock()
        
        await handler.shutdown()
        
        handler.http_session.close.assert_called_once()
        assert not handler.is_initialized


if __name__ == "__main__":
    pytest.main([__file__])