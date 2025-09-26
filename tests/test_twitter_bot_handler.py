"""
Unit tests for TwitterBotHandler command parsing and response formatting.

Tests the Twitter bot handler's ability to parse commands, format responses,
and handle Twitter-specific communication protocols.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
from typing import Dict, Any
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the models directly to avoid circular imports
from bots.models import (
    BotCommand, BotResponse, PlatformCommand, FormattedResponse,
    CommandType, ResponseType, DeliveryMethod
)

# Mock the settings and other dependencies to avoid circular imports
class MockSettings:
    TWITTER_BOT_BEARER_TOKEN = "mock_token"

class MockPlatformType:
    TWITTER = "twitter"

# Patch the imports before importing the handler
with patch.dict('sys.modules', {
    'src.config.settings': Mock(settings=MockSettings()),
    'src.models.social_protection': Mock(PlatformType=MockPlatformType()),
}):
    from bots.handlers.twitter_bot_handler import TwitterBotHandler


class TestTwitterBotHandler:
    """Test cases for TwitterBotHandler class."""
    
    @pytest.fixture
    def handler(self):
        """Create a TwitterBotHandler instance for testing."""
        handler = TwitterBotHandler()
        handler.is_initialized = True  # Skip initialization for tests
        return handler
    
    @pytest.fixture
    def mock_http_session(self):
        """Mock HTTP session for API calls."""
        session = Mock()
        session.post = AsyncMock()
        session.get = AsyncMock()
        return session
    
    def test_handler_initialization(self):
        """Test TwitterBotHandler initialization."""
        handler = TwitterBotHandler()
        
        assert handler.platform == PlatformType.TWITTER
        assert handler.max_tweet_length == 280
        assert handler.max_thread_tweets == 5
        assert not handler.is_initialized
    
    @pytest.mark.asyncio
    async def test_parse_account_analysis_command(self, handler):
        """Test parsing account analysis commands from Twitter mentions."""
        # Test mention with account analysis
        tweet_data = {
            "id_str": "123456789",
            "text": "@bot analyze @testuser",
            "user": {
                "id_str": "987654321",
                "screen_name": "requester",
                "name": "Test User"
            }
        }
        
        command = await handler.parse_command(tweet_data)
        
        assert command is not None
        assert command.command_type == CommandType.ANALYZE_ACCOUNT
        assert command.platform == PlatformType.TWITTER
        assert command.user_id == "987654321"
        assert command.parameters["account_identifier"] == "testuser"
        assert "original_text" in command.metadata
    
    @pytest.mark.asyncio
    async def test_parse_compliance_check_command(self, handler):
        """Test parsing compliance check commands."""
        tweet_data = {
            "id_str": "123456789",
            "text": '@bot check_compliance "This is my content to check"',
            "user": {
                "id_str": "987654321",
                "screen_name": "requester"
            }
        }
        
        command = await handler.parse_command(tweet_data)
        
        assert command is not None
        assert command.command_type == CommandType.CHECK_COMPLIANCE
        assert command.platform == PlatformType.TWITTER
        assert command.user_id == "987654321"
        assert command.parameters["content"] == "This is my content to check"
    
    @pytest.mark.asyncio
    async def test_parse_follower_analysis_command(self, handler):
        """Test parsing follower analysis commands."""
        tweet_data = {
            "id_str": "123456789",
            "text": "@bot analyze_followers",
            "user": {
                "id_str": "987654321",
                "screen_name": "requester"
            }
        }
        
        command = await handler.parse_command(tweet_data)
        
        assert command is not None
        assert command.command_type == CommandType.ANALYZE_FOLLOWERS
        assert command.platform == PlatformType.TWITTER
        assert command.user_id == "987654321"
        assert command.parameters == {}
    
    @pytest.mark.asyncio
    async def test_parse_direct_message_command(self, handler):
        """Test parsing commands from direct messages."""
        dm_data = {
            "id": "dm123456789",
            "message_create": {
                "sender_id": "987654321",
                "message_data": {
                    "text": "analyze @testuser"
                }
            }
        }
        
        command = await handler.parse_command(dm_data)
        
        assert command is not None
        assert command.command_type == CommandType.ANALYZE_ACCOUNT
        assert command.user_id == "987654321"
        assert command.parameters["account_identifier"] == "testuser"
    
    @pytest.mark.asyncio
    async def test_parse_invalid_command(self, handler):
        """Test parsing invalid or unrecognized commands."""
        tweet_data = {
            "id_str": "123456789",
            "text": "Hello @bot, how are you?",
            "user": {
                "id_str": "987654321",
                "screen_name": "requester"
            }
        }
        
        command = await handler.parse_command(tweet_data)
        
        assert command is None
    
    @pytest.mark.asyncio
    async def test_format_account_analysis_response(self, handler):
        """Test formatting account analysis responses for Twitter."""
        bot_response = BotResponse.success_response(
            data={
                "risk_level": "medium",
                "risk_score": 65,
                "account_identifier": "testuser",
                "recommendations": [
                    "Verify account authenticity",
                    "Check recent activity"
                ]
            },
            response_type=ResponseType.ANALYSIS_RESULT
        )
        
        formatted_response = await handler.format_response(bot_response)
        
        assert formatted_response.platform == PlatformType.TWITTER
        assert formatted_response.delivery_method in [DeliveryMethod.REPLY, DeliveryMethod.THREAD]
        assert "text" in formatted_response.response_data
        
        text = formatted_response.response_data["text"]
        assert "⚠️" in text  # Medium risk indicator
        assert "testuser" in text
        assert "65/100" in text
    
    @pytest.mark.asyncio
    async def test_format_compliance_check_response(self, handler):
        """Test formatting compliance check responses for Twitter."""
        bot_response = BotResponse.success_response(
            data={
                "is_compliant": True,
                "compliance_score": 85,
                "violations": []
            },
            response_type=ResponseType.COMPLIANCE_CHECK
        )
        
        formatted_response = await handler.format_response(bot_response)
        
        assert formatted_response.platform == PlatformType.TWITTER
        text = formatted_response.response_data["text"]
        assert "✅" in text  # Compliant indicator
        assert "85/100" in text
        assert "Compliant" in text
    
    @pytest.mark.asyncio
    async def test_format_follower_analysis_response(self, handler):
        """Test formatting follower analysis responses for Twitter."""
        bot_response = BotResponse.success_response(
            data={
                "verified_followers_count": 42,
                "high_value_count": 8,
                "total_followers": 1250
            },
            response_type=ResponseType.FOLLOWER_ANALYSIS
        )
        
        formatted_response = await handler.format_response(bot_response)
        
        assert formatted_response.platform == PlatformType.TWITTER
        text = formatted_response.response_data["text"]
        assert "👥" in text  # Follower indicator
        assert "42" in text  # Verified count
        assert "8" in text   # High-value count
        assert "1250" in text # Total followers
    
    @pytest.mark.asyncio
    async def test_format_error_response(self, handler):
        """Test formatting error responses for Twitter."""
        bot_response = BotResponse.error_response(
            error_message="Analysis failed due to rate limiting",
            response_type=ResponseType.ERROR
        )
        
        formatted_response = await handler.format_response(bot_response)
        
        assert formatted_response.platform == PlatformType.TWITTER
        text = formatted_response.response_data["text"]
        assert "❌" in text or "Error" in text
    
    def test_determine_delivery_method_short_message(self, handler):
        """Test delivery method determination for short messages."""
        bot_response = BotResponse.success_response(
            data={"message": "Short message"},
            response_type=ResponseType.ANALYSIS_RESULT
        )
        
        delivery_method = handler._determine_delivery_method(bot_response)
        
        assert delivery_method == DeliveryMethod.REPLY
    
    def test_determine_delivery_method_long_message(self, handler):
        """Test delivery method determination for long messages."""
        long_message = "This is a very long message " * 20  # Over 280 characters
        bot_response = BotResponse.success_response(
            data={"message": long_message},
            response_type=ResponseType.ANALYSIS_RESULT
        )
        
        delivery_method = handler._determine_delivery_method(bot_response)
        
        assert delivery_method == DeliveryMethod.THREAD
    
    def test_determine_delivery_method_dm_context(self, handler):
        """Test delivery method determination for DM context."""
        bot_response = BotResponse.success_response(
            data={"message": "DM response"},
            response_type=ResponseType.ANALYSIS_RESULT,
            formatting_hints={"is_dm": True}
        )
        
        delivery_method = handler._determine_delivery_method(bot_response)
        
        assert delivery_method == DeliveryMethod.DM
    
    def test_split_text_for_thread(self, handler):
        """Test splitting long text into Twitter thread chunks."""
        long_text = "This is a very long message that needs to be split into multiple tweets. " * 10
        
        chunks = handler._split_text_for_thread(long_text, "testuser")
        
        assert len(chunks) > 1
        for chunk in chunks:
            # Account for mention and thread numbering space
            assert len(chunk) <= handler.max_tweet_length - 20
    
    def test_extract_user_context_tweet(self, handler):
        """Test extracting user context from tweet data."""
        tweet_data = {
            "user": {
                "id_str": "123456789",
                "screen_name": "testuser",
                "name": "Test User",
                "verified": True,
                "followers_count": 1000
            }
        }
        
        context = handler._extract_user_context(tweet_data)
        
        assert context["user_id"] == "123456789"
        assert context["screen_name"] == "testuser"
        assert context["display_name"] == "Test User"
        assert context["verified"] is True
        assert context["followers_count"] == 1000
    
    def test_extract_user_context_dm(self, handler):
        """Test extracting user context from DM data."""
        dm_data = {
            "message_create": {
                "sender_id": "987654321"
            }
        }
        
        context = handler._extract_user_context(dm_data)
        
        assert context["user_id"] == "987654321"
        assert context["is_dm"] is True
    
    def test_create_help_response(self, handler):
        """Test creating help response."""
        help_response = handler._create_help_response()
        
        assert help_response.success is True
        assert help_response.response_type == ResponseType.ANALYSIS_RESULT
        assert "LinkShield" in help_response.data["message"]
        assert "analyze" in help_response.data["message"]
        assert "compliance" in help_response.data["message"]
        assert "followers" in help_response.data["message"]
    
    @pytest.mark.asyncio
    async def test_process_bot_command_account_analysis(self, handler):
        """Test processing account analysis command."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=PlatformType.TWITTER,
            user_id="123456789",
            parameters={"account_identifier": "testuser"}
        )
        
        response = await handler._process_bot_command(command)
        
        assert response.success is True
        assert response.response_type == ResponseType.ANALYSIS_RESULT
        assert "risk_level" in response.data
        assert "account_identifier" in response.data
        assert response.data["account_identifier"] == "testuser"
    
    @pytest.mark.asyncio
    async def test_process_bot_command_compliance_check(self, handler):
        """Test processing compliance check command."""
        command = BotCommand(
            command_type=CommandType.CHECK_COMPLIANCE,
            platform=PlatformType.TWITTER,
            user_id="123456789",
            parameters={"content": "Test content"}
        )
        
        response = await handler._process_bot_command(command)
        
        assert response.success is True
        assert response.response_type == ResponseType.COMPLIANCE_CHECK
        assert "is_compliant" in response.data
        assert "compliance_score" in response.data
    
    @pytest.mark.asyncio
    async def test_process_bot_command_follower_analysis(self, handler):
        """Test processing follower analysis command."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_FOLLOWERS,
            platform=PlatformType.TWITTER,
            user_id="123456789",
            parameters={}
        )
        
        response = await handler._process_bot_command(command)
        
        assert response.success is True
        assert response.response_type == ResponseType.FOLLOWER_ANALYSIS
        assert "verified_followers_count" in response.data
        assert "high_value_count" in response.data
    
    @pytest.mark.asyncio
    async def test_send_reply_success(self, handler, mock_http_session):
        """Test successful reply sending."""
        handler.http_session = mock_http_session
        
        # Mock successful API response
        mock_response = Mock()
        mock_response.status = 201
        mock_http_session.post.return_value.__aenter__.return_value = mock_response
        
        response_data = {"text": "Test reply"}
        context = {
            "tweet_id": "123456789",
            "user_screen_name": "testuser"
        }
        
        success = await handler._send_reply(response_data, context)
        
        assert success is True
        mock_http_session.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_dm_success(self, handler, mock_http_session):
        """Test successful DM sending."""
        handler.http_session = mock_http_session
        
        # Mock successful API response
        mock_response = Mock()
        mock_response.status = 201
        mock_http_session.post.return_value.__aenter__.return_value = mock_response
        
        response_data = {"text": "Test DM"}
        context = {
            "sender_id": "987654321"
        }
        
        success = await handler._send_direct_message_response(response_data, context)
        
        assert success is True
        mock_http_session.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_handle_webhook_tweet_event(self, handler):
        """Test handling webhook with tweet events."""
        payload = {
            "tweet_create_events": [
                {
                    "id_str": "123456789",
                    "text": "@bot analyze @testuser",
                    "user": {
                        "id_str": "987654321",
                        "screen_name": "requester"
                    }
                }
            ]
        }
        
        with patch.object(handler, '_handle_tweet_event', new_callable=AsyncMock) as mock_handle:
            mock_handle.return_value = {"type": "tweet_mention", "success": True}
            
            result = await handler.handle_webhook(payload)
            
            assert "processed_events" in result
            assert len(result["processed_events"]) == 1
            mock_handle.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_handle_webhook_dm_event(self, handler):
        """Test handling webhook with DM events."""
        payload = {
            "direct_message_events": [
                {
                    "id": "dm123456789",
                    "message_create": {
                        "sender_id": "987654321",
                        "message_data": {
                            "text": "analyze @testuser"
                        }
                    }
                }
            ]
        }
        
        with patch.object(handler, '_handle_direct_message_event', new_callable=AsyncMock) as mock_handle:
            mock_handle.return_value = {"type": "direct_message", "success": True}
            
            result = await handler.handle_webhook(payload)
            
            assert "processed_events" in result
            assert len(result["processed_events"]) == 1
            mock_handle.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_format_response_character_limit(self, handler):
        """Test response formatting respects Twitter character limits."""
        # Create a response with very long text
        long_text = "This is a very long analysis result " * 20
        bot_response = BotResponse.success_response(
            data={
                "risk_level": "high",
                "risk_score": 90,
                "account_identifier": "testuser",
                "analysis_summary": long_text
            },
            response_type=ResponseType.ANALYSIS_RESULT
        )
        
        formatted_response = await handler.format_response(bot_response)
        
        # Should either be truncated or use thread delivery
        if formatted_response.delivery_method == DeliveryMethod.REPLY:
            assert len(formatted_response.response_data["text"]) <= handler.max_tweet_length
        else:
            assert formatted_response.delivery_method == DeliveryMethod.THREAD


class TestTwitterBotHandlerIntegration:
    """Integration tests for TwitterBotHandler with mock services."""
    
    @pytest.fixture
    def handler_with_mocks(self):
        """Create handler with mocked dependencies."""
        handler = TwitterBotHandler()
        handler.is_initialized = True
        
        # Mock HTTP session
        handler.http_session = Mock()
        handler.http_session.post = AsyncMock()
        handler.http_session.get = AsyncMock()
        
        return handler
    
    @pytest.mark.asyncio
    async def test_end_to_end_tweet_processing(self, handler_with_mocks):
        """Test complete tweet processing flow."""
        handler = handler_with_mocks
        
        # Mock successful API response
        mock_response = Mock()
        mock_response.status = 201
        handler.http_session.post.return_value.__aenter__.return_value = mock_response
        
        # Simulate tweet event
        event = {
            "id_str": "123456789",
            "text": "@bot analyze @suspicioususer",
            "user": {
                "id_str": "987654321",
                "screen_name": "requester",
                "name": "Test User"
            }
        }
        
        result = await handler._handle_tweet_event(event, {})
        
        assert result["type"] == "tweet_mention"
        assert result["command_type"] == "analyze_account"
        assert result["user"] == "requester"
        assert result["success"] is True
    
    @pytest.mark.asyncio
    async def test_end_to_end_dm_processing(self, handler_with_mocks):
        """Test complete DM processing flow."""
        handler = handler_with_mocks
        
        # Mock successful API response
        mock_response = Mock()
        mock_response.status = 201
        handler.http_session.post.return_value.__aenter__.return_value = mock_response
        
        # Simulate DM event
        event = {
            "id": "dm123456789",
            "message_create": {
                "sender_id": "987654321",
                "message_data": {
                    "text": 'check_compliance "This is my content to verify"'
                }
            }
        }
        
        result = await handler._handle_direct_message_event(event, {})
        
        assert result["type"] == "direct_message"
        assert result["command_type"] == "check_compliance"
        assert result["sender"] == "987654321"
        assert result["success"] is True


if __name__ == "__main__":
    pytest.main([__file__])