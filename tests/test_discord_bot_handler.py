"""
Unit tests for Discord Bot Handler.

Tests Discord command parsing, response formatting, and webhook handling
for the standardized bot command interface.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import json

from src.bots.handlers.discord_bot_handler import DiscordBotHandler
from src.bots.models import (
    BotCommand, BotResponse, CommandType, ResponseType, 
    DeliveryMethod, FormattedResponse
)


class TestDiscordBotHandler:
    """Test cases for Discord bot handler functionality."""
    
    @pytest.fixture
    def handler(self):
        """Create a Discord bot handler instance for testing."""
        with patch('src.bots.handlers.discord_bot_handler.settings') as mock_settings:
            mock_settings.DISCORD_BOT_TOKEN = "test_token"
            handler = DiscordBotHandler()
            return handler
    
    @pytest.fixture
    def sample_interaction_data(self):
        """Sample Discord interaction data for testing."""
        return {
            "id": "123456789",
            "type": 2,  # APPLICATION_COMMAND
            "token": "test_interaction_token",
            "data": {
                "name": "analyze_account",
                "options": [
                    {
                        "name": "user",
                        "value": "@testuser"
                    }
                ]
            },
            "user": {
                "id": "987654321",
                "username": "testuser",
                "discriminator": "1234"
            },
            "guild": {
                "id": "guild123",
                "name": "Test Guild"
            },
            "channel": {
                "id": "channel456",
                "name": "general"
            }
        }
    
    @pytest.fixture
    def sample_bot_response(self):
        """Sample bot response for testing."""
        return BotResponse.success_response(
            data={
                "risk_level": "medium",
                "risk_score": 65,
                "account_identifier": "testuser",
                "analysis_summary": "Account shows moderate risk indicators",
                "recommendations": [
                    "Verify account authenticity before engaging",
                    "Check recent activity patterns"
                ],
                "threats_detected": ["Suspicious follower patterns"]
            },
            response_type=ResponseType.ANALYSIS_RESULT,
            formatting_hints={"risk_level": "medium", "use_emoji": True}
        )
    
    def test_initialization(self, handler):
        """Test handler initialization."""
        assert handler.platform == "discord"
        assert handler.api_base_url == "https://discord.com/api/v10"
        assert not handler.is_initialized
        assert handler.application_id is None
    
    def test_extract_user_context(self, handler, sample_interaction_data):
        """Test user context extraction from Discord interaction data."""
        context = handler._extract_user_context(sample_interaction_data)
        
        assert context["user_id"] == "987654321"
        assert context["username"] == "testuser"
        assert context["discriminator"] == "1234"
        assert context["guild_id"] == "guild123"
        assert context["guild_name"] == "Test Guild"
        assert context["channel_id"] == "channel456"
        assert context["channel_name"] == "general"
        assert context["interaction_id"] == "123456789"
        assert context["interaction_token"] == "test_interaction_token"
    
    @pytest.mark.asyncio
    async def test_manual_parse_analyze_account_command(self, handler, sample_interaction_data):
        """Test manual parsing of analyze_account command."""
        bot_command = await handler._manual_parse_discord_command(sample_interaction_data)
        
        assert bot_command is not None
        assert bot_command.command_type == CommandType.ANALYZE_ACCOUNT
        assert bot_command.platform == "discord"
        assert bot_command.user_id == "987654321"
        assert bot_command.parameters["account_identifier"] == "testuser"
        assert bot_command.metadata["original_command"] == "analyze_account"
        assert bot_command.metadata["guild_id"] == "guild123"
        assert bot_command.metadata["channel_id"] == "channel456"
    
    @pytest.mark.asyncio
    async def test_manual_parse_compliance_check_command(self, handler):
        """Test manual parsing of check_compliance command."""
        interaction_data = {
            "data": {
                "name": "check_compliance",
                "options": [
                    {
                        "name": "content",
                        "value": "This is test content to check"
                    }
                ]
            },
            "user": {
                "id": "987654321",
                "username": "testuser"
            },
            "guild": {"id": "guild123"},
            "channel": {"id": "channel456"}
        }
        
        bot_command = await handler._manual_parse_discord_command(interaction_data)
        
        assert bot_command is not None
        assert bot_command.command_type == CommandType.CHECK_COMPLIANCE
        assert bot_command.platform == "discord"
        assert bot_command.user_id == "987654321"
        assert bot_command.parameters["content"] == "This is test content to check"
        assert bot_command.metadata["original_command"] == "check_compliance"
    
    @pytest.mark.asyncio
    async def test_manual_parse_followers_command(self, handler):
        """Test manual parsing of analyze_followers command."""
        interaction_data = {
            "data": {
                "name": "analyze_followers",
                "options": []
            },
            "user": {
                "id": "987654321",
                "username": "testuser"
            },
            "guild": {"id": "guild123"},
            "channel": {"id": "channel456"}
        }
        
        bot_command = await handler._manual_parse_discord_command(interaction_data)
        
        assert bot_command is not None
        assert bot_command.command_type == CommandType.ANALYZE_FOLLOWERS
        assert bot_command.platform == "discord"
        assert bot_command.user_id == "987654321"
        assert bot_command.parameters == {}
        assert bot_command.metadata["original_command"] == "analyze_followers"
    
    @pytest.mark.asyncio
    async def test_manual_parse_invalid_command(self, handler):
        """Test manual parsing with invalid command."""
        interaction_data = {
            "data": {
                "name": "unknown_command",
                "options": []
            },
            "user": {
                "id": "987654321",
                "username": "testuser"
            }
        }
        
        bot_command = await handler._manual_parse_discord_command(interaction_data)
        assert bot_command is None
    
    def test_determine_delivery_method(self, handler, sample_bot_response):
        """Test delivery method determination."""
        # Successful analysis should use embed
        delivery_method = handler._determine_delivery_method(sample_bot_response)
        assert delivery_method == DeliveryMethod.EMBED
        
        # Error response should use reply
        error_response = BotResponse.error_response("Test error")
        delivery_method = handler._determine_delivery_method(error_response)
        assert delivery_method == DeliveryMethod.REPLY
    
    @pytest.mark.asyncio
    async def test_format_response_analysis_result(self, handler, sample_bot_response):
        """Test formatting of analysis result response."""
        formatted_response = await handler.format_response(sample_bot_response)
        
        assert isinstance(formatted_response, FormattedResponse)
        assert formatted_response.platform == "discord"
        assert formatted_response.delivery_method == DeliveryMethod.EMBED
        assert "discord_embed" in formatted_response.formatting_applied
        assert "ephemeral" in formatted_response.formatting_applied
        
        # Check that response data has embeds
        assert "embeds" in formatted_response.response_data
        assert "flags" in formatted_response.response_data
        assert formatted_response.response_data["flags"] == 64  # EPHEMERAL
    
    def test_format_analysis_embed(self, handler, sample_bot_response):
        """Test formatting of analysis result as Discord embed."""
        response_data = {}
        handler._format_analysis_embed(response_data, sample_bot_response)
        
        assert "embeds" in response_data
        embed = response_data["embeds"][0]
        
        assert "Account Safety Analysis" in embed["title"]
        assert "testuser" in embed["description"]
        assert embed["color"] == 0xff8800  # Orange for medium risk
        
        # Check fields
        field_names = [field["name"] for field in embed["fields"]]
        assert "🎯 Risk Level" in field_names
        assert "📊 Risk Score" in field_names
        assert "🕒 Analyzed" in field_names
        assert "💡 Recommendations" in field_names
        assert "⚠️ Threats Detected" in field_names
    
    def test_format_compliance_embed(self, handler):
        """Test formatting of compliance check result as Discord embed."""
        compliance_response = BotResponse.success_response(
            data={
                "is_compliant": False,
                "compliance_score": 75,
                "violations": [
                    {"severity": "medium", "description": "Potential spam content"},
                    {"severity": "low", "description": "Minor formatting issue"}
                ],
                "remediation_suggestions": [
                    "Remove promotional language",
                    "Improve content structure"
                ]
            },
            response_type=ResponseType.COMPLIANCE_CHECK
        )
        
        response_data = {}
        handler._format_compliance_embed(response_data, compliance_response)
        
        assert "embeds" in response_data
        embed = response_data["embeds"][0]
        
        assert "Content Compliance Check" in embed["title"]
        assert "Issues Found" in embed["title"]
        assert embed["color"] == 0xff8800  # Orange for issues found
        
        # Check for violations field
        violation_field = next(
            (field for field in embed["fields"] if "Violations Found" in field["name"]), 
            None
        )
        assert violation_field is not None
        assert "🟠" in violation_field["value"]  # Medium severity emoji
        assert "🟡" in violation_field["value"]  # Low severity emoji
    
    def test_format_follower_embed(self, handler):
        """Test formatting of follower analysis result as Discord embed."""
        follower_response = BotResponse.success_response(
            data={
                "verified_followers_count": 150,
                "total_followers": 5000,
                "high_value_followers": 25,
                "follower_categories": {
                    "influencers": 10,
                    "businesses": 8,
                    "media": 5,
                    "verified": 2
                },
                "networking_opportunities": [
                    "Connect with tech industry leaders",
                    "Engage with verified journalists"
                ]
            },
            response_type=ResponseType.FOLLOWER_ANALYSIS
        )
        
        response_data = {}
        handler._format_follower_embed(response_data, follower_response)
        
        assert "embeds" in response_data
        embed = response_data["embeds"][0]
        
        assert "Verified Followers Analysis" in embed["title"]
        assert embed["color"] == 0x0099ff  # Blue
        
        # Check for key fields
        field_names = [field["name"] for field in embed["fields"]]
        assert "✅ Verified Followers" in field_names
        assert "📊 Verification Rate" in field_names
        assert "⭐ High-Value Followers" in field_names
        assert "📈 Follower Breakdown" in field_names
        assert "🤝 Networking Opportunities" in field_names
    
    @pytest.mark.asyncio
    async def test_format_response_error(self, handler):
        """Test formatting of error response."""
        error_response = BotResponse.error_response(
            "Analysis failed due to network timeout",
            ResponseType.ERROR
        )
        
        formatted_response = await handler.format_response(error_response)
        
        assert isinstance(formatted_response, FormattedResponse)
        assert formatted_response.platform == "discord"
        assert formatted_response.delivery_method == DeliveryMethod.REPLY
        assert "flags" in formatted_response.response_data
        assert formatted_response.response_data["flags"] == 64  # EPHEMERAL
    
    @pytest.mark.asyncio
    async def test_handle_webhook_ping(self, handler):
        """Test handling of Discord ping interaction."""
        ping_payload = {"type": 1}  # PING
        
        response = await handler.handle_webhook(ping_payload)
        
        assert response == {"type": 1}  # PONG
    
    @pytest.mark.asyncio
    async def test_handle_webhook_unknown_type(self, handler):
        """Test handling of unknown interaction type."""
        unknown_payload = {"type": 99}  # Unknown type
        
        response = await handler.handle_webhook(unknown_payload)
        
        assert response["type"] == 4  # CHANNEL_MESSAGE_WITH_SOURCE
        assert "Unsupported interaction type" in response["data"]["content"]
        assert response["data"]["flags"] == 64  # EPHEMERAL
    
    @pytest.mark.asyncio
    async def test_handle_help_command(self, handler):
        """Test handling of help command."""
        help_interaction = {
            "type": 2,
            "data": {"name": "help"},
            "user": {"id": "123", "username": "testuser"}
        }
        
        response = await handler._handle_help_command(help_interaction)
        
        assert response["type"] == 4  # CHANNEL_MESSAGE_WITH_SOURCE
        assert "embeds" in response["data"]
        
        embed = response["data"]["embeds"][0]
        assert "LinkShield Social Protection Bot" in embed["title"]
        assert "analyze_account" in embed["fields"][0]["value"]
        assert "check_compliance" in embed["fields"][0]["value"]
        assert "analyze_followers" in embed["fields"][0]["value"]
    
    @pytest.mark.asyncio
    async def test_send_response_initial(self, handler):
        """Test sending initial response."""
        formatted_response = FormattedResponse(
            platform="discord",
            response_data={"content": "Test response", "flags": 64},
            delivery_method=DeliveryMethod.REPLY
        )
        
        context = {"interaction_token": "test_token", "is_initial_response": True}
        
        # Initial responses are handled by returning from webhook handler
        result = await handler.send_response(formatted_response, context)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_response_no_token(self, handler):
        """Test sending response without interaction token."""
        formatted_response = FormattedResponse(
            platform="discord",
            response_data={"content": "Test response"},
            delivery_method=DeliveryMethod.REPLY
        )
        
        context = {}  # No interaction token
        
        result = await handler.send_response(formatted_response, context)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_apply_discord_formatting(self, handler, sample_bot_response):
        """Test applying Discord-specific formatting."""
        formatted_response = FormattedResponse(
            platform="discord",
            response_data={"text": "Original text"},
            delivery_method=DeliveryMethod.EMBED
        )
        
        await handler._apply_discord_formatting(formatted_response, sample_bot_response)
        
        # Should have embeds instead of text
        assert "embeds" in formatted_response.response_data
        assert "text" not in formatted_response.response_data
        assert formatted_response.response_data["flags"] == 64  # EPHEMERAL
        assert "discord_embed" in formatted_response.formatting_applied
        assert "ephemeral" in formatted_response.formatting_applied
    
    @pytest.mark.asyncio
    async def test_message_component_reanalyze(self, handler):
        """Test handling of reanalyze button component."""
        component_interaction = {
            "type": 3,  # MESSAGE_COMPONENT
            "data": {
                "custom_id": "reanalyze_account:testuser"
            },
            "user": {
                "id": "987654321",
                "username": "testuser"
            }
        }
        
        response = await handler._handle_message_component(component_interaction)
        
        assert response["type"] == 4  # CHANNEL_MESSAGE_WITH_SOURCE
        assert "Re-analyzing account @testuser" in response["data"]["content"]
        assert response["data"]["flags"] == 64  # EPHEMERAL
    
    @pytest.mark.asyncio
    async def test_message_component_unknown(self, handler):
        """Test handling of unknown message component."""
        component_interaction = {
            "type": 3,  # MESSAGE_COMPONENT
            "data": {
                "custom_id": "unknown_action:data"
            },
            "user": {
                "id": "987654321",
                "username": "testuser"
            }
        }
        
        response = await handler._handle_message_component(component_interaction)
        
        assert response["type"] == 4  # CHANNEL_MESSAGE_WITH_SOURCE
        assert "Unknown button interaction" in response["data"]["content"]
        assert response["data"]["flags"] == 64  # EPHEMERAL
    
    @pytest.mark.asyncio
    async def test_shutdown(self, handler):
        """Test handler shutdown."""
        # Mock HTTP session
        handler.http_session = AsyncMock()
        handler.is_initialized = True
        handler.application_id = "test_app_id"
        
        await handler.shutdown()
        
        handler.http_session.close.assert_called_once()
        assert not handler.is_initialized
        assert handler.application_id is None


class TestDiscordBotHandlerIntegration:
    """Integration tests for Discord bot handler with mocked external dependencies."""
    
    @pytest.fixture
    def handler_with_session(self):
        """Create handler with mocked HTTP session."""
        with patch('src.bots.handlers.discord_bot_handler.settings') as mock_settings:
            mock_settings.DISCORD_BOT_TOKEN = "test_token"
            handler = DiscordBotHandler()
            handler.http_session = AsyncMock()
            handler.is_initialized = True
            handler.application_id = "test_app_id"
            return handler
    
    @pytest.mark.asyncio
    async def test_edit_interaction_response_success(self, handler_with_session):
        """Test successful interaction response editing."""
        handler_with_session.http_session.patch.return_value.__aenter__.return_value.status = 200
        
        response_data = {"content": "Updated response"}
        result = await handler_with_session._edit_interaction_response("test_token", response_data)
        
        assert result is True
        handler_with_session.http_session.patch.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_edit_interaction_response_failure(self, handler_with_session):
        """Test failed interaction response editing."""
        mock_response = AsyncMock()
        mock_response.status = 400
        mock_response.text.return_value = "Bad Request"
        handler_with_session.http_session.patch.return_value.__aenter__.return_value = mock_response
        
        response_data = {"content": "Updated response"}
        result = await handler_with_session._edit_interaction_response("test_token", response_data)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_get_application_id_cached(self, handler_with_session):
        """Test getting cached application ID."""
        handler_with_session.application_id = "cached_id"
        
        app_id = await handler_with_session._get_application_id()
        
        assert app_id == "cached_id"
        # Should not make HTTP request when cached
        handler_with_session.http_session.get.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_get_application_id_from_api(self, handler_with_session):
        """Test getting application ID from API."""
        handler_with_session.application_id = None
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {"id": "api_app_id"}
        handler_with_session.http_session.get.return_value.__aenter__.return_value = mock_response
        
        app_id = await handler_with_session._get_application_id()
        
        assert app_id == "api_app_id"
        assert handler_with_session.application_id == "api_app_id"
        handler_with_session.http_session.get.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])