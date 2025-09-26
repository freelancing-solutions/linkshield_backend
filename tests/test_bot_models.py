"""
Unit tests for bot command and response data models.

Tests validation, serialization, and functionality of standardized bot models
for social media platform integration.
"""

import pytest
from datetime import datetime, timedelta
from typing import Dict, Any

# Import directly from models to avoid gateway import issues
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from bots.models import (
    BotCommand,
    BotResponse,
    PlatformCommand,
    FormattedResponse,
    CommandRegistry,
    CommandType,
    ResponseType,
    DeliveryMethod,
    create_account_analysis_command,
    create_compliance_check_command,
    create_follower_analysis_command,
    parse_platform_command,
    format_response_for_platform
)
from models.social_protection import PlatformType


class TestBotCommand:
    """Test cases for BotCommand dataclass."""
    
    def test_bot_command_creation(self):
        """Test basic BotCommand creation."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=PlatformType.TWITTER,
            user_id="12345",
            parameters={"account_identifier": "testuser"},
            metadata={"original_message": "test"}
        )
        
        assert command.command_type == CommandType.ANALYZE_ACCOUNT
        assert command.platform == PlatformType.TWITTER
        assert command.user_id == "12345"
        assert command.parameters["account_identifier"] == "testuser"
        assert command.metadata["original_message"] == "test"
        assert isinstance(command.timestamp, datetime)
    
    def test_bot_command_validation(self):
        """Test BotCommand validation."""
        # Test invalid command type
        with pytest.raises(ValueError, match="Invalid command_type"):
            BotCommand(
                command_type="invalid",
                platform=PlatformType.TWITTER,
                user_id="12345"
            )
        
        # Test invalid platform
        with pytest.raises(ValueError, match="Invalid platform"):
            BotCommand(
                command_type=CommandType.ANALYZE_ACCOUNT,
                platform="invalid",
                user_id="12345"
            )
        
        # Test missing user_id
        with pytest.raises(ValueError, match="user_id is required"):
            BotCommand(
                command_type=CommandType.ANALYZE_ACCOUNT,
                platform=PlatformType.TWITTER,
                user_id=""
            )
    
    def test_bot_command_parameter_access(self):
        """Test parameter and metadata access methods."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=PlatformType.TWITTER,
            user_id="12345",
            parameters={"account_identifier": "testuser"},
            metadata={"source": "mention"}
        )
        
        assert command.get_parameter("account_identifier") == "testuser"
        assert command.get_parameter("nonexistent", "default") == "default"
        assert command.get_metadata("source") == "mention"
        assert command.get_metadata("nonexistent", "default") == "default"
    
    def test_bot_command_serialization(self):
        """Test BotCommand to_dict and from_dict methods."""
        original_command = BotCommand(
            command_type=CommandType.CHECK_COMPLIANCE,
            platform=PlatformType.TELEGRAM,
            user_id="67890",
            parameters={"content": "test content"},
            metadata={"chat_id": "123"}
        )
        
        # Test to_dict
        command_dict = original_command.to_dict()
        assert command_dict["command_type"] == "check_compliance"
        assert command_dict["platform"] == "telegram"
        assert command_dict["user_id"] == "67890"
        assert command_dict["parameters"]["content"] == "test content"
        assert command_dict["metadata"]["chat_id"] == "123"
        assert "timestamp" in command_dict
        
        # Test from_dict
        restored_command = BotCommand.from_dict(command_dict)
        assert restored_command.command_type == original_command.command_type
        assert restored_command.platform == original_command.platform
        assert restored_command.user_id == original_command.user_id
        assert restored_command.parameters == original_command.parameters
        assert restored_command.metadata == original_command.metadata


class TestBotResponse:
    """Test cases for BotResponse dataclass."""
    
    def test_bot_response_creation(self):
        """Test basic BotResponse creation."""
        response = BotResponse(
            success=True,
            data={"risk_level": "safe", "score": 95},
            response_type=ResponseType.ANALYSIS_RESULT,
            formatting_hints={"use_emoji": True}
        )
        
        assert response.success is True
        assert response.data["risk_level"] == "safe"
        assert response.response_type == ResponseType.ANALYSIS_RESULT
        assert response.formatting_hints["use_emoji"] is True
        assert response.error_message is None
        assert isinstance(response.timestamp, datetime)
    
    def test_bot_response_validation(self):
        """Test BotResponse validation."""
        # Test invalid response type
        with pytest.raises(ValueError, match="Invalid response_type"):
            BotResponse(
                success=True,
                response_type="invalid"
            )
        
        # Test missing error message for failed response
        with pytest.raises(ValueError, match="error_message is required"):
            BotResponse(
                success=False,
                response_type=ResponseType.ERROR
            )


class TestCommandRegistry:
    """Test cases for CommandRegistry class."""
    
    def test_get_commands_for_platform(self):
        """Test getting commands for specific platforms."""
        twitter_commands = CommandRegistry.get_commands_for_platform(PlatformType.TWITTER)
        assert CommandType.ANALYZE_ACCOUNT in twitter_commands
        assert CommandType.CHECK_COMPLIANCE in twitter_commands
        assert CommandType.ANALYZE_FOLLOWERS in twitter_commands
        
        telegram_commands = CommandRegistry.get_commands_for_platform("telegram")
        assert CommandType.ANALYZE_ACCOUNT in telegram_commands
        
    def test_validate_command_syntax(self):
        """Test command syntax validation."""
        # Twitter commands
        twitter_command = CommandRegistry.validate_command_syntax(
            "@bot analyze @testuser", 
            PlatformType.TWITTER
        )
        assert twitter_command == CommandType.ANALYZE_ACCOUNT
        
        # Invalid command
        invalid_command = CommandRegistry.validate_command_syntax(
            "invalid command", 
            PlatformType.TWITTER
        )
        assert invalid_command is None


class TestUtilityFunctions:
    """Test cases for utility functions."""
    
    def test_create_account_analysis_command(self):
        """Test account analysis command creation utility."""
        command = create_account_analysis_command(
            platform=PlatformType.TWITTER,
            user_id="12345",
            account_identifier="testuser",
            metadata={"source": "mention"}
        )
        
        assert command.command_type == CommandType.ANALYZE_ACCOUNT
        assert command.platform == PlatformType.TWITTER
        assert command.user_id == "12345"
        assert command.parameters["account_identifier"] == "testuser"
        assert command.metadata["source"] == "mention"


if __name__ == "__main__":
    pytest.main([__file__])