"""
Unit tests for QuickAccessBotGateway command routing functionality.

Tests the routing of standardized BotCommand objects to appropriate BotController methods
and proper handling of different command types with error scenarios.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from linkshield.bots.gateway import QuickAccessBotGateway
from linkshield.bots.models import BotCommand, BotResponse, CommandType, Platform
from linkshield.models.user import User


class TestQuickAccessBotGateway:
    """Test suite for QuickAccessBotGateway command routing functionality."""
    
    @pytest.fixture
    async def gateway(self):
        """Create a QuickAccessBotGateway instance for testing."""
        gateway = QuickAccessBotGateway()
        # Mock the initialization to avoid actual service setup
        gateway.is_initialized = True
        gateway.bot_controller = AsyncMock()
        gateway.quick_analysis_service = AsyncMock()
        return gateway
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock User object for testing."""
        user = MagicMock(spec=User)
        user.id = "test_user_123"
        user.email = "test@example.com"
        return user
    
    @pytest.fixture
    def sample_bot_command(self, mock_user):
        """Create a sample BotCommand for testing."""
        return BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=Platform.TWITTER,
            user_id="test_user_123",
            user=mock_user,
            arguments={"account_identifier": "@testuser"},
            raw_message="analyze @testuser",
            timestamp=datetime.utcnow()
        )
    
    @pytest.mark.asyncio
    async def test_route_command_analyze_account_success(self, gateway, sample_bot_command):
        """Test successful account analysis command routing."""
        # Setup mock response from BotController
        expected_result = {
            "account_id": "@testuser",
            "risk_level": "low",
            "safety_score": 85,
            "analysis_details": {"verified": True, "follower_count": 1000}
        }
        gateway.bot_controller.analyze_account_safety.return_value = expected_result
        
        # Execute command routing
        response = await gateway.route_command(sample_bot_command)
        
        # Verify response
        assert response.success is True
        assert response.message == "Account analysis completed"
        assert response.data == expected_result
        assert response.error_code is None
        
        # Verify BotController was called correctly
        gateway.bot_controller.analyze_account_safety.assert_called_once_with(
            user=sample_bot_command.user,
            account_identifier="@testuser",
            platform=Platform.TWITTER
        )
    
    @pytest.mark.asyncio
    async def test_route_command_analyze_account_missing_identifier(self, gateway, mock_user):
        """Test account analysis command with missing account identifier."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=Platform.TWITTER,
            user_id="test_user_123",
            user=mock_user,
            arguments={},  # Missing account_identifier
            raw_message="analyze",
            timestamp=datetime.utcnow()
        )
        
        response = await gateway.route_command(command)
        
        assert response.success is False
        assert response.message == "Account identifier is required for analysis"
        assert response.error_code == "MISSING_ACCOUNT"
        assert response.data == {}
        
        # Verify BotController was not called
        gateway.bot_controller.analyze_account_safety.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_route_command_compliance_check_success(self, gateway, mock_user):
        """Test successful compliance check command routing."""
        command = BotCommand(
            command_type=CommandType.CHECK_COMPLIANCE,
            platform=Platform.TELEGRAM,
            user_id="test_user_123",
            user=mock_user,
            arguments={"content": "This is test content to check"},
            raw_message="check compliance",
            timestamp=datetime.utcnow()
        )
        
        expected_result = {
            "compliance_status": "compliant",
            "violations": [],
            "confidence_score": 95
        }
        gateway.bot_controller.check_content_compliance.return_value = expected_result
        
        response = await gateway.route_command(command)
        
        assert response.success is True
        assert response.message == "Compliance check completed"
        assert response.data == expected_result
        
        gateway.bot_controller.check_content_compliance.assert_called_once_with(
            user=mock_user,
            content="This is test content to check",
            platform=Platform.TELEGRAM
        )
    
    @pytest.mark.asyncio
    async def test_route_command_follower_analysis_success(self, gateway, mock_user):
        """Test successful follower analysis command routing."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_FOLLOWERS,
            platform=Platform.DISCORD,
            user_id="test_user_123",
            user=mock_user,
            arguments={"account_identifier": "@influencer"},
            raw_message="analyze followers @influencer",
            timestamp=datetime.utcnow()
        )
        
        expected_result = {
            "account_id": "@influencer",
            "verified_followers": 150,
            "total_followers": 10000,
            "verification_rate": 1.5,
            "top_verified_followers": ["@verified1", "@verified2"]
        }
        gateway.bot_controller.analyze_verified_followers.return_value = expected_result
        
        response = await gateway.route_command(command)
        
        assert response.success is True
        assert response.message == "Follower analysis completed"
        assert response.data == expected_result
        
        gateway.bot_controller.analyze_verified_followers.assert_called_once_with(
            user=mock_user,
            account_identifier="@influencer",
            platform=Platform.DISCORD
        )
    
    @pytest.mark.asyncio
    async def test_route_command_url_analysis_success(self, gateway, mock_user):
        """Test successful URL analysis command routing."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_URL,
            platform=Platform.TWITTER,
            user_id="test_user_123",
            user=mock_user,
            arguments={"url": "https://example.com/suspicious"},
            raw_message="analyze https://example.com/suspicious",
            timestamp=datetime.utcnow()
        )
        
        expected_result = {
            "url": "https://example.com/suspicious",
            "risk_level": "medium",
            "threats_detected": ["phishing_indicators"],
            "safety_score": 60
        }
        gateway.analyze_url_quick = AsyncMock(return_value=expected_result)
        
        response = await gateway.route_command(command)
        
        assert response.success is True
        assert response.message == "URL analysis completed"
        assert response.data == expected_result
        
        gateway.analyze_url_quick.assert_called_once_with(
            url="https://example.com/suspicious",
            user_id="test_user_123",
            platform="twitter"
        )
    
    @pytest.mark.asyncio
    async def test_route_command_help_request(self, gateway, mock_user):
        """Test help command routing."""
        command = BotCommand(
            command_type=CommandType.GET_HELP,
            platform=Platform.TELEGRAM,
            user_id="test_user_123",
            user=mock_user,
            arguments={},
            raw_message="/help",
            timestamp=datetime.utcnow()
        )
        
        response = await gateway.route_command(command)
        
        assert response.success is True
        assert response.message == "Available commands and help information"
        assert "available_commands" in response.data
        assert "platform" in response.data
        assert response.data["platform"] == "telegram"
        assert len(response.data["available_commands"]) == 5
    
    @pytest.mark.asyncio
    async def test_route_command_unknown_command_type(self, gateway, mock_user):
        """Test routing of unknown command type."""
        # Create command with invalid command type
        command = BotCommand(
            command_type="INVALID_COMMAND",  # Invalid command type
            platform=Platform.TWITTER,
            user_id="test_user_123",
            user=mock_user,
            arguments={},
            raw_message="invalid command",
            timestamp=datetime.utcnow()
        )
        
        response = await gateway.route_command(command)
        
        assert response.success is False
        assert response.message == "Unknown command type"
        assert response.error_code == "UNKNOWN_COMMAND"
        assert response.data == {}
    
    @pytest.mark.asyncio
    async def test_route_command_bot_controller_exception(self, gateway, sample_bot_command):
        """Test handling of BotController exceptions during command routing."""
        # Setup BotController to raise exception
        gateway.bot_controller.analyze_account_safety.side_effect = Exception("Database connection failed")
        
        response = await gateway.route_command(sample_bot_command)
        
        assert response.success is False
        assert response.message == "Failed to analyze account"
        assert response.error_code == "ANALYSIS_ERROR"
        assert response.data == {}
    
    @pytest.mark.asyncio
    async def test_route_command_initialization_on_demand(self):
        """Test that gateway initializes itself when not initialized."""
        gateway = QuickAccessBotGateway()
        gateway.is_initialized = False
        
        # Mock the initialize method
        gateway.initialize = AsyncMock()
        gateway.bot_controller = AsyncMock()
        
        command = BotCommand(
            command_type=CommandType.GET_HELP,
            platform=Platform.TWITTER,
            user_id="test_user_123",
            user=MagicMock(),
            arguments={},
            raw_message="/help",
            timestamp=datetime.utcnow()
        )
        
        await gateway.route_command(command)
        
        # Verify initialization was called
        gateway.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_handle_account_analysis_error_handling(self, gateway, mock_user):
        """Test error handling in account analysis handler."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=Platform.TWITTER,
            user_id="test_user_123",
            user=mock_user,
            arguments={"account_identifier": "@testuser"},
            raw_message="analyze @testuser",
            timestamp=datetime.utcnow()
        )
        
        # Setup BotController to raise exception
        gateway.bot_controller.analyze_account_safety.side_effect = ValueError("Invalid account format")
        
        response = await gateway.handle_account_analysis(command)
        
        assert response.success is False
        assert response.message == "Failed to analyze account"
        assert response.error_code == "ANALYSIS_ERROR"
    
    @pytest.mark.asyncio
    async def test_handle_compliance_check_missing_content(self, gateway, mock_user):
        """Test compliance check with missing content."""
        command = BotCommand(
            command_type=CommandType.CHECK_COMPLIANCE,
            platform=Platform.TELEGRAM,
            user_id="test_user_123",
            user=mock_user,
            arguments={},  # Missing content
            raw_message="check compliance",
            timestamp=datetime.utcnow()
        )
        
        response = await gateway.handle_compliance_check(command)
        
        assert response.success is False
        assert response.message == "Content is required for compliance check"
        assert response.error_code == "MISSING_CONTENT"
        
        gateway.bot_controller.check_content_compliance.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_handle_url_analysis_missing_url(self, gateway, mock_user):
        """Test URL analysis with missing URL."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_URL,
            platform=Platform.DISCORD,
            user_id="test_user_123",
            user=mock_user,
            arguments={},  # Missing URL
            raw_message="analyze url",
            timestamp=datetime.utcnow()
        )
        
        response = await gateway.handle_url_analysis(command)
        
        assert response.success is False
        assert response.message == "URL is required for analysis"
        assert response.error_code == "MISSING_URL"
    
    @pytest.mark.asyncio
    async def test_command_routing_performance(self, gateway, mock_user):
        """Test that command routing completes within performance requirements."""
        command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=Platform.TWITTER,
            user_id="test_user_123",
            user=mock_user,
            arguments={"account_identifier": "@testuser"},
            raw_message="analyze @testuser",
            timestamp=datetime.utcnow()
        )
        
        # Mock quick response from BotController
        gateway.bot_controller.analyze_account_safety.return_value = {"result": "success"}
        
        start_time = datetime.utcnow()
        response = await gateway.route_command(command)
        end_time = datetime.utcnow()
        
        # Verify response time is reasonable (should be very fast with mocks)
        response_time = (end_time - start_time).total_seconds()
        assert response_time < 1.0  # Should complete in under 1 second with mocks
        assert response.success is True
    
    @pytest.mark.asyncio
    async def test_multiple_concurrent_commands(self, gateway, mock_user):
        """Test handling multiple concurrent command requests."""
        # Create multiple commands
        commands = []
        for i in range(5):
            command = BotCommand(
                command_type=CommandType.ANALYZE_ACCOUNT,
                platform=Platform.TWITTER,
                user_id=f"test_user_{i}",
                user=mock_user,
                arguments={"account_identifier": f"@testuser{i}"},
                raw_message=f"analyze @testuser{i}",
                timestamp=datetime.utcnow()
            )
            commands.append(command)
        
        # Mock BotController responses
        gateway.bot_controller.analyze_account_safety.return_value = {"result": "success"}
        
        # Execute commands concurrently
        tasks = [gateway.route_command(cmd) for cmd in commands]
        responses = await asyncio.gather(*tasks)
        
        # Verify all responses are successful
        for response in responses:
            assert response.success is True
            assert response.message == "Account analysis completed"
        
        # Verify BotController was called for each command
        assert gateway.bot_controller.analyze_account_safety.call_count == 5