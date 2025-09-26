"""
Simple tests for bot registration functionality.

Basic tests to verify the bot registration system works correctly.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from src.bots.registration import BotRegistrationManager, BotConfigurationManager
from src.bots.lifecycle import BotLifecycleManager, BotStatus
from src.config.settings import settings


class TestBotRegistrationBasic:
    """Basic tests for bot registration system."""
    
    @pytest.mark.asyncio
    async def test_registration_manager_creation(self):
        """Test that registration manager can be created."""
        manager = BotRegistrationManager()
        assert manager is not None
        assert not manager.is_initialized
        assert manager.registered_commands == {}
        assert manager.webhook_endpoints == {}
    
    @pytest.mark.asyncio
    async def test_configuration_manager_creation(self):
        """Test that configuration manager can be created."""
        manager = BotConfigurationManager()
        assert manager is not None
        assert not manager.is_initialized
        assert manager.platform_configs == {}
    
    @pytest.mark.asyncio
    async def test_lifecycle_manager_creation(self):
        """Test that lifecycle manager can be created."""
        manager = BotLifecycleManager()
        assert manager is not None
        assert manager.status == BotStatus.STOPPED
        assert manager.platform_statuses == {}
        assert manager.startup_time is None
    
    @pytest.mark.asyncio
    async def test_registration_manager_initialization(self):
        """Test registration manager initialization."""
        manager = BotRegistrationManager()
        
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value = mock_session
            
            await manager.initialize()
            
            assert manager.is_initialized
            assert manager.http_session is not None
            assert "discord" in manager.api_endpoints
            assert "telegram" in manager.api_endpoints
            assert "twitter" in manager.api_endpoints
            
            await manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_configuration_manager_initialization(self):
        """Test configuration manager initialization."""
        manager = BotConfigurationManager()
        
        await manager.initialize()
        
        assert manager.is_initialized
        assert "discord" in manager.platform_configs
        assert "telegram" in manager.platform_configs
        assert "twitter" in manager.platform_configs
        
        # Check Discord config structure
        discord_config = manager.platform_configs["discord"]
        assert "enabled" in discord_config
        assert "features" in discord_config
        assert "limits" in discord_config
    
    @pytest.mark.asyncio
    async def test_webhook_endpoints_setup(self):
        """Test webhook endpoints are set up correctly."""
        manager = BotRegistrationManager()
        
        with patch('aiohttp.ClientSession'):
            await manager.initialize()
            
            assert "discord" in manager.webhook_endpoints
            assert "telegram" in manager.webhook_endpoints
            assert "twitter" in manager.webhook_endpoints
            
            # Check endpoint format
            discord_endpoint = manager.webhook_endpoints["discord"]
            assert "/api/v1/bots/discord/webhook" in discord_endpoint
            
            await manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_discord_commands_structure(self):
        """Test Discord command structure is correct."""
        manager = BotRegistrationManager()
        
        commands = manager._build_discord_commands()
        
        assert len(commands) >= 4  # At least 4 commands
        
        # Check command structure
        for command in commands:
            assert "name" in command
            assert "description" in command
            assert "options" in command
        
        # Check specific commands exist
        command_names = [cmd["name"] for cmd in commands]
        assert "analyze_account" in command_names
        assert "check_compliance" in command_names
        assert "analyze_followers" in command_names
        assert "help" in command_names
    
    @pytest.mark.asyncio
    async def test_platform_credential_validation(self):
        """Test platform credential validation."""
        manager = BotConfigurationManager()
        await manager.initialize()
        
        # Test with mock credentials
        with patch.object(settings, 'DISCORD_BOT_TOKEN', 'test_token'), \
             patch.object(settings, 'BOT_ENABLE_DISCORD', True):
            
            await manager._load_platform_configurations()
            result = await manager.validate_platform_credentials("discord")
            assert result is True
        
        # Test without credentials
        with patch.object(settings, 'DISCORD_BOT_TOKEN', None), \
             patch.object(settings, 'BOT_ENABLE_DISCORD', True):
            
            await manager._load_platform_configurations()
            result = await manager.validate_platform_credentials("discord")
            assert result is False
    
    @pytest.mark.asyncio
    async def test_enabled_platforms_detection(self):
        """Test enabled platforms are detected correctly."""
        manager = BotConfigurationManager()
        await manager.initialize()
        
        # Mock settings for testing
        with patch.object(settings, 'BOT_ENABLE_DISCORD', True), \
             patch.object(settings, 'DISCORD_BOT_TOKEN', 'token'), \
             patch.object(settings, 'BOT_ENABLE_TELEGRAM', False), \
             patch.object(settings, 'BOT_ENABLE_TWITTER', True), \
             patch.object(settings, 'TWITTER_BOT_BEARER_TOKEN', 'token'):
            
            await manager._load_platform_configurations()
            enabled_platforms = await manager.get_enabled_platforms()
            
            assert "discord" in enabled_platforms
            assert "telegram" not in enabled_platforms
            assert "twitter" in enabled_platforms
    
    @pytest.mark.asyncio
    async def test_lifecycle_manager_status_tracking(self):
        """Test lifecycle manager tracks status correctly."""
        manager = BotLifecycleManager()
        
        # Initial state
        assert manager.status == BotStatus.STOPPED
        
        # Mock dependencies for initialization
        with patch('src.bots.lifecycle.bot_configuration_manager') as mock_config, \
             patch('src.bots.lifecycle.bot_registration_manager') as mock_registration, \
             patch('src.bots.lifecycle.bot_gateway') as mock_gateway, \
             patch('src.bots.lifecycle.bot_error_handler') as mock_error_handler:
            
            mock_config.initialize = AsyncMock()
            mock_registration.initialize = AsyncMock()
            mock_gateway.initialize = AsyncMock()
            mock_error_handler.initialize = AsyncMock()
            mock_config.get_enabled_platforms = AsyncMock(return_value=["discord"])
            
            await manager.initialize()
            
            assert manager.status == BotStatus.RUNNING
            assert manager.startup_time is not None
            assert "discord" in manager.platform_statuses
    
    @pytest.mark.asyncio
    async def test_metrics_tracking(self):
        """Test metrics are tracked correctly."""
        manager = BotLifecycleManager()
        
        # Initial metrics
        assert manager.metrics["total_commands_processed"] == 0
        assert manager.metrics["successful_commands"] == 0
        assert manager.metrics["failed_commands"] == 0
        
        # Update metrics
        manager.update_metrics(command_success=True, response_time=1.5)
        
        assert manager.metrics["total_commands_processed"] == 1
        assert manager.metrics["successful_commands"] == 1
        assert manager.metrics["failed_commands"] == 0
        assert manager.metrics["average_response_time"] == 1.5
        
        # Update with failure
        manager.update_metrics(command_success=False, response_time=2.0)
        
        assert manager.metrics["total_commands_processed"] == 2
        assert manager.metrics["successful_commands"] == 1
        assert manager.metrics["failed_commands"] == 1
        assert manager.metrics["average_response_time"] == 1.75  # (1.5 + 2.0) / 2
    
    @pytest.mark.asyncio
    async def test_error_tracking(self):
        """Test error tracking functionality."""
        manager = BotLifecycleManager()
        
        # Initialize platform health
        manager.platform_health["discord"] = {
            "status": "healthy",
            "error_count": 0
        }
        
        # Record error
        manager.record_platform_error("discord")
        
        assert manager.error_counts["discord"] == 1
        assert "discord" in manager.last_errors
        assert manager.platform_health["discord"]["error_count"] == 1
        
        # Record another error
        manager.record_platform_error("discord")
        
        assert manager.error_counts["discord"] == 2
        assert manager.platform_health["discord"]["error_count"] == 2


class TestBotRegistrationIntegration:
    """Integration tests for bot registration components."""
    
    @pytest.mark.asyncio
    async def test_full_initialization_workflow(self):
        """Test the complete initialization workflow."""
        from src.bots.startup import initialize_bot_service
        
        # Mock all external dependencies
        with patch('src.bots.startup.bot_configuration_manager') as mock_config, \
             patch('src.bots.startup.bot_registration_manager') as mock_registration, \
             patch('src.bots.startup.bot_lifecycle_manager') as mock_lifecycle:
            
            # Mock successful initialization
            mock_config.initialize = AsyncMock()
            mock_config.get_enabled_platforms = AsyncMock(return_value=["discord"])
            
            mock_registration.initialize = AsyncMock()
            mock_registration.register_all_commands = AsyncMock(return_value={"discord": True})
            
            mock_lifecycle.initialize = AsyncMock()
            mock_lifecycle.start_all_bots = AsyncMock()
            
            # Run initialization
            results = await initialize_bot_service()
            
            # Check results
            assert results["success"] is True
            assert "configuration_manager" in results["initialized_components"]
            assert "registration_manager" in results["initialized_components"]
            assert "lifecycle_manager" in results["initialized_components"]
            assert "discord" in results["registered_platforms"]
            assert len(results["errors"]) == 0
    
    @pytest.mark.asyncio
    async def test_initialization_with_failures(self):
        """Test initialization workflow with component failures."""
        from src.bots.startup import initialize_bot_service
        
        # Mock configuration manager failure
        with patch('src.bots.startup.bot_configuration_manager') as mock_config:
            mock_config.initialize = AsyncMock(side_effect=Exception("Config error"))
            
            results = await initialize_bot_service()
            
            assert results["success"] is False
            assert len(results["errors"]) > 0
            assert "Config error" in str(results["errors"])
    
    @pytest.mark.asyncio
    async def test_health_check_functionality(self):
        """Test health check functionality."""
        from src.bots.startup import check_bot_service_health
        
        # Mock dependencies
        with patch('src.bots.startup.bot_lifecycle_manager') as mock_lifecycle, \
             patch('src.bots.startup.bot_configuration_manager') as mock_config, \
             patch('src.bots.startup.bot_registration_manager') as mock_registration:
            
            mock_lifecycle.get_status = AsyncMock(return_value={
                "overall_status": "running",
                "platform_statuses": {"discord": "running"}
            })
            mock_lifecycle.get_health_status = AsyncMock(return_value={
                "healthy": True,
                "status": "running"
            })
            mock_config.get_enabled_platforms = AsyncMock(return_value=["discord"])
            mock_registration.get_bot_info = AsyncMock(return_value={"username": "test_bot"})
            
            health = await check_bot_service_health()
            
            assert health["healthy"] is True
            assert "discord" in health["enabled_platforms"]
            assert health["platform_info"]["discord"]["bot_info_available"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])