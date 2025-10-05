"""
Integration tests for bot command registration and webhook setup.

Tests the complete bot registration workflow, webhook verification,
and platform-specific command registration functionality.
"""

import pytest
import asyncio
import json
import hmac
import hashlib
import base64
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
from typing import Dict, Any

from linkshield.bots.registration import BotRegistrationManager, BotConfigurationManager
from linkshield.bots.lifecycle import BotLifecycleManager, BotStatus
from linkshield.routes.bot_webhooks import router
from linkshield.config.settings import settings
from fastapi.testclient import TestClient
from fastapi import FastAPI


class TestBotRegistrationIntegration:
    """Integration tests for bot registration system."""
    
    @pytest.fixture
    def registration_manager(self):
        """Create a bot registration manager for testing."""
        return BotRegistrationManager()
    
    @pytest.fixture
    def config_manager(self):
        """Create a bot configuration manager for testing."""
        return BotConfigurationManager()
    
    @pytest.fixture
    def lifecycle_manager(self):
        """Create a bot lifecycle manager for testing."""
        return BotLifecycleManager()
    
    @pytest.fixture
    def mock_http_session(self):
        """Create a mock HTTP session."""
        session = AsyncMock()
        session.post = AsyncMock()
        session.get = AsyncMock()
        session.delete = AsyncMock()
        return session
    
    @pytest.fixture
    def app(self):
        """Create FastAPI app with bot webhook routes."""
        app = FastAPI()
        app.include_router(router)
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(create_app())
    
    @pytest.mark.asyncio
    async def test_registration_manager_initialization(self, registration_manager):
        """Test registration manager initialization."""
        # Test initialization
        await registration_manager.initialize()
        
        assert registration_manager.is_initialized
        assert registration_manager.http_session is not None
        assert "discord" in registration_manager.api_endpoints
        assert "telegram" in registration_manager.api_endpoints
        assert "twitter" in registration_manager.api_endpoints
        
        # Cleanup
        await registration_manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_discord_command_registration(self, registration_manager, mock_http_session):
        """Test Discord slash command registration."""
        registration_manager.http_session = mock_http_session
        registration_manager.is_initialized = True
        
        # Mock Discord API responses
        # Application ID response
        app_id_response = Mock()
        app_id_response.status = 200
        app_id_response.json = AsyncMock(return_value={"id": "test_app_id"})
        mock_http_session.get.return_value.__aenter__.return_value = app_id_response
        
        # Existing commands response (empty)
        existing_commands_response = Mock()
        existing_commands_response.status = 200
        existing_commands_response.json = AsyncMock(return_value=[])
        
        # Command registration responses
        command_response = Mock()
        command_response.status = 201
        command_response.json = AsyncMock(return_value={"id": "command_id", "name": "test_command"})
        
        # Set up mock responses
        mock_http_session.get.return_value.__aenter__.return_value = existing_commands_response
        mock_http_session.post.return_value.__aenter__.return_value = command_response
        
        with patch.object(settings, 'DISCORD_BOT_TOKEN', 'test_token'):
            result = await registration_manager.register_discord_commands()
        
        assert result is True
        assert mock_http_session.post.call_count >= 4  # At least 4 commands registered
        assert "discord" in registration_manager.registered_commands
    
    @pytest.mark.asyncio
    async def test_telegram_webhook_setup(self, registration_manager, mock_http_session):
        """Test Telegram webhook setup."""
        registration_manager.http_session = mock_http_session
        registration_manager.is_initialized = True
        registration_manager.webhook_endpoints["telegram"] = "https://example.com/webhook"
        
        # Mock Telegram API response
        webhook_response = Mock()
        webhook_response.status = 200
        webhook_response.json = AsyncMock(return_value={"ok": True, "result": True})
        mock_http_session.post.return_value.__aenter__.return_value = webhook_response
        
        with patch.object(settings, 'TELEGRAM_BOT_TOKEN', 'test_token'):
            result = await registration_manager.setup_telegram_webhook()
        
        assert result is True
        mock_http_session.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_webhook_signature_verification(self, registration_manager):
        """Test webhook signature verification for all platforms."""
        await registration_manager.initialize()
        
        # Test Discord signature verification
        payload = b'{"test": "data"}'
        signature = "test_signature"
        timestamp = "1234567890"
        
        with patch.object(registration_manager, '_verify_discord_signature', return_value=True):
            result = await registration_manager.verify_webhook_signature(
                "discord", payload, signature, timestamp
            )
            assert result is True
        
        # Test Telegram signature verification
        secret = "test_secret"
        registration_manager.webhook_secrets["telegram"] = secret
        
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        result = await registration_manager.verify_webhook_signature(
            "telegram", payload, expected_signature
        )
        assert result is True
        
        # Test invalid signature
        result = await registration_manager.verify_webhook_signature(
            "telegram", payload, "invalid_signature"
        )
        assert result is False
        
        await registration_manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_bot_info_retrieval(self, registration_manager, mock_http_session):
        """Test bot information retrieval for all platforms."""
        registration_manager.http_session = mock_http_session
        registration_manager.is_initialized = True
        
        # Mock Discord bot info
        discord_response = Mock()
        discord_response.status = 200
        discord_response.json = AsyncMock(return_value={"id": "bot_id", "username": "test_bot"})
        
        # Mock Telegram bot info
        telegram_response = Mock()
        telegram_response.status = 200
        telegram_response.json = AsyncMock(return_value={
            "ok": True,
            "result": {"id": 123456, "username": "test_bot"}
        })
        
        # Mock Twitter bot info
        twitter_response = Mock()
        twitter_response.status = 200
        twitter_response.json = AsyncMock(return_value={
            "data": {"id": "twitter_id", "username": "test_bot"}
        })
        
        mock_http_session.get.return_value.__aenter__.return_value = discord_response
        
        with patch.object(settings, 'DISCORD_BOT_TOKEN', 'test_token'):
            discord_info = await registration_manager.get_bot_info("discord")
            assert discord_info is not None
            assert discord_info["username"] == "test_bot"
        
        mock_http_session.get.return_value.__aenter__.return_value = telegram_response
        
        with patch.object(settings, 'TELEGRAM_BOT_TOKEN', 'test_token'):
            telegram_info = await registration_manager.get_bot_info("telegram")
            assert telegram_info is not None
            assert telegram_info["username"] == "test_bot"
        
        mock_http_session.get.return_value.__aenter__.return_value = twitter_response
        
        with patch.object(settings, 'TWITTER_BOT_BEARER_TOKEN', 'test_token'):
            twitter_info = await registration_manager.get_bot_info("twitter")
            assert twitter_info is not None
            assert twitter_info["username"] == "test_bot"
    
    @pytest.mark.asyncio
    async def test_configuration_manager_initialization(self, config_manager):
        """Test configuration manager initialization."""
        await config_manager.initialize()
        
        assert config_manager.is_initialized
        assert "discord" in config_manager.platform_configs
        assert "telegram" in config_manager.platform_configs
        assert "twitter" in config_manager.platform_configs
    
    @pytest.mark.asyncio
    async def test_platform_credential_validation(self, config_manager):
        """Test platform credential validation."""
        await config_manager.initialize()
        
        # Test with valid credentials
        with patch.object(settings, 'DISCORD_BOT_TOKEN', 'valid_token'), \
             patch.object(settings, 'BOT_ENABLE_DISCORD', True):
            
            await config_manager._load_platform_configurations()
            result = await config_manager.validate_platform_credentials("discord")
            assert result is True
        
        # Test with missing credentials
        with patch.object(settings, 'DISCORD_BOT_TOKEN', None), \
             patch.object(settings, 'BOT_ENABLE_DISCORD', True):
            
            await config_manager._load_platform_configurations()
            result = await config_manager.validate_platform_credentials("discord")
            assert result is False
    
    @pytest.mark.asyncio
    async def test_enabled_platforms_detection(self, config_manager):
        """Test enabled platforms detection."""
        await config_manager.initialize()
        
        with patch.object(settings, 'BOT_ENABLE_DISCORD', True), \
             patch.object(settings, 'DISCORD_BOT_TOKEN', 'token'), \
             patch.object(settings, 'BOT_ENABLE_TELEGRAM', False), \
             patch.object(settings, 'BOT_ENABLE_TWITTER', True), \
             patch.object(settings, 'TWITTER_BOT_BEARER_TOKEN', 'token'):
            
            await config_manager._load_platform_configurations()
            enabled_platforms = await config_manager.get_enabled_platforms()
            
            assert "discord" in enabled_platforms
            assert "telegram" not in enabled_platforms
            assert "twitter" in enabled_platforms
    
    @pytest.mark.asyncio
    async def test_lifecycle_manager_initialization(self, lifecycle_manager):
        """Test lifecycle manager initialization."""
        with patch('src.bots.lifecycle.bot_configuration_manager') as mock_config, \
             patch('src.bots.lifecycle.bot_registration_manager') as mock_registration, \
             patch('src.bots.lifecycle.bot_gateway') as mock_gateway, \
             patch('src.bots.lifecycle.bot_error_handler') as mock_error_handler:
            
            mock_config.initialize = AsyncMock()
            mock_registration.initialize = AsyncMock()
            mock_gateway.initialize = AsyncMock()
            mock_error_handler.initialize = AsyncMock()
            mock_config.get_enabled_platforms = AsyncMock(return_value=["discord", "telegram"])
            
            await lifecycle_manager.initialize()
            
            assert lifecycle_manager.status == BotStatus.RUNNING
            assert lifecycle_manager.startup_time is not None
            assert "discord" in lifecycle_manager.platform_statuses
            assert "telegram" in lifecycle_manager.platform_statuses
    
    @pytest.mark.asyncio
    async def test_complete_bot_startup_workflow(self, lifecycle_manager):
        """Test complete bot startup workflow."""
        with patch('src.bots.lifecycle.bot_configuration_manager') as mock_config, \
             patch('src.bots.lifecycle.bot_registration_manager') as mock_registration, \
             patch('src.bots.lifecycle.bot_gateway') as mock_gateway, \
             patch('src.bots.lifecycle.bot_error_handler') as mock_error_handler:
            
            # Mock all dependencies
            mock_config.initialize = AsyncMock()
            mock_registration.initialize = AsyncMock()
            mock_gateway.initialize = AsyncMock()
            mock_error_handler.initialize = AsyncMock()
            mock_config.get_enabled_platforms = AsyncMock(return_value=["discord"])
            mock_registration.register_all_commands = AsyncMock(return_value={"discord": True})
            
            # Mock signal setup
            with patch('src.bots.lifecycle.signal'):
                await lifecycle_manager.start_all_bots()
            
            assert lifecycle_manager.status == BotStatus.RUNNING
            assert lifecycle_manager.platform_statuses["discord"] == BotStatus.RUNNING
            
            # Test shutdown
            await lifecycle_manager.shutdown()
            assert lifecycle_manager.status == BotStatus.STOPPED


class TestWebhookIntegration:
    """Integration tests for webhook handling."""
    
    @pytest.fixture
    def app(self):
        """Create FastAPI app with bot webhook routes."""
        app = FastAPI()
        app.include_router(router)
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(create_app())
    
    def test_discord_webhook_ping(self, client):
        """Test Discord webhook PING interaction."""
        payload = {"type": 1}  # PING
        
        response = client.post("/api/v1/bots/discord/webhook", json=payload)
        
        assert response.status_code == 200
        assert response.json() == {"type": 1}  # PONG
    
    def test_discord_webhook_with_signature_verification(self, client):
        """Test Discord webhook with signature verification."""
        payload = {"type": 1}
        
        with patch.object(settings, 'DISCORD_WEBHOOK_SECRET', 'test_secret'), \
             patch('src.routes.bot_webhooks.bot_registration_manager') as mock_manager:
            
            mock_manager.verify_webhook_signature = AsyncMock(return_value=True)
            
            response = client.post(
                "/api/v1/bots/discord/webhook",
                json=payload,
                headers={
                    "X-Signature-Ed25519": "valid_signature",
                    "X-Signature-Timestamp": "1234567890"
                }
            )
            
            assert response.status_code == 200
    
    def test_discord_webhook_invalid_signature(self, client):
        """Test Discord webhook with invalid signature."""
        payload = {"type": 1}
        
        with patch.object(settings, 'DISCORD_WEBHOOK_SECRET', 'test_secret'), \
             patch('src.routes.bot_webhooks.bot_registration_manager') as mock_manager:
            
            mock_manager.verify_webhook_signature = AsyncMock(return_value=False)
            
            response = client.post(
                "/api/v1/bots/discord/webhook",
                json=payload,
                headers={
                    "X-Signature-Ed25519": "invalid_signature",
                    "X-Signature-Timestamp": "1234567890"
                }
            )
            
            assert response.status_code == 401
    
    def test_telegram_webhook_processing(self, client):
        """Test Telegram webhook processing."""
        payload = {
            "update_id": 123456,
            "message": {
                "message_id": 1,
                "from": {"id": 12345, "username": "testuser"},
                "chat": {"id": 12345, "type": "private"},
                "text": "/help"
            }
        }
        
        with patch('src.routes.bot_webhooks.bot_gateway') as mock_gateway:
            mock_gateway.handle_webhook = AsyncMock(return_value={"processed": True})
            
            response = client.post("/api/v1/bots/telegram/webhook", json=payload)
            
            assert response.status_code == 200
            assert response.json() == {"ok": True}
    
    def test_telegram_webhook_with_secret_token(self, client):
        """Test Telegram webhook with secret token verification."""
        payload = {"update_id": 123456}
        
        with patch.object(settings, 'TELEGRAM_WEBHOOK_SECRET', 'test_secret'):
            response = client.post(
                "/api/v1/bots/telegram/webhook",
                json=payload,
                headers={"X-Telegram-Bot-Api-Secret-Token": "test_secret"}
            )
            
            assert response.status_code == 200
    
    def test_telegram_webhook_invalid_secret_token(self, client):
        """Test Telegram webhook with invalid secret token."""
        payload = {"update_id": 123456}
        
        with patch.object(settings, 'TELEGRAM_WEBHOOK_SECRET', 'test_secret'):
            response = client.post(
                "/api/v1/bots/telegram/webhook",
                json=payload,
                headers={"X-Telegram-Bot-Api-Secret-Token": "wrong_secret"}
            )
            
            assert response.status_code == 401
    
    def test_twitter_webhook_crc_challenge(self, client):
        """Test Twitter webhook CRC challenge response."""
        crc_token = "test_crc_token"
        
        with patch.object(settings, 'TWITTER_WEBHOOK_SECRET', 'test_secret'):
            response = client.get(f"/api/v1/bots/twitter/webhook?crc_token={crc_token}")
            
            assert response.status_code == 200
            response_data = response.json()
            assert "response_token" in response_data
            assert response_data["response_token"].startswith("sha256=")
    
    def test_twitter_webhook_missing_crc_token(self, client):
        """Test Twitter webhook without CRC token."""
        response = client.get("/api/v1/bots/twitter/webhook")
        
        assert response.status_code == 400
        assert "Missing crc_token parameter" in response.json()["detail"]
    
    def test_bot_status_endpoint(self, client):
        """Test bot status endpoint."""
        with patch('src.routes.bot_webhooks.bot_lifecycle_manager') as mock_manager:
            mock_status = {
                "overall_status": "running",
                "platform_statuses": {"discord": "running"},
                "uptime_seconds": 3600
            }
            mock_manager.get_status = AsyncMock(return_value=mock_status)
            
            response = client.get("/api/v1/bots/status")
            
            assert response.status_code == 200
            assert response.json() == mock_status
    
    def test_bot_health_endpoint(self, client):
        """Test bot health endpoint."""
        with patch('src.routes.bot_webhooks.bot_lifecycle_manager') as mock_manager:
            mock_health = {
                "healthy": True,
                "status": "running",
                "platforms": {"discord": {"status": "running", "healthy": True}}
            }
            mock_manager.get_health_status = AsyncMock(return_value=mock_health)
            
            response = client.get("/api/v1/bots/health")
            
            assert response.status_code == 200
            assert response.json() == mock_health
    
    def test_bot_health_endpoint_unhealthy(self, client):
        """Test bot health endpoint when unhealthy."""
        with patch('src.routes.bot_webhooks.bot_lifecycle_manager') as mock_manager:
            mock_health = {
                "healthy": False,
                "status": "error",
                "platforms": {"discord": {"status": "error", "healthy": False}}
            }
            mock_manager.get_health_status = AsyncMock(return_value=mock_health)
            
            response = client.get("/api/v1/bots/health")
            
            assert response.status_code == 503
            assert response.json() == mock_health
    
    def test_command_registration_endpoint(self, client):
        """Test manual command registration endpoint."""
        with patch('src.routes.bot_webhooks.bot_registration_manager') as mock_manager:
            mock_results = {"discord": True, "telegram": True}
            mock_manager.register_all_commands = AsyncMock(return_value=mock_results)
            
            response = client.post("/api/v1/bots/commands/register")
            
            assert response.status_code == 200
            response_data = response.json()
            assert response_data["results"] == mock_results
    
    def test_platform_restart_endpoint(self, client):
        """Test platform restart endpoint."""
        with patch('src.routes.bot_webhooks.bot_lifecycle_manager') as mock_manager:
            mock_manager.restart_platform = AsyncMock()
            
            response = client.post("/api/v1/bots/platforms/discord/restart")
            
            assert response.status_code == 200
            mock_manager.restart_platform.assert_called_once_with("discord")
    
    def test_platform_restart_invalid_platform(self, client):
        """Test platform restart with invalid platform."""
        response = client.post("/api/v1/bots/platforms/invalid/restart")
        
        assert response.status_code == 400
        assert "Invalid platform" in response.json()["detail"]
    
    def test_platform_info_endpoint(self, client):
        """Test platform info endpoint."""
        with patch('src.routes.bot_webhooks.bot_registration_manager') as mock_reg_manager, \
             patch('src.routes.bot_webhooks.bot_lifecycle_manager') as mock_life_manager:
            
            mock_bot_info = {"id": "bot_id", "username": "test_bot"}
            mock_config = {"enabled": True, "features": {}, "limits": {}}
            mock_status = {
                "platform_statuses": {"discord": "running"},
                "platform_health": {"discord": {"status": "healthy"}}
            }
            
            mock_reg_manager.get_bot_info = AsyncMock(return_value=mock_bot_info)
            mock_reg_manager.bot_configuration_manager.get_platform_config = AsyncMock(return_value=mock_config)
            mock_life_manager.get_status = AsyncMock(return_value=mock_status)
            
            response = client.get("/api/v1/bots/platforms/discord/info")
            
            assert response.status_code == 200
            response_data = response.json()
            assert response_data["platform"] == "discord"
            assert response_data["bot_info"] == mock_bot_info
            assert response_data["config"]["enabled"] is True


class TestBotRegistrationErrorHandling:
    """Test error handling in bot registration system."""
    
    @pytest.mark.asyncio
    async def test_registration_manager_network_error(self):
        """Test registration manager handling network errors."""
        manager = BotRegistrationManager()
        
        # Mock network error
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session.get.side_effect = Exception("Network error")
            mock_session_class.return_value = mock_session
            
            await manager.initialize()
            
            with patch.object(settings, 'DISCORD_BOT_TOKEN', 'test_token'):
                result = await manager.register_discord_commands()
                assert result is False
            
            await manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_lifecycle_manager_initialization_failure(self):
        """Test lifecycle manager handling initialization failures."""
        manager = BotLifecycleManager()
        
        with patch('src.bots.lifecycle.bot_configuration_manager') as mock_config:
            mock_config.initialize = AsyncMock(side_effect=Exception("Init error"))
            
            with pytest.raises(Exception):
                await manager.initialize()
            
            assert manager.status == BotStatus.ERROR
    
    @pytest.mark.asyncio
    async def test_webhook_signature_verification_error(self):
        """Test webhook signature verification error handling."""
        manager = BotRegistrationManager()
        await manager.initialize()
        
        # Test with malformed signature
        result = await manager.verify_webhook_signature(
            "discord", b"payload", "malformed_signature", "timestamp"
        )
        assert result is False
        
        # Test with unknown platform
        result = await manager.verify_webhook_signature(
            "unknown_platform", b"payload", "signature"
        )
        assert result is False
        
        await manager.shutdown()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])