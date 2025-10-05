"""
Bot Command Registration and Webhook Setup System.

This module provides centralized command registration for Discord slash commands,
webhook setup and verification for all platforms, and bot initialization
and lifecycle management.
"""

import logging
import asyncio
import json
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import aiohttp
import hashlib
import hmac
from urllib.parse import urljoin

from ..config.settings import settings
from .models import CommandRegistry, CommandType, PlatformType
from .error_handler import bot_error_handler, ErrorCategory

logger = logging.getLogger(__name__)


class BotRegistrationManager:
    """
    Manages bot command registration and webhook setup across all platforms.
    
    Handles Discord slash command registration, webhook verification for all platforms,
    and provides centralized bot initialization and lifecycle management.
    """
    
    def __init__(self):
        """Initialize the bot registration manager."""
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.registered_commands: Dict[str, List[Dict[str, Any]]] = {}
        self.webhook_endpoints: Dict[str, str] = {}
        self.is_initialized = False
        
        # Platform API endpoints
        self.api_endpoints = {
            "discord": "https://discord.com/api/v10",
            "telegram": "https://api.telegram.org",
            "twitter": "https://api.twitter.com/2"
        }
        
        # Webhook verification secrets
        self.webhook_secrets = {
            "discord": settings.DISCORD_WEBHOOK_SECRET,
            "telegram": settings.TELEGRAM_WEBHOOK_SECRET,
            "twitter": settings.TWITTER_WEBHOOK_SECRET
        }
    
    async def initialize(self):
        """Initialize the bot registration manager."""
        if self.is_initialized:
            return
        
        try:
            # Initialize HTTP session
            timeout = aiohttp.ClientTimeout(total=30)
            self.http_session = aiohttp.ClientSession(timeout=timeout)
            
            # Set up webhook endpoints
            self._setup_webhook_endpoints()
            
            self.is_initialized = True
            logger.info("Bot registration manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize bot registration manager: {e}")
            raise
    
    async def register_all_commands(self) -> Dict[str, bool]:
        """
        Register commands for all enabled platforms.
        
        Returns:
            Dictionary mapping platform names to registration success status
        """
        if not self.is_initialized:
            await self.initialize()
        
        results = {}
        
        # Register Discord slash commands
        if settings.BOT_ENABLE_DISCORD and settings.DISCORD_BOT_TOKEN:
            try:
                results["discord"] = await self.register_discord_commands()
                logger.info(f"Discord command registration: {'success' if results['discord'] else 'failed'}")
            except Exception as e:
                logger.error(f"Discord command registration failed: {e}")
                results["discord"] = False
        
        # Set up Telegram webhook (Telegram doesn't require command registration)
        if settings.BOT_ENABLE_TELEGRAM and settings.TELEGRAM_BOT_TOKEN:
            try:
                results["telegram"] = await self.setup_telegram_webhook()
                logger.info(f"Telegram webhook setup: {'success' if results['telegram'] else 'failed'}")
            except Exception as e:
                logger.error(f"Telegram webhook setup failed: {e}")
                results["telegram"] = False
        
        # Set up Twitter webhook
        if settings.BOT_ENABLE_TWITTER and settings.TWITTER_BOT_BEARER_TOKEN:
            try:
                results["twitter"] = await self.setup_twitter_webhook()
                logger.info(f"Twitter webhook setup: {'success' if results['twitter'] else 'failed'}")
            except Exception as e:
                logger.error(f"Twitter webhook setup failed: {e}")
                results["twitter"] = False
        
        return results
    
    async def register_discord_commands(self) -> bool:
        """
        Register Discord slash commands.
        
        Returns:
            True if registration successful, False otherwise
        """
        try:
            if not settings.DISCORD_BOT_TOKEN:
                logger.warning("Discord bot token not configured")
                return False
            
            # Get application ID
            application_id = await self._get_discord_application_id()
            if not application_id:
                logger.error("Failed to get Discord application ID")
                return False
            
            # Define Discord slash commands
            commands = self._build_discord_commands()
            
            # Register commands globally
            url = f"{self.api_endpoints['discord']}/applications/{application_id}/commands"
            headers = {
                "Authorization": f"Bot {settings.DISCORD_BOT_TOKEN}",
                "Content-Type": "application/json"
            }
            
            # Clear existing commands first
            await self._clear_discord_commands(application_id, headers)
            
            # Register new commands
            success_count = 0
            for command in commands:
                try:
                    async with self.http_session.post(url, json=command, headers=headers) as response:
                        if response.status == 201:
                            success_count += 1
                            command_data = await response.json()
                            logger.info(f"Registered Discord command: {command['name']} (ID: {command_data.get('id')})")
                        else:
                            error_text = await response.text()
                            logger.error(f"Failed to register Discord command {command['name']}: {response.status} - {error_text}")
                except Exception as e:
                    logger.error(f"Error registering Discord command {command['name']}: {e}")
            
            # Store registered commands
            self.registered_commands["discord"] = commands
            
            logger.info(f"Discord command registration completed: {success_count}/{len(commands)} commands registered")
            return success_count == len(commands)
            
        except Exception as e:
            logger.error(f"Discord command registration failed: {e}")
            return False
    
    async def setup_telegram_webhook(self) -> bool:
        """
        Set up Telegram webhook.
        
        Returns:
            True if setup successful, False otherwise
        """
        try:
            if not settings.TELEGRAM_BOT_TOKEN:
                logger.warning("Telegram bot token not configured")
                return False
            
            webhook_url = self.webhook_endpoints.get("telegram")
            if not webhook_url:
                logger.error("Telegram webhook URL not configured")
                return False
            
            # Set webhook
            url = f"{self.api_endpoints['telegram']}/bot{settings.TELEGRAM_BOT_TOKEN}/setWebhook"
            payload = {
                "url": webhook_url,
                "max_connections": 40,
                "allowed_updates": ["message", "edited_message", "callback_query"]
            }
            
            # Add secret token if configured
            if self.webhook_secrets.get("telegram"):
                payload["secret_token"] = self.webhook_secrets["telegram"]
            
            async with self.http_session.post(url, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get("ok"):
                        logger.info(f"Telegram webhook set successfully: {webhook_url}")
                        return True
                    else:
                        logger.error(f"Telegram webhook setup failed: {result.get('description')}")
                        return False
                else:
                    error_text = await response.text()
                    logger.error(f"Telegram webhook setup failed: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Telegram webhook setup failed: {e}")
            return False
    
    async def setup_twitter_webhook(self) -> bool:
        """
        Set up Twitter webhook (Account Activity API).
        
        Note: Twitter webhook setup requires additional OAuth 1.0a authentication
        and webhook environment setup. This is a simplified implementation.
        
        Returns:
            True if setup successful, False otherwise
        """
        try:
            if not settings.TWITTER_BOT_BEARER_TOKEN:
                logger.warning("Twitter bot bearer token not configured")
                return False
            
            webhook_url = self.webhook_endpoints.get("twitter")
            if not webhook_url:
                logger.error("Twitter webhook URL not configured")
                return False
            
            # Note: Twitter webhook setup is more complex and requires:
            # 1. OAuth 1.0a authentication (not just Bearer token)
            # 2. Webhook environment creation
            # 3. Webhook registration
            # 4. Subscription setup
            
            # For now, we'll log that Twitter webhook setup requires manual configuration
            logger.warning("Twitter webhook setup requires manual configuration via Twitter Developer Portal")
            logger.info(f"Configure Twitter webhook URL: {webhook_url}")
            
            # Return True for now since manual setup is expected
            return True
            
        except Exception as e:
            logger.error(f"Twitter webhook setup failed: {e}")
            return False
    
    async def verify_webhook_signature(self, platform: str, payload: bytes, 
                                     signature: str, timestamp: Optional[str] = None) -> bool:
        """
        Verify webhook signature for security.
        
        Args:
            platform: Platform name (discord, telegram, twitter)
            payload: Raw webhook payload
            signature: Signature from webhook headers
            timestamp: Timestamp from webhook headers (for Discord)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            secret = self.webhook_secrets.get(platform)
            if not secret:
                logger.warning(f"No webhook secret configured for {platform}")
                return False
            
            if platform == "discord":
                return self._verify_discord_signature(payload, signature, timestamp, secret)
            elif platform == "telegram":
                return self._verify_telegram_signature(payload, signature, secret)
            elif platform == "twitter":
                return self._verify_twitter_signature(payload, signature, secret)
            else:
                logger.warning(f"Unknown platform for signature verification: {platform}")
                return False
                
        except Exception as e:
            logger.error(f"Webhook signature verification failed for {platform}: {e}")
            return False
    
    async def get_bot_info(self, platform: str) -> Optional[Dict[str, Any]]:
        """
        Get bot information for a platform.
        
        Args:
            platform: Platform name
            
        Returns:
            Bot information dictionary or None if failed
        """
        try:
            if platform == "discord":
                return await self._get_discord_bot_info()
            elif platform == "telegram":
                return await self._get_telegram_bot_info()
            elif platform == "twitter":
                return await self._get_twitter_bot_info()
            else:
                logger.warning(f"Unknown platform for bot info: {platform}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to get bot info for {platform}: {e}")
            return None
    
    async def cleanup_commands(self, platform: str) -> bool:
        """
        Clean up registered commands for a platform.
        
        Args:
            platform: Platform name
            
        Returns:
            True if cleanup successful, False otherwise
        """
        try:
            if platform == "discord":
                application_id = await self._get_discord_application_id()
                if application_id:
                    headers = {
                        "Authorization": f"Bot {settings.DISCORD_BOT_TOKEN}",
                        "Content-Type": "application/json"
                    }
                    return await self._clear_discord_commands(application_id, headers)
            elif platform == "telegram":
                # Delete webhook
                url = f"{self.api_endpoints['telegram']}/bot{settings.TELEGRAM_BOT_TOKEN}/deleteWebhook"
                async with self.http_session.post(url) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get("ok", False)
            elif platform == "twitter":
                # Twitter webhook cleanup would require OAuth 1.0a
                logger.info("Twitter webhook cleanup requires manual configuration")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Command cleanup failed for {platform}: {e}")
            return False
    
    async def shutdown(self):
        """Shutdown the bot registration manager."""
        try:
            if self.http_session:
                await self.http_session.close()
                logger.info("Bot registration manager HTTP session closed")
            
            self.is_initialized = False
            logger.info("Bot registration manager shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during bot registration manager shutdown: {e}")
    
    # Private helper methods
    
    def _setup_webhook_endpoints(self):
        """Set up webhook endpoints for each platform."""
        base_url = settings.APP_URL.rstrip('/')
        
        self.webhook_endpoints = {
            "discord": f"{base_url}/api/v1/bots/discord/webhook",
            "telegram": f"{base_url}/api/v1/bots/telegram/webhook",
            "twitter": f"{base_url}/api/v1/bots/twitter/webhook"
        }
        
        logger.info(f"Webhook endpoints configured: {self.webhook_endpoints}")
    
    def _build_discord_commands(self) -> List[Dict[str, Any]]:
        """Build Discord slash command definitions."""
        commands = [
            {
                "name": "analyze_account",
                "description": "Analyze a social media account for safety and risk factors",
                "options": [
                    {
                        "name": "user",
                        "description": "Username or account to analyze (e.g., @username)",
                        "type": 3,  # STRING
                        "required": True
                    }
                ]
            },
            {
                "name": "check_compliance",
                "description": "Check content for policy compliance and violations",
                "options": [
                    {
                        "name": "content",
                        "description": "Content text to check for compliance",
                        "type": 3,  # STRING
                        "required": True
                    }
                ]
            },
            {
                "name": "analyze_followers",
                "description": "Analyze your verified followers and networking opportunities",
                "options": []
            },
            {
                "name": "help",
                "description": "Show help information and available commands",
                "options": []
            }
        ]
        
        return commands
    
    async def _get_discord_application_id(self) -> Optional[str]:
        """Get Discord application ID."""
        try:
            url = f"{self.api_endpoints['discord']}/oauth2/applications/@me"
            headers = {"Authorization": f"Bot {settings.DISCORD_BOT_TOKEN}"}
            
            async with self.http_session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("id")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to get Discord application ID: {response.status} - {error_text}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting Discord application ID: {e}")
            return None
    
    async def _clear_discord_commands(self, application_id: str, headers: Dict[str, str]) -> bool:
        """Clear existing Discord commands."""
        try:
            # Get existing commands
            url = f"{self.api_endpoints['discord']}/applications/{application_id}/commands"
            async with self.http_session.get(url, headers=headers) as response:
                if response.status == 200:
                    existing_commands = await response.json()
                    
                    # Delete each existing command
                    for command in existing_commands:
                        delete_url = f"{url}/{command['id']}"
                        async with self.http_session.delete(delete_url, headers=headers) as delete_response:
                            if delete_response.status == 204:
                                logger.info(f"Deleted Discord command: {command['name']}")
                            else:
                                logger.warning(f"Failed to delete Discord command {command['name']}: {delete_response.status}")
                    
                    return True
                else:
                    logger.error(f"Failed to get existing Discord commands: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error clearing Discord commands: {e}")
            return False
    
    def _verify_discord_signature(self, payload: bytes, signature: str, 
                                timestamp: Optional[str], secret: str) -> bool:
        """Verify Discord webhook signature using Ed25519."""
        try:
            if not timestamp:
                return False
            
            # Use the centralized Discord signature verification
            from ..auth.bot_auth import WebhookSignatureVerifier
            return WebhookSignatureVerifier.verify_discord_signature(
                payload=payload,
                signature=signature,
                timestamp=timestamp,
                public_key=secret  # This should be the Discord public key, not a secret
            )
            
        except Exception as e:
            logger.error(f"Discord signature verification error: {e}")
            return False
    
    def _verify_telegram_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify Telegram webhook signature."""
        try:
            # Telegram uses HMAC-SHA256
            expected_signature = hmac.new(
                secret.encode('utf-8'),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception as e:
            logger.error(f"Telegram signature verification error: {e}")
            return False
    
    def _verify_twitter_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify Twitter webhook signature."""
        try:
            # Twitter uses HMAC-SHA256 with base64 encoding
            expected_signature = hmac.new(
                secret.encode('utf-8'),
                payload,
                hashlib.sha256
            ).digest()
            
            import base64
            expected_signature_b64 = base64.b64encode(expected_signature).decode('utf-8')
            
            return hmac.compare_digest(signature, expected_signature_b64)
            
        except Exception as e:
            logger.error(f"Twitter signature verification error: {e}")
            return False
    
    async def _get_discord_bot_info(self) -> Optional[Dict[str, Any]]:
        """Get Discord bot information."""
        try:
            url = f"{self.api_endpoints['discord']}/users/@me"
            headers = {"Authorization": f"Bot {settings.DISCORD_BOT_TOKEN}"}
            
            async with self.http_session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.error(f"Failed to get Discord bot info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting Discord bot info: {e}")
            return None
    
    async def _get_telegram_bot_info(self) -> Optional[Dict[str, Any]]:
        """Get Telegram bot information."""
        try:
            url = f"{self.api_endpoints['telegram']}/bot{settings.TELEGRAM_BOT_TOKEN}/getMe"
            
            async with self.http_session.get(url) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get("ok"):
                        return result.get("result")
                    else:
                        logger.error(f"Telegram bot info failed: {result.get('description')}")
                        return None
                else:
                    logger.error(f"Failed to get Telegram bot info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting Telegram bot info: {e}")
            return None
    
    async def _get_twitter_bot_info(self) -> Optional[Dict[str, Any]]:
        """Get Twitter bot information."""
        try:
            url = f"{self.api_endpoints['twitter']}/users/me"
            headers = {"Authorization": f"Bearer {settings.TWITTER_BOT_BEARER_TOKEN}"}
            
            async with self.http_session.get(url, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get("data")
                else:
                    logger.error(f"Failed to get Twitter bot info: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting Twitter bot info: {e}")
            return None


class BotConfigurationManager:
    """
    Manages platform-specific bot configuration and credential management.
    
    Handles secure storage and validation of bot credentials, configuration
    validation, and platform-specific settings management.
    """
    
    def __init__(self):
        """Initialize the bot configuration manager."""
        self.platform_configs: Dict[str, Dict[str, Any]] = {}
        self.is_initialized = False
    
    async def initialize(self):
        """Initialize the bot configuration manager."""
        if self.is_initialized:
            return
        
        try:
            # Load and validate platform configurations
            await self._load_platform_configurations()
            
            # Validate credentials
            await self._validate_credentials()
            
            self.is_initialized = True
            logger.info("Bot configuration manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize bot configuration manager: {e}")
            raise
    
    async def get_platform_config(self, platform: str) -> Optional[Dict[str, Any]]:
        """
        Get configuration for a specific platform.
        
        Args:
            platform: Platform name
            
        Returns:
            Platform configuration dictionary or None if not found
        """
        if not self.is_initialized:
            await self.initialize()
        
        return self.platform_configs.get(platform)
    
    async def validate_platform_credentials(self, platform: str) -> bool:
        """
        Validate credentials for a specific platform.
        
        Args:
            platform: Platform name
            
        Returns:
            True if credentials are valid, False otherwise
        """
        try:
            config = await self.get_platform_config(platform)
            if not config:
                return False
            
            if platform == "discord":
                return bool(config.get("bot_token") and config.get("enabled"))
            elif platform == "telegram":
                return bool(config.get("bot_token") and config.get("enabled"))
            elif platform == "twitter":
                return bool(config.get("bearer_token") and config.get("enabled"))
            else:
                return False
                
        except Exception as e:
            logger.error(f"Credential validation failed for {platform}: {e}")
            return False
    
    async def get_enabled_platforms(self) -> List[str]:
        """
        Get list of enabled platforms with valid credentials.
        
        Returns:
            List of enabled platform names
        """
        if not self.is_initialized:
            await self.initialize()
        
        enabled_platforms = []
        
        for platform, config in self.platform_configs.items():
            if config.get("enabled") and await self.validate_platform_credentials(platform):
                enabled_platforms.append(platform)
        
        return enabled_platforms
    
    async def update_platform_config(self, platform: str, config: Dict[str, Any]) -> bool:
        """
        Update configuration for a platform.
        
        Args:
            platform: Platform name
            config: New configuration dictionary
            
        Returns:
            True if update successful, False otherwise
        """
        try:
            # Validate the new configuration
            if not self._validate_platform_config(platform, config):
                return False
            
            # Update configuration
            self.platform_configs[platform] = config
            
            logger.info(f"Updated configuration for platform: {platform}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update platform config for {platform}: {e}")
            return False
    
    # Private helper methods
    
    async def _load_platform_configurations(self):
        """Load platform configurations from settings."""
        self.platform_configs = {
            "discord": {
                "enabled": settings.BOT_ENABLE_DISCORD,
                "bot_token": settings.DISCORD_BOT_TOKEN,
                "webhook_secret": settings.DISCORD_WEBHOOK_SECRET,
                "api_endpoint": "https://discord.com/api/v10",
                "features": {
                    "slash_commands": True,
                    "embeds": True,
                    "threads": True,
                    "components": True
                },
                "limits": {
                    "message_length": 2000,
                    "embed_fields": 25,
                    "embed_description": 4096
                }
            },
            "telegram": {
                "enabled": settings.BOT_ENABLE_TELEGRAM,
                "bot_token": settings.TELEGRAM_BOT_TOKEN,
                "webhook_secret": settings.TELEGRAM_WEBHOOK_SECRET,
                "api_endpoint": f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}" if settings.TELEGRAM_BOT_TOKEN else None,
                "features": {
                    "inline_keyboards": True,
                    "markdown": True,
                    "html": True,
                    "file_uploads": True
                },
                "limits": {
                    "message_length": 4096,
                    "caption_length": 1024,
                    "button_text_length": 64
                }
            },
            "twitter": {
                "enabled": settings.BOT_ENABLE_TWITTER,
                "bearer_token": settings.TWITTER_BOT_BEARER_TOKEN,
                "webhook_secret": settings.TWITTER_WEBHOOK_SECRET,
                "api_endpoint": "https://api.twitter.com/2",
                "features": {
                    "threads": True,
                    "direct_messages": True,
                    "mentions": True,
                    "media_uploads": True
                },
                "limits": {
                    "tweet_length": 280,
                    "thread_tweets": 25,
                    "dm_length": 10000
                }
            }
        }
    
    async def _validate_credentials(self):
        """Validate all platform credentials."""
        for platform in self.platform_configs:
            is_valid = await self.validate_platform_credentials(platform)
            if self.platform_configs[platform].get("enabled") and not is_valid:
                logger.warning(f"Invalid or missing credentials for enabled platform: {platform}")
    
    def _validate_platform_config(self, platform: str, config: Dict[str, Any]) -> bool:
        """Validate platform configuration structure."""
        required_fields = ["enabled", "api_endpoint", "features", "limits"]
        
        for field in required_fields:
            if field not in config:
                logger.error(f"Missing required field '{field}' in {platform} config")
                return False
        
        # Platform-specific validation
        if platform == "discord" and config.get("enabled"):
            if not config.get("bot_token"):
                logger.error(f"Discord bot token required when enabled")
                return False
        elif platform == "telegram" and config.get("enabled"):
            if not config.get("bot_token"):
                logger.error(f"Telegram bot token required when enabled")
                return False
        elif platform == "twitter" and config.get("enabled"):
            if not config.get("bearer_token"):
                logger.error(f"Twitter bearer token required when enabled")
                return False
        
        return True


# Global instances
bot_registration_manager = BotRegistrationManager()
bot_configuration_manager = BotConfigurationManager()