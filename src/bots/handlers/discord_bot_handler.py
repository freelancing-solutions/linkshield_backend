"""
Discord Bot Handler for processing slash commands and interactions.

This module handles Discord interactions, processes slash commands,
and provides URL analysis responses through Discord Bot API.
"""

import logging
import re
import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
from datetime import datetime
import json

from ...config.settings import settings

logger = logging.getLogger(__name__)


class DiscordBotHandler:
    """
    Handler for Discord bot interactions and slash command processing.
    
    Processes Discord interactions including slash commands, message components,
    and provides URL analysis responses.
    """
    
    def __init__(self):
        """Initialize the Discord bot handler."""
        self.bot_token = settings.DISCORD_BOT_TOKEN
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.api_base_url = "https://discord.com/api/v10"
        self.is_initialized = False
        
    async def initialize(self):
        """Initialize the Discord bot handler with API session."""
        if self.is_initialized:
            return
            
        if not self.bot_token:
            logger.warning("Discord bot token not configured")
            return
            
        try:
            # Initialize HTTP session with Discord API headers
            headers = {
                "Authorization": f"Bot {self.bot_token}",
                "Content-Type": "application/json",
                "User-Agent": "LinkShield-Bot/1.0"
            }
            
            timeout = aiohttp.ClientTimeout(total=10)
            self.http_session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout
            )
            
            # Test API connection
            await self._test_api_connection()
            
            self.is_initialized = True
            logger.info("Discord bot handler initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Discord bot handler: {e}")
            raise
    
    async def handle_interaction(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle incoming Discord interactions.
        
        Args:
            payload: Discord interaction payload
            
        Returns:
            Interaction response
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            interaction_type = payload.get("type")
            interaction_id = payload.get("id")
            
            # Handle different interaction types
            if interaction_type == 1:  # PING
                return {"type": 1}  # PONG
            
            elif interaction_type == 2:  # APPLICATION_COMMAND
                return await self._handle_slash_command(payload)
            
            elif interaction_type == 3:  # MESSAGE_COMPONENT
                return await self._handle_message_component(payload)
            
            else:
                logger.warning(f"Unhandled interaction type: {interaction_type}")
                return {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": "❌ Unsupported interaction type",
                        "flags": 64  # EPHEMERAL
                    }
                }
                
        except Exception as e:
            logger.error(f"Error handling Discord interaction: {e}")
            return {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "content": "❌ An error occurred while processing your request",
                    "flags": 64  # EPHEMERAL
                }
            }
    
    async def _handle_slash_command(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle slash command interactions.
        
        Args:
            interaction: Interaction data
            
        Returns:
            Interaction response
        """
        try:
            command_data = interaction.get("data", {})
            command_name = command_data.get("name")
            user = interaction.get("member", {}).get("user") or interaction.get("user", {})
            user_id = user.get("id")
            username = user.get("username", "unknown")
            
            logger.info(f"Processing slash command /{command_name} from {username} (ID: {user_id})")
            
            if command_name == "analyze":
                return await self._handle_analyze_command(interaction)
            
            elif command_name == "help":
                return await self._handle_help_command(interaction)
            
            elif command_name == "stats":
                return await self._handle_stats_command(interaction)
            
            else:
                return {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": f"❌ Unknown command: /{command_name}",
                        "flags": 64  # EPHEMERAL
                    }
                }
                
        except Exception as e:
            logger.error(f"Error handling slash command: {e}")
            return {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "content": "❌ Error processing command",
                    "flags": 64  # EPHEMERAL
                }
            }
    
    async def _handle_analyze_command(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle /analyze command.
        
        Args:
            interaction: Interaction data
            
        Returns:
            Interaction response
        """
        try:
            command_data = interaction.get("data", {})
            options = command_data.get("options", [])
            user = interaction.get("member", {}).get("user") or interaction.get("user", {})
            user_id = user.get("id")
            
            # Extract URL from command options
            url = None
            for option in options:
                if option.get("name") == "url":
                    url = option.get("value")
                    break
            
            if not url:
                return {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": "❌ Please provide a URL to analyze",
                        "flags": 64  # EPHEMERAL
                    }
                }
            
            # Validate URL format
            if not self._is_valid_url(url):
                return {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": "❌ Invalid URL format. Please provide a valid URL starting with http:// or https://",
                        "flags": 64  # EPHEMERAL
                    }
                }
            
            # Send initial "analyzing" response
            initial_response = {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "content": f"🔍 Analyzing URL: {url}\nPlease wait...",
                    "flags": 64  # EPHEMERAL
                }
            }
            
            # Start analysis in background and edit response
            asyncio.create_task(self._analyze_and_edit_response(interaction, url, user_id))
            
            return initial_response
            
        except Exception as e:
            logger.error(f"Error handling analyze command: {e}")
            return {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "content": "❌ Error processing analyze command",
                    "flags": 64  # EPHEMERAL
                }
            }
    
    async def _analyze_and_edit_response(self, interaction: Dict[str, Any], url: str, user_id: str):
        """
        Analyze URL and edit the interaction response.
        
        Args:
            interaction: Original interaction data
            url: URL to analyze
            user_id: User ID
        """
        try:
            # Import here to avoid circular imports
            from ...bots.gateway import bot_gateway
            analysis_result = await bot_gateway.analyze_url_quick(url, user_id, "discord")
            
            # Format response
            response_data = self._format_analysis_response(url, analysis_result)
            
            # Edit original response
            await self._edit_interaction_response(interaction["token"], response_data)
            
        except Exception as e:
            logger.error(f"Error analyzing URL and editing response: {e}")
            # Try to edit with error message
            try:
                error_data = {
                    "content": f"❌ Error analyzing URL: {url}",
                    "flags": 64  # EPHEMERAL
                }
                await self._edit_interaction_response(interaction["token"], error_data)
            except:
                pass  # If editing fails, just log the original error
    
    async def _handle_help_command(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """Handle /help command."""
        help_embed = {
            "title": "🛡️ LinkShield Security Bot",
            "description": "I help analyze URLs for security threats and malware.",
            "color": 0x00ff00,  # Green
            "fields": [
                {
                    "name": "📋 Commands",
                    "value": (
                        "`/analyze <url>` - Analyze a URL for security threats\n"
                        "`/help` - Show this help message\n"
                        "`/stats` - Show your analysis statistics"
                    ),
                    "inline": False
                },
                {
                    "name": "🔍 How it works",
                    "value": (
                        "• Send me any URL to check for malware, phishing, and other threats\n"
                        "• I'll analyze the URL and provide a safety rating\n"
                        "• Results include risk level and detailed information"
                    ),
                    "inline": False
                },
                {
                    "name": "🔒 Stay Safe",
                    "value": "Always verify URLs before clicking, especially from unknown sources!",
                    "inline": False
                }
            ],
            "footer": {
                "text": "LinkShield - Protecting you online"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return {
            "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
            "data": {
                "embeds": [help_embed],
                "flags": 64  # EPHEMERAL
            }
        }
    
    async def _handle_stats_command(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """Handle /stats command."""
        try:
            user = interaction.get("member", {}).get("user") or interaction.get("user", {})
            user_id = user.get("id")
            username = user.get("username", "User")
            
            # Import here to avoid circular imports
            from ...bots.gateway import bot_gateway
            stats = await bot_gateway.get_user_stats(user_id, "discord")
            
            stats_embed = {
                "title": f"📊 Analysis Statistics for {username}",
                "color": 0x0099ff,  # Blue
                "fields": [
                    {
                        "name": "🔢 Total URLs Analyzed",
                        "value": str(stats.get("total_analyzed", 0)),
                        "inline": True
                    },
                    {
                        "name": "✅ Safe URLs",
                        "value": str(stats.get("safe_count", 0)),
                        "inline": True
                    },
                    {
                        "name": "⚠️ Risky URLs Detected",
                        "value": str(stats.get("risky_count", 0)),
                        "inline": True
                    },
                    {
                        "name": "🕒 Last Analysis",
                        "value": stats.get("last_analysis", "Never"),
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "Keep staying safe online! 🛡️"
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "embeds": [stats_embed],
                    "flags": 64  # EPHEMERAL
                }
            }
            
        except Exception as e:
            logger.error(f"Error handling stats command: {e}")
            return {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "content": "❌ Error retrieving statistics",
                    "flags": 64  # EPHEMERAL
                }
            }
    
    async def _handle_message_component(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """Handle message component interactions (buttons, select menus)."""
        try:
            component_data = interaction.get("data", {})
            custom_id = component_data.get("custom_id", "")
            user = interaction.get("member", {}).get("user") or interaction.get("user", {})
            user_id = user.get("id")
            
            if custom_id.startswith("reanalyze:"):
                url = custom_id.split(":", 1)[1]
                
                # Send analyzing response
                analyzing_response = {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": f"🔄 Re-analyzing URL: {url}\nPlease wait...",
                        "flags": 64  # EPHEMERAL
                    }
                }
                
                # Start re-analysis in background
                asyncio.create_task(self._analyze_and_edit_response(interaction, url, user_id))
                
                return analyzing_response
            
            else:
                return {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": "❌ Unknown button interaction",
                        "flags": 64  # EPHEMERAL
                    }
                }
                
        except Exception as e:
            logger.error(f"Error handling message component: {e}")
            return {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "content": "❌ Error processing button interaction",
                    "flags": 64  # EPHEMERAL
                }
            }
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL has valid format."""
        return bool(re.match(r'^https?://.+', url))
    
    def _format_analysis_response(self, url: str, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format analysis result into Discord response.
        
        Args:
            url: Analyzed URL
            analysis_result: Analysis result
            
        Returns:
            Formatted Discord response data
        """
        try:
            risk_level = analysis_result.get("risk_level", "unknown")
            message = analysis_result.get("message", "Analysis completed")
            risk_score = analysis_result.get("risk_score", 0)
            
            # Truncate URL for display
            display_url = url if len(url) <= 60 else url[:57] + "..."
            
            # Determine embed color and emoji based on risk level
            if risk_level == "high":
                color = 0xff0000  # Red
                emoji = "🚨"
                title = "HIGH RISK DETECTED"
                description = "⚠️ **This URL may be dangerous - avoid clicking!**"
            elif risk_level == "medium":
                color = 0xff8800  # Orange
                emoji = "⚠️"
                title = "MEDIUM RISK DETECTED"
                description = "🔍 **Proceed with caution**"
            elif risk_level == "low":
                color = 0xffff00  # Yellow
                emoji = "⚠️"
                title = "LOW RISK DETECTED"
                description = "✅ **Generally safe, but be cautious**"
            elif risk_level == "safe":
                color = 0x00ff00  # Green
                emoji = "✅"
                title = "URL IS SAFE"
                description = "👍 **This URL appears to be safe**"
            else:
                color = 0x888888  # Gray
                emoji = "❓"
                title = "ANALYSIS INCONCLUSIVE"
                description = "🔍 **Could not determine safety - be cautious**"
            
            # Create embed
            embed = {
                "title": f"{emoji} {title}",
                "description": description,
                "color": color,
                "fields": [
                    {
                        "name": "🔗 URL",
                        "value": f"`{display_url}`",
                        "inline": False
                    },
                    {
                        "name": "📊 Risk Score",
                        "value": f"{risk_score}/100",
                        "inline": True
                    },
                    {
                        "name": "🕒 Analyzed",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "inline": True
                    }
                ],
                "footer": {
                    "text": "LinkShield Security Analysis"
                }
            }
            
            # Add re-analyze button for non-safe results
            components = []
            if risk_level != "safe":
                components = [
                    {
                        "type": 1,  # ACTION_ROW
                        "components": [
                            {
                                "type": 2,  # BUTTON
                                "style": 2,  # SECONDARY
                                "label": "🔄 Re-analyze",
                                "custom_id": f"reanalyze:{url}"
                            }
                        ]
                    }
                ]
            
            response_data = {
                "embeds": [embed],
                "flags": 64  # EPHEMERAL
            }
            
            if components:
                response_data["components"] = components
            
            return response_data
            
        except Exception as e:
            logger.error(f"Error formatting analysis response: {e}")
            return {
                "content": f"❌ Error formatting analysis result for URL: {url}",
                "flags": 64  # EPHEMERAL
            }
    
    async def _edit_interaction_response(self, interaction_token: str, response_data: Dict[str, Any]):
        """
        Edit an interaction response.
        
        Args:
            interaction_token: Interaction token
            response_data: New response data
        """
        if not self.http_session:
            logger.error("HTTP session not initialized")
            return
        
        try:
            url = f"{self.api_base_url}/webhooks/{await self._get_application_id()}/{interaction_token}/messages/@original"
            
            async with self.http_session.patch(url, json=response_data) as response:
                if response.status == 200:
                    logger.info("Successfully edited interaction response")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to edit interaction response: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error editing interaction response: {e}")
    
    async def _get_application_id(self) -> str:
        """Get the application ID for the bot."""
        # This would typically be cached or configured
        # For now, we'll extract it from a test API call
        try:
            url = f"{self.api_base_url}/oauth2/applications/@me"
            async with self.http_session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("id", "")
                else:
                    logger.error("Failed to get application ID")
                    return ""
        except Exception as e:
            logger.error(f"Error getting application ID: {e}")
            return ""
    
    async def _test_api_connection(self):
        """Test Discord API connection."""
        if not self.http_session:
            raise Exception("HTTP session not initialized")
        
        try:
            url = f"{self.api_base_url}/users/@me"
            async with self.http_session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Discord API connection successful. Bot: {data.get('username', 'unknown')}#{data.get('discriminator', '0000')}")
                else:
                    error_text = await response.text()
                    raise Exception(f"Discord API test failed: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Discord API connection test failed: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown the Discord bot handler."""
        try:
            if self.http_session:
                await self.http_session.close()
                logger.info("Discord bot handler HTTP session closed")
            
            self.is_initialized = False
            logger.info("Discord bot handler shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during Discord bot handler shutdown: {e}")