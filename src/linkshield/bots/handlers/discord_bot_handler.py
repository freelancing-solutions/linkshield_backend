"""
Discord Bot Handler for processing slash commands and interactions.

This module handles Discord interactions, processes slash commands,
and provides social protection analysis responses through Discord Bot API.
Implements the standardized bot command interface for consistent cross-platform behavior.
"""

import logging
import re
import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
from datetime import datetime
import json

from ...config.settings import settings
from ...database.models import PlatformType, BotUser, User
from ...database.crud.bot_user import get_or_create_bot_user
from ...database.database import get_db
from ...services.subscription_validator import BotSubscriptionValidator
from ..models import (
    BotCommand, BotResponse, PlatformCommand, FormattedResponse,
    CommandType, ResponseType, DeliveryMethod, CommandRegistry,
    parse_platform_command, format_response_for_platform
)
from ..error_handler import bot_error_handler, ErrorCategory, ErrorSeverity

logger = logging.getLogger(__name__)


class DiscordBotHandler:
    """
    Handler for Discord bot interactions and slash command processing.
    
    Processes Discord interactions including slash commands, message components,
    and provides social protection analysis responses through standardized
    bot command interface.
    """
    
    def __init__(self):
        """Initialize the Discord bot handler."""
        self.bot_token = settings.DISCORD_BOT_TOKEN
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.api_base_url = "https://discord.com/api/v10"
        self.is_initialized = False
        self.platform = "discord"
        self.application_id: Optional[str] = None
        self.subscription_validator = BotSubscriptionValidator()
        
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
    
    @bot_error_handler(ErrorCategory.PLATFORM_INTEGRATION, ErrorSeverity.HIGH)
    async def handle_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle incoming Discord webhook events (interactions).
        
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
    
    @bot_error_handler(ErrorCategory.COMMAND_PARSING, ErrorSeverity.MEDIUM)
    async def parse_command(self, interaction_data: Dict[str, Any]) -> Optional[BotCommand]:
        """
        Parse Discord interactions into standardized commands.
        
        Args:
            interaction_data: Discord interaction data
            
        Returns:
            Standardized BotCommand or None if parsing fails
        """
        try:
            # Create platform command from Discord data
            platform_command = PlatformCommand(
                platform=self.platform,
                raw_data=interaction_data,
                user_context=self._extract_user_context(interaction_data)
            )
            
            # Parse into standardized command
            bot_command = parse_platform_command(platform_command)
            
            if not bot_command:
                # Try manual parsing for Discord-specific patterns
                bot_command = await self._manual_parse_discord_command(interaction_data)
            
            return bot_command
            
        except Exception as e:
            logger.error(f"Error parsing Discord command: {e}")
            return None
    
    @bot_error_handler(ErrorCategory.RESPONSE_FORMATTING, ErrorSeverity.MEDIUM)
    async def format_response(self, bot_response: BotResponse) -> FormattedResponse:
        """
        Format BotController response for Discord embeds, components, and structured responses.
        
        Args:
            bot_response: Standardized bot response
            
        Returns:
            Discord-formatted response
        """
        try:
            # Determine delivery method based on response type and content
            delivery_method = self._determine_delivery_method(bot_response)
            
            # Format response for Discord
            formatted_response = format_response_for_platform(
                bot_response, self.platform, delivery_method
            )
            
            # Apply Discord-specific formatting
            await self._apply_discord_formatting(formatted_response, bot_response)
            
            return formatted_response
            
        except Exception as e:
            logger.error(f"Error formatting Discord response: {e}")
            # Return basic error response
            return FormattedResponse(
                platform=self.platform,
                response_data={
                    "content": "❌ Error formatting response. Please try again.",
                    "flags": 64  # EPHEMERAL
                },
                delivery_method=DeliveryMethod.EMBED,
                formatting_applied=["error_fallback"]
            )
    
    @bot_error_handler(ErrorCategory.PLATFORM_INTEGRATION, ErrorSeverity.HIGH)
    async def send_response(self, formatted_response: FormattedResponse, 
                          context: Dict[str, Any]) -> bool:
        """
        Send response back to Discord platform.
        
        Args:
            formatted_response: Platform-formatted response
            context: Context data (interaction_token, etc.)
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            interaction_token = context.get("interaction_token")
            is_initial_response = context.get("is_initial_response", True)
            
            if not interaction_token:
                logger.error("No interaction token provided for Discord response")
                return False
            
            if is_initial_response:
                # This is handled by returning the response from the webhook handler
                return True
            else:
                # Edit the original response
                return await self._edit_interaction_response(
                    interaction_token, 
                    formatted_response.response_data
                )
                
        except Exception as e:
            logger.error(f"Error sending Discord response: {e}")
            return False
    
    async def _handle_slash_command(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle slash command interactions using standardized interface.
        
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
            
            # Handle basic commands first
            if command_name == "help":
                return await self._handle_help_command(interaction)
            
            # Parse command using standardized interface
            bot_command = await self.parse_command(interaction)
            
            if not bot_command:
                # Unknown or invalid command
                return {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": f"❌ Unknown command: /{command_name}. Use /help to see available commands.",
                        "flags": 64  # EPHEMERAL
                    }
                }
            
            # Send initial processing response
            initial_response = {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "content": f"🔄 Processing {bot_command.command_type.value.replace('_', ' ')}...\nPlease wait.",
                    "flags": 64  # EPHEMERAL
                }
            }
            
            # Process command in background and edit response
            asyncio.create_task(self._process_command_and_edit_response(interaction, bot_command))
            
            return initial_response
                
        except Exception as e:
            logger.error(f"Error handling slash command: {e}")
            return {
                "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                "data": {
                    "content": "❌ Error processing command",
                    "flags": 64  # EPHEMERAL
                }
            }
    
    async def _process_command_and_edit_response(self, interaction: Dict[str, Any], bot_command: BotCommand):
        """
        Process bot command and edit the interaction response.
        
        Args:
            interaction: Original interaction data
            bot_command: Standardized bot command
        """
        try:
            # Route command to gateway for processing
            from ..gateway import bot_gateway
            bot_response = await bot_gateway.route_command(bot_command)
            
            # Format response for Discord
            formatted_response = await self.format_response(bot_response)
            
            # Edit original response
            success = await self._edit_interaction_response(
                interaction["token"], 
                formatted_response.response_data
            )
            
            if not success:
                logger.error("Failed to edit Discord interaction response")
            
        except Exception as e:
            logger.error(f"Error processing command and editing response: {e}")
            # Try to edit with error message
            try:
                error_data = {
                    "content": f"❌ Error processing {bot_command.command_type.value.replace('_', ' ')}. Please try again.",
                    "flags": 64  # EPHEMERAL
                }
                await self._edit_interaction_response(interaction["token"], error_data)
            except:
                pass  # If editing fails, just log the original error
    
    async def _handle_help_command(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """Handle /help command."""
        help_embed = {
            "title": "🛡️ LinkShield Social Protection Bot",
            "description": "I help analyze social media accounts, content compliance, and follower insights.",
            "color": 0x00ff00,  # Green
            "fields": [
                {
                    "name": "📋 Available Commands",
                    "value": (
                        "`/analyze_account user:@username` - Analyze account safety and risk factors\n"
                        "`/check_compliance content:\"text\"` - Check content for policy compliance\n"
                        "`/analyze_followers` - Analyze your verified followers and networking opportunities\n"
                        "`/help` - Show this help message"
                    ),
                    "inline": False
                },
                {
                    "name": "🔍 How it works",
                    "value": (
                        "• **Account Analysis**: Get risk assessments for social media accounts\n"
                        "• **Compliance Check**: Verify content meets platform guidelines\n"
                        "• **Follower Analysis**: Discover networking opportunities with verified followers\n"
                        "• All analysis uses advanced AI and threat intelligence"
                    ),
                    "inline": False
                },
                {
                    "name": "📝 Examples",
                    "value": (
                        "• `/analyze_account user:@elonmusk`\n"
                        "• `/check_compliance content:\"Check this post for violations\"`\n"
                        "• `/analyze_followers`"
                    ),
                    "inline": False
                },
                {
                    "name": "🔒 Stay Safe",
                    "value": "Always verify accounts and content before engaging on social media!",
                    "inline": False
                }
            ],
            "footer": {
                "text": "LinkShield - Protecting you on social media"
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
    
    def _extract_user_context(self, interaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract user context from Discord interaction data."""
        try:
            user = interaction_data.get("member", {}).get("user") or interaction_data.get("user", {})
            guild = interaction_data.get("guild")
            channel = interaction_data.get("channel")
            
            return {
                "user_id": user.get("id"),
                "username": user.get("username"),
                "discriminator": user.get("discriminator"),
                "display_name": user.get("global_name") or user.get("username"),
                "guild_id": guild.get("id") if guild else None,
                "guild_name": guild.get("name") if guild else None,
                "channel_id": channel.get("id") if channel else None,
                "channel_name": channel.get("name") if channel else None,
                "interaction_id": interaction_data.get("id"),
                "interaction_token": interaction_data.get("token")
            }
        except Exception as e:
            logger.error(f"Error extracting user context: {e}")
            return {}
    
    async def _manual_parse_discord_command(self, interaction_data: Dict[str, Any]) -> Optional[BotCommand]:
        """Manually parse Discord-specific command patterns."""
        try:
            command_data = interaction_data.get("data", {})
            command_name = command_data.get("name", "")
            options = command_data.get("options", [])
            user = interaction_data.get("member", {}).get("user") or interaction_data.get("user", {})
            user_id = user.get("id", "")
            
            if not command_name or not user_id:
                return None
            
            # Parse based on command name
            if command_name in ["analyze_account", "check_account", "analyze", "safety"]:
                # Extract user parameter
                account_identifier = None
                for option in options:
                    if option.get("name") == "user":
                        account_identifier = option.get("value", "").strip().lstrip("@")
                        break
                
                if account_identifier:
                    return BotCommand(
                        command_type=CommandType.ANALYZE_ACCOUNT,
                        platform=self.platform,
                        user_id=user_id,
                        parameters={"account_identifier": account_identifier},
                        metadata={
                            "original_command": command_name,
                            "platform_data": interaction_data,
                            "guild_id": interaction_data.get("guild", {}).get("id"),
                            "channel_id": interaction_data.get("channel", {}).get("id")
                        }
                    )
            
            elif command_name in ["check_compliance", "compliance", "check"]:
                # Extract content parameter
                content = None
                for option in options:
                    if option.get("name") == "content":
                        content = option.get("value", "").strip()
                        break
                
                if content:
                    return BotCommand(
                        command_type=CommandType.CHECK_COMPLIANCE,
                        platform=self.platform,
                        user_id=user_id,
                        parameters={"content": content},
                        metadata={
                            "original_command": command_name,
                            "platform_data": interaction_data,
                            "guild_id": interaction_data.get("guild", {}).get("id"),
                            "channel_id": interaction_data.get("channel", {}).get("id")
                        }
                    )
            
            elif command_name in ["analyze_followers", "followers", "verified_followers"]:
                return BotCommand(
                    command_type=CommandType.ANALYZE_FOLLOWERS,
                    platform=self.platform,
                    user_id=user_id,
                    parameters={},
                    metadata={
                        "original_command": command_name,
                        "platform_data": interaction_data,
                        "guild_id": interaction_data.get("guild", {}).get("id"),
                        "channel_id": interaction_data.get("channel", {}).get("id")
                    }
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in manual Discord command parsing: {e}")
            return None
    
    def _determine_delivery_method(self, bot_response: BotResponse) -> DeliveryMethod:
        """Determine the best delivery method for a Discord response."""
        # Discord supports rich embeds, so prefer them for structured responses
        if bot_response.success and bot_response.response_type in [
            ResponseType.ANALYSIS_RESULT, 
            ResponseType.COMPLIANCE_CHECK, 
            ResponseType.FOLLOWER_ANALYSIS
        ]:
            return DeliveryMethod.EMBED
        else:
            # Use simple reply for errors or basic responses
            return DeliveryMethod.REPLY
    
    async def _apply_discord_formatting(self, formatted_response: FormattedResponse, 
                                      bot_response: BotResponse):
        """Apply Discord-specific formatting to the response."""
        try:
            response_data = formatted_response.response_data
            
            # Convert to Discord embed format if using embed delivery
            if formatted_response.delivery_method == DeliveryMethod.EMBED:
                if bot_response.response_type == ResponseType.ANALYSIS_RESULT:
                    self._format_analysis_embed(response_data, bot_response)
                elif bot_response.response_type == ResponseType.COMPLIANCE_CHECK:
                    self._format_compliance_embed(response_data, bot_response)
                elif bot_response.response_type == ResponseType.FOLLOWER_ANALYSIS:
                    self._format_follower_embed(response_data, bot_response)
                else:
                    self._format_generic_embed(response_data, bot_response)
            
            # Ensure ephemeral flag for privacy
            response_data["flags"] = 64  # EPHEMERAL
            
            formatted_response.add_formatting("discord_embed")
            formatted_response.add_formatting("ephemeral")
            
        except Exception as e:
            logger.error(f"Error applying Discord formatting: {e}")
    
    def _format_analysis_embed(self, response_data: Dict[str, Any], bot_response: BotResponse):
        """Format account analysis result as Discord embed."""
        risk_level = bot_response.get_data("risk_level", "unknown")
        risk_score = bot_response.get_data("risk_score", 0)
        account_identifier = bot_response.get_data("account_identifier", "Unknown")
        
        # Determine embed color and emoji based on risk level
        color_map = {
            "safe": 0x00ff00,      # Green
            "low": 0xffff00,       # Yellow
            "medium": 0xff8800,    # Orange
            "high": 0xff0000,      # Red
            "critical": 0x8b0000,  # Dark Red
            "unknown": 0x888888    # Gray
        }
        
        risk_indicator = CommandRegistry.get_risk_indicator(risk_level)
        color = color_map.get(risk_level, color_map["unknown"])
        
        embed = {
            "title": f"{risk_indicator} Account Safety Analysis",
            "description": f"Analysis results for **@{account_identifier}**",
            "color": color,
            "fields": [
                {
                    "name": "🎯 Risk Level",
                    "value": f"**{risk_level.title()}**",
                    "inline": True
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
                "text": "LinkShield Social Protection Analysis"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add recommendations if available
        recommendations = bot_response.get_data("recommendations", [])
        if recommendations:
            rec_text = "\n".join([f"• {rec}" for rec in recommendations[:3]])
            embed["fields"].append({
                "name": "💡 Recommendations",
                "value": rec_text,
                "inline": False
            })
        
        # Add threat details if available
        threats = bot_response.get_data("threats_detected", [])
        if threats:
            threat_text = "\n".join([f"• {threat}" for threat in threats[:2]])
            embed["fields"].append({
                "name": "⚠️ Threats Detected",
                "value": threat_text,
                "inline": False
            })
        
        response_data["embeds"] = [embed]
        if "text" in response_data:
            del response_data["text"]  # Remove text when using embeds
    
    def _format_compliance_embed(self, response_data: Dict[str, Any], bot_response: BotResponse):
        """Format compliance check result as Discord embed."""
        is_compliant = bot_response.get_data("is_compliant", True)
        compliance_score = bot_response.get_data("compliance_score", 100)
        
        # Choose color and indicator based on compliance
        if is_compliant:
            color = 0x00ff00  # Green
            indicator = "✅"
            title = "Content Compliance Check - Compliant"
        else:
            color = 0xff8800  # Orange
            indicator = "⚠️"
            title = "Content Compliance Check - Issues Found"
        
        embed = {
            "title": f"{indicator} {title}",
            "description": "Content compliance analysis results",
            "color": color,
            "fields": [
                {
                    "name": "📋 Status",
                    "value": "**Compliant**" if is_compliant else "**Issues Found**",
                    "inline": True
                },
                {
                    "name": "📊 Compliance Score",
                    "value": f"{compliance_score}/100",
                    "inline": True
                },
                {
                    "name": "🕒 Checked",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": True
                }
            ],
            "footer": {
                "text": "LinkShield Content Compliance Check"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add violations if any
        violations = bot_response.get_data("violations", [])
        if violations:
            violation_text = ""
            for violation in violations[:3]:
                severity = violation.get("severity", "medium")
                severity_emoji = {"low": "🟡", "medium": "🟠", "high": "🔴"}.get(severity, "⚪")
                violation_text += f"{severity_emoji} {violation.get('description', 'Policy violation')}\n"
            
            embed["fields"].append({
                "name": f"🚫 Violations Found ({len(violations)})",
                "value": violation_text.strip(),
                "inline": False
            })
        
        # Add remediation suggestions
        suggestions = bot_response.get_data("remediation_suggestions", [])
        if suggestions:
            suggestion_text = "\n".join([f"• {suggestion}" for suggestion in suggestions[:2]])
            embed["fields"].append({
                "name": "💡 Suggestions",
                "value": suggestion_text,
                "inline": False
            })
        
        response_data["embeds"] = [embed]
        if "text" in response_data:
            del response_data["text"]
    
    def _format_follower_embed(self, response_data: Dict[str, Any], bot_response: BotResponse):
        """Format follower analysis result as Discord embed."""
        verified_count = bot_response.get_data("verified_followers_count", 0)
        total_followers = bot_response.get_data("total_followers", 0)
        high_value_count = bot_response.get_data("high_value_followers", 0)
        
        embed = {
            "title": "👥 Verified Followers Analysis",
            "description": "Analysis of your verified followers and networking opportunities",
            "color": 0x0099ff,  # Blue
            "fields": [
                {
                    "name": "✅ Verified Followers",
                    "value": f"**{verified_count:,}**",
                    "inline": True
                }
            ],
            "footer": {
                "text": "LinkShield Follower Analysis"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if total_followers > 0:
            verification_rate = (verified_count / total_followers) * 100
            embed["fields"].append({
                "name": "📊 Verification Rate",
                "value": f"{verification_rate:.1f}%",
                "inline": True
            })
        
        if high_value_count > 0:
            embed["fields"].append({
                "name": "⭐ High-Value Followers",
                "value": f"**{high_value_count:,}**",
                "inline": True
            })
        
        # Add follower categories
        categories = bot_response.get_data("follower_categories", {})
        if categories:
            category_text = ""
            emoji_map = {"influencers": "🌟", "businesses": "🏢", "media": "📺", "verified": "✅"}
            for category, count in categories.items():
                if count > 0:
                    emoji = emoji_map.get(category, "👤")
                    category_text += f"{emoji} {category.title()}: {count:,}\n"
            
            if category_text:
                embed["fields"].append({
                    "name": "📈 Follower Breakdown",
                    "value": category_text.strip(),
                    "inline": False
                })
        
        # Add networking opportunities
        opportunities = bot_response.get_data("networking_opportunities", [])
        if opportunities:
            opp_text = "\n".join([f"• {opp}" for opp in opportunities[:2]])
            embed["fields"].append({
                "name": "🤝 Networking Opportunities",
                "value": opp_text,
                "inline": False
            })
        
        response_data["embeds"] = [embed]
        if "text" in response_data:
            del response_data["text"]
    
    def _format_generic_embed(self, response_data: Dict[str, Any], bot_response: BotResponse):
        """Format generic response as Discord embed."""
        if bot_response.success:
            embed = {
                "title": "✅ Operation Completed Successfully",
                "description": "Your request has been processed.",
                "color": 0x00ff00,  # Green
                "fields": [],
                "footer": {
                    "text": "LinkShield Bot"
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Add any data from the response
            for key, value in bot_response.data.items():
                if isinstance(value, (str, int, float)) and len(embed["fields"]) < 5:
                    embed["fields"].append({
                        "name": key.replace('_', ' ').title(),
                        "value": str(value),
                        "inline": True
                    })
        else:
            embed = {
                "title": "❌ Error",
                "description": bot_response.error_message or "An error occurred",
                "color": 0xff0000,  # Red
                "footer": {
                    "text": "Please try again or contact support"
                },
                "timestamp": datetime.utcnow().isoformat()
            }
        
        response_data["embeds"] = [embed]
        if "text" in response_data:
            del response_data["text"]
    
    async def _handle_message_component(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """Handle message component interactions (buttons, select menus)."""
        try:
            component_data = interaction.get("data", {})
            custom_id = component_data.get("custom_id", "")
            user = interaction.get("member", {}).get("user") or interaction.get("user", {})
            user_id = user.get("id")
            username = user.get("username", "")
            
            # Resolve or create bot user
            db = next(get_db())
            try:
                bot_user = await get_or_create_bot_user(
                    db=db,
                    platform=PlatformType.DISCORD,
                    platform_user_id=str(user_id),
                    platform_username=username
                )
                
                # Validate subscription access
                validation_result = await self.subscription_validator.validate_bot_user_subscription(
                    db=db,
                    bot_user=bot_user,
                    requested_feature="bot_access"
                )
                
                if not validation_result.is_valid:
                    # Send subscription required message
                    error_message = validation_result.error_message or "Subscription required for bot access"
                    return {
                        "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                        "data": {
                            "content": f"❌ {error_message}",
                            "flags": 64  # EPHEMERAL
                        }
                    }
                
            finally:
                db.close()
            
            if custom_id.startswith("reanalyze_account:"):
                account_id = custom_id.split(":", 1)[1]
                
                # Create re-analysis command
                bot_command = BotCommand(
                    command_type=CommandType.ANALYZE_ACCOUNT,
                    platform=self.platform,
                    user_id=user_id,
                    parameters={"account_identifier": account_id},
                    metadata={"is_reanalysis": True, "platform_data": interaction}
                )
                
                # Send analyzing response
                analyzing_response = {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": f"🔄 Re-analyzing account @{account_id}...\nPlease wait.",
                        "flags": 64  # EPHEMERAL
                    }
                }
                
                # Start re-analysis in background
                asyncio.create_task(self._process_command_and_edit_response(interaction, bot_command))
                
                return analyzing_response
            
            elif custom_id.startswith("recheck_compliance:"):
                # Handle compliance re-check (content would need to be stored or passed differently)
                return {
                    "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
                    "data": {
                        "content": "🔄 Re-checking compliance...\nPlease use the slash command for new content analysis.",
                        "flags": 64  # EPHEMERAL
                    }
                }
            
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
    

    
    async def _edit_interaction_response(self, interaction_token: str, response_data: Dict[str, Any]) -> bool:
        """
        Edit an interaction response.
        
        Args:
            interaction_token: Interaction token
            response_data: New response data
            
        Returns:
            True if successful, False otherwise
        """
        if not self.http_session:
            logger.error("HTTP session not initialized")
            return False
        
        try:
            url = f"{self.api_base_url}/webhooks/{await self._get_application_id()}/{interaction_token}/messages/@original"
            
            async with self.http_session.patch(url, json=response_data) as response:
                if response.status == 200:
                    logger.info("Successfully edited interaction response")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to edit interaction response: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error editing interaction response: {e}")
            return False
    
    async def _get_application_id(self) -> str:
        """Get the application ID for the bot."""
        if self.application_id:
            return self.application_id
            
        # Cache the application ID from API call
        try:
            url = f"{self.api_base_url}/oauth2/applications/@me"
            async with self.http_session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    self.application_id = data.get("id", "")
                    return self.application_id
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
                    bot_tag = f"{data.get('username', 'unknown')}#{data.get('discriminator', '0000')}"
                    logger.info(f"Discord API connection successful. Bot: {bot_tag}")
                    
                    # Cache application ID while we're here
                    self.application_id = data.get("id")
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
            self.application_id = None
            logger.info("Discord bot handler shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during Discord bot handler shutdown: {e}")