"""
Telegram Bot Handler for processing webhook updates and bot commands.

This module handles Telegram webhook updates, processes messages and commands,
and provides social protection analysis responses through Telegram Bot API.
Implements the standardized bot command interface for consistent cross-platform behavior.
"""

import logging
import re
import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
from datetime import datetime

from ...config.settings import settings
from ..models import (
    BotCommand, BotResponse, PlatformCommand, FormattedResponse,
    CommandType, ResponseType, DeliveryMethod, CommandRegistry
)
from ...models.social_protection import PlatformType
from ...models.bot import BotUser, get_or_create_bot_user
from ...models.user import User
from ...services.bot_subscription_validator import BotSubscriptionValidator
from ...config.database import get_db
from ..error_handler import bot_error_handler_instance, ErrorCategory, ErrorSeverity

logger = logging.getLogger(__name__)


class TelegramBotHandler:
    """
    Handler for Telegram bot interactions and webhook processing.
    
    Processes Telegram webhook updates including messages, slash commands,
    and provides social protection analysis responses through standardized
    bot command interface.
    """
    
    def __init__(self):
        """Initialize the Telegram bot handler."""
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.api_base_url = f"https://api.telegram.org/bot{self.bot_token}" if self.bot_token else None
        self.is_initialized = False
        self.platform = "telegram"
        self.subscription_validator = BotSubscriptionValidator()
        
    async def initialize(self):
        """Initialize the Telegram bot handler with API session."""
        if self.is_initialized:
            return
            
        if not self.bot_token:
            logger.warning("Telegram bot token not configured")
            return
            
        try:
            # Initialize HTTP session
            timeout = aiohttp.ClientTimeout(total=10)
            self.http_session = aiohttp.ClientSession(timeout=timeout)
            
            # Test API connection
            await self._test_api_connection()
            
            self.is_initialized = True
            logger.info("Telegram bot handler initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Telegram bot handler: {e}")
            raise
    
    async def handle_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle incoming Telegram webhook updates.
        
        Args:
            payload: Telegram webhook update payload
            
        Returns:
            Processing result
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            update_id = payload.get("update_id")
            
            # Handle different types of updates
            if "message" in payload:
                return await self._handle_message(payload["message"])
            elif "edited_message" in payload:
                return await self._handle_edited_message(payload["edited_message"])
            elif "callback_query" in payload:
                return await self._handle_callback_query(payload["callback_query"])
            else:
                logger.info(f"Unhandled update type in update {update_id}")
                return {"update_id": update_id, "action": "ignored"}
                
        except Exception as e:
            logger.error(f"Error handling Telegram webhook: {e}")
            return {"error": str(e)}
    
    async def parse_command(self, message_data: Dict[str, Any]) -> Optional[BotCommand]:
        """
        Parse Telegram message into standardized BotCommand.
        
        Args:
            message_data: Telegram message data
            
        Returns:
            Standardized BotCommand or None if parsing fails
        """
        try:
            text = message_data.get("text", "").strip()
            user_id = str(message_data.get("from", {}).get("id", ""))
            username = message_data.get("from", {}).get("username", "")
            
            if not text or not user_id:
                return None
            
            # Check if it's a command (starts with /)
            if not text.startswith("/"):
                return None
            
            # Validate command syntax and get command type
            command_type = CommandRegistry.validate_command_syntax(text, self.platform)
            if not command_type:
                return None
            
            # Extract parameters based on command type
            parameters = CommandRegistry.extract_parameters(text, command_type, self.platform)
            
            # Create metadata with Telegram-specific context
            metadata = {
                "original_command": text,
                "username": username,
                "chat_id": message_data.get("chat", {}).get("id"),
                "message_id": message_data.get("message_id"),
                "chat_type": message_data.get("chat", {}).get("type", "private"),
                "platform_data": message_data
            }
            
            return BotCommand(
                command_type=command_type,
                platform=self.platform,
                user_id=user_id,
                parameters=parameters,
                metadata=metadata
            )
            
        except Exception as e:
            # Use centralized error handling for command parsing errors
            await bot_error_handler_instance.handle_error(
                category=ErrorCategory.COMMAND_PARSING,
                severity=ErrorSeverity.MEDIUM,
                platform=self.platform,
                user_id=user_id if 'user_id' in locals() else None,
                original_error=e,
                context={
                    "message_data": message_data,
                    "text": text if 'text' in locals() else None
                }
            )
            logger.error(f"Error parsing Telegram command: {e}")
            return None
    
    async def format_response(self, bot_response: BotResponse) -> FormattedResponse:
        """
        Format BotController response for Telegram platform.
        
        Args:
            bot_response: Standardized bot response
            
        Returns:
            Telegram-formatted response
        """
        try:
            # Get platform formatting preferences
            platform_formatting = CommandRegistry.get_platform_formatting(self.platform)
            
            # Determine delivery method
            delivery_method = DeliveryMethod.MESSAGE
            if bot_response.get_formatting_hint("use_inline_keyboard"):
                delivery_method = DeliveryMethod.INLINE_KEYBOARD
            
            # Format response based on type
            if bot_response.success:
                if bot_response.response_type == ResponseType.ANALYSIS_RESULT:
                    response_data = self._format_account_analysis(bot_response)
                elif bot_response.response_type == ResponseType.COMPLIANCE_CHECK:
                    response_data = self._format_compliance_check(bot_response)
                elif bot_response.response_type == ResponseType.FOLLOWER_ANALYSIS:
                    response_data = self._format_follower_analysis(bot_response)
                else:
                    response_data = self._format_generic_success(bot_response)
            else:
                response_data = self._format_error_response(bot_response)
            
            return FormattedResponse(
                platform=self.platform,
                response_data=response_data,
                delivery_method=delivery_method,
                formatting_applied=["telegram_markdown", "emoji_indicators", "structured_message"]
            )
            
        except Exception as e:
            # Use centralized error handling for response formatting errors
            await bot_error_handler_instance.handle_error(
                category=ErrorCategory.RESPONSE_FORMATTING,
                severity=ErrorSeverity.HIGH,
                platform=self.platform,
                original_error=e,
                context={
                    "bot_response": {
                        "success": bot_response.success if bot_response else None,
                        "response_type": bot_response.response_type.value if bot_response and bot_response.response_type else None
                    }
                }
            )
            logger.error(f"Error formatting Telegram response: {e}")
            # Return basic error response
            return FormattedResponse(
                platform=self.platform,
                response_data={
                    "text": "❌ Error formatting response. Please try again.",
                    "parse_mode": "Markdown"
                },
                delivery_method=DeliveryMethod.MESSAGE,
                formatting_applied=["error_fallback"]
            )
    
    async def send_response(self, formatted_response: FormattedResponse, chat_id: int) -> bool:
        """
        Send formatted response back to Telegram platform.
        
        Args:
            formatted_response: Platform-formatted response
            chat_id: Telegram chat ID to send to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if formatted_response.delivery_method == DeliveryMethod.INLINE_KEYBOARD:
                return await self._send_message_with_keyboard(
                    chat_id, 
                    formatted_response.response_data
                )
            else:
                return await self._send_message(
                    chat_id,
                    formatted_response.response_data.get("text", ""),
                    formatted_response.response_data.get("parse_mode", "Markdown")
                ) is not None
                
        except Exception as e:
            logger.error(f"Error sending Telegram response: {e}")
            return False
    
    def _format_account_analysis(self, bot_response: BotResponse) -> Dict[str, Any]:
        """Format account analysis result for Telegram."""
        risk_level = bot_response.get_data("risk_level", "unknown")
        risk_score = bot_response.get_data("risk_score", 0)
        account_identifier = bot_response.get_data("account_identifier", "Unknown")
        
        # Get risk indicator emoji
        risk_indicator = CommandRegistry.get_risk_indicator(risk_level)
        
        # Build formatted message
        message = f"{risk_indicator} *Account Safety Analysis*\n\n"
        message += f"📱 Account: `{account_identifier}`\n"
        message += f"🎯 Risk Level: *{risk_level.title()}*\n"
        message += f"📊 Risk Score: {risk_score}/100\n\n"
        
        # Add recommendations if available
        recommendations = bot_response.get_data("recommendations", [])
        if recommendations:
            message += "💡 *Recommendations:*\n"
            for i, rec in enumerate(recommendations[:3], 1):
                message += f"{i}. {rec}\n"
        
        # Add threat details if available
        threats = bot_response.get_data("threats_detected", [])
        if threats:
            message += f"\n⚠️ *Threats Detected:* {len(threats)}\n"
            for threat in threats[:2]:
                message += f"• {threat}\n"
        
        message += f"\n🕒 Analysis completed at {datetime.now().strftime('%H:%M:%S')}"
        
        return {
            "text": message,
            "parse_mode": "Markdown"
        }
    
    def _format_compliance_check(self, bot_response: BotResponse) -> Dict[str, Any]:
        """Format compliance check result for Telegram."""
        is_compliant = bot_response.get_data("is_compliant", True)
        compliance_score = bot_response.get_data("compliance_score", 100)
        
        # Choose indicator based on compliance
        indicator = "✅" if is_compliant else "⚠️"
        status = "Compliant" if is_compliant else "Issues Found"
        
        message = f"{indicator} *Content Compliance Check*\n\n"
        message += f"📋 Status: *{status}*\n"
        message += f"📊 Compliance Score: {compliance_score}/100\n\n"
        
        # Add violations if any
        violations = bot_response.get_data("violations", [])
        if violations:
            message += f"🚫 *Violations Found:* {len(violations)}\n"
            for i, violation in enumerate(violations[:3], 1):
                severity = violation.get("severity", "medium")
                severity_emoji = {"low": "🟡", "medium": "🟠", "high": "🔴"}.get(severity, "⚪")
                message += f"{severity_emoji} {violation.get('description', 'Policy violation')}\n"
        
        # Add remediation suggestions
        suggestions = bot_response.get_data("remediation_suggestions", [])
        if suggestions:
            message += f"\n💡 *Suggestions:*\n"
            for suggestion in suggestions[:2]:
                message += f"• {suggestion}\n"
        
        message += f"\n🕒 Check completed at {datetime.now().strftime('%H:%M:%S')}"
        
        return {
            "text": message,
            "parse_mode": "Markdown"
        }
    
    def _format_follower_analysis(self, bot_response: BotResponse) -> Dict[str, Any]:
        """Format follower analysis result for Telegram."""
        verified_count = bot_response.get_data("verified_followers_count", 0)
        total_followers = bot_response.get_data("total_followers", 0)
        high_value_count = bot_response.get_data("high_value_followers", 0)
        
        message = f"👥 *Verified Followers Analysis*\n\n"
        message += f"✅ Verified Followers: *{verified_count:,}*\n"
        
        if total_followers > 0:
            verification_rate = (verified_count / total_followers) * 100
            message += f"📊 Verification Rate: {verification_rate:.1f}%\n"
        
        if high_value_count > 0:
            message += f"⭐ High-Value Followers: *{high_value_count:,}*\n"
        
        # Add follower categories
        categories = bot_response.get_data("follower_categories", {})
        if categories:
            message += f"\n📈 *Follower Breakdown:*\n"
            for category, count in categories.items():
                if count > 0:
                    emoji = {"influencers": "🌟", "businesses": "🏢", "media": "📺", "verified": "✅"}.get(category, "👤")
                    message += f"{emoji} {category.title()}: {count:,}\n"
        
        # Add networking opportunities
        opportunities = bot_response.get_data("networking_opportunities", [])
        if opportunities:
            message += f"\n🤝 *Networking Opportunities:*\n"
            for opp in opportunities[:2]:
                message += f"• {opp}\n"
        
        message += f"\n🕒 Analysis completed at {datetime.now().strftime('%H:%M:%S')}"
        
        return {
            "text": message,
            "parse_mode": "Markdown"
        }
    
    def _format_generic_success(self, bot_response: BotResponse) -> Dict[str, Any]:
        """Format generic success response for Telegram."""
        message = "✅ *Operation Completed Successfully*\n\n"
        
        # Add any data from the response
        for key, value in bot_response.data.items():
            if isinstance(value, (str, int, float)):
                message += f"• {key.replace('_', ' ').title()}: {value}\n"
        
        return {
            "text": message,
            "parse_mode": "Markdown"
        }
    
    def _format_error_response(self, bot_response: BotResponse) -> Dict[str, Any]:
        """Format error response for Telegram."""
        message = f"❌ *Error*\n\n"
        message += f"🚫 {bot_response.error_message}\n\n"
        message += "Please try again or use /help for assistance."
        
        return {
            "text": message,
            "parse_mode": "Markdown"
        }

    async def _handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle incoming message.
        
        Args:
            message: Message data
            
        Returns:
            Message processing result
        """
        try:
            message_id = message.get("message_id")
            chat_id = message.get("chat", {}).get("id")
            user_id = message.get("from", {}).get("id")
            username = message.get("from", {}).get("username", "")
            text = message.get("text", "")
            
            logger.info(f"Processing message from @{username} (ID: {user_id}): {text}")
            
            # Resolve or create bot user
            db = next(get_db())
            try:
                bot_user = await get_or_create_bot_user(
                    db=db,
                    platform=PlatformType.TELEGRAM,
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
                    await self._send_message(chat_id, f"❌ {error_message}", "Markdown")
                    
                    return {
                        "type": "message",
                        "message_id": message_id,
                        "action": "subscription_required",
                        "user": username,
                        "error": "subscription_required"
                    }
                
            finally:
                db.close()
            
            # Handle commands using standardized interface
            if text.startswith("/"):
                return await self._handle_standardized_command(message)
            
            # For non-command messages, provide help
            help_text = (
                "👋 Hi! I can help with social media safety analysis.\n\n"
                "*Available Commands:*\n"
                "/analyze_account @username - Analyze account safety\n"
                "/check_compliance \"content\" - Check content compliance\n"
                "/analyze_followers - Analyze your verified followers\n\n"
                "/start - Get started\n"
                "/help - Show this help message"
            )
            
            await self._send_message(chat_id, help_text, "Markdown")
            
            return {
                "type": "message",
                "message_id": message_id,
                "action": "help_sent",
                "user": username
            }
            
        except Exception as e:
            logger.error(f"Error handling message: {e}")
            return {"type": "message", "error": str(e)}
    
    async def _handle_standardized_command(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle bot commands using standardized interface.
        
        Args:
            message: Message data containing command
            
        Returns:
            Command processing result
        """
        try:
            chat_id = message.get("chat", {}).get("id")
            user_id = message.get("from", {}).get("id")
            username = message.get("from", {}).get("username", "")
            text = message.get("text", "")
            
            # Handle basic commands first
            if text.lower() in ["/start", "/help"]:
                return await self._handle_help_command(chat_id, username)
            
            # Parse command using standardized interface
            bot_command = await self.parse_command(message)
            
            if not bot_command:
                # Unknown command
                await self._send_message(
                    chat_id,
                    "❌ Unknown command. Use /help to see available commands.",
                    "Markdown"
                )
                return {
                    "type": "command",
                    "action": "unknown_command",
                    "user": username
                }
            
            # Send processing message
            processing_msg = await self._send_message(
                chat_id,
                f"🔄 Processing {bot_command.command_type.value.replace('_', ' ')}...\nPlease wait.",
                "Markdown"
            )
            
            # Route command to gateway for processing
            from ..gateway import bot_gateway
            bot_response = await bot_gateway.route_command(bot_command)
            
            # Format response for Telegram
            formatted_response = await self.format_response(bot_response)
            
            # Send formatted response
            success = await self.send_response(formatted_response, chat_id)
            
            # Clean up processing message if response was sent successfully
            if success and processing_msg:
                try:
                    await self._delete_message(chat_id, processing_msg["message_id"])
                except:
                    pass  # Ignore deletion errors
            
            return {
                "type": "command",
                "command_type": bot_command.command_type.value,
                "success": success,
                "response_type": bot_response.response_type.value,
                "action": "command_processed",
                "user": username
            }
            
        except Exception as e:
            logger.error(f"Error handling standardized command: {e}")
            # Send error message to user
            try:
                await self._send_message(
                    chat_id,
                    "❌ An error occurred while processing your command. Please try again.",
                    "Markdown"
                )
            except:
                pass
            
            return {"type": "command", "error": str(e)}
    
    async def _handle_help_command(self, chat_id: int, username: str) -> Dict[str, Any]:
        """Handle help and start commands."""
        help_text = (
            "🛡️ *LinkShield Social Protection Bot*\n\n"
            "I help analyze social media accounts, content compliance, and follower insights.\n\n"
            "*Available Commands:*\n\n"
            "🔍 `/analyze_account @username`\n"
            "   Analyze account safety and risk factors\n\n"
            "📋 `/check_compliance \"your content here\"`\n"
            "   Check content for policy compliance\n\n"
            "👥 `/analyze_followers`\n"
            "   Analyze your verified followers and networking opportunities\n\n"
            "ℹ️ `/help` - Show this help message\n\n"
            "*Examples:*\n"
            "• `/analyze_account @elonmusk`\n"
            "• `/check_compliance \"Check this post for violations\"`\n"
            "• `/analyze_followers`\n\n"
            "Stay safe on social media! 🔒"
        )
        
        await self._send_message(chat_id, help_text, "Markdown")
        
        return {
            "type": "command",
            "command": "help",
            "action": "help_sent",
            "user": username
        }
    

    
    async def _handle_edited_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle edited message (usually ignored)."""
        return {"type": "edited_message", "action": "ignored"}
    
    async def _handle_callback_query(self, callback_query: Dict[str, Any]) -> Dict[str, Any]:
        """Handle callback query from inline keyboards."""
        try:
            query_id = callback_query.get("id")
            data = callback_query.get("data", "")
            
            # Answer callback query to remove loading state
            await self._answer_callback_query(query_id, "Processing...")
            
            # Handle different callback data
            if data.startswith("reanalyze:"):
                url = data.split(":", 1)[1]
                chat_id = callback_query.get("message", {}).get("chat", {}).get("id")
                user_id = callback_query.get("from", {}).get("id")
                
                # Re-analyze URL
                from ...bots.gateway import bot_gateway
                analysis_result = await bot_gateway.analyze_url_quick(url, str(user_id), "telegram")
                
                response_text = self._format_analysis_response(url, analysis_result)
                await self._send_message(chat_id, f"🔄 Re-analysis results:\n\n{response_text}")
                
                return {
                    "type": "callback_query",
                    "action": "reanalyzed",
                    "url": url
                }
            
            return {"type": "callback_query", "action": "handled"}
            
        except Exception as e:
            logger.error(f"Error handling callback query: {e}")
            return {"type": "callback_query", "error": str(e)}
    

    
    async def _send_message_with_keyboard(self, chat_id: int, response_data: Dict[str, Any]) -> bool:
        """Send message with inline keyboard."""
        try:
            url = f"{self.api_base_url}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": response_data.get("text", ""),
                "parse_mode": response_data.get("parse_mode", "Markdown")
            }
            
            if "reply_markup" in response_data:
                payload["reply_markup"] = response_data["reply_markup"]
            
            async with self.http_session.post(url, json=payload) as response:
                success = response.status == 200
                if not success:
                    error_text = await response.text()
                    logger.error(f"Failed to send keyboard message: {response.status} - {error_text}")
                return success
                
        except Exception as e:
            logger.error(f"Error sending keyboard message: {e}")
            return False
    
    async def _delete_message(self, chat_id: int, message_id: int) -> bool:
        """Delete a message."""
        try:
            url = f"{self.api_base_url}/deleteMessage"
            payload = {
                "chat_id": chat_id,
                "message_id": message_id
            }
            
            async with self.http_session.post(url, json=payload) as response:
                return response.status == 200
                
        except Exception as e:
            logger.error(f"Error deleting message: {e}")
            return False

    async def _send_message(self, chat_id: int, text: str, parse_mode: str = None) -> Optional[Dict[str, Any]]:
        """
        Send a message to a chat.
        
        Args:
            chat_id: Chat ID to send message to
            text: Message text
            parse_mode: Parse mode (Markdown, HTML, etc.)
            
        Returns:
            Message data if successful
        """
        if not self.http_session or not self.api_base_url:
            logger.error("HTTP session or API URL not initialized")
            return None
        
        try:
            url = f"{self.api_base_url}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": text
            }
            
            if parse_mode:
                payload["parse_mode"] = parse_mode
            
            async with self.http_session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Successfully sent message to chat {chat_id}")
                    return data.get("result")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to send message to chat {chat_id}: {response.status} - {error_text}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error sending message to chat {chat_id}: {e}")
            return None
    
    async def _edit_message(self, chat_id: int, message_id: int, text: str, parse_mode: str = None):
        """
        Edit a message.
        
        Args:
            chat_id: Chat ID
            message_id: Message ID to edit
            text: New message text
            parse_mode: Parse mode (Markdown, HTML, etc.)
        """
        if not self.http_session or not self.api_base_url:
            logger.error("HTTP session or API URL not initialized")
            return
        
        try:
            url = f"{self.api_base_url}/editMessageText"
            payload = {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text
            }
            
            if parse_mode:
                payload["parse_mode"] = parse_mode
            
            async with self.http_session.post(url, json=payload) as response:
                if response.status == 200:
                    logger.info(f"Successfully edited message {message_id} in chat {chat_id}")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to edit message {message_id} in chat {chat_id}: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error editing message {message_id} in chat {chat_id}: {e}")
    
    async def _answer_callback_query(self, callback_query_id: str, text: str = ""):
        """Answer a callback query."""
        if not self.http_session or not self.api_base_url:
            return
        
        try:
            url = f"{self.api_base_url}/answerCallbackQuery"
            payload = {
                "callback_query_id": callback_query_id,
                "text": text
            }
            
            async with self.http_session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"Failed to answer callback query: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error answering callback query: {e}")
    
    async def _test_api_connection(self):
        """Test Telegram API connection."""
        if not self.http_session or not self.api_base_url:
            raise Exception("HTTP session or API URL not initialized")
        
        try:
            url = f"{self.api_base_url}/getMe"
            async with self.http_session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    bot_info = data.get("result", {})
                    logger.info(f"Telegram API connection successful. Bot: @{bot_info.get('username', 'unknown')}")
                else:
                    error_text = await response.text()
                    raise Exception(f"Telegram API test failed: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Telegram API connection test failed: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown the Telegram bot handler."""
        try:
            if self.http_session:
                await self.http_session.close()
                logger.info("Telegram bot handler HTTP session closed")
            
            self.is_initialized = False
            logger.info("Telegram bot handler shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during Telegram bot handler shutdown: {e}")