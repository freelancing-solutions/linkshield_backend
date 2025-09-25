"""
Telegram Bot Handler for processing webhook updates and bot commands.

This module handles Telegram webhook updates, processes messages and commands,
and provides URL analysis responses through Telegram Bot API.
"""

import logging
import re
import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
from datetime import datetime

from ...config.settings import settings

logger = logging.getLogger(__name__)


class TelegramBotHandler:
    """
    Handler for Telegram bot interactions and webhook processing.
    
    Processes Telegram webhook updates including messages, commands,
    and provides URL analysis responses.
    """
    
    def __init__(self):
        """Initialize the Telegram bot handler."""
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.api_base_url = f"https://api.telegram.org/bot{self.bot_token}" if self.bot_token else None
        self.is_initialized = False
        
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
            
            # Handle commands
            if text.startswith("/"):
                return await self._handle_command(message)
            
            # Extract URLs from message text
            urls = self._extract_urls(text)
            
            if not urls:
                # No URLs found, send help message
                help_text = (
                    "👋 Hi! I can help analyze URLs for security threats.\n\n"
                    "Just send me a URL and I'll check it for you!\n"
                    "Example: https://example.com\n\n"
                    "Commands:\n"
                    "/start - Get started\n"
                    "/help - Show this help message\n"
                    "/analyze <url> - Analyze a specific URL"
                )
                
                await self._send_message(chat_id, help_text)
                
                return {
                    "type": "message",
                    "message_id": message_id,
                    "action": "help_sent",
                    "user": username
                }
            
            # Analyze the first URL found
            url = urls[0]
            
            # Send "analyzing" message
            analyzing_msg = await self._send_message(
                chat_id, 
                f"🔍 Analyzing URL: {url}\nPlease wait..."
            )
            
            # Import here to avoid circular imports
            from ...bots.gateway import bot_gateway
            analysis_result = await bot_gateway.analyze_url_quick(url, str(user_id), "telegram")
            
            # Format response based on analysis
            response_text = self._format_analysis_response(url, analysis_result)
            
            # Edit the analyzing message with results
            if analyzing_msg:
                await self._edit_message(chat_id, analyzing_msg["message_id"], response_text)
            else:
                await self._send_message(chat_id, response_text)
            
            return {
                "type": "message",
                "message_id": message_id,
                "url_analyzed": url,
                "risk_level": analysis_result.get("risk_level", "unknown"),
                "action": "analysis_sent",
                "user": username
            }
            
        except Exception as e:
            logger.error(f"Error handling message: {e}")
            return {"type": "message", "error": str(e)}
    
    async def _handle_command(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle bot commands.
        
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
            
            # Parse command and arguments
            parts = text.split()
            command = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            if command in ["/start", "/help"]:
                help_text = (
                    "🛡️ *LinkShield Security Bot*\n\n"
                    "I help analyze URLs for security threats and malware.\n\n"
                    "*How to use:*\n"
                    "• Send me any URL to analyze\n"
                    "• Use /analyze <url> for specific analysis\n"
                    "• I'll check for malware, phishing, and other threats\n\n"
                    "*Commands:*\n"
                    "/start - Show this welcome message\n"
                    "/help - Show help information\n"
                    "/analyze <url> - Analyze a specific URL\n"
                    "/stats - Show your analysis statistics\n\n"
                    "Stay safe online! 🔒"
                )
                
                await self._send_message(chat_id, help_text, parse_mode="Markdown")
                
                return {
                    "type": "command",
                    "command": command,
                    "action": "help_sent",
                    "user": username
                }
            
            elif command == "/analyze":
                if not args:
                    await self._send_message(
                        chat_id, 
                        "Please provide a URL to analyze.\nExample: /analyze https://example.com"
                    )
                    return {
                        "type": "command",
                        "command": command,
                        "action": "missing_url",
                        "user": username
                    }
                
                url = args[0]
                
                # Validate URL format
                if not self._is_valid_url(url):
                    await self._send_message(
                        chat_id,
                        "❌ Invalid URL format. Please provide a valid URL starting with http:// or https://"
                    )
                    return {
                        "type": "command",
                        "command": command,
                        "action": "invalid_url",
                        "user": username
                    }
                
                # Send analyzing message
                analyzing_msg = await self._send_message(
                    chat_id,
                    f"🔍 Analyzing URL: {url}\nPlease wait..."
                )
                
                # Import here to avoid circular imports
                from ...bots.gateway import bot_gateway
                analysis_result = await bot_gateway.analyze_url_quick(url, str(user_id), "telegram")
                
                # Format response
                response_text = self._format_analysis_response(url, analysis_result)
                
                # Edit analyzing message with results
                if analyzing_msg:
                    await self._edit_message(chat_id, analyzing_msg["message_id"], response_text)
                else:
                    await self._send_message(chat_id, response_text)
                
                return {
                    "type": "command",
                    "command": command,
                    "url_analyzed": url,
                    "risk_level": analysis_result.get("risk_level", "unknown"),
                    "action": "analysis_sent",
                    "user": username
                }
            
            elif command == "/stats":
                # Import here to avoid circular imports
                from ...bots.gateway import bot_gateway
                stats = await bot_gateway.get_user_stats(str(user_id), "telegram")
                
                stats_text = (
                    f"📊 *Your Analysis Statistics*\n\n"
                    f"Total URLs analyzed: {stats.get('total_analyzed', 0)}\n"
                    f"Safe URLs: {stats.get('safe_count', 0)}\n"
                    f"Risky URLs detected: {stats.get('risky_count', 0)}\n"
                    f"Last analysis: {stats.get('last_analysis', 'Never')}\n\n"
                    f"Keep staying safe online! 🛡️"
                )
                
                await self._send_message(chat_id, stats_text, parse_mode="Markdown")
                
                return {
                    "type": "command",
                    "command": command,
                    "action": "stats_sent",
                    "user": username
                }
            
            else:
                await self._send_message(
                    chat_id,
                    f"Unknown command: {command}\nUse /help to see available commands."
                )
                
                return {
                    "type": "command",
                    "command": command,
                    "action": "unknown_command",
                    "user": username
                }
                
        except Exception as e:
            logger.error(f"Error handling command: {e}")
            return {"type": "command", "error": str(e)}
    
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
    
    def _extract_urls(self, text: str) -> List[str]:
        """
        Extract URLs from text.
        
        Args:
            text: Text to extract URLs from
            
        Returns:
            List of URLs found
        """
        # URL regex pattern
        url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        urls = re.findall(url_pattern, text)
        return urls
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL has valid format."""
        return bool(re.match(r'^https?://.+', url))
    
    def _format_analysis_response(self, url: str, analysis_result: Dict[str, Any]) -> str:
        """
        Format analysis result into Telegram response.
        
        Args:
            url: Analyzed URL
            analysis_result: Analysis result
            
        Returns:
            Formatted response text
        """
        try:
            risk_level = analysis_result.get("risk_level", "unknown")
            message = analysis_result.get("message", "Analysis completed")
            risk_score = analysis_result.get("risk_score", 0)
            
            # Truncate URL for display
            display_url = url if len(url) <= 50 else url[:47] + "..."
            
            # Build response with emojis and formatting
            if risk_level == "high":
                response = f"🚨 *HIGH RISK DETECTED*\n\n"
                response += f"URL: `{display_url}`\n"
                response += f"⚠️ *This URL may be dangerous - avoid clicking!*\n"
                response += f"Risk Score: {risk_score}/100\n\n"
                response += f"Detected threats may include malware, phishing, or other security risks."
            
            elif risk_level == "medium":
                response = f"⚠️ *MEDIUM RISK DETECTED*\n\n"
                response += f"URL: `{display_url}`\n"
                response += f"🔍 *Proceed with caution*\n"
                response += f"Risk Score: {risk_score}/100\n\n"
                response += f"Some suspicious indicators found. Be careful when visiting this URL."
            
            elif risk_level == "low":
                response = f"⚠️ *LOW RISK DETECTED*\n\n"
                response += f"URL: `{display_url}`\n"
                response += f"✅ *Generally safe, but be cautious*\n"
                response += f"Risk Score: {risk_score}/100\n\n"
                response += f"Minor concerns detected. The URL appears mostly safe."
            
            elif risk_level == "safe":
                response = f"✅ *URL IS SAFE*\n\n"
                response += f"URL: `{display_url}`\n"
                response += f"👍 *This URL appears to be safe*\n"
                response += f"Risk Score: {risk_score}/100\n\n"
                response += f"No security threats detected. Safe to visit."
            
            else:
                response = f"❓ *ANALYSIS INCONCLUSIVE*\n\n"
                response += f"URL: `{display_url}`\n"
                response += f"🔍 *Could not determine safety - be cautious*\n\n"
                response += f"Unable to complete analysis. Exercise caution when visiting this URL."
            
            # Add timestamp
            response += f"\n🕒 Analyzed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            return response
            
        except Exception as e:
            logger.error(f"Error formatting analysis response: {e}")
            return f"❌ Error analyzing URL: {url}"
    
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