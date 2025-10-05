"""
Twitter Bot Handler for processing webhook events and API interactions.

This module handles Twitter webhook events, processes mentions and direct messages,
and provides standardized bot command responses through Twitter API.
"""

import logging
import re
import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
from datetime import datetime

from src.config.settings import settings
from src.bots.models import (
    BotCommand, BotResponse, PlatformCommand, FormattedResponse,
    CommandRegistry, CommandType, ResponseType, DeliveryMethod,
    parse_platform_command, format_response_for_platform
)
from src.models.social_protection import PlatformType
from src.bots.error_handler import bot_error_handler_instance, ErrorCategory
from src.models.bot import BotUser, get_or_create_bot_user
from src.models.user import User
from src.services.bot_subscription_validator import BotSubscriptionValidator
from src.config.database import get_db

logger = logging.getLogger(__name__)


class TwitterBotHandler:
    """
    Handler for Twitter bot interactions and webhook processing.
    
    Processes Twitter webhook events including mentions, direct messages,
    and provides standardized bot command responses for account analysis,
    compliance checking, and follower analysis.
    """
    
    def __init__(self):
        """Initialize the Twitter bot handler."""
        self.bearer_token = settings.TWITTER_BOT_BEARER_TOKEN
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.api_base_url = "https://api.twitter.com/2"
        self.is_initialized = False
        self.platform = PlatformType.TWITTER
        self.max_tweet_length = 280
        self.max_thread_tweets = 5
        self.subscription_validator = BotSubscriptionValidator()
        
    async def initialize(self):
        """Initialize the Twitter bot handler with API session."""
        if self.is_initialized:
            return
            
        if not self.bearer_token:
            logger.warning("Twitter bot bearer token not configured")
            return
            
        try:
            # Initialize HTTP session with Twitter API headers
            headers = {
                "Authorization": f"Bearer {self.bearer_token}",
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
            logger.info("Twitter bot handler initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Twitter bot handler: {e}")
            raise
    
    async def handle_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle incoming Twitter webhook events.        
        Args:
            payload: Twitter webhook payload
            
        Returns:
            Processing result
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            result = {"processed_events": []}
            
            # Handle tweet creation events (mentions)
            if "tweet_create_events" in payload:
                for event in payload["tweet_create_events"]:
                    event_result = await self._handle_tweet_event(event, payload.get("users", {}))
                    result["processed_events"].append(event_result)
            
            # Handle direct message events
            if "direct_message_events" in payload:
                for event in payload["direct_message_events"]:
                    event_result = await self._handle_direct_message_event(event, payload.get("users", {}))
                    result["processed_events"].append(event_result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error handling Twitter webhook: {e}")
            return {"error": str(e)}
    
    async def parse_command(self, tweet_data: Dict[str, Any]) -> Optional[BotCommand]:
        """
        Parse Twitter mentions/DMs into standardized commands.
        
        Args:
            tweet_data: Twitter event data (tweet or DM)
            
        Returns:
            Standardized BotCommand or None if parsing fails
        """
        try:
            # Create platform command from Twitter data
            platform_command = PlatformCommand(
                platform=self.platform,
                raw_data=tweet_data,
                user_context=self._extract_user_context(tweet_data)
            )
            
            # Parse into standardized command
            bot_command = parse_platform_command(platform_command)
            
            if not bot_command:
                # Try manual parsing for Twitter-specific patterns
                bot_command = await self._manual_parse_twitter_command(tweet_data)
            
            return bot_command
            
        except Exception as e:
            # Use centralized error handling for parsing errors
            raw_command = tweet_data.get("text", "")
            user_id = tweet_data.get("user", {}).get("id_str", "")
            
            error_response = await bot_error_handler_instance.handle_command_parsing_error(
                error=e,
                platform=self.platform,
                raw_command=raw_command,
                user_id=user_id
            )
            
            logger.error(f"Twitter command parsing failed: {e}", extra={
                "error_response": error_response.to_dict(),
                "raw_command": raw_command,
                "user_id": user_id
            })
            return None
    
    async def format_response(self, bot_response: BotResponse) -> FormattedResponse:
        """
        Format BotController response for Twitter (thread, DM, etc.).
        
        Args:
            bot_response: Standardized bot response
            
        Returns:
            Twitter-formatted response
        """
        try:
            # Determine delivery method based on response type and content length
            delivery_method = self._determine_delivery_method(bot_response)
            
            # Format response for Twitter
            formatted_response = format_response_for_platform(
                bot_response, self.platform, delivery_method
            )
            
            # Apply Twitter-specific formatting
            await self._apply_twitter_formatting(formatted_response, bot_response)
            
            return formatted_response
            
        except Exception as e:
            # Use centralized error handling for formatting errors
            return await bot_error_handler_instance.handle_response_formatting_error(
                error=e,
                bot_response=bot_response,
                platform=self.platform,
                delivery_method=DeliveryMethod.REPLY
            )
    
    async def send_response(self, formatted_response: FormattedResponse, 
                          context: Dict[str, Any]) -> bool:
        """
        Send response back to Twitter platform.
        
        Args:
            formatted_response: Platform-formatted response
            context: Context data (tweet_id, user_id, etc.)
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            delivery_method = formatted_response.delivery_method
            response_data = formatted_response.response_data
            
            if delivery_method == DeliveryMethod.REPLY:
                return await self._send_reply(response_data, context)
            elif delivery_method == DeliveryMethod.DM:
                return await self._send_direct_message_response(response_data, context)
            elif delivery_method == DeliveryMethod.THREAD:
                return await self._send_thread(response_data, context)
            else:
                logger.warning(f"Unsupported delivery method for Twitter: {delivery_method}")
                # Fallback to reply
                return await self._send_reply(response_data, context)
                
        except Exception as e:
            logger.error(f"Error sending Twitter response: {e}")
            return False
    
    async def _handle_tweet_event(self, event: Dict[str, Any], users: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle tweet creation event (mentions).
        
        Args:
            event: Tweet event data
            users: User data from webhook
            
        Returns:
            Event processing result
        """
        try:
            tweet_id = event.get("id_str")
            tweet_text = event.get("text", "")
            user_id = event.get("user", {}).get("id_str")
            user_screen_name = event.get("user", {}).get("screen_name")
            
            logger.info(f"Processing tweet mention from @{user_screen_name}: {tweet_text}")
            
            # Resolve or create bot user
            db = next(get_db())
            try:
                bot_user = await get_or_create_bot_user(
                    db=db,
                    platform=PlatformType.TWITTER,
                    platform_user_id=user_id,
                    platform_username=user_screen_name
                )
                
                # Validate subscription access
                validation_result = await self.subscription_validator.validate_bot_user_subscription(
                    db=db,
                    bot_user=bot_user,
                    requested_feature="bot_access"
                )
                
                if not validation_result.is_valid:
                    # Send subscription required message
                    error_response = BotResponse(
                        response_type=ResponseType.ERROR,
                        content=validation_result.error_message or "Subscription required for bot access",
                        metadata={"error_code": "SUBSCRIPTION_REQUIRED"}
                    )
                    formatted_response = await self.format_response(error_response)
                    
                    context = {
                        "tweet_id": tweet_id,
                        "user_id": user_id,
                        "user_screen_name": user_screen_name
                    }
                    
                    await self.send_response(formatted_response, context)
                    
                    return {
                        "type": "tweet_mention",
                        "tweet_id": tweet_id,
                        "action": "subscription_required",
                        "user": user_screen_name,
                        "error": "subscription_required"
                    }
                
            finally:
                db.close()
            
            # Parse command from tweet
            bot_command = await self.parse_command(event)
            
            if not bot_command:
                # No valid command found, send help message
                help_response = self._create_help_response()
                formatted_response = await self.format_response(help_response)
                
                context = {
                    "tweet_id": tweet_id,
                    "user_id": user_id,
                    "user_screen_name": user_screen_name
                }
                
                await self.send_response(formatted_response, context)
                
                return {
                    "type": "tweet_mention",
                    "tweet_id": tweet_id,
                    "action": "help_sent",
                    "user": user_screen_name,
                    "command_type": None
                }
            
            # Process command through gateway (this would route to BotController)
            # For now, we'll create a mock response based on command type
            bot_response = await self._process_bot_command(bot_command)
            
            # Format and send response
            formatted_response = await self.format_response(bot_response)
            
            context = {
                "tweet_id": tweet_id,
                "user_id": user_id,
                "user_screen_name": user_screen_name,
                "original_command": tweet_text
            }
            
            success = await self.send_response(formatted_response, context)
            
            return {
                "type": "tweet_mention",
                "tweet_id": tweet_id,
                "command_type": bot_command.command_type.value,
                "action": "response_sent" if success else "response_failed",
                "user": user_screen_name,
                "success": success
            }
            
        except Exception as e:
            logger.error(f"Error handling tweet event: {e}")
            return {"type": "tweet_mention", "error": str(e)}
    
    async def _handle_direct_message_event(self, event: Dict[str, Any], users: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle direct message event.
        
        Args:
            event: Direct message event data
            users: User data from webhook
            
        Returns:
            Event processing result
        """
        try:
            message_id = event.get("id")
            message_text = event.get("message_create", {}).get("message_data", {}).get("text", "")
            sender_id = event.get("message_create", {}).get("sender_id")
            
            # Don't respond to our own messages
            if sender_id == event.get("message_create", {}).get("target", {}).get("recipient_id"):
                return {"type": "direct_message", "action": "ignored_self"}
            
            logger.info(f"Processing direct message from user {sender_id}: {message_text}")
            
            # Resolve or create bot user
            db = next(get_db())
            try:
                bot_user = await get_or_create_bot_user(
                    db=db,
                    platform=PlatformType.TWITTER,
                    platform_user_id=sender_id,
                    platform_username=None  # Username not available in DM events
                )
                
                # Validate subscription access
                validation_result = await self.subscription_validator.validate_bot_user_subscription(
                    db=db,
                    bot_user=bot_user,
                    requested_feature="bot_access"
                )
                
                if not validation_result.is_valid:
                    # Send subscription required message
                    error_response = BotResponse(
                        response_type=ResponseType.ERROR,
                        content=validation_result.error_message or "Subscription required for bot access",
                        metadata={"error_code": "SUBSCRIPTION_REQUIRED"}
                    )
                    formatted_response = await self.format_response(error_response)
                    
                    context = {
                        "message_id": message_id,
                        "sender_id": sender_id,
                        "is_dm": True
                    }
                    
                    await self.send_response(formatted_response, context)
                    
                    return {
                        "type": "direct_message",
                        "message_id": message_id,
                        "action": "subscription_required",
                        "sender": sender_id,
                        "error": "subscription_required"
                    }
                
            finally:
                db.close()
            
            # Parse command from DM
            bot_command = await self.parse_command(event)
            
            if not bot_command:
                # No valid command found, send help message
                help_response = self._create_help_response()
                formatted_response = await self.format_response(help_response)
                
                context = {
                    "message_id": message_id,
                    "sender_id": sender_id,
                    "is_dm": True
                }
                
                await self.send_response(formatted_response, context)
                
                return {
                    "type": "direct_message",
                    "message_id": message_id,
                    "action": "help_sent",
                    "sender": sender_id,
                    "command_type": None
                }
            
            # Process command through gateway (this would route to BotController)
            bot_response = await self._process_bot_command(bot_command)
            
            # Format and send response
            formatted_response = await self.format_response(bot_response)
            
            context = {
                "message_id": message_id,
                "sender_id": sender_id,
                "is_dm": True,
                "original_command": message_text
            }
            
            success = await self.send_response(formatted_response, context)
            
            return {
                "type": "direct_message",
                "message_id": message_id,
                "command_type": bot_command.command_type.value,
                "action": "response_sent" if success else "response_failed",
                "sender": sender_id,
                "success": success
            }
            
        except Exception as e:
            logger.error(f"Error handling direct message event: {e}")
            return {"type": "direct_message", "error": str(e)}
    
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
    
    def _format_analysis_response(self, url: str, analysis_result: Dict[str, Any], mention_user: Optional[str] = None) -> str:
        """
        Format analysis result into Twitter response.
        
        Args:
            url: Analyzed URL
            analysis_result: Analysis result
            mention_user: User to mention in response (for tweet replies)
            
        Returns:
            Formatted response text
        """
        try:
            risk_level = analysis_result.get("risk_level", "unknown")
            message = analysis_result.get("message", "Analysis completed")
            risk_score = analysis_result.get("risk_score", 0)
            
            # Truncate URL for display
            display_url = url if len(url) <= 30 else url[:27] + "..."
            
            # Build response
            response_parts = []
            
            if mention_user:
                response_parts.append(f"@{mention_user}")
            
            # Add emoji based on risk level
            if risk_level == "high":
                response_parts.append(f"🚨 HIGH RISK: {display_url}")
                response_parts.append("⚠️ This URL may be dangerous - avoid clicking!")
            elif risk_level == "medium":
                response_parts.append(f"⚠️ MEDIUM RISK: {display_url}")
                response_parts.append("🔍 Proceed with caution")
            elif risk_level == "low":
                response_parts.append(f"⚠️ LOW RISK: {display_url}")
                response_parts.append("✅ Generally safe, but be cautious")
            elif risk_level == "safe":
                response_parts.append(f"✅ SAFE: {display_url}")
                response_parts.append("👍 This URL appears to be safe")
            else:
                response_parts.append(f"❓ UNKNOWN: {display_url}")
                response_parts.append("🔍 Could not determine safety - be cautious")
            
            # Add risk score if available
            if risk_score > 0:
                response_parts.append(f"Risk Score: {risk_score}/100")
            
            # Join response parts
            response_text = "\n".join(response_parts)
            
            # Ensure response fits Twitter's character limit
            if len(response_text) > settings.BOT_MAX_RESPONSE_LENGTH:
                # Truncate and add ellipsis
                response_text = response_text[:settings.BOT_MAX_RESPONSE_LENGTH - 3] + "..."
            
            return response_text
            
        except Exception as e:
            logger.error(f"Error formatting analysis response: {e}")
            return f"Error analyzing URL: {url}"
    
    async def _reply_to_tweet(self, tweet_id: str, text: str):
        """
        Reply to a tweet.
        
        Args:
            tweet_id: ID of tweet to reply to
            text: Reply text
        """
        if not self.http_session:
            logger.error("HTTP session not initialized")
            return
        
        try:
            url = f"{self.api_base_url}/tweets"
            payload = {
                "text": text,
                "reply": {
                    "in_reply_to_tweet_id": tweet_id
                }
            }
            
            async with self.http_session.post(url, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Successfully replied to tweet {tweet_id}")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to reply to tweet {tweet_id}: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error replying to tweet {tweet_id}: {e}")
    
    async def _send_direct_message(self, recipient_id: str, text: str):
        """
        Send a direct message.
        
        Args:
            recipient_id: Recipient user ID
            text: Message text
        """
        if not self.http_session:
            logger.error("HTTP session not initialized")
            return
        
        try:
            url = f"{self.api_base_url}/dm_conversations/with/{recipient_id}/messages"
            payload = {
                "text": text,
                "media_id": None
            }
            
            async with self.http_session.post(url, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Successfully sent DM to user {recipient_id}")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to send DM to user {recipient_id}: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error sending DM to user {recipient_id}: {e}")
    
    async def _test_api_connection(self):
        """Test Twitter API connection."""
        if not self.http_session:
            raise Exception("HTTP session not initialized")
        
        try:
            url = f"{self.api_base_url}/users/me"
            async with self.http_session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Twitter API connection successful. Bot user: {data.get('data', {}).get('username', 'unknown')}")
                else:
                    error_text = await response.text()
                    raise Exception(f"Twitter API test failed: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Twitter API connection test failed: {e}")
            raise
    
    # New helper methods for standardized bot command system
    
    def _extract_user_context(self, tweet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract user context from Twitter event data."""
        try:
            if "user" in tweet_data:
                # Tweet event
                return {
                    "user_id": tweet_data["user"].get("id_str"),
                    "screen_name": tweet_data["user"].get("screen_name"),
                    "display_name": tweet_data["user"].get("name"),
                    "verified": tweet_data["user"].get("verified", False),
                    "followers_count": tweet_data["user"].get("followers_count", 0)
                }
            elif "message_create" in tweet_data:
                # DM event
                sender_id = tweet_data["message_create"].get("sender_id")
                return {
                    "user_id": sender_id,
                    "is_dm": True
                }
            else:
                return {}
        except Exception as e:
            logger.error(f"Error extracting user context: {e}")
            return {}
    
    async def _manual_parse_twitter_command(self, tweet_data: Dict[str, Any]) -> Optional[BotCommand]:
        """Manually parse Twitter-specific command patterns."""
        try:
            # Extract text from tweet or DM
            if "text" in tweet_data:
                text = tweet_data["text"]
                user_id = tweet_data.get("user", {}).get("id_str", "")
            elif "message_create" in tweet_data:
                text = tweet_data["message_create"].get("message_data", {}).get("text", "")
                user_id = tweet_data["message_create"].get("sender_id", "")
            else:
                return None
            
            if not text or not user_id:
                return None
            
            text = text.strip().lower()
            
            # Check for account analysis patterns
            if any(pattern in text for pattern in ["@bot analyze", "@bot check", "@bot safety"]):
                # Extract username
                username_match = re.search(r'@(\w+)', text.replace('@bot', ''))
                if username_match:
                    account_identifier = username_match.group(1)
                    return BotCommand(
                        command_type=CommandType.ANALYZE_ACCOUNT,
                        platform=self.platform,
                        user_id=user_id,
                        parameters={"account_identifier": account_identifier},
                        metadata={"original_text": text, "platform_data": tweet_data}
                    )
            
            # Check for compliance check patterns
            elif any(pattern in text for pattern in ["@bot compliance", "@bot check_compliance"]):
                # Extract quoted content
                content_match = re.search(r'"([^"]+)"', text)
                if content_match:
                    content = content_match.group(1)
                    return BotCommand(
                        command_type=CommandType.CHECK_COMPLIANCE,
                        platform=self.platform,
                        user_id=user_id,
                        parameters={"content": content},
                        metadata={"original_text": text, "platform_data": tweet_data}
                    )
            
            # Check for follower analysis patterns
            elif any(pattern in text for pattern in ["@bot followers", "@bot analyze_followers", "@bot verified"]):
                return BotCommand(
                    command_type=CommandType.ANALYZE_FOLLOWERS,
                    platform=self.platform,
                    user_id=user_id,
                    parameters={},
                    metadata={"original_text": text, "platform_data": tweet_data}
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in manual Twitter command parsing: {e}")
            return None
    
    def _create_help_response(self) -> BotResponse:
        """Create a help response for Twitter."""
        help_text = (
            "🛡️ LinkShield Social Protection Bot\n\n"
            "I can help you with:\n"
            "• Account Analysis: @bot analyze @username\n"
            "• Compliance Check: @bot check_compliance \"your content\"\n"
            "• Follower Analysis: @bot analyze_followers\n\n"
            "Stay safe on social media! 🔒"
        )
        
        return BotResponse.success_response(
            data={"message": help_text},
            response_type=ResponseType.ANALYSIS_RESULT,
            formatting_hints={"use_emoji": True, "is_help": True}
        )
    
    async def _process_bot_command(self, bot_command: BotCommand) -> BotResponse:
        """
        Process bot command and return response.
        
        This is a mock implementation - in the real system, this would
        route to the BotController through the gateway.
        """
        try:
            if bot_command.command_type == CommandType.ANALYZE_ACCOUNT:
                account_id = bot_command.get_parameter("account_identifier", "unknown")
                return BotResponse.success_response(
                    data={
                        "risk_level": "medium",
                        "risk_score": 65,
                        "account_identifier": account_id,
                        "analysis_summary": f"Account @{account_id} shows moderate risk indicators",
                        "recommendations": [
                            "Verify account authenticity before engaging",
                            "Check recent activity patterns",
                            "Be cautious with personal information sharing"
                        ]
                    },
                    response_type=ResponseType.ANALYSIS_RESULT,
                    formatting_hints={"risk_level": "medium", "use_emoji": True}
                )
            
            elif bot_command.command_type == CommandType.CHECK_COMPLIANCE:
                content = bot_command.get_parameter("content", "")
                return BotResponse.success_response(
                    data={
                        "is_compliant": True,
                        "compliance_score": 85,
                        "content_preview": content[:50] + "..." if len(content) > 50 else content,
                        "violations": [],
                        "recommendations": ["Content appears to meet platform guidelines"]
                    },
                    response_type=ResponseType.COMPLIANCE_CHECK,
                    formatting_hints={"is_compliant": True, "use_emoji": True}
                )
            
            elif bot_command.command_type == CommandType.ANALYZE_FOLLOWERS:
                return BotResponse.success_response(
                    data={
                        "verified_followers_count": 42,
                        "high_value_count": 8,
                        "total_followers": 1250,
                        "verification_rate": 3.4,
                        "networking_opportunities": [
                            "Connect with verified industry professionals",
                            "Engage with high-influence accounts"
                        ]
                    },
                    response_type=ResponseType.FOLLOWER_ANALYSIS,
                    formatting_hints={"use_emoji": True}
                )
            
            else:
                return BotResponse.error_response(
                    error_message="Unsupported command type",
                    response_type=ResponseType.ERROR
                )
                
        except Exception as e:
            logger.error(f"Error processing bot command: {e}")
            return BotResponse.error_response(
                error_message="An error occurred while processing your request",
                response_type=ResponseType.ERROR
            )
    
    def _determine_delivery_method(self, bot_response: BotResponse) -> DeliveryMethod:
        """Determine the best delivery method for a response."""
        # Check if it's a DM context from formatting hints
        if bot_response.get_formatting_hint("is_dm", False):
            return DeliveryMethod.DM
        
        # Estimate response length
        message = bot_response.get_data("message", "")
        if not message:
            # Build message from data
            if bot_response.response_type == ResponseType.ANALYSIS_RESULT:
                message = f"Analysis result for account analysis"
            elif bot_response.response_type == ResponseType.COMPLIANCE_CHECK:
                message = f"Compliance check result"
            elif bot_response.response_type == ResponseType.FOLLOWER_ANALYSIS:
                message = f"Follower analysis result"
            else:
                message = "Response"
        
        # If message is long, use thread; otherwise use reply
        if len(message) > self.max_tweet_length:
            return DeliveryMethod.THREAD
        else:
            return DeliveryMethod.REPLY
    
    async def _apply_twitter_formatting(self, formatted_response: FormattedResponse, 
                                      bot_response: BotResponse):
        """Apply Twitter-specific formatting to the response."""
        try:
            response_data = formatted_response.response_data
            
            # Add Twitter-specific formatting
            if bot_response.response_type == ResponseType.ANALYSIS_RESULT:
                self._format_analysis_for_twitter(response_data, bot_response)
            elif bot_response.response_type == ResponseType.COMPLIANCE_CHECK:
                self._format_compliance_for_twitter(response_data, bot_response)
            elif bot_response.response_type == ResponseType.FOLLOWER_ANALYSIS:
                self._format_followers_for_twitter(response_data, bot_response)
            
            # Ensure character limits
            if "text" in response_data:
                text = response_data["text"]
                if len(text) > self.max_tweet_length and formatted_response.delivery_method != DeliveryMethod.THREAD:
                    # Truncate and add continuation indicator
                    response_data["text"] = text[:self.max_tweet_length - 4] + "..."
                    formatted_response.add_formatting("truncated")
            
            formatted_response.add_formatting("twitter_specific")
            
        except Exception as e:
            logger.error(f"Error applying Twitter formatting: {e}")
    
    def _format_analysis_for_twitter(self, response_data: Dict[str, Any], bot_response: BotResponse):
        """Format account analysis result for Twitter."""
        risk_level = bot_response.get_data("risk_level", "unknown")
        risk_score = bot_response.get_data("risk_score", 0)
        account_id = bot_response.get_data("account_identifier", "account")
        
        # Get risk indicator emoji
        risk_indicator = CommandRegistry.get_risk_indicator(risk_level)
        
        message = f"{risk_indicator} Account Analysis: @{account_id}\n"
        message += f"Risk Level: {risk_level.title()}\n"
        message += f"Risk Score: {risk_score}/100\n"
        
        recommendations = bot_response.get_data("recommendations", [])
        if recommendations:
            message += f"\nRecommendations:\n"
            for i, rec in enumerate(recommendations[:2], 1):  # Limit for Twitter
                message += f"{i}. {rec}\n"
        
        response_data["text"] = message
    
    def _format_compliance_for_twitter(self, response_data: Dict[str, Any], bot_response: BotResponse):
        """Format compliance check result for Twitter."""
        is_compliant = bot_response.get_data("is_compliant", True)
        compliance_score = bot_response.get_data("compliance_score", 0)
        
        indicator = "✅" if is_compliant else "⚠️"
        
        message = f"{indicator} Compliance Check Result\n"
        message += f"Status: {'Compliant' if is_compliant else 'Issues Found'}\n"
        message += f"Score: {compliance_score}/100\n"
        
        violations = bot_response.get_data("violations", [])
        if violations:
            message += f"\nViolations: {len(violations)} found\n"
        
        response_data["text"] = message
    
    def _format_followers_for_twitter(self, response_data: Dict[str, Any], bot_response: BotResponse):
        """Format follower analysis result for Twitter."""
        verified_count = bot_response.get_data("verified_followers_count", 0)
        high_value_count = bot_response.get_data("high_value_count", 0)
        total_followers = bot_response.get_data("total_followers", 0)
        
        message = f"👥 Follower Analysis Results\n"
        message += f"Verified Followers: {verified_count}\n"
        message += f"High-Value Followers: {high_value_count}\n"
        message += f"Total Followers: {total_followers}\n"
        
        if verified_count > 0:
            verification_rate = (verified_count / total_followers) * 100 if total_followers > 0 else 0
            message += f"Verification Rate: {verification_rate:.1f}%\n"
        
        response_data["text"] = message
    
    async def _send_reply(self, response_data: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Send a reply to a tweet."""
        try:
            tweet_id = context.get("tweet_id")
            user_screen_name = context.get("user_screen_name")
            text = response_data.get("text", "")
            
            if not tweet_id or not text:
                logger.error("Missing tweet_id or text for reply")
                return False
            
            # Add mention if replying to a user
            if user_screen_name and not text.startswith(f"@{user_screen_name}"):
                text = f"@{user_screen_name} {text}"
            
            await self._reply_to_tweet(tweet_id, text)
            return True
            
        except Exception as e:
            logger.error(f"Error sending reply: {e}")
            return False
    
    async def _send_direct_message_response(self, response_data: Dict[str, Any], 
                                          context: Dict[str, Any]) -> bool:
        """Send a direct message response."""
        try:
            sender_id = context.get("sender_id")
            text = response_data.get("text", "")
            
            if not sender_id or not text:
                logger.error("Missing sender_id or text for DM")
                return False
            
            await self._send_direct_message(sender_id, text)
            return True
            
        except Exception as e:
            logger.error(f"Error sending DM response: {e}")
            return False
    
    async def _send_thread(self, response_data: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Send a Twitter thread for long responses."""
        try:
            tweet_id = context.get("tweet_id")
            user_screen_name = context.get("user_screen_name")
            text = response_data.get("text", "")
            
            if not tweet_id or not text:
                logger.error("Missing tweet_id or text for thread")
                return False
            
            # Split text into tweet-sized chunks
            chunks = self._split_text_for_thread(text, user_screen_name)
            
            # Send first tweet as reply
            current_tweet_id = tweet_id
            for i, chunk in enumerate(chunks):
                if i == 0:
                    # First tweet is a reply
                    if user_screen_name and not chunk.startswith(f"@{user_screen_name}"):
                        chunk = f"@{user_screen_name} {chunk}"
                    await self._reply_to_tweet(current_tweet_id, chunk)
                else:
                    # Subsequent tweets are replies to the previous tweet
                    # Note: In a real implementation, we'd need to get the tweet ID of the previous reply
                    # For now, we'll just send as replies to the original tweet
                    chunk = f"{i+1}/{len(chunks)} {chunk}"
                    await self._reply_to_tweet(current_tweet_id, chunk)
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending thread: {e}")
            return False
    
    def _split_text_for_thread(self, text: str, mention_user: Optional[str] = None) -> List[str]:
        """Split long text into Twitter thread chunks."""
        chunks = []
        max_length = self.max_tweet_length
        
        # Reserve space for mention and thread numbering
        if mention_user:
            max_length -= len(f"@{mention_user} ")
        max_length -= 10  # Reserve space for "1/N " numbering
        
        # Simple splitting by sentences or lines
        sentences = text.split('\n')
        current_chunk = ""
        
        for sentence in sentences:
            if len(current_chunk + sentence + '\n') <= max_length:
                current_chunk += sentence + '\n'
            else:
                if current_chunk:
                    chunks.append(current_chunk.strip())
                    current_chunk = sentence + '\n'
                else:
                    # Single sentence is too long, split it
                    while len(sentence) > max_length:
                        chunks.append(sentence[:max_length])
                        sentence = sentence[max_length:]
                    current_chunk = sentence + '\n'
        
        if current_chunk:
            chunks.append(current_chunk.strip())
        
        return chunks if chunks else [text[:max_length]]

    async def shutdown(self):
        """Shutdown the Twitter bot handler."""
        try:
            if self.http_session:
                await self.http_session.close()
                logger.info("Twitter bot handler HTTP session closed")
            
            self.is_initialized = False
            logger.info("Twitter bot handler shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during Twitter bot handler shutdown: {e}")