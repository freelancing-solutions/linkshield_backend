"""
Twitter Bot Handler for processing webhook events and API interactions.

This module handles Twitter webhook events, processes mentions and direct messages,
and provides URL analysis responses through Twitter API.
"""

import logging
import re
import asyncio
from typing import Dict, Any, Optional, List
import aiohttp
from datetime import datetime
# Import here to avoid circular imports
from src.config.settings import settings
from src.bots.gateway import bot_gateway
logger = logging.getLogger(__name__)


class TwitterBotHandler:
    """
    Handler for Twitter bot interactions and webhook processing.
    
    Processes Twitter webhook events including mentions, direct messages,
    and provides URL analysis responses.
    """
    
    def __init__(self):
        """Initialize the Twitter bot handler."""
        self.bearer_token = settings.TWITTER_BOT_BEARER_TOKEN
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.api_base_url = "https://api.twitter.com/2"
        self.is_initialized = False
        
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
            
            # Extract URLs from tweet text
            urls = self._extract_urls(tweet_text)
            
            if not urls:
                # No URLs found, send help message
                response_text = ("👋 Hi! I can help analyze URLs for security threats. "
                               "Just mention me with a URL and I'll check it for you! "
                               "Example: @linkshield_bot https://example.com")        
                await self._reply_to_tweet(tweet_id, response_text)
                
                return {
                    "type": "tweet_mention",
                    "tweet_id": tweet_id,
                    "action": "help_sent",
                    "user": user_screen_name
                }
            
            # Analyze the first URL found
            url = urls[0]
            
            

            analysis_result = await bot_gateway.analyze_url_quick(url, user_id, "twitter")
            
            # Format response based on analysis
            response_text = self._format_analysis_response(url, analysis_result, user_screen_name)
            
            # Reply to the tweet
            await self._reply_to_tweet(tweet_id, response_text)
            
            return {
                "type": "tweet_mention",
                "tweet_id": tweet_id,
                "url_analyzed": url,
                "risk_level": analysis_result.get("risk_level", "unknown"),
                "action": "analysis_sent",
                "user": user_screen_name
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
            
            # Extract URLs from message
            urls = self._extract_urls(message_text)
            
            if not urls:
                # No URLs found, send help message
                response_text = ("Hi! I can analyze URLs for security threats. "
                               "Just send me a URL and I'll check it for you!")
                
                await self._send_direct_message(sender_id, response_text)
                
                return {
                    "type": "direct_message",
                    "message_id": message_id,
                    "action": "help_sent",
                    "sender": sender_id
                }
            
            # Analyze the first URL found
            url = urls[0]
            
            # Import here to avoid circular imports
            from ...bots.gateway import bot_gateway
            analysis_result = await bot_gateway.analyze_url_quick(url, sender_id, "twitter")
            
            # Format response
            response_text = self._format_analysis_response(url, analysis_result)
            
            # Send direct message response
            await self._send_direct_message(sender_id, response_text)
            
            return {
                "type": "direct_message",
                "message_id": message_id,
                "url_analyzed": url,
                "risk_level": analysis_result.get("risk_level", "unknown"),
                "action": "analysis_sent",
                "sender": sender_id
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