"""
QuickAccessBotGateway for coordinating bot platforms and handling quick analysis requests.

This module provides a centralized gateway for managing bot interactions across
Twitter, Telegram, and Discord platforms with fast response times.
"""

import asyncio
import logging
from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta

from ..config.settings import settings
from ..services.quick_analysis_service import QuickAnalysisService
from ..models.bot import BotInteraction, BotUser
from ..config.database import get_db_session

logger = logging.getLogger(__name__)


class QuickAccessBotGateway:
    """
    Central gateway for coordinating bot interactions across multiple platforms.
    
    Handles quick analysis requests with sub-3-second response times and manages
    platform-specific bot handlers for Twitter, Telegram, and Discord.
    """
    
    def __init__(self):
        """Initialize the bot gateway with platform handlers and services."""
        self.quick_analysis_service = QuickAnalysisService()
        self.platform_handlers: Dict[str, Any] = {}
        self.rate_limiter: Dict[str, List[datetime]] = {}
        self.is_initialized = False
        
    async def initialize(self):
        """Initialize all platform handlers and services."""
        if self.is_initialized:
            return
            
        try:
            # Initialize platform handlers
            await self._initialize_platform_handlers()
            
            # Initialize quick analysis service
            await self.quick_analysis_service.initialize()
            
            self.is_initialized = True
            logger.info("QuickAccessBotGateway initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize QuickAccessBotGateway: {e}")
            raise
    
    async def _initialize_platform_handlers(self):
        """Initialize platform-specific bot handlers."""
        # Import handlers dynamically to avoid circular imports
        from .handlers.twitter_bot_handler import TwitterBotHandler
        from .handlers.telegram_bot_handler import TelegramBotHandler
        from .handlers.discord_bot_handler import DiscordBotHandler
        
        # Initialize Twitter handler if token is available
        if settings.TWITTER_BOT_BEARER_TOKEN:
            self.platform_handlers['twitter'] = TwitterBotHandler()
            await self.platform_handlers['twitter'].initialize()
            logger.info("Twitter bot handler initialized")
        
        # Initialize Telegram handler if token is available
        if settings.TELEGRAM_BOT_TOKEN:
            self.platform_handlers['telegram'] = TelegramBotHandler()
            await self.platform_handlers['telegram'].initialize()
            logger.info("Telegram bot handler initialized")
        
        # Initialize Discord handler if token is available
        if settings.DISCORD_BOT_TOKEN:
            self.platform_handlers['discord'] = DiscordBotHandler()
            await self.platform_handlers['discord'].initialize()
            logger.info("Discord bot handler initialized")
    
    async def handle_webhook(self, platform: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle incoming webhook from a specific platform.
        
        Args:
            platform: Platform name (twitter, telegram, discord)
            payload: Webhook payload data
            
        Returns:
            Response data for the webhook
        """
        if not self.is_initialized:
            await self.initialize()
        
        # Check if platform handler exists
        if platform not in self.platform_handlers:
            logger.warning(f"No handler found for platform: {platform}")
            return {"error": f"Platform {platform} not supported"}
        
        try:
            # Apply rate limiting
            if not await self._check_rate_limit(platform, payload):
                return {"error": "Rate limit exceeded"}
            
            # Process webhook through platform handler
            handler = self.platform_handlers[platform]
            response = await handler.handle_webhook(payload)
            
            # Log interaction
            await self._log_interaction(platform, payload, response)
            
            return response
            
        except Exception as e:
            logger.error(f"Error handling {platform} webhook: {e}")
            return {"error": "Internal server error"}
    
    async def analyze_url_quick(self, url: str, user_id: str, platform: str) -> Dict[str, Any]:
        """
        Perform quick URL analysis with sub-3-second response time.
        
        Args:
            url: URL to analyze
            user_id: User identifier from the platform
            platform: Platform name (twitter, telegram, discord)
            
        Returns:
            Quick analysis results
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            # Start analysis with timeout
            analysis_task = asyncio.create_task(
                self.quick_analysis_service.analyze_url(url)
            )
            
            # Wait for analysis with timeout
            try:
                result = await asyncio.wait_for(
                    analysis_task,
                    timeout=settings.QUICK_ANALYSIS_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                # Return cached result or basic analysis if timeout
                result = await self.quick_analysis_service.get_cached_result(url)
                if not result:
                    result = {
                        "status": "timeout",
                        "risk_level": "unknown",
                        "message": "Analysis timed out, please try again later"
                    }
            
            # Log the analysis request
            await self._log_analysis_request(url, user_id, platform, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in quick URL analysis: {e}")
            return {
                "status": "error",
                "risk_level": "unknown",
                "message": "Analysis failed, please try again later"
            }
    
    async def get_user_stats(self, user_id: str, platform: str) -> Dict[str, Any]:
        """
        Get user statistics for bot interactions.
        
        Args:
            user_id: User identifier from the platform
            platform: Platform name
            
        Returns:
            User statistics
        """
        try:
            async with get_db_session() as session:
                # Query user interactions from database
                # This would be implemented based on the BotUser and BotInteraction models
                stats = {
                    "total_requests": 0,
                    "urls_analyzed": 0,
                    "threats_detected": 0,
                    "last_activity": None
                }
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return {"error": "Failed to retrieve user statistics"}
    
    async def _check_rate_limit(self, platform: str, payload: Dict[str, Any]) -> bool:
        """
        Check if the request is within rate limits.
        
        Args:
            platform: Platform name
            payload: Request payload
            
        Returns:
            True if within rate limits, False otherwise
        """
        # Extract user identifier from payload (platform-specific)
        user_key = f"{platform}:user"  # This would be more specific based on payload
        
        now = datetime.utcnow()
        minute_ago = now - timedelta(minutes=1)
        
        # Initialize rate limiter for user if not exists
        if user_key not in self.rate_limiter:
            self.rate_limiter[user_key] = []
        
        # Clean old requests
        self.rate_limiter[user_key] = [
            req_time for req_time in self.rate_limiter[user_key]
            if req_time > minute_ago
        ]
        
        # Check if within rate limit
        if len(self.rate_limiter[user_key]) >= settings.BOT_RATE_LIMIT_PER_MINUTE:
            return False
        
        # Add current request
        self.rate_limiter[user_key].append(now)
        return True
    
    async def _log_interaction(self, platform: str, payload: Dict[str, Any], response: Dict[str, Any]):
        """
        Log bot interaction to database.
        
        Args:
            platform: Platform name
            payload: Request payload
            response: Response data
        """
        try:
            # This would create a BotInteraction record in the database
            # Implementation depends on the database models
            logger.info(f"Bot interaction logged for platform: {platform}")
            
        except Exception as e:
            logger.error(f"Error logging interaction: {e}")
    
    async def _log_analysis_request(self, url: str, user_id: str, platform: str, result: Dict[str, Any]):
        """
        Log URL analysis request to database.
        
        Args:
            url: Analyzed URL
            user_id: User identifier
            platform: Platform name
            result: Analysis result
        """
        try:
            # This would create analysis log records in the database
            logger.info(f"Analysis request logged: {url} for user {user_id} on {platform}")
            
        except Exception as e:
            logger.error(f"Error logging analysis request: {e}")
    
    async def shutdown(self):
        """Shutdown the bot gateway and cleanup resources."""
        try:
            # Shutdown platform handlers
            for platform, handler in self.platform_handlers.items():
                if hasattr(handler, 'shutdown'):
                    await handler.shutdown()
                    logger.info(f"{platform} handler shutdown")
            
            # Shutdown quick analysis service
            if hasattr(self.quick_analysis_service, 'shutdown'):
                await self.quick_analysis_service.shutdown()
            
            self.is_initialized = False
            logger.info("QuickAccessBotGateway shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during gateway shutdown: {e}")


# Global gateway instance
bot_gateway = QuickAccessBotGateway()