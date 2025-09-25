"""
Bot Controller for handling bot business logic and coordination.

This module provides high-level business logic for bot operations,
coordinating between different services and managing bot workflows.
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import hashlib
import json

from sqlalchemy.orm import Session
from ..database.connection import get_db
from ..models.bot import (
    BotUser, BotAnalysisRequest, BotRateLimit, BotSession, 
    BotAnalyticsEvent, get_or_create_bot_user, update_user_stats, 
    check_rate_limit
)
from ..services.quick_analysis_service import QuickAnalysisService
from ..config.settings import settings

logger = logging.getLogger(__name__)


class BotController:
    """
    Controller for managing bot operations and business logic.
    
    Coordinates between bot handlers, analysis services, and database operations
    to provide a unified interface for bot functionality.
    """
    
    def __init__(self):
        """Initialize the bot controller."""
        self.quick_analysis_service = QuickAnalysisService()
        self.is_initialized = False
        
    async def initialize(self):
        """Initialize the bot controller and its dependencies."""
        if self.is_initialized:
            return
            
        try:
            await self.quick_analysis_service.initialize()
            self.is_initialized = True
            logger.info("Bot controller initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize bot controller: {e}")
            raise
    
    async def process_url_analysis(self, url: str, user_id: str, platform: str, 
                                 request_type: str = "quick") -> Dict[str, Any]:
        """
        Process a URL analysis request from a bot user.
        
        Args:
            url: URL to analyze
            user_id: Platform-specific user ID
            platform: Platform name (twitter, telegram, discord)
            request_type: Type of analysis (quick, deep)
            
        Returns:
            Analysis result with metadata
        """
        if not self.is_initialized:
            await self.initialize()
        
        start_time = datetime.utcnow()
        db_session = None
        
        try:
            # Get database session
            db_session = next(get_db())
            
            # Get or create bot user
            bot_user = get_or_create_bot_user(db_session, platform, user_id)
            
            # Check rate limits
            is_allowed, rate_limit = check_rate_limit(db_session, bot_user, platform)
            if not is_allowed:
                return {
                    "success": False,
                    "error": "rate_limit_exceeded",
                    "message": "You have exceeded the rate limit. Please try again later.",
                    "retry_after": rate_limit.blocked_until.isoformat() if rate_limit.blocked_until else None
                }
            
            # Create URL hash for deduplication and caching
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            
            # Check for recent analysis of the same URL by the same user
            recent_analysis = db_session.query(BotAnalysisRequest).filter(
                BotAnalysisRequest.user_id == bot_user.id,
                BotAnalysisRequest.url_hash == url_hash,
                BotAnalysisRequest.requested_at > datetime.utcnow() - timedelta(hours=1)
            ).first()
            
            if recent_analysis and recent_analysis.risk_level:
                # Return cached result
                analysis_result = {
                    "success": True,
                    "risk_level": recent_analysis.risk_level,
                    "risk_score": recent_analysis.risk_score or 0,
                    "message": recent_analysis.analysis_message or "Analysis completed",
                    "cached": True,
                    "analyzed_at": recent_analysis.completed_at.isoformat() if recent_analysis.completed_at else None
                }
                
                # Log analytics event
                await self._log_analytics_event(
                    db_session, bot_user.id, "analysis_completed", "user_action", 
                    platform, {"url_hash": url_hash, "cached": True}
                )
                
                return analysis_result
            
            # Create analysis request record
            analysis_request = BotAnalysisRequest(
                user_id=bot_user.id,
                url=url,
                url_hash=url_hash,
                platform=platform,
                request_type=request_type
            )
            db_session.add(analysis_request)
            db_session.commit()
            db_session.refresh(analysis_request)
            
            # Perform analysis
            if request_type == "quick":
                analysis_result = await self.quick_analysis_service.analyze_url(url)
            else:
                # For deep analysis, we would call a different service
                # For now, fall back to quick analysis
                analysis_result = await self.quick_analysis_service.analyze_url(url)
            
            # Calculate analysis duration
            end_time = datetime.utcnow()
            duration_ms = int((end_time - start_time).total_seconds() * 1000)
            
            # Update analysis request with results
            analysis_request.risk_level = analysis_result.get("risk_level", "unknown")
            analysis_request.risk_score = analysis_result.get("risk_score", 0)
            analysis_request.analysis_message = analysis_result.get("message", "Analysis completed")
            analysis_request.threats_detected = json.dumps(analysis_result.get("threats", []))
            analysis_request.analysis_duration_ms = duration_ms
            analysis_request.cache_hit = analysis_result.get("cached", False)
            analysis_request.error_occurred = not analysis_result.get("success", True)
            analysis_request.completed_at = end_time
            
            if analysis_request.error_occurred:
                analysis_request.error_message = analysis_result.get("error", "Unknown error")
            
            db_session.commit()
            
            # Update user statistics
            if analysis_result.get("success", True):
                update_user_stats(db_session, bot_user, analysis_request.risk_level)
            
            # Log analytics event
            await self._log_analytics_event(
                db_session, bot_user.id, "analysis_completed", "user_action",
                platform, {
                    "url_hash": url_hash,
                    "risk_level": analysis_request.risk_level,
                    "duration_ms": duration_ms,
                    "cached": analysis_request.cache_hit
                }
            )
            
            # Prepare response
            response = {
                "success": analysis_result.get("success", True),
                "risk_level": analysis_request.risk_level,
                "risk_score": analysis_request.risk_score,
                "message": analysis_request.analysis_message,
                "threats": analysis_result.get("threats", []),
                "cached": analysis_request.cache_hit,
                "analysis_duration_ms": duration_ms,
                "analyzed_at": end_time.isoformat()
            }
            
            if analysis_request.error_occurred:
                response["error"] = analysis_request.error_message
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing URL analysis: {e}")
            
            # Log error analytics event
            if db_session:
                try:
                    bot_user = get_or_create_bot_user(db_session, platform, user_id)
                    await self._log_analytics_event(
                        db_session, bot_user.id, "analysis_error", "error",
                        platform, {"error": str(e), "url_hash": hashlib.sha256(url.encode()).hexdigest()}
                    )
                except:
                    pass  # Don't let analytics logging errors break the main flow
            
            return {
                "success": False,
                "error": "analysis_failed",
                "message": "An error occurred while analyzing the URL. Please try again later.",
                "risk_level": "unknown"
            }
            
        finally:
            if db_session:
                db_session.close()
    
    async def get_user_statistics(self, user_id: str, platform: str) -> Dict[str, Any]:
        """
        Get statistics for a bot user.
        
        Args:
            user_id: Platform-specific user ID
            platform: Platform name
            
        Returns:
            User statistics
        """
        db_session = None
        
        try:
            db_session = next(get_db())
            
            # Get bot user
            bot_user = get_or_create_bot_user(db_session, platform, user_id)
            
            # Get recent analysis requests
            recent_analyses = db_session.query(BotAnalysisRequest).filter(
                BotAnalysisRequest.user_id == bot_user.id,
                BotAnalysisRequest.requested_at > datetime.utcnow() - timedelta(days=30)
            ).count()
            
            # Prepare statistics
            stats = {
                "total_analyzed": bot_user.total_analyses,
                "safe_count": bot_user.safe_urls_count,
                "risky_count": bot_user.risky_urls_count,
                "recent_analyses_30d": recent_analyses,
                "last_analysis": bot_user.last_analysis_at.strftime("%Y-%m-%d %H:%M:%S") if bot_user.last_analysis_at else "Never",
                "member_since": bot_user.created_at.strftime("%Y-%m-%d"),
                "notifications_enabled": bot_user.notifications_enabled,
                "deep_analysis_enabled": bot_user.deep_analysis_enabled
            }
            
            # Log analytics event
            await self._log_analytics_event(
                db_session, bot_user.id, "stats_viewed", "user_action",
                platform, {"stats_requested": True}
            )
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting user statistics: {e}")
            return {
                "total_analyzed": 0,
                "safe_count": 0,
                "risky_count": 0,
                "recent_analyses_30d": 0,
                "last_analysis": "Never",
                "member_since": "Unknown",
                "notifications_enabled": True,
                "deep_analysis_enabled": False
            }
            
        finally:
            if db_session:
                db_session.close()
    
    async def update_user_preferences(self, user_id: str, platform: str, 
                                    preferences: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update user preferences.
        
        Args:
            user_id: Platform-specific user ID
            platform: Platform name
            preferences: Dictionary of preferences to update
            
        Returns:
            Update result
        """
        db_session = None
        
        try:
            db_session = next(get_db())
            
            # Get bot user
            bot_user = get_or_create_bot_user(db_session, platform, user_id)
            
            # Update preferences
            if "notifications_enabled" in preferences:
                bot_user.notifications_enabled = bool(preferences["notifications_enabled"])
            
            if "deep_analysis_enabled" in preferences:
                bot_user.deep_analysis_enabled = bool(preferences["deep_analysis_enabled"])
            
            if "language_preference" in preferences:
                bot_user.language_preference = str(preferences["language_preference"])[:10]
            
            bot_user.updated_at = datetime.utcnow()
            db_session.commit()
            
            # Log analytics event
            await self._log_analytics_event(
                db_session, bot_user.id, "preferences_updated", "user_action",
                platform, {"preferences": preferences}
            )
            
            return {
                "success": True,
                "message": "Preferences updated successfully",
                "preferences": {
                    "notifications_enabled": bot_user.notifications_enabled,
                    "deep_analysis_enabled": bot_user.deep_analysis_enabled,
                    "language_preference": bot_user.language_preference
                }
            }
            
        except Exception as e:
            logger.error(f"Error updating user preferences: {e}")
            return {
                "success": False,
                "error": "update_failed",
                "message": "Failed to update preferences. Please try again later."
            }
            
        finally:
            if db_session:
                db_session.close()
    
    async def get_platform_analytics(self, platform: str, days: int = 7) -> Dict[str, Any]:
        """
        Get analytics for a specific platform.
        
        Args:
            platform: Platform name
            days: Number of days to include in analytics
            
        Returns:
            Platform analytics
        """
        db_session = None
        
        try:
            db_session = next(get_db())
            
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get analysis requests
            total_requests = db_session.query(BotAnalysisRequest).filter(
                BotAnalysisRequest.platform == platform,
                BotAnalysisRequest.requested_at >= start_date
            ).count()
            
            successful_requests = db_session.query(BotAnalysisRequest).filter(
                BotAnalysisRequest.platform == platform,
                BotAnalysisRequest.requested_at >= start_date,
                BotAnalysisRequest.error_occurred == False
            ).count()
            
            # Get active users
            active_users = db_session.query(BotUser).filter(
                BotUser.platform == platform,
                BotUser.last_analysis_at >= start_date
            ).count()
            
            # Get risk level distribution
            risk_levels = db_session.query(
                BotAnalysisRequest.risk_level,
                db_session.query(BotAnalysisRequest).filter(
                    BotAnalysisRequest.platform == platform,
                    BotAnalysisRequest.requested_at >= start_date,
                    BotAnalysisRequest.risk_level == BotAnalysisRequest.risk_level
                ).count().label('count')
            ).filter(
                BotAnalysisRequest.platform == platform,
                BotAnalysisRequest.requested_at >= start_date
            ).group_by(BotAnalysisRequest.risk_level).all()
            
            risk_distribution = {level: count for level, count in risk_levels}
            
            # Calculate average response time
            avg_duration = db_session.query(
                db_session.query(BotAnalysisRequest.analysis_duration_ms).filter(
                    BotAnalysisRequest.platform == platform,
                    BotAnalysisRequest.requested_at >= start_date,
                    BotAnalysisRequest.analysis_duration_ms.isnot(None)
                ).subquery().c.analysis_duration_ms
            ).scalar() or 0
            
            return {
                "platform": platform,
                "period_days": days,
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "success_rate": (successful_requests / total_requests * 100) if total_requests > 0 else 0,
                "active_users": active_users,
                "risk_distribution": risk_distribution,
                "average_response_time_ms": avg_duration,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting platform analytics: {e}")
            return {
                "platform": platform,
                "period_days": days,
                "error": str(e),
                "generated_at": datetime.utcnow().isoformat()
            }
            
        finally:
            if db_session:
                db_session.close()
    
    async def handle_bot_command(self, command: str, args: List[str], user_id: str, 
                                platform: str) -> Dict[str, Any]:
        """
        Handle bot commands from users.
        
        Args:
            command: Command name
            args: Command arguments
            user_id: Platform-specific user ID
            platform: Platform name
            
        Returns:
            Command result
        """
        db_session = None
        
        try:
            db_session = next(get_db())
            
            # Get bot user
            bot_user = get_or_create_bot_user(db_session, platform, user_id)
            
            # Log command usage
            await self._log_analytics_event(
                db_session, bot_user.id, "command_used", "user_action",
                platform, {"command": command, "args_count": len(args)}
            )
            
            # Handle different commands
            if command == "help":
                return await self._handle_help_command(platform)
            
            elif command == "stats":
                return await self.get_user_statistics(user_id, platform)
            
            elif command == "analyze":
                if not args:
                    return {
                        "success": False,
                        "error": "missing_url",
                        "message": "Please provide a URL to analyze."
                    }
                
                url = args[0]
                return await self.process_url_analysis(url, user_id, platform)
            
            elif command == "preferences":
                if not args:
                    # Get current preferences
                    stats = await self.get_user_statistics(user_id, platform)
                    return {
                        "success": True,
                        "preferences": {
                            "notifications_enabled": stats.get("notifications_enabled", True),
                            "deep_analysis_enabled": stats.get("deep_analysis_enabled", False)
                        }
                    }
                else:
                    # Update preferences
                    prefs = {}
                    for arg in args:
                        if "=" in arg:
                            key, value = arg.split("=", 1)
                            if key in ["notifications_enabled", "deep_analysis_enabled"]:
                                prefs[key] = value.lower() in ["true", "1", "yes", "on"]
                    
                    return await self.update_user_preferences(user_id, platform, prefs)
            
            else:
                return {
                    "success": False,
                    "error": "unknown_command",
                    "message": f"Unknown command: {command}. Use 'help' to see available commands."
                }
                
        except Exception as e:
            logger.error(f"Error handling bot command: {e}")
            return {
                "success": False,
                "error": "command_failed",
                "message": "An error occurred while processing the command."
            }
            
        finally:
            if db_session:
                db_session.close()
    
    async def _handle_help_command(self, platform: str) -> Dict[str, Any]:
        """Handle help command."""
        help_text = {
            "twitter": (
                "🛡️ LinkShield Security Bot\n\n"
                "I help analyze URLs for security threats and malware.\n\n"
                "Commands:\n"
                "• Mention me with a URL to analyze it\n"
                "• Send me a DM with a URL for private analysis\n\n"
                "Stay safe online! 🔒"
            ),
            "telegram": (
                "🛡️ LinkShield Security Bot\n\n"
                "I help analyze URLs for security threats and malware.\n\n"
                "Commands:\n"
                "/start - Show welcome message\n"
                "/help - Show this help\n"
                "/analyze <url> - Analyze a URL\n"
                "/stats - Show your statistics\n\n"
                "You can also just send me any URL to analyze it!\n\n"
                "Stay safe online! 🔒"
            ),
            "discord": (
                "🛡️ LinkShield Security Bot\n\n"
                "I help analyze URLs for security threats and malware.\n\n"
                "Commands:\n"
                "/analyze <url> - Analyze a URL for threats\n"
                "/help - Show this help message\n"
                "/stats - Show your analysis statistics\n\n"
                "Stay safe online! 🔒"
            )
        }
        
        return {
            "success": True,
            "message": help_text.get(platform, help_text["telegram"])
        }
    
    async def _log_analytics_event(self, db_session: Session, user_id: Optional[int], 
                                 event_type: str, event_category: str, platform: str, 
                                 event_data: Dict[str, Any]):
        """Log an analytics event."""
        try:
            event = BotAnalyticsEvent(
                user_id=user_id,
                event_type=event_type,
                event_category=event_category,
                platform=platform,
                event_data=json.dumps(event_data),
                success=True
            )
            db_session.add(event)
            db_session.commit()
            
        except Exception as e:
            logger.error(f"Error logging analytics event: {e}")
            # Don't raise the exception to avoid breaking the main flow
    
    async def shutdown(self):
        """Shutdown the bot controller."""
        try:
            if self.quick_analysis_service:
                await self.quick_analysis_service.shutdown()
            
            self.is_initialized = False
            logger.info("Bot controller shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during bot controller shutdown: {e}")


# Global bot controller instance
bot_controller = BotController()