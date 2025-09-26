"""
Extension Controller for Social Protection

This controller provides a specialized facade for browser extension integration,
focusing on real-time content analysis, extension data processing, and seamless
browser-to-backend communication.
"""

import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from fastapi import HTTPException, status, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.authentication.auth_service import AuthService
from src.controllers.base_controller import BaseController
from src.models.user import User, UserRole
from src.models.project import Project
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.social_protection.types import PlatformType, RiskLevel, ScanStatus
from src.social_protection.data_models import ContentRiskAssessment, ContentType
from src.social_protection.services import SocialScanService
from src.social_protection.content_analyzer import (
    ContentRiskAnalyzer, LinkPenaltyDetector, SpamPatternDetector, CommunityNotesAnalyzer
)
from src.social_protection.algorithm_health import (
    VisibilityScorer, EngagementAnalyzer, PenaltyDetector, ShadowBanDetector
)
from src.utils import utc_datetime
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class ExtensionEventType(Enum):
    """Types of extension events"""
    PAGE_LOAD = "page_load"
    CONTENT_CHANGE = "content_change"
    LINK_HOVER = "link_hover"
    POST_COMPOSE = "post_compose"
    PROFILE_VIEW = "profile_view"
    FEED_SCROLL = "feed_scroll"
    INTERACTION = "interaction"


class ExtensionAnalysisMode(Enum):
    """Analysis modes for extension requests"""
    REAL_TIME = "real_time"
    BACKGROUND = "background"
    ON_DEMAND = "on_demand"
    BATCH = "batch"


class ExtensionResponseType(Enum):
    """Response types for extension communication"""
    IMMEDIATE = "immediate"
    PROGRESSIVE = "progressive"
    CACHED = "cached"
    DEFERRED = "deferred"


class ExtensionController(BaseController):
    """
    Specialized controller for browser extension integration.
    
    This controller provides optimized endpoints for browser extensions,
    focusing on real-time analysis, efficient data processing, and
    seamless user experience integration.
    """
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        social_scan_service: SocialScanService,
        content_risk_analyzer: ContentRiskAnalyzer,
        link_penalty_detector: LinkPenaltyDetector,
        spam_pattern_detector: SpamPatternDetector,
        community_notes_analyzer: CommunityNotesAnalyzer,
        visibility_scorer: VisibilityScorer,
        engagement_analyzer: EngagementAnalyzer,
        penalty_detector: PenaltyDetector,
        shadow_ban_detector: ShadowBanDetector
    ):
        """Initialize extension controller with all required services"""
        super().__init__(security_service, auth_service, email_service)
        
        # Core services
        self.social_scan_service = social_scan_service
        
        # Content analyzer services
        self.content_risk_analyzer = content_risk_analyzer
        self.link_penalty_detector = link_penalty_detector
        self.spam_pattern_detector = spam_pattern_detector
        self.community_notes_analyzer = community_notes_analyzer
        
        # Algorithm health services
        self.visibility_scorer = visibility_scorer
        self.engagement_analyzer = engagement_analyzer
        self.penalty_detector = penalty_detector
        self.shadow_ban_detector = shadow_ban_detector
        
        # Extension-specific rate limits (optimized for real-time usage)
        self.max_realtime_requests_per_minute = 60
        self.max_background_requests_per_hour = 500
        self.max_batch_items = 20
        
        # Response caching for extension performance
        self._response_cache = {}
        self._cache_ttl = 180  # 3 minutes for extension responses
        
        # Extension session tracking
        self._active_sessions = {}
    
    async def process_extension_data(
        self,
        user: User,
        extension_data: Dict[str, Any],
        analysis_mode: ExtensionAnalysisMode = ExtensionAnalysisMode.REAL_TIME,
        response_type: ExtensionResponseType = ExtensionResponseType.IMMEDIATE,
        background_tasks: Optional[BackgroundTasks] = None,
        request: Optional[Request] = None
    ) -> Dict[str, Any]:
        """
        Process data from browser extension with optimized analysis
        
        Args:
            user: User from extension
            extension_data: Data sent from extension
            analysis_mode: Mode of analysis to perform
            response_type: Type of response expected
            background_tasks: FastAPI background tasks
            request: HTTP request object
            
        Returns:
            Dict containing processed extension data and analysis
        """
        try:
            # Validate extension data
            required_fields = ["event_type", "platform", "url", "timestamp"]
            missing_fields = [field for field in required_fields if field not in extension_data]
            if missing_fields:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Missing extension data fields: {missing_fields}"
                )
            
            # Check rate limits based on analysis mode
            rate_limit_key = f"extension_{analysis_mode.value}"
            if analysis_mode == ExtensionAnalysisMode.REAL_TIME:
                rate_limit = self.max_realtime_requests_per_minute
                window = 60
            else:
                rate_limit = self.max_background_requests_per_hour
                window = 3600
            
            if not await self.check_rate_limit(user.id, rate_limit_key, rate_limit, window_seconds=window):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Extension rate limit exceeded for {analysis_mode.value} mode"
                )
            
            # Parse extension event
            event_type = ExtensionEventType(extension_data["event_type"])
            platform = PlatformType(extension_data["platform"])
            
            # Track extension session
            session_id = extension_data.get("session_id", str(uuid.uuid4()))
            await self._track_extension_session(user.id, session_id, event_type, platform)
            
            # Process based on event type and analysis mode
            processing_result = await self._process_extension_event(
                user, event_type, platform, extension_data, analysis_mode
            )
            
            # Handle response type
            if response_type == ExtensionResponseType.IMMEDIATE:
                response = await self._format_immediate_response(processing_result, extension_data)
            elif response_type == ExtensionResponseType.PROGRESSIVE:
                response = await self._format_progressive_response(processing_result, extension_data)
                # Schedule additional processing if needed
                if background_tasks:
                    background_tasks.add_task(
                        self._continue_progressive_analysis,
                        user.id, session_id, processing_result
                    )
            elif response_type == ExtensionResponseType.CACHED:
                response = await self._get_or_create_cached_response(processing_result, extension_data)
            else:  # DEFERRED
                response = await self._format_deferred_response(processing_result, extension_data)
                if background_tasks:
                    background_tasks.add_task(
                        self._process_deferred_analysis,
                        user.id, session_id, extension_data, processing_result
                    )
            
            # Add extension-specific metadata
            response["extension_metadata"] = {
                "session_id": session_id,
                "event_type": event_type.value,
                "analysis_mode": analysis_mode.value,
                "response_type": response_type.value,
                "processing_time": processing_result.get("processing_time", 0.0),
                "cached": processing_result.get("from_cache", False)
            }
            
            self.log_operation(
                "Extension data processed",
                user_id=user.id,
                details={
                    "event_type": event_type.value,
                    "platform": platform.value,
                    "analysis_mode": analysis_mode.value,
                    "response_type": response_type.value,
                    "session_id": session_id
                }
            )
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error processing extension data: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to process extension data"
            )
    
    async def analyze_content_real_time(
        self,
        user: User,
        content_data: Dict[str, Any],
        platform: PlatformType,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform real-time content analysis for extension
        
        Args:
            user: User requesting analysis
            content_data: Content to analyze
            platform: Platform context
            context: Additional context from extension
            
        Returns:
            Dict containing real-time analysis results
        """
        try:
            # Check real-time rate limits
            if not await self.check_rate_limit(
                user.id, "extension_realtime_analysis", 
                self.max_realtime_requests_per_minute, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Real-time analysis rate limit exceeded"
                )
            
            # Validate content data
            if not content_data.get("content"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Content is required for analysis"
                )
            
            content = content_data["content"]
            
            # Check cache first for performance
            cache_key = self._generate_content_cache_key(content, platform)
            cached_result = self._get_cached_analysis(cache_key)
            if cached_result:
                return self._format_cached_analysis_response(cached_result)
            
            # Perform lightweight analysis optimized for real-time
            start_time = utc_datetime()
            
            # Quick risk assessment (most important for real-time)
            risk_analysis = await self._quick_risk_assessment(content, platform, context)
            
            # Link safety check if content contains links
            link_analysis = None
            if content_data.get("links"):
                link_analysis = await self._quick_link_safety_check(
                    content_data["links"], platform
                )
            
            # Spam detection (lightweight version)
            spam_analysis = await self._quick_spam_detection(content, platform)
            
            processing_time = (utc_datetime() - start_time).total_seconds()
            
            # Compile real-time analysis result
            analysis_result = {
                "overall_risk_score": risk_analysis["risk_score"],
                "risk_level": risk_analysis["risk_level"],
                "primary_concerns": risk_analysis.get("primary_concerns", []),
                "link_safety": link_analysis,
                "spam_indicators": spam_analysis,
                "processing_time": processing_time,
                "confidence": self._calculate_confidence_score(risk_analysis, link_analysis, spam_analysis)
            }
            
            # Cache result for performance
            self._cache_analysis_result(cache_key, analysis_result)
            
            # Format response for extension
            response = {
                "success": True,
                "analysis": analysis_result,
                "recommendations": await self._generate_realtime_recommendations(analysis_result),
                "ui_indicators": await self._generate_ui_indicators(analysis_result, platform),
                "timestamp": utc_datetime().isoformat()
            }
            
            self.log_operation(
                "Real-time content analysis completed",
                user_id=user.id,
                details={
                    "platform": platform.value,
                    "risk_score": analysis_result["overall_risk_score"],
                    "processing_time": processing_time,
                    "has_links": link_analysis is not None
                }
            )
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in real-time content analysis: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Real-time analysis failed"
            )
    
    async def get_extension_settings(
        self,
        user: User,
        extension_version: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get extension-specific settings and configuration
        
        Args:
            user: User requesting settings
            extension_version: Version of the extension
            
        Returns:
            Dict containing extension settings
        """
        try:
            # Get user's subscription-based settings
            subscription_features = {
                "real_time_analysis": True,
                "advanced_warnings": user.subscription_plan == "premium",
                "batch_analysis": user.subscription_plan == "premium",
                "custom_rules": user.subscription_plan == "premium",
                "detailed_reports": user.subscription_plan == "premium",
                "priority_support": user.subscription_plan == "premium"
            }
            
            # Extension configuration
            extension_config = {
                "user_id": str(user.id),
                "subscription_plan": user.subscription_plan or "free",
                "features": subscription_features,
                "rate_limits": {
                    "real_time_requests_per_minute": self.max_realtime_requests_per_minute,
                    "background_requests_per_hour": self.max_background_requests_per_hour,
                    "batch_size_limit": self.max_batch_items
                },
                "ui_preferences": {
                    "show_risk_indicators": True,
                    "show_detailed_warnings": subscription_features["advanced_warnings"],
                    "auto_scan_enabled": user.subscription_plan == "premium",
                    "notification_level": "medium",
                    "theme": "auto"
                },
                "platform_settings": {
                    "twitter": {"enabled": True, "auto_scan": False},
                    "instagram": {"enabled": True, "auto_scan": False},
                    "facebook": {"enabled": True, "auto_scan": False},
                    "linkedin": {"enabled": True, "auto_scan": False},
                    "tiktok": {"enabled": False, "auto_scan": False},
                    "discord": {"enabled": False, "auto_scan": False}
                },
                "analysis_settings": {
                    "risk_threshold": 0.7,
                    "spam_sensitivity": "medium",
                    "link_checking": True,
                    "content_monitoring": True,
                    "algorithm_tracking": subscription_features["advanced_warnings"]
                },
                "cache_settings": {
                    "enable_caching": True,
                    "cache_duration": self._cache_ttl,
                    "max_cache_size": 100
                }
            }
            
            # Add version-specific configurations
            if extension_version:
                extension_config["version_info"] = {
                    "current_version": extension_version,
                    "minimum_supported": "1.0.0",
                    "update_available": False,  # Would check against latest version
                    "compatibility": "full"
                }
            
            self.log_operation(
                "Extension settings retrieved",
                user_id=user.id,
                details={
                    "extension_version": extension_version,
                    "subscription_plan": user.subscription_plan,
                    "features_enabled": len([k for k, v in subscription_features.items() if v])
                }
            )
            
            return {
                "success": True,
                "settings": extension_config,
                "last_updated": utc_datetime().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error retrieving extension settings: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve extension settings"
            )
    
    async def update_extension_settings(
        self,
        user: User,
        settings_update: Dict[str, Any],
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Update extension-specific settings
        
        Args:
            user: User updating settings
            settings_update: Settings to update
            db: Database session
            
        Returns:
            Dict containing updated settings
        """
        try:
            # Validate settings update
            allowed_sections = {
                "ui_preferences", "platform_settings", "analysis_settings", "cache_settings"
            }
            
            invalid_sections = set(settings_update.keys()) - allowed_sections
            if invalid_sections:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid settings sections: {list(invalid_sections)}"
                )
            
            # Apply subscription-based restrictions
            if user.subscription_plan != "premium":
                restricted_settings = {
                    "ui_preferences.show_detailed_warnings": False,
                    "platform_settings.*.auto_scan": False,
                    "analysis_settings.algorithm_tracking": False
                }
                
                # Override restricted settings for free users
                for section, updates in settings_update.items():
                    if isinstance(updates, dict):
                        for key, value in updates.items():
                            restriction_key = f"{section}.{key}"
                            if restriction_key in restricted_settings:
                                settings_update[section][key] = restricted_settings[restriction_key]
            
            # Validate specific settings
            if "analysis_settings" in settings_update:
                analysis_settings = settings_update["analysis_settings"]
                
                # Validate risk threshold
                if "risk_threshold" in analysis_settings:
                    threshold = analysis_settings["risk_threshold"]
                    if not isinstance(threshold, (int, float)) or not 0.0 <= threshold <= 1.0:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Risk threshold must be between 0.0 and 1.0"
                        )
                
                # Validate spam sensitivity
                if "spam_sensitivity" in analysis_settings:
                    sensitivity = analysis_settings["spam_sensitivity"]
                    if sensitivity not in ["low", "medium", "high"]:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Spam sensitivity must be 'low', 'medium', or 'high'"
                        )
            
            # Store updated settings (in real implementation, update database)
            # For now, simulate successful update
            
            # Get updated settings
            updated_settings = await self.get_extension_settings(user)
            
            self.log_operation(
                "Extension settings updated",
                user_id=user.id,
                details={
                    "updated_sections": list(settings_update.keys()),
                    "subscription_plan": user.subscription_plan
                }
            )
            
            return {
                "success": True,
                "message": "Extension settings updated successfully",
                "settings": updated_settings["settings"],
                "updated_at": utc_datetime().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating extension settings: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update extension settings"
            )
    
    async def get_extension_analytics(
        self,
        user: User,
        time_range: str = "24h",
        include_details: bool = False
    ) -> Dict[str, Any]:
        """
        Get analytics for extension usage and protection
        
        Args:
            user: User requesting analytics
            time_range: Time range for analytics
            include_details: Whether to include detailed breakdown
            
        Returns:
            Dict containing extension analytics
        """
        try:
            # Validate time range
            valid_ranges = ["1h", "24h", "7d", "30d"]
            if time_range not in valid_ranges:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid time range. Must be one of: {valid_ranges}"
                )
            
            # Calculate time range
            time_delta_map = {
                "1h": timedelta(hours=1),
                "24h": timedelta(days=1),
                "7d": timedelta(days=7),
                "30d": timedelta(days=30)
            }
            
            start_time = utc_datetime() - time_delta_map[time_range]
            
            # Get extension analytics data (mock data for now)
            analytics_data = await self._get_extension_analytics_data(user, start_time)
            
            # Compile analytics summary
            analytics_summary = {
                "time_range": time_range,
                "period": {
                    "start": start_time.isoformat(),
                    "end": utc_datetime().isoformat()
                },
                "usage_stats": {
                    "total_requests": analytics_data.get("total_requests", 0),
                    "real_time_analyses": analytics_data.get("real_time_analyses", 0),
                    "background_analyses": analytics_data.get("background_analyses", 0),
                    "cached_responses": analytics_data.get("cached_responses", 0),
                    "average_response_time": analytics_data.get("avg_response_time", 0.0)
                },
                "protection_stats": {
                    "threats_detected": analytics_data.get("threats_detected", 0),
                    "high_risk_content": analytics_data.get("high_risk_content", 0),
                    "spam_blocked": analytics_data.get("spam_blocked", 0),
                    "unsafe_links": analytics_data.get("unsafe_links", 0)
                },
                "platform_breakdown": analytics_data.get("platform_breakdown", {}),
                "performance_metrics": {
                    "cache_hit_rate": analytics_data.get("cache_hit_rate", 0.0),
                    "success_rate": analytics_data.get("success_rate", 0.0),
                    "error_rate": analytics_data.get("error_rate", 0.0)
                }
            }
            
            # Add detailed breakdown if requested
            if include_details:
                analytics_summary["detailed_breakdown"] = {
                    "hourly_usage": analytics_data.get("hourly_breakdown", []),
                    "risk_distribution": analytics_data.get("risk_distribution", {}),
                    "event_types": analytics_data.get("event_types", {}),
                    "response_times": analytics_data.get("response_time_distribution", {})
                }
            
            self.log_operation(
                "Extension analytics retrieved",
                user_id=user.id,
                details={
                    "time_range": time_range,
                    "include_details": include_details,
                    "total_requests": analytics_summary["usage_stats"]["total_requests"]
                }
            )
            
            return {
                "success": True,
                "analytics": analytics_summary,
                "generated_at": utc_datetime().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error retrieving extension analytics: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve extension analytics"
            )
    
    async def sync_extension_state(
        self,
        user: User,
        extension_state: Dict[str, Any],
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sync extension state with backend
        
        Args:
            user: User syncing state
            extension_state: Current extension state
            session_id: Extension session ID
            
        Returns:
            Dict containing sync results and updated state
        """
        try:
            # Validate extension state
            required_fields = ["version", "active_tabs", "settings_hash"]
            missing_fields = [field for field in required_fields if field not in extension_state]
            if missing_fields:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Missing extension state fields: {missing_fields}"
                )
            
            session_id = session_id or str(uuid.uuid4())
            
            # Process active tabs and update session tracking
            active_tabs = extension_state.get("active_tabs", [])
            for tab in active_tabs:
                if "platform" in tab and "url" in tab:
                    try:
                        platform = PlatformType(tab["platform"])
                        await self._update_tab_tracking(user.id, session_id, platform, tab)
                    except ValueError:
                        # Skip invalid platforms
                        continue
            
            # Check for settings synchronization
            settings_hash = extension_state.get("settings_hash")
            current_settings = await self.get_extension_settings(user)
            current_hash = self._calculate_settings_hash(current_settings["settings"])
            
            sync_result = {
                "session_id": session_id,
                "sync_timestamp": utc_datetime().isoformat(),
                "settings_synchronized": settings_hash == current_hash,
                "active_tabs_count": len(active_tabs),
                "backend_state": {
                    "settings_hash": current_hash,
                    "last_activity": utc_datetime().isoformat(),
                    "session_active": True
                }
            }
            
            # If settings are out of sync, provide updated settings
            if not sync_result["settings_synchronized"]:
                sync_result["updated_settings"] = current_settings["settings"]
                sync_result["sync_required"] = True
            else:
                sync_result["sync_required"] = False
            
            # Update session tracking
            await self._update_extension_session(user.id, session_id, extension_state)
            
            self.log_operation(
                "Extension state synchronized",
                user_id=user.id,
                details={
                    "session_id": session_id,
                    "active_tabs": len(active_tabs),
                    "settings_synchronized": sync_result["settings_synchronized"],
                    "sync_required": sync_result["sync_required"]
                }
            )
            
            return {
                "success": True,
                "sync_result": sync_result
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error syncing extension state: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to sync extension state"
            )
    
    # Helper methods
    
    async def _track_extension_session(
        self,
        user_id: uuid.UUID,
        session_id: str,
        event_type: ExtensionEventType,
        platform: PlatformType
    ) -> None:
        """Track extension session activity"""
        session_key = f"{user_id}:{session_id}"
        
        if session_key not in self._active_sessions:
            self._active_sessions[session_key] = {
                "user_id": user_id,
                "session_id": session_id,
                "start_time": utc_datetime(),
                "last_activity": utc_datetime(),
                "event_count": 0,
                "platforms": set(),
                "events": []
            }
        
        session = self._active_sessions[session_key]
        session["last_activity"] = utc_datetime()
        session["event_count"] += 1
        session["platforms"].add(platform.value)
        session["events"].append({
            "type": event_type.value,
            "platform": platform.value,
            "timestamp": utc_datetime().isoformat()
        })
        
        # Keep only recent events (last 100)
        if len(session["events"]) > 100:
            session["events"] = session["events"][-100:]
    
    async def _process_extension_event(
        self,
        user: User,
        event_type: ExtensionEventType,
        platform: PlatformType,
        extension_data: Dict[str, Any],
        analysis_mode: ExtensionAnalysisMode
    ) -> Dict[str, Any]:
        """Process extension event based on type and mode"""
        
        start_time = utc_datetime()
        
        if event_type == ExtensionEventType.POST_COMPOSE:
            # Analyze content being composed
            content = extension_data.get("content", "")
            if content:
                result = await self._quick_risk_assessment(content, platform, extension_data)
            else:
                result = {"risk_score": 0.0, "risk_level": "low", "message": "No content to analyze"}
        
        elif event_type == ExtensionEventType.LINK_HOVER:
            # Quick link safety check
            link = extension_data.get("link", "")
            if link:
                result = await self._quick_link_safety_check([link], platform)
            else:
                result = {"safe": True, "message": "No link to analyze"}
        
        elif event_type == ExtensionEventType.PROFILE_VIEW:
            # Basic profile risk assessment
            profile_data = extension_data.get("profile", {})
            result = await self._quick_profile_assessment(profile_data, platform)
        
        elif event_type == ExtensionEventType.CONTENT_CHANGE:
            # Monitor content changes for real-time analysis
            content = extension_data.get("content", "")
            if content and analysis_mode == ExtensionAnalysisMode.REAL_TIME:
                result = await self._quick_risk_assessment(content, platform, extension_data)
            else:
                result = {"status": "monitored", "analysis_deferred": True}
        
        else:
            # Default processing for other events
            result = {
                "event_processed": True,
                "event_type": event_type.value,
                "platform": platform.value,
                "analysis_mode": analysis_mode.value
            }
        
        processing_time = (utc_datetime() - start_time).total_seconds()
        result["processing_time"] = processing_time
        
        return result
    
    async def _quick_risk_assessment(
        self,
        content: str,
        platform: PlatformType,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Perform quick risk assessment optimized for real-time"""
        try:
            # Use lightweight version of content risk analyzer
            risk_result = await self.content_risk_analyzer.analyze_content_risk(
                content, platform, context or {}
            )
            
            return {
                "risk_score": risk_result.overall_risk_score,
                "risk_level": risk_result.risk_level.value,
                "primary_concerns": [
                    factor.risk_type for factor in risk_result.risk_factors[:3]
                ],
                "confidence": risk_result.confidence
            }
        except Exception as e:
            logger.error(f"Quick risk assessment failed: {str(e)}")
            return {
                "risk_score": 0.0,
                "risk_level": "unknown",
                "error": "Assessment failed",
                "confidence": 0.0
            }
    
    async def _quick_link_safety_check(
        self,
        links: List[str],
        platform: PlatformType
    ) -> Dict[str, Any]:
        """Perform quick link safety check"""
        try:
            # Use lightweight version of link penalty detector
            penalty_result = await self.link_penalty_detector.detect_link_penalties(
                links, platform, {}
            )
            
            return {
                "safe": penalty_result.penalty_score < 0.5,
                "penalty_score": penalty_result.penalty_score,
                "risky_links": penalty_result.affected_links,
                "warnings": penalty_result.recommendations[:2]  # Limit for real-time
            }
        except Exception as e:
            logger.error(f"Quick link safety check failed: {str(e)}")
            return {
                "safe": True,
                "error": "Safety check failed",
                "penalty_score": 0.0
            }
    
    async def _quick_spam_detection(
        self,
        content: str,
        platform: PlatformType
    ) -> Dict[str, Any]:
        """Perform quick spam detection"""
        try:
            spam_result = await self.spam_pattern_detector.detect_spam_patterns(
                content, platform, {}
            )
            
            return {
                "is_spam": spam_result.spam_score > 0.7,
                "spam_score": spam_result.spam_score,
                "detected_patterns": [
                    pattern.pattern_type for pattern in spam_result.detected_patterns[:3]
                ]
            }
        except Exception as e:
            logger.error(f"Quick spam detection failed: {str(e)}")
            return {
                "is_spam": False,
                "spam_score": 0.0,
                "error": "Spam detection failed"
            }
    
    async def _quick_profile_assessment(
        self,
        profile_data: Dict[str, Any],
        platform: PlatformType
    ) -> Dict[str, Any]:
        """Perform quick profile risk assessment"""
        # Basic profile risk indicators
        risk_indicators = []
        risk_score = 0.0
        
        # Check for suspicious profile characteristics
        if profile_data.get("follower_count", 0) == 0:
            risk_indicators.append("no_followers")
            risk_score += 0.2
        
        if profile_data.get("verified", False) is False:
            risk_indicators.append("unverified")
            risk_score += 0.1
        
        if not profile_data.get("profile_image"):
            risk_indicators.append("no_profile_image")
            risk_score += 0.1
        
        return {
            "risk_score": min(risk_score, 1.0),
            "risk_level": "high" if risk_score > 0.7 else "medium" if risk_score > 0.3 else "low",
            "risk_indicators": risk_indicators,
            "profile_analysis": "basic"
        }
    
    def _generate_content_cache_key(self, content: str, platform: PlatformType) -> str:
        """Generate cache key for content analysis"""
        import hashlib
        content_hash = hashlib.md5(content.encode()).hexdigest()
        return f"extension_content:{platform.value}:{content_hash}"
    
    def _get_cached_analysis(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis result"""
        if cache_key in self._response_cache:
            cached_data = self._response_cache[cache_key]
            if utc_datetime().timestamp() - cached_data["timestamp"] < self._cache_ttl:
                return cached_data["result"]
            else:
                del self._response_cache[cache_key]
        return None
    
    def _cache_analysis_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Cache analysis result"""
        self._response_cache[cache_key] = {
            "result": result,
            "timestamp": utc_datetime().timestamp()
        }
        
        # Simple cache cleanup
        if len(self._response_cache) > 500:
            oldest_key = min(
                self._response_cache.keys(),
                key=lambda k: self._response_cache[k]["timestamp"]
            )
            del self._response_cache[oldest_key]
    
    def _calculate_confidence_score(
        self,
        risk_analysis: Dict[str, Any],
        link_analysis: Optional[Dict[str, Any]],
        spam_analysis: Dict[str, Any]
    ) -> float:
        """Calculate overall confidence score for analysis"""
        confidence_scores = []
        
        if "confidence" in risk_analysis:
            confidence_scores.append(risk_analysis["confidence"])
        
        if spam_analysis.get("spam_score", 0) > 0:
            confidence_scores.append(0.8)  # High confidence for spam detection
        
        if link_analysis and not link_analysis.get("error"):
            confidence_scores.append(0.9)  # High confidence for link analysis
        
        return sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.5
    
    async def _generate_realtime_recommendations(
        self,
        analysis_result: Dict[str, Any]
    ) -> List[str]:
        """Generate real-time recommendations for extension UI"""
        recommendations = []
        
        risk_score = analysis_result.get("overall_risk_score", 0.0)
        
        if risk_score > 0.8:
            recommendations.append("⚠️ High risk content detected - review before posting")
        elif risk_score > 0.5:
            recommendations.append("⚡ Medium risk detected - consider revising content")
        
        if analysis_result.get("spam_indicators", {}).get("is_spam"):
            recommendations.append("🚫 Spam patterns detected - content may be restricted")
        
        if analysis_result.get("link_safety", {}).get("safe") is False:
            recommendations.append("🔗 Unsafe links detected - verify before sharing")
        
        return recommendations[:3]  # Limit for UI
    
    async def _generate_ui_indicators(
        self,
        analysis_result: Dict[str, Any],
        platform: PlatformType
    ) -> Dict[str, Any]:
        """Generate UI indicators for extension"""
        risk_score = analysis_result.get("overall_risk_score", 0.0)
        
        return {
            "risk_indicator": {
                "color": "red" if risk_score > 0.7 else "yellow" if risk_score > 0.3 else "green",
                "icon": "warning" if risk_score > 0.5 else "info",
                "text": f"Risk: {analysis_result.get('risk_level', 'low').title()}"
            },
            "badges": [
                {"type": "spam", "show": analysis_result.get("spam_indicators", {}).get("is_spam", False)},
                {"type": "unsafe_links", "show": not analysis_result.get("link_safety", {}).get("safe", True)}
            ],
            "tooltip": f"Content risk score: {risk_score:.1f}/1.0"
        }
    
    async def _format_immediate_response(
        self,
        processing_result: Dict[str, Any],
        extension_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Format immediate response for extension"""
        return {
            "success": True,
            "result": processing_result,
            "response_type": "immediate",
            "timestamp": utc_datetime().isoformat()
        }
    
    async def _format_progressive_response(
        self,
        processing_result: Dict[str, Any],
        extension_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Format progressive response for extension"""
        return {
            "success": True,
            "initial_result": processing_result,
            "response_type": "progressive",
            "more_analysis_pending": True,
            "timestamp": utc_datetime().isoformat()
        }
    
    async def _get_or_create_cached_response(
        self,
        processing_result: Dict[str, Any],
        extension_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Get or create cached response"""
        return {
            "success": True,
            "result": processing_result,
            "response_type": "cached",
            "from_cache": processing_result.get("from_cache", False),
            "timestamp": utc_datetime().isoformat()
        }
    
    async def _format_deferred_response(
        self,
        processing_result: Dict[str, Any],
        extension_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Format deferred response for extension"""
        return {
            "success": True,
            "acknowledgment": "Request received and queued for processing",
            "response_type": "deferred",
            "processing_id": str(uuid.uuid4()),
            "timestamp": utc_datetime().isoformat()
        }
    
    async def _continue_progressive_analysis(
        self,
        user_id: uuid.UUID,
        session_id: str,
        initial_result: Dict[str, Any]
    ) -> None:
        """Continue progressive analysis in background"""
        try:
            # Perform additional analysis
            logger.info(f"Continuing progressive analysis for session {session_id}")
            # Implementation would perform deeper analysis
        except Exception as e:
            logger.error(f"Progressive analysis failed: {str(e)}")
    
    async def _process_deferred_analysis(
        self,
        user_id: uuid.UUID,
        session_id: str,
        extension_data: Dict[str, Any],
        initial_result: Dict[str, Any]
    ) -> None:
        """Process deferred analysis in background"""
        try:
            # Perform comprehensive analysis
            logger.info(f"Processing deferred analysis for session {session_id}")
            # Implementation would perform full analysis
        except Exception as e:
            logger.error(f"Deferred analysis failed: {str(e)}")
    
    async def _get_extension_analytics_data(
        self,
        user: User,
        start_time: datetime
    ) -> Dict[str, Any]:
        """Get extension analytics data"""
        # Mock data for now - in real implementation, query database
        return {
            "total_requests": 250,
            "real_time_analyses": 180,
            "background_analyses": 70,
            "cached_responses": 85,
            "avg_response_time": 0.08,
            "threats_detected": 12,
            "high_risk_content": 8,
            "spam_blocked": 15,
            "unsafe_links": 5,
            "platform_breakdown": {
                "twitter": 120,
                "instagram": 80,
                "facebook": 30,
                "linkedin": 20
            },
            "cache_hit_rate": 0.34,
            "success_rate": 0.96,
            "error_rate": 0.04
        }
    
    async def _update_tab_tracking(
        self,
        user_id: uuid.UUID,
        session_id: str,
        platform: PlatformType,
        tab_data: Dict[str, Any]
    ) -> None:
        """Update tab tracking information"""
        # Implementation would track active tabs
        pass
    
    async def _update_extension_session(
        self,
        user_id: uuid.UUID,
        session_id: str,
        extension_state: Dict[str, Any]
    ) -> None:
        """Update extension session with current state"""
        session_key = f"{user_id}:{session_id}"
        if session_key in self._active_sessions:
            self._active_sessions[session_key]["last_sync"] = utc_datetime()
            self._active_sessions[session_key]["state"] = extension_state
    
    def _calculate_settings_hash(self, settings: Dict[str, Any]) -> str:
        """Calculate hash of settings for synchronization"""
        import hashlib
        settings_str = json.dumps(settings, sort_keys=True)
        return hashlib.md5(settings_str.encode()).hexdigest()
    
    def _format_cached_analysis_response(self, cached_result: Dict[str, Any]) -> Dict[str, Any]:
        """Format cached analysis response"""
        return {
            "success": True,
            "analysis": cached_result,
            "from_cache": True,
            "timestamp": utc_datetime().isoformat()
        }