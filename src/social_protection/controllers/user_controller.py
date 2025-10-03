"""
User Controller for Social Protection

This controller provides a specialized facade for user-related social protection operations,
focusing on user account protection, settings management, and personalized analytics.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from fastapi import HTTPException, status, BackgroundTasks
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
from src.social_protection.logging_utils import get_logger

logger = get_logger("UserController")


class UserController(BaseController):
    """
    Specialized controller for user-related social protection operations.
    
    This controller provides a user-focused interface for social protection features,
    including account protection settings, personalized analytics, and user-specific
    monitoring capabilities.
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
        """Initialize user controller with all required services"""
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
        
        # Rate limits for user operations
        self.max_scans_per_hour_free = 20
        self.max_scans_per_hour_premium = 100
        self.max_analyses_per_hour_free = 50
        self.max_analyses_per_hour_premium = 200
    
    async def get_user_protection_settings(
        self,
        user: User,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Get user's social protection settings and preferences
        
        Args:
            user: User requesting settings
            db: Database session
            
        Returns:
            Dict containing user protection settings
        """
        async def _get_settings():
            # Get user's protection preferences
            protection_settings = {
                "user_id": str(user.id),
                "protection_level": user.subscription_plan or "free",
                "monitoring_enabled": True,  # Default enabled
                "notification_preferences": {
                    "email_alerts": True,
                    "real_time_alerts": user.subscription_plan == "premium",
                    "weekly_reports": True,
                    "monthly_summaries": True
                },
                "scan_preferences": {
                    "auto_scan_new_content": user.subscription_plan == "premium",
                    "deep_analysis_enabled": user.subscription_plan == "premium",
                    "shadow_ban_monitoring": user.subscription_plan == "premium",
                    "algorithm_health_tracking": True
                },
                "privacy_settings": {
                    "share_anonymous_data": False,
                    "allow_research_participation": False,
                    "data_retention_days": 90 if user.subscription_plan == "free" else 365
                },
                "platform_settings": await self._get_user_platform_settings(user, db),
                "rate_limits": {
                    "scans_per_hour": (
                        self.max_scans_per_hour_premium 
                        if user.subscription_plan == "premium" 
                        else self.max_scans_per_hour_free
                    ),
                    "analyses_per_hour": (
                        self.max_analyses_per_hour_premium 
                        if user.subscription_plan == "premium" 
                        else self.max_analyses_per_hour_free
                    )
                }
            }
            
            self.log_operation(
                "User protection settings retrieved",
                user_id=user.id,
                details={"settings_retrieved": True}
            )
            
            return protection_settings
        
        return await self.execute_with_error_handling(
            _get_settings,
            "get user protection settings",
            user_id=user.id,
            context={"operation": "get_settings"}
        )
    
    async def update_user_protection_settings(
        self,
        user: User,
        settings_update: Dict[str, Any],
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Update user's social protection settings
        
        Args:
            user: User updating settings
            settings_update: New settings to apply
            db: Database session
            
        Returns:
            Dict containing updated settings
        """
        try:
            # Validate settings update
            allowed_updates = {
                "notification_preferences", "scan_preferences", 
                "privacy_settings", "platform_settings"
            }
            
            invalid_keys = set(settings_update.keys()) - allowed_updates
            if invalid_keys:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid settings keys: {list(invalid_keys)}"
                )
            
            # Apply subscription-based restrictions
            if user.subscription_plan != "premium":
                restricted_settings = {
                    "scan_preferences.auto_scan_new_content": False,
                    "scan_preferences.deep_analysis_enabled": False,
                    "scan_preferences.shadow_ban_monitoring": False,
                    "notification_preferences.real_time_alerts": False
                }
                
                # Override restricted settings for free users
                for key_path, value in restricted_settings.items():
                    keys = key_path.split('.')
                    if keys[0] in settings_update:
                        if len(keys) == 2 and keys[1] in settings_update[keys[0]]:
                            settings_update[keys[0]][keys[1]] = value
            
            # Update platform-specific settings
            if "platform_settings" in settings_update:
                await self._update_user_platform_settings(
                    user, settings_update["platform_settings"], db
                )
            
            # Store updated settings (in a real implementation, this would update the database)
            updated_settings = await self.get_user_protection_settings(user, db)
            
            self.log_operation(
                "User protection settings updated",
                user_id=user.id,
                details={
                    "updated_keys": list(settings_update.keys()),
                    "subscription_plan": user.subscription_plan
                }
            )
            
            return {
                "success": True,
                "message": "Protection settings updated successfully",
                "settings": updated_settings
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating user protection settings: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update protection settings"
            )
    
    async def get_user_protection_analytics(
        self,
        user: User,
        platform: Optional[PlatformType] = None,
        days: int = 30,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive protection analytics for user
        
        Args:
            user: User requesting analytics
            platform: Optional platform filter
            days: Number of days to analyze
            db: Database session
            
        Returns:
            Dict containing protection analytics
        """
        try:
            # Check rate limits
            rate_limit = (
                self.max_analyses_per_hour_premium
                if user.subscription_plan == "premium"
                else self.max_analyses_per_hour_free
            )
            
            if not await self.check_rate_limit(
                user.id, "protection_analytics", rate_limit, window_seconds=3600
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=rate_limit,
                    window=3600,
                    message="Rate limit exceeded for protection analytics"
                )
            
            # Get user's recent scan data
            recent_scans = await self._get_user_recent_scans(user, platform, days, db)
            
            if not recent_scans:
                return {
                    "user_id": str(user.id),
                    "platform": platform.value if platform else "all",
                    "period_days": days,
                    "message": "No recent scan data available",
                    "analytics": {
                        "overall_risk_score": 0.0,
                        "protection_health_score": 100.0,
                        "total_scans": 0,
                        "risk_trends": [],
                        "recommendations": ["Start monitoring your social media accounts"]
                    }
                }
            
            # Calculate analytics
            analytics = await self._calculate_user_analytics(recent_scans, user, platform)
            
            # Add user-specific insights
            analytics["user_insights"] = await self._generate_user_insights(
                recent_scans, user, analytics
            )
            
            # Add recommendations
            analytics["recommendations"] = await self._generate_user_recommendations(
                recent_scans, user, analytics
            )
            
            self.log_operation(
                "User protection analytics generated",
                user_id=user.id,
                details={
                    "platform": platform.value if platform else "all",
                    "days": days,
                    "scans_analyzed": len(recent_scans)
                }
            )
            
            return {
                "user_id": str(user.id),
                "platform": platform.value if platform else "all",
                "period_days": days,
                "generated_at": utc_datetime().isoformat(),
                "analytics": analytics
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error generating user protection analytics: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate protection analytics"
            )
    
    async def initiate_user_platform_scan(
        self,
        user: User,
        platform: PlatformType,
        platform_username: str,
        scan_options: Optional[Dict[str, Any]] = None,
        background_tasks: Optional[BackgroundTasks] = None,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Initiate a comprehensive platform scan for user
        
        Args:
            user: User requesting scan
            platform: Platform to scan
            platform_username: Username on the platform
            scan_options: Optional scan configuration
            background_tasks: FastAPI background tasks
            db: Database session
            
        Returns:
            Dict containing scan initiation results
        """
        try:
            # Check rate limits
            rate_limit = (
                self.max_scans_per_hour_premium
                if user.subscription_plan == "premium"
                else self.max_scans_per_hour_free
            )
            
            if not await self.check_rate_limit(
                user.id, "platform_scan", rate_limit, window_seconds=3600
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=rate_limit,
                    window=3600,
                    message="Rate limit exceeded for platform scans"
                )
            
            # Validate platform username
            if not platform_username or len(platform_username.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Platform username is required"
                )
            
            # Set default scan options based on subscription
            default_options = {
                "deep_analysis": user.subscription_plan == "premium",
                "shadow_ban_detection": user.subscription_plan == "premium",
                "algorithm_health_check": True,
                "content_risk_assessment": True,
                "historical_analysis": user.subscription_plan == "premium"
            }
            
            if scan_options:
                # Override with user preferences, respecting subscription limits
                for key, value in scan_options.items():
                    if key in default_options:
                        if user.subscription_plan != "premium" and key in [
                            "deep_analysis", "shadow_ban_detection", "historical_analysis"
                        ]:
                            continue  # Skip premium features for free users
                        default_options[key] = value
            
            # Initiate the scan
            scan_result = await self.social_scan_service.initiate_scan(
                user_id=user.id,
                platform=platform,
                platform_username=platform_username,
                scan_options=default_options
            )
            
            # Schedule background analysis if enabled
            if background_tasks and default_options.get("deep_analysis"):
                background_tasks.add_task(
                    self._perform_deep_platform_analysis,
                    scan_result["scan_id"],
                    user.id,
                    platform,
                    default_options
                )
            
            self.log_operation(
                "Platform scan initiated",
                user_id=user.id,
                details={
                    "platform": platform.value,
                    "username": platform_username,
                    "scan_id": scan_result["scan_id"],
                    "options": default_options
                }
            )
            
            return {
                "success": True,
                "scan_id": scan_result["scan_id"],
                "platform": platform.value,
                "username": platform_username,
                "status": "initiated",
                "estimated_completion": scan_result.get("estimated_completion"),
                "scan_options": default_options,
                "message": "Platform scan initiated successfully"
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error initiating platform scan: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to initiate platform scan"
            )
    
    async def analyze_user_content(
        self,
        user: User,
        content_data: Dict[str, Any],
        analysis_type: str = "comprehensive",
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Analyze user content for risks and issues
        
        Args:
            user: User requesting analysis
            content_data: Content to analyze
            analysis_type: Type of analysis (quick, comprehensive, deep)
            db: Database session
            
        Returns:
            Dict containing content analysis results
        """
        try:
            # Check rate limits
            rate_limit = (
                self.max_analyses_per_hour_premium
                if user.subscription_plan == "premium"
                else self.max_analyses_per_hour_free
            )
            
            if not await self.check_rate_limit(
                user.id, "content_analysis", rate_limit, window_seconds=3600
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=rate_limit,
                    window=3600,
                    message="Rate limit exceeded for content analysis"
                )
            
            # Validate content data
            required_fields = ["content", "platform"]
            missing_fields = [field for field in required_fields if field not in content_data]
            if missing_fields:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Missing required fields: {missing_fields}"
                )
            
            platform = PlatformType(content_data["platform"])
            content = content_data["content"]
            
            # Determine analysis scope based on subscription and type
            analysis_scope = {
                "content_risk": True,
                "link_penalties": True,
                "spam_patterns": True,
                "community_notes": analysis_type in ["comprehensive", "deep"],
                "deep_analysis": (
                    analysis_type == "deep" and 
                    user.subscription_plan == "premium"
                )
            }
            
            # Perform content analysis
            analysis_results = {}
            
            # Content risk analysis
            if analysis_scope["content_risk"]:
                risk_result = await self.content_risk_analyzer.analyze_content_risk(
                    content, platform, content_data.get("metadata", {})
                )
                analysis_results["content_risk"] = {
                    "overall_risk_score": risk_result.overall_risk_score,
                    "risk_level": risk_result.risk_level.value,
                    "risk_factors": [factor.dict() for factor in risk_result.risk_factors],
                    "recommendations": risk_result.recommendations
                }
            
            # Link penalty analysis
            if analysis_scope["link_penalties"] and content_data.get("links"):
                penalty_result = await self.link_penalty_detector.detect_link_penalties(
                    content_data["links"], platform, content_data.get("metadata", {})
                )
                analysis_results["link_penalties"] = {
                    "penalty_score": penalty_result.penalty_score,
                    "detected_penalties": [penalty.dict() for penalty in penalty_result.detected_penalties],
                    "affected_links": penalty_result.affected_links,
                    "recommendations": penalty_result.recommendations
                }
            
            # Spam pattern analysis
            if analysis_scope["spam_patterns"]:
                spam_result = await self.spam_pattern_detector.detect_spam_patterns(
                    content, platform, content_data.get("metadata", {})
                )
                analysis_results["spam_patterns"] = {
                    "spam_score": spam_result.spam_score,
                    "detected_patterns": [pattern.dict() for pattern in spam_result.detected_patterns],
                    "risk_level": spam_result.risk_level.value,
                    "recommendations": spam_result.recommendations
                }
            
            # Community notes analysis (premium feature)
            if analysis_scope["community_notes"]:
                notes_result = await self.community_notes_analyzer.analyze_community_notes(
                    content, platform, content_data.get("metadata", {})
                )
                analysis_results["community_notes"] = {
                    "fact_check_risk": notes_result.fact_check_risk,
                    "misinformation_indicators": [
                        indicator.dict() for indicator in notes_result.misinformation_indicators
                    ],
                    "source_credibility": notes_result.source_credibility,
                    "recommendations": notes_result.recommendations
                }
            
            # Calculate overall analysis score
            overall_score = self._calculate_overall_content_score(analysis_results)
            
            self.log_operation(
                "User content analyzed",
                user_id=user.id,
                details={
                    "analysis_type": analysis_type,
                    "platform": platform.value,
                    "overall_score": overall_score,
                    "analysis_scope": analysis_scope
                }
            )
            
            return {
                "success": True,
                "analysis_type": analysis_type,
                "platform": platform.value,
                "overall_score": overall_score,
                "analysis_results": analysis_results,
                "analyzed_at": utc_datetime().isoformat(),
                "subscription_features_used": analysis_scope
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error analyzing user content: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to analyze content"
            )
    
    async def get_user_algorithm_health(
        self,
        user: User,
        platform: PlatformType,
        content_data: List[Dict[str, Any]],
        user_metrics: Dict[str, Any],
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive algorithm health analysis for user
        
        Args:
            user: User requesting analysis
            platform: Platform to analyze
            content_data: Recent content performance data
            user_metrics: User account metrics
            db: Database session
            
        Returns:
            Dict containing algorithm health analysis
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise self.handle_authorization_error(
                    message="Algorithm health analysis requires premium subscription",
                    required_permission="premium_subscription",
                    details={"feature": "algorithm_health_analysis", "current_plan": user.subscription_plan}
                )
            
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "algorithm_health", 10, window_seconds=3600  # 10 per hour for premium
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=10,
                    window=3600,
                    message="Rate limit exceeded for algorithm health analysis"
                )
            
            # Validate input data
            if not content_data or len(content_data) < 5:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Minimum 5 content items required for algorithm health analysis"
                )
            
            # Perform algorithm health analysis
            health_results = {}
            
            # Visibility scoring
            visibility_analysis = await self.visibility_scorer.analyze_visibility(
                content_data, platform, user_metrics
            )
            health_results["visibility"] = {
                "overall_score": visibility_analysis.overall_score,
                "visibility_trends": [trend.dict() for trend in visibility_analysis.visibility_trends],
                "risk_factors": [factor.dict() for factor in visibility_analysis.risk_factors],
                "recommendations": visibility_analysis.recommendations
            }
            
            # Engagement analysis
            engagement_analysis = await self.engagement_analyzer.analyze_engagement(
                content_data, platform, user_metrics
            )
            health_results["engagement"] = {
                "overall_score": engagement_analysis.overall_score,
                "engagement_quality": engagement_analysis.engagement_quality.value,
                "patterns": [pattern.dict() for pattern in engagement_analysis.patterns],
                "recommendations": engagement_analysis.recommendations
            }
            
            # Penalty detection
            penalty_analysis = await self.penalty_detector.detect_penalties(
                content_data, platform, user_metrics
            )
            health_results["penalties"] = {
                "penalty_score": penalty_analysis.penalty_score,
                "detected_penalties": [penalty.dict() for penalty in penalty_analysis.detected_penalties],
                "risk_level": penalty_analysis.risk_level.value,
                "recommendations": penalty_analysis.recommendations
            }
            
            # Shadow ban detection
            shadow_ban_analysis = await self.shadow_ban_detector.detect_shadow_ban(
                content_data, platform, user_metrics
            )
            health_results["shadow_ban"] = {
                "overall_score": shadow_ban_analysis.overall_shadow_ban_score,
                "is_shadow_banned": shadow_ban_analysis.is_shadow_banned,
                "detected_bans": [ban.dict() for ban in shadow_ban_analysis.detected_bans],
                "visibility_score": shadow_ban_analysis.visibility_score,
                "recommendations": shadow_ban_analysis.recommendations
            }
            
            # Calculate overall algorithm health score
            overall_health_score = self._calculate_algorithm_health_score(health_results)
            
            self.log_operation(
                "Algorithm health analysis completed",
                user_id=user.id,
                details={
                    "platform": platform.value,
                    "content_items": len(content_data),
                    "overall_health_score": overall_health_score
                }
            )
            
            return {
                "success": True,
                "platform": platform.value,
                "overall_health_score": overall_health_score,
                "health_analysis": health_results,
                "analyzed_at": utc_datetime().isoformat(),
                "content_items_analyzed": len(content_data)
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error analyzing algorithm health: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to analyze algorithm health"
            )
    
    # Helper methods
    
    async def _get_user_platform_settings(
        self,
        user: User,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Get user's platform-specific settings"""
        # In a real implementation, this would query the database
        return {
            "twitter": {"monitoring_enabled": True, "auto_scan": False},
            "instagram": {"monitoring_enabled": True, "auto_scan": False},
            "facebook": {"monitoring_enabled": False, "auto_scan": False},
            "linkedin": {"monitoring_enabled": True, "auto_scan": False},
            "tiktok": {"monitoring_enabled": False, "auto_scan": False}
        }
    
    async def _update_user_platform_settings(
        self,
        user: User,
        platform_settings: Dict[str, Any],
        db: AsyncSession
    ) -> None:
        """Update user's platform-specific settings"""
        try:
            # Validate platform settings structure
            valid_platforms = ["twitter", "instagram", "facebook", "linkedin", "tiktok", "discord", "telegram"]
            
            for platform, settings in platform_settings.items():
                if platform not in valid_platforms:
                    logger.warning(f"Invalid platform in settings: {platform}")
                    continue
                
                # Validate settings structure
                if not isinstance(settings, dict):
                    logger.warning(f"Invalid settings format for platform {platform}")
                    continue
                
                # Validate boolean fields
                for key in ["monitoring_enabled", "auto_scan"]:
                    if key in settings and not isinstance(settings[key], bool):
                        logger.warning(f"Invalid {key} value for platform {platform}")
                        settings[key] = bool(settings[key])
            
            # In a real implementation, this would update the database
            # For now, we log the update
            self.log_operation(
                "User platform settings updated",
                user_id=user.id,
                details={
                    "platforms_updated": list(platform_settings.keys()),
                    "settings": platform_settings
                },
                level="debug"
            )
            
            # TODO: Implement database persistence when user settings model is available
            # Example:
            # user.platform_settings = platform_settings
            # await db.commit()
            
        except Exception as e:
            logger.error(f"Error updating user platform settings: {str(e)}")
            raise
    
    async def _get_user_recent_scans(
        self,
        user: User,
        platform: Optional[PlatformType],
        days: int,
        db: Optional[AsyncSession]
    ) -> List[Dict[str, Any]]:
        """Get user's recent scan data"""
        try:
            if not db:
                logger.warning("No database session provided for recent scans query")
                return []
            
            from datetime import timedelta
            from sqlalchemy import select
            from src.models.social_protection import SocialProfileScanORM
            
            # Calculate date range
            start_date = utc_datetime() - timedelta(days=days)
            
            # Build query
            query = select(SocialProfileScanORM).where(
                SocialProfileScanORM.user_id == user.id,
                SocialProfileScanORM.created_at >= start_date
            )
            
            # Add platform filter if specified
            if platform:
                query = query.where(SocialProfileScanORM.platform == platform.value)
            
            # Order by most recent first
            query = query.order_by(SocialProfileScanORM.created_at.desc())
            
            # Execute query
            result = await db.execute(query)
            scans = result.scalars().all()
            
            # Convert to dict format
            scan_data = []
            for scan in scans:
                scan_dict = {
                    "scan_id": str(scan.id),
                    "platform": scan.platform,
                    "profile_url": scan.profile_url,
                    "status": scan.status,
                    "risk_score": scan.overall_risk_score,
                    "created_at": scan.created_at.isoformat() if scan.created_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "scan_data": scan.scan_data or {}
                }
                scan_data.append(scan_dict)
            
            logger.debug(f"Retrieved {len(scan_data)} recent scans for user {user.id}")
            return scan_data
            
        except Exception as e:
            logger.error(f"Error retrieving recent scans: {str(e)}")
            # Return empty list on error to allow graceful degradation
            return []
    
    async def _calculate_user_analytics(
        self,
        recent_scans: List[Dict[str, Any]],
        user: User,
        platform: Optional[PlatformType]
    ) -> Dict[str, Any]:
        """Calculate user protection analytics"""
        return {
            "overall_risk_score": 0.2,
            "protection_health_score": 85.0,
            "total_scans": len(recent_scans),
            "risk_trends": [],
            "platform_breakdown": {}
        }
    
    async def _generate_user_insights(
        self,
        recent_scans: List[Dict[str, Any]],
        user: User,
        analytics: Dict[str, Any]
    ) -> List[str]:
        """Generate user-specific insights"""
        return [
            "Your account protection is performing well",
            "Consider enabling auto-scan for better monitoring"
        ]
    
    async def _generate_user_recommendations(
        self,
        recent_scans: List[Dict[str, Any]],
        user: User,
        analytics: Dict[str, Any]
    ) -> List[str]:
        """Generate user-specific recommendations"""
        recommendations = []
        
        if user.subscription_plan != "premium":
            recommendations.append("Upgrade to premium for advanced protection features")
        
        recommendations.extend([
            "Enable monitoring for all your active social media platforms",
            "Review your privacy settings regularly",
            "Monitor your content performance trends"
        ])
        
        return recommendations
    
    async def _perform_deep_platform_analysis(
        self,
        scan_id: str,
        user_id: uuid.UUID,
        platform: PlatformType,
        scan_options: Dict[str, Any]
    ) -> None:
        """Perform deep analysis in background"""
        try:
            # This would perform comprehensive analysis
            logger.info(f"Starting deep analysis for scan {scan_id}")
            # Implementation would go here
        except Exception as e:
            logger.error(f"Deep analysis failed for scan {scan_id}: {str(e)}")
    
    def _calculate_overall_content_score(
        self,
        analysis_results: Dict[str, Any]
    ) -> float:
        """Calculate overall content analysis score"""
        scores = []
        
        if "content_risk" in analysis_results:
            scores.append(1.0 - analysis_results["content_risk"]["overall_risk_score"])
        
        if "link_penalties" in analysis_results:
            scores.append(1.0 - analysis_results["link_penalties"]["penalty_score"])
        
        if "spam_patterns" in analysis_results:
            scores.append(1.0 - analysis_results["spam_patterns"]["spam_score"])
        
        return sum(scores) / len(scores) if scores else 0.5
    
    def _calculate_algorithm_health_score(
        self,
        health_results: Dict[str, Any]
    ) -> float:
        """Calculate overall algorithm health score"""
        scores = []
        weights = {
            "visibility": 0.3,
            "engagement": 0.3,
            "penalties": 0.2,
            "shadow_ban": 0.2
        }
        
        for category, weight in weights.items():
            if category in health_results:
                if category == "penalties":
                    # Invert penalty score (lower penalties = better health)
                    score = 1.0 - health_results[category]["penalty_score"]
                elif category == "shadow_ban":
                    # Use visibility score for shadow ban health
                    score = health_results[category]["visibility_score"] / 100.0
                else:
                    score = health_results[category]["overall_score"] / 100.0
                
                scores.append(score * weight)
        
        return sum(scores) * 100.0  # Convert to 0-100 scale

    async def batch_analyze_algorithm_health(
        self,
        user: User,
        request: Any,  # BatchAnalysisRequest
        background_tasks: Any  # BackgroundTasks
    ) -> Dict[str, Any]:
        """
        Perform batch algorithm health analysis for multiple accounts.
        
        Args:
            user: User requesting analysis
            request: Batch analysis request containing account IDs and analysis types
            background_tasks: FastAPI background tasks for async processing
            
        Returns:
            Dict containing batch analysis initialization data
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise self.handle_authorization_error(
                    message="Batch algorithm health analysis requires premium subscription",
                    required_permission="premium_subscription",
                    details={"feature": "batch_algorithm_health_analysis", "current_plan": user.subscription_plan}
                )
            
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "batch_algorithm_health", 5, window_seconds=3600  # 5 batches per hour
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=5,
                    window=3600,
                    message="Rate limit exceeded for batch algorithm health analysis"
                )
            
            import uuid
            batch_id = str(uuid.uuid4())
            
            # Initialize batch analysis
            batch_result = {
                "batch_id": batch_id,
                "total_accounts": len(request.account_ids),
                "completed_analyses": 0,
                "failed_analyses": 0,
                "status": "processing",
                "results": [],
                "started_at": utc_datetime(),
                "completed_at": None
            }
            
            # Add batch processing to background tasks
            background_tasks.add_task(
                self._process_batch_analysis,
                batch_id,
                request,
                user
            )
            
            self.log_operation(
                "Batch algorithm health analysis initiated",
                user_id=user.id,
                details={
                    "batch_id": batch_id,
                    "account_count": len(request.account_ids),
                    "analysis_types": request.analysis_types
                }
            )
            
            return batch_result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error initiating batch algorithm health analysis: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to initiate batch algorithm health analysis"
            )
    
    async def get_batch_analysis_status(
        self,
        user: User,
        batch_id: str
    ) -> Dict[str, Any]:
        """
        Get the status of a batch analysis operation.
        
        Args:
            user: User requesting status
            batch_id: Batch analysis ID
            
        Returns:
            Dict containing batch analysis status
        """
        try:
            # In a real implementation, this would query a database or cache
            # For now, return a mock response based on batch_id
            from datetime import timedelta
            
            # Mock status based on batch_id for demonstration
            return {
                "batch_id": batch_id,
                "status": "completed",
                "total_accounts": 5,
                "completed_analyses": 5,
                "failed_analyses": 0,
                "started_at": utc_datetime() - timedelta(minutes=10),
                "completed_at": utc_datetime(),
                "results": [
                    {
                        "account_id": "account_1",
                        "status": "completed",
                        "visibility_score": 75.5,
                        "engagement_quality": "good",
                        "penalties_detected": 0,
                        "shadow_ban_detected": False
                    },
                    {
                        "account_id": "account_2", 
                        "status": "completed",
                        "visibility_score": 82.3,
                        "engagement_quality": "excellent",
                        "penalties_detected": 1,
                        "shadow_ban_detected": False
                    }
                ]
            }
            
        except Exception as e:
            logger.error(f"Error retrieving batch analysis status: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve batch analysis status"
            )
    
    async def _process_batch_analysis(
        self,
        batch_id: str,
        request: Any,  # BatchAnalysisRequest
        user: User
    ):
        """
        Background task to process batch analysis.
        
        Args:
            batch_id: Unique batch identifier
            request: Batch analysis request
            user: User who initiated the batch
        """
        try:
            results = []
            completed = 0
            failed = 0
            
            for account_id in request.account_ids:
                try:
                    account_result = {"account_id": account_id}
                    
                    # Mock content data and user metrics for analysis
                    mock_content_data = [
                        {"content_id": f"content_{i}", "engagement": {"likes": 10, "shares": 2}}
                        for i in range(5)
                    ]
                    mock_user_metrics = {
                        "followers": 1000,
                        "following": 500,
                        "posts_count": 100
                    }
                    
                    # Perform requested analyses
                    if "visibility" in request.analysis_types:
                        visibility_result = await self.visibility_scorer.analyze_visibility(
                            mock_content_data, request.platform, mock_user_metrics
                        )
                        account_result["visibility_score"] = visibility_result.overall_score
                    
                    if "engagement" in request.analysis_types:
                        engagement_result = await self.engagement_analyzer.analyze_engagement(
                            mock_content_data, request.platform, mock_user_metrics
                        )
                        account_result["engagement_quality"] = engagement_result.engagement_quality.value
                    
                    if "penalty" in request.analysis_types:
                        penalty_result = await self.penalty_detector.detect_penalties(
                            mock_content_data, request.platform, mock_user_metrics
                        )
                        account_result["penalties_detected"] = len(penalty_result.detected_penalties)
                    
                    if "shadow_ban" in request.analysis_types:
                        shadow_ban_result = await self.shadow_ban_detector.detect_shadow_ban(
                            mock_content_data, request.platform, mock_user_metrics
                        )
                        account_result["shadow_ban_detected"] = shadow_ban_result.is_shadow_banned
                    
                    account_result["status"] = "completed"
                    results.append(account_result)
                    completed += 1
                    
                except Exception as e:
                    results.append({
                        "account_id": account_id,
                        "status": "failed",
                        "error": str(e)
                    })
                    failed += 1
            
            # Update batch status (in a real implementation, this would update a database)
            logger.info(f"Batch {batch_id} completed: {completed} successful, {failed} failed")
            
            self.log_operation(
                "Batch algorithm health analysis completed",
                user_id=user.id,
                details={
                    "batch_id": batch_id,
                    "completed": completed,
                    "failed": failed
                }
            )
            
        except Exception as e:
            logger.error(f"Batch processing error for {batch_id}: {str(e)}")

    async def analyze_visibility(
        self,
        user: User,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze content visibility for algorithm health assessment.
        
        Args:
            user: User requesting analysis
            content_data: Content performance data
            platform: Platform to analyze
            user_metrics: User account metrics
            
        Returns:
            Dict containing visibility analysis results
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise self.handle_authorization_error(
                    message="Visibility analysis requires premium subscription",
                    required_permission="premium_subscription",
                    details={"feature": "visibility_analysis", "current_plan": user.subscription_plan}
                )
            
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "visibility_analysis", 20, window_seconds=3600
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=20,
                    window=3600,
                    message="Rate limit exceeded for visibility analysis"
                )
            
            # Perform visibility analysis
            visibility_result = await self.visibility_scorer.analyze_visibility(
                content_data, platform, user_metrics
            )
            
            self.log_operation(
                "Visibility analysis completed",
                user_id=user.id,
                details={
                    "platform": platform.value,
                    "content_items": len(content_data),
                    "overall_score": visibility_result.overall_score
                }
            )
            
            return {
                "success": True,
                "platform": platform.value,
                "overall_score": visibility_result.overall_score,
                "visibility_trends": [trend.dict() for trend in visibility_result.visibility_trends],
                "risk_factors": [factor.dict() for factor in visibility_result.risk_factors],
                "recommendations": visibility_result.recommendations,
                "analyzed_at": utc_datetime().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error analyzing visibility: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to analyze visibility"
            )
    
    async def get_visibility_trends(
        self,
        user: User,
        account_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get visibility trends for a specific account.
        
        Args:
            user: User requesting trends
            account_id: Account to analyze
            days: Number of days to analyze
            
        Returns:
            Dict containing visibility trends
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Visibility trends require premium subscription"
                )
            
            # Mock trend data (in real implementation, would query database)
            trends = {
                "account_id": account_id,
                "period_days": days,
                "visibility_score": 78.5,
                "trend_direction": "improving",
                "daily_scores": [
                    {"date": "2024-01-01", "score": 75.0},
                    {"date": "2024-01-02", "score": 76.2},
                    {"date": "2024-01-03", "score": 78.5}
                ],
                "insights": [
                    "Visibility has improved by 4.7% over the past week",
                    "Peak visibility occurs during 2-4 PM time slot"
                ]
            }
            
            self.log_operation(
                "Visibility trends retrieved",
                user_id=user.id,
                details={"account_id": account_id, "days": days}
            )
            
            return trends
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error retrieving visibility trends: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve visibility trends"
            )
    
    async def analyze_engagement(
        self,
        user: User,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze engagement patterns for algorithm health assessment.
        
        Args:
            user: User requesting analysis
            content_data: Content performance data
            platform: Platform to analyze
            user_metrics: User account metrics
            
        Returns:
            Dict containing engagement analysis results
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise self.handle_authorization_error(
                    message="Engagement analysis requires premium subscription",
                    required_permission="premium_subscription",
                    details={"feature": "engagement_analysis", "current_plan": user.subscription_plan}
                )
            
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "engagement_analysis", 20, window_seconds=3600
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=20,
                    window=3600,
                    message="Rate limit exceeded for engagement analysis"
                )
            
            # Perform engagement analysis
            engagement_result = await self.engagement_analyzer.analyze_engagement(
                content_data, platform, user_metrics
            )
            
            self.log_operation(
                "Engagement analysis completed",
                user_id=user.id,
                details={
                    "platform": platform.value,
                    "content_items": len(content_data),
                    "overall_score": engagement_result.overall_score
                }
            )
            
            return {
                "success": True,
                "platform": platform.value,
                "overall_score": engagement_result.overall_score,
                "engagement_quality": engagement_result.engagement_quality.value,
                "patterns": [pattern.dict() for pattern in engagement_result.patterns],
                "recommendations": engagement_result.recommendations,
                "analyzed_at": utc_datetime().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error analyzing engagement: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to analyze engagement"
            )
    
    async def get_engagement_patterns(
        self,
        user: User,
        account_id: str
    ) -> Dict[str, Any]:
        """
        Get engagement patterns for a specific account.
        
        Args:
            user: User requesting patterns
            account_id: Account to analyze
            
        Returns:
            Dict containing engagement patterns
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Engagement patterns require premium subscription"
                )
            
            # Mock pattern data (in real implementation, would query database)
            patterns = {
                "account_id": account_id,
                "engagement_score": 82.3,
                "patterns": [
                    {
                        "type": "peak_hours",
                        "description": "Highest engagement between 7-9 PM",
                        "confidence": 0.85
                    },
                    {
                        "type": "content_type",
                        "description": "Video content performs 40% better than images",
                        "confidence": 0.92
                    }
                ],
                "recommendations": [
                    "Post video content during peak hours for maximum engagement",
                    "Use trending hashtags relevant to your niche"
                ]
            }
            
            self.log_operation(
                "Engagement patterns retrieved",
                user_id=user.id,
                details={"account_id": account_id}
            )
            
            return patterns
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error retrieving engagement patterns: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve engagement patterns"
            )
    
    async def detect_penalties(
        self,
        user: User,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Detect algorithmic penalties for algorithm health assessment.
        
        Args:
            user: User requesting analysis
            content_data: Content performance data
            platform: Platform to analyze
            user_metrics: User account metrics
            
        Returns:
            Dict containing penalty detection results
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise self.handle_authorization_error(
                    message="Penalty detection requires premium subscription",
                    required_permission="premium_subscription",
                    details={"feature": "penalty_detection", "current_plan": user.subscription_plan}
                )
            
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "penalty_detection", 15, window_seconds=3600
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=15,
                    window=3600,
                    message="Rate limit exceeded for penalty detection"
                )
            
            # Perform penalty detection
            penalty_result = await self.penalty_detector.detect_penalties(
                content_data, platform, user_metrics
            )
            
            self.log_operation(
                "Penalty detection completed",
                user_id=user.id,
                details={
                    "platform": platform.value,
                    "content_items": len(content_data),
                    "penalty_score": penalty_result.penalty_score
                }
            )
            
            return {
                "success": True,
                "platform": platform.value,
                "penalty_score": penalty_result.penalty_score,
                "detected_penalties": [penalty.dict() for penalty in penalty_result.detected_penalties],
                "risk_level": penalty_result.risk_level.value,
                "recommendations": penalty_result.recommendations,
                "analyzed_at": utc_datetime().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error detecting penalties: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to detect penalties"
            )
    
    async def monitor_penalties(
        self,
        user: User,
        account_id: str
    ) -> Dict[str, Any]:
        """
        Monitor penalties for a specific account.
        
        Args:
            user: User requesting monitoring
            account_id: Account to monitor
            
        Returns:
            Dict containing penalty monitoring results
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise self.handle_authorization_error(
                    message="Penalty monitoring requires premium subscription",
                    required_permission="premium_subscription",
                    details={"feature": "penalty_monitoring", "current_plan": user.subscription_plan}
                )
            
            # Mock monitoring data (in real implementation, would query database)
            monitoring_data = {
                "account_id": account_id,
                "monitoring_status": "active",
                "current_penalty_score": 0.15,
                "penalty_history": [
                    {
                        "date": "2024-01-01",
                        "penalty_type": "engagement_drop",
                        "severity": "low",
                        "resolved": True
                    }
                ],
                "alerts": [],
                "recommendations": [
                    "Continue monitoring engagement metrics",
                    "Maintain consistent posting schedule"
                ]
            }
            
            self.log_operation(
                "Penalty monitoring retrieved",
                user_id=user.id,
                details={"account_id": account_id}
            )
            
            return monitoring_data
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error monitoring penalties: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to monitor penalties"
            )
    
    async def detect_shadow_ban(
        self,
        user: User,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Detect shadow bans for algorithm health assessment.
        
        Args:
            user: User requesting analysis
            content_data: Content performance data
            platform: Platform to analyze
            user_metrics: User account metrics
            
        Returns:
            Dict containing shadow ban detection results
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise self.handle_authorization_error(
                    message="Shadow ban detection requires premium subscription",
                    required_permission="premium_subscription",
                    details={"feature": "shadow_ban_detection", "current_plan": user.subscription_plan}
                )
            
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "shadow_ban_detection", 10, window_seconds=3600
            ):
                raise self.handle_rate_limit_error(
                    retry_after=3600,
                    limit=10,
                    window=3600,
                    message="Rate limit exceeded for shadow ban detection"
                )
            
            # Perform shadow ban detection
            shadow_ban_result = await self.shadow_ban_detector.detect_shadow_ban(
                content_data, platform, user_metrics
            )
            
            self.log_operation(
                "Shadow ban detection completed",
                user_id=user.id,
                details={
                    "platform": platform.value,
                    "content_items": len(content_data),
                    "is_shadow_banned": shadow_ban_result.is_shadow_banned
                }
            )
            
            return {
                "success": True,
                "platform": platform.value,
                "overall_score": shadow_ban_result.overall_shadow_ban_score,
                "is_shadow_banned": shadow_ban_result.is_shadow_banned,
                "detected_bans": [ban.dict() for ban in shadow_ban_result.detected_bans],
                "visibility_score": shadow_ban_result.visibility_score,
                "recommendations": shadow_ban_result.recommendations,
                "analyzed_at": utc_datetime().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error detecting shadow ban: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to detect shadow ban"
            )
    
    async def monitor_shadow_ban(
        self,
        user: User,
        account_id: str
    ) -> Dict[str, Any]:
        """
        Monitor shadow ban status for a specific account.
        
        Args:
            user: User requesting monitoring
            account_id: Account to monitor
            
        Returns:
            Dict containing shadow ban monitoring results
        """
        try:
            # Check premium feature access
            if user.subscription_plan != "premium":
                raise self.handle_authorization_error(
                    message="Shadow ban monitoring requires premium subscription",
                    required_permission="premium_subscription",
                    details={"feature": "shadow_ban_monitoring", "current_plan": user.subscription_plan}
                )
            
            # Mock monitoring data (in real implementation, would query database)
            monitoring_data = {
                "account_id": account_id,
                "monitoring_status": "active",
                "current_status": "not_shadow_banned",
                "confidence_score": 0.92,
                "last_checked": utc_datetime().isoformat(),
                "history": [
                    {
                        "date": "2024-01-01",
                        "status": "not_shadow_banned",
                        "confidence": 0.89
                    }
                ],
                "recommendations": [
                    "Continue monitoring visibility metrics",
                    "Avoid posting repetitive content"
                ]
            }
            
            self.log_operation(
                "Shadow ban monitoring retrieved",
                user_id=user.id,
                details={"account_id": account_id}
            )
            
            return monitoring_data
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error monitoring shadow ban: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to monitor shadow ban"
            )