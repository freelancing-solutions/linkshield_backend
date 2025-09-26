"""
Shadow Ban Detector for Social Media Algorithm Health Analysis

This module provides specialized shadow ban detection for social media accounts,
focusing on identifying subtle algorithmic restrictions that limit content visibility.
"""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import logging
import statistics
import math
from ..types import PlatformType, RiskLevel

logger = logging.getLogger(__name__)


class ShadowBanType(Enum):
    """Types of shadow ban restrictions"""
    SEARCH_BAN = "search_ban"
    HASHTAG_BAN = "hashtag_ban"
    REPLY_DEBOOSTING = "reply_deboosting"
    TIMELINE_SUPPRESSION = "timeline_suppression"
    DISCOVERY_BAN = "discovery_ban"
    PARTIAL_SHADOW_BAN = "partial_shadow_ban"
    COMPLETE_SHADOW_BAN = "complete_shadow_ban"
    TEMPORARY_RESTRICTION = "temporary_restriction"


class ShadowBanSeverity(Enum):
    """Severity levels of shadow ban"""
    NONE = "none"
    LIGHT = "light"
    MODERATE = "moderate"
    HEAVY = "heavy"
    COMPLETE = "complete"


class DetectionMethod(Enum):
    """Methods used for shadow ban detection"""
    REACH_ANALYSIS = "reach_analysis"
    ENGAGEMENT_PATTERN = "engagement_pattern"
    VISIBILITY_TEST = "visibility_test"
    HASHTAG_PERFORMANCE = "hashtag_performance"
    SEARCH_VISIBILITY = "search_visibility"
    TIMELINE_PRESENCE = "timeline_presence"
    COMPARATIVE_ANALYSIS = "comparative_analysis"


@dataclass
class ShadowBanEvidence:
    """Evidence supporting shadow ban detection"""
    method: DetectionMethod
    confidence: float
    description: str
    data_points: Dict[str, Any]
    detected_at: datetime


@dataclass
class ShadowBanTest:
    """Individual shadow ban test result"""
    test_type: ShadowBanType
    severity: ShadowBanSeverity
    confidence: float
    evidence: List[ShadowBanEvidence]
    affected_features: List[str]
    platform_specific_data: Dict[str, Any]


@dataclass
class ShadowBanAnalysis:
    """Comprehensive shadow ban analysis result"""
    overall_shadow_ban_score: float
    is_shadow_banned: bool
    detected_bans: List[ShadowBanTest]
    risk_level: RiskLevel
    visibility_score: float
    affected_areas: List[str]
    detection_confidence: float
    recommendations: List[str]
    recovery_suggestions: List[str]
    monitoring_recommendations: List[str]
    platform_insights: Dict[str, Any]
    analysis_timestamp: datetime
    test_period: Tuple[datetime, datetime]


class ShadowBanDetector:
    """
    Advanced shadow ban detection system for social media accounts.
    
    Uses multiple detection methods to identify various types of shadow bans
    and algorithmic restrictions that limit content visibility.
    """
    
    def __init__(self):
        """Initialize the shadow ban detector with platform-specific configurations"""
        self.platform_configs = self._load_platform_configs()
        self.detection_thresholds = self._load_detection_thresholds()
        
    def _load_platform_configs(self) -> Dict[PlatformType, Dict[str, Any]]:
        """Load platform-specific shadow ban detection configurations"""
        return {
            PlatformType.TWITTER: {
                "shadow_ban_indicators": {
                    "search_visibility_threshold": 0.1,  # 10% of expected search visibility
                    "reply_visibility_threshold": 0.3,   # 30% of replies visible
                    "timeline_presence_threshold": 0.2,  # 20% timeline presence
                    "hashtag_reach_threshold": 0.15,     # 15% hashtag reach
                    "engagement_drop_threshold": 0.4     # 60% engagement drop
                },
                "detection_methods": [
                    DetectionMethod.SEARCH_VISIBILITY,
                    DetectionMethod.REPLY_DEBOOSTING,
                    DetectionMethod.HASHTAG_PERFORMANCE,
                    DetectionMethod.TIMELINE_PRESENCE
                ],
                "test_parameters": {
                    "min_posts_for_analysis": 10,
                    "analysis_window_hours": 168,  # 1 week
                    "comparison_window_hours": 336  # 2 weeks for comparison
                }
            },
            PlatformType.INSTAGRAM: {
                "shadow_ban_indicators": {
                    "hashtag_reach_threshold": 0.05,     # 5% hashtag reach
                    "explore_visibility_threshold": 0.02, # 2% explore visibility
                    "story_visibility_threshold": 0.4,   # 40% story visibility
                    "profile_visit_threshold": 0.3,      # 30% profile visits
                    "engagement_drop_threshold": 0.5     # 50% engagement drop
                },
                "detection_methods": [
                    DetectionMethod.HASHTAG_PERFORMANCE,
                    DetectionMethod.DISCOVERY_BAN,
                    DetectionMethod.REACH_ANALYSIS,
                    DetectionMethod.ENGAGEMENT_PATTERN
                ],
                "test_parameters": {
                    "min_posts_for_analysis": 8,
                    "analysis_window_hours": 120,  # 5 days
                    "comparison_window_hours": 240  # 10 days for comparison
                }
            },
            PlatformType.FACEBOOK: {
                "shadow_ban_indicators": {
                    "organic_reach_threshold": 0.03,     # 3% organic reach
                    "timeline_visibility_threshold": 0.1, # 10% timeline visibility
                    "search_visibility_threshold": 0.05, # 5% search visibility
                    "engagement_drop_threshold": 0.6     # 40% engagement drop
                },
                "detection_methods": [
                    DetectionMethod.REACH_ANALYSIS,
                    DetectionMethod.TIMELINE_PRESENCE,
                    DetectionMethod.SEARCH_VISIBILITY
                ],
                "test_parameters": {
                    "min_posts_for_analysis": 12,
                    "analysis_window_hours": 240,  # 10 days
                    "comparison_window_hours": 480  # 20 days for comparison
                }
            },
            PlatformType.LINKEDIN: {
                "shadow_ban_indicators": {
                    "feed_visibility_threshold": 0.15,   # 15% feed visibility
                    "connection_reach_threshold": 0.25,  # 25% connection reach
                    "search_visibility_threshold": 0.1,  # 10% search visibility
                    "engagement_drop_threshold": 0.5     # 50% engagement drop
                },
                "detection_methods": [
                    DetectionMethod.REACH_ANALYSIS,
                    DetectionMethod.SEARCH_VISIBILITY,
                    DetectionMethod.ENGAGEMENT_PATTERN
                ],
                "test_parameters": {
                    "min_posts_for_analysis": 8,
                    "analysis_window_hours": 168,  # 1 week
                    "comparison_window_hours": 336  # 2 weeks for comparison
                }
            },
            PlatformType.TIKTOK: {
                "shadow_ban_indicators": {
                    "fyp_visibility_threshold": 0.05,    # 5% FYP visibility
                    "hashtag_reach_threshold": 0.1,      # 10% hashtag reach
                    "discovery_threshold": 0.03,         # 3% discovery rate
                    "engagement_drop_threshold": 0.4     # 60% engagement drop
                },
                "detection_methods": [
                    DetectionMethod.DISCOVERY_BAN,
                    DetectionMethod.HASHTAG_PERFORMANCE,
                    DetectionMethod.REACH_ANALYSIS
                ],
                "test_parameters": {
                    "min_posts_for_analysis": 6,
                    "analysis_window_hours": 72,   # 3 days
                    "comparison_window_hours": 168  # 1 week for comparison
                }
            }
        }
    
    def _load_detection_thresholds(self) -> Dict[ShadowBanType, Dict[str, float]]:
        """Load shadow ban detection thresholds"""
        return {
            ShadowBanType.SEARCH_BAN: {
                "light_threshold": 0.3,
                "moderate_threshold": 0.6,
                "heavy_threshold": 0.8,
                "complete_threshold": 0.95
            },
            ShadowBanType.HASHTAG_BAN: {
                "light_threshold": 0.4,
                "moderate_threshold": 0.7,
                "heavy_threshold": 0.85,
                "complete_threshold": 0.95
            },
            ShadowBanType.REPLY_DEBOOSTING: {
                "light_threshold": 0.2,
                "moderate_threshold": 0.5,
                "heavy_threshold": 0.75,
                "complete_threshold": 0.9
            },
            ShadowBanType.TIMELINE_SUPPRESSION: {
                "light_threshold": 0.3,
                "moderate_threshold": 0.6,
                "heavy_threshold": 0.8,
                "complete_threshold": 0.95
            },
            ShadowBanType.DISCOVERY_BAN: {
                "light_threshold": 0.4,
                "moderate_threshold": 0.7,
                "heavy_threshold": 0.85,
                "complete_threshold": 0.95
            }
        }
    
    async def detect_shadow_ban(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None,
        test_period_days: int = 7
    ) -> ShadowBanAnalysis:
        """
        Perform comprehensive shadow ban detection analysis
        
        Args:
            content_data: Recent content performance data
            platform: Social media platform
            user_metrics: User account metrics (followers, etc.)
            historical_data: Historical performance data for comparison
            test_period_days: Number of days to analyze for shadow ban detection
            
        Returns:
            ShadowBanAnalysis: Comprehensive shadow ban analysis results
        """
        try:
            logger.info(f"Starting shadow ban detection for {platform.value} with {len(content_data)} content items")
            
            config = self.platform_configs.get(platform, {})
            test_params = config.get('test_parameters', {})
            min_posts = test_params.get('min_posts_for_analysis', 8)
            
            # Filter recent content for analysis
            cutoff_date = datetime.now() - timedelta(days=test_period_days)
            recent_content = [
                item for item in content_data
                if datetime.fromisoformat(item.get('created_at', '')) > cutoff_date
            ]
            
            if len(recent_content) < min_posts:
                logger.warning(f"Insufficient recent content for shadow ban analysis: {len(recent_content)} < {min_posts}")
                return self._create_insufficient_data_analysis(platform, test_period_days)
            
            # Run shadow ban detection tests
            detected_bans = []
            
            # Test for search ban
            search_ban = await self._test_search_ban(
                recent_content, platform, user_metrics, historical_data
            )
            if search_ban:
                detected_bans.append(search_ban)
            
            # Test for hashtag ban
            hashtag_ban = await self._test_hashtag_ban(
                recent_content, platform, user_metrics, historical_data
            )
            if hashtag_ban:
                detected_bans.append(hashtag_ban)
            
            # Test for reply deboosting (Twitter specific)
            if platform == PlatformType.TWITTER:
                reply_ban = await self._test_reply_deboosting(
                    recent_content, platform, user_metrics, historical_data
                )
                if reply_ban:
                    detected_bans.append(reply_ban)
            
            # Test for timeline suppression
            timeline_ban = await self._test_timeline_suppression(
                recent_content, platform, user_metrics, historical_data
            )
            if timeline_ban:
                detected_bans.append(timeline_ban)
            
            # Test for discovery ban (Instagram/TikTok specific)
            if platform in [PlatformType.INSTAGRAM, PlatformType.TIKTOK]:
                discovery_ban = await self._test_discovery_ban(
                    recent_content, platform, user_metrics, historical_data
                )
                if discovery_ban:
                    detected_bans.append(discovery_ban)
            
            # Calculate overall shadow ban score
            overall_score = self._calculate_shadow_ban_score(detected_bans)
            
            # Determine if shadow banned
            is_shadow_banned = overall_score > 0.3 or len(detected_bans) >= 2
            
            # Calculate visibility score
            visibility_score = self._calculate_visibility_score(
                recent_content, detected_bans, platform, user_metrics
            )
            
            # Identify affected areas
            affected_areas = self._identify_affected_areas(detected_bans)
            
            # Calculate detection confidence
            detection_confidence = self._calculate_detection_confidence(
                recent_content, detected_bans, historical_data
            )
            
            # Assess risk level
            risk_level = self._assess_shadow_ban_risk_level(overall_score, detected_bans)
            
            # Generate recommendations
            recommendations = self._generate_shadow_ban_recommendations(
                detected_bans, platform, overall_score
            )
            
            # Generate recovery suggestions
            recovery_suggestions = self._generate_recovery_suggestions(
                detected_bans, platform, visibility_score
            )
            
            # Generate monitoring recommendations
            monitoring_recommendations = self._generate_monitoring_recommendations(
                detected_bans, platform
            )
            
            # Generate platform insights
            platform_insights = await self._generate_shadow_ban_insights(
                detected_bans, recent_content, platform, user_metrics
            )
            
            test_period = (cutoff_date, datetime.now())
            
            return ShadowBanAnalysis(
                overall_shadow_ban_score=overall_score,
                is_shadow_banned=is_shadow_banned,
                detected_bans=detected_bans,
                risk_level=risk_level,
                visibility_score=visibility_score,
                affected_areas=affected_areas,
                detection_confidence=detection_confidence,
                recommendations=recommendations,
                recovery_suggestions=recovery_suggestions,
                monitoring_recommendations=monitoring_recommendations,
                platform_insights=platform_insights,
                analysis_timestamp=datetime.now(),
                test_period=test_period
            )
            
        except Exception as e:
            logger.error(f"Error in shadow ban detection: {str(e)}")
            return self._create_error_analysis(platform, test_period_days, str(e))
    
    async def _test_search_ban(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[ShadowBanTest]:
        """Test for search visibility ban"""
        evidence = []
        config = self.platform_configs.get(platform, {})
        indicators = config.get('shadow_ban_indicators', {})
        
        # Calculate search visibility metrics
        search_impressions = [item.get('search_impressions', 0) for item in content_data]
        total_impressions = [item.get('impressions', item.get('reach', 0)) for item in content_data]
        
        if not search_impressions or not total_impressions:
            return None
        
        # Calculate search visibility ratio
        total_search = sum(search_impressions)
        total_reach = sum(total_impressions)
        
        if total_reach == 0:
            return None
        
        search_visibility_ratio = total_search / total_reach
        threshold = indicators.get('search_visibility_threshold', 0.1)
        
        confidence_factors = []
        
        if search_visibility_ratio < threshold:
            evidence.append(
                ShadowBanEvidence(
                    method=DetectionMethod.SEARCH_VISIBILITY,
                    confidence=0.7,
                    description=f"Search visibility is {search_visibility_ratio*100:.1f}% (expected >{threshold*100:.1f}%)",
                    data_points={
                        "search_visibility_ratio": search_visibility_ratio,
                        "threshold": threshold,
                        "total_search_impressions": total_search,
                        "total_impressions": total_reach
                    },
                    detected_at=datetime.now()
                )
            )
            confidence_factors.append(0.7)
        
        # Compare with historical data if available
        if historical_data:
            historical_search = [item.get('search_impressions', 0) for item in historical_data]
            historical_total = [item.get('impressions', item.get('reach', 0)) for item in historical_data]
            
            if historical_search and historical_total:
                hist_search_total = sum(historical_search)
                hist_total_reach = sum(historical_total)
                
                if hist_total_reach > 0:
                    historical_ratio = hist_search_total / hist_total_reach
                    ratio_drop = (historical_ratio - search_visibility_ratio) / max(historical_ratio, 0.01)
                    
                    if ratio_drop > 0.5:  # 50% drop in search visibility
                        evidence.append(
                            ShadowBanEvidence(
                                method=DetectionMethod.COMPARATIVE_ANALYSIS,
                                confidence=0.8,
                                description=f"Search visibility dropped {ratio_drop*100:.1f}% compared to historical average",
                                data_points={
                                    "current_ratio": search_visibility_ratio,
                                    "historical_ratio": historical_ratio,
                                    "drop_percentage": ratio_drop
                                },
                                detected_at=datetime.now()
                            )
                        )
                        confidence_factors.append(0.8)
        
        # Check for consistent low search performance
        low_search_posts = sum(1 for impressions in search_impressions if impressions == 0)
        if low_search_posts >= len(search_impressions) * 0.7:  # 70% of posts have no search impressions
            evidence.append(
                ShadowBanEvidence(
                    method=DetectionMethod.SEARCH_VISIBILITY,
                    confidence=0.6,
                    description=f"{low_search_posts}/{len(search_impressions)} posts have zero search impressions",
                    data_points={
                        "zero_search_posts": low_search_posts,
                        "total_posts": len(search_impressions),
                        "percentage": (low_search_posts / len(search_impressions)) * 100
                    },
                    detected_at=datetime.now()
                )
            )
            confidence_factors.append(0.6)
        
        if not confidence_factors:
            return None
        
        overall_confidence = min(sum(confidence_factors), 1.0)
        severity = self._determine_severity(overall_confidence, ShadowBanType.SEARCH_BAN)
        
        return ShadowBanTest(
            test_type=ShadowBanType.SEARCH_BAN,
            severity=severity,
            confidence=overall_confidence,
            evidence=evidence,
            affected_features=["search_results", "discoverability"],
            platform_specific_data={
                "search_visibility_ratio": search_visibility_ratio,
                "threshold": threshold,
                "posts_analyzed": len(content_data)
            }
        )
    
    async def _test_hashtag_ban(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[ShadowBanTest]:
        """Test for hashtag ban"""
        evidence = []
        config = self.platform_configs.get(platform, {})
        indicators = config.get('shadow_ban_indicators', {})
        
        # Analyze hashtag performance
        hashtag_posts = [item for item in content_data if item.get('hashtags')]
        if not hashtag_posts:
            return None
        
        confidence_factors = []
        
        # Calculate hashtag reach ratio
        hashtag_reaches = []
        total_reaches = []
        
        for item in hashtag_posts:
            hashtag_reach = item.get('hashtag_reach', 0)
            total_reach = item.get('reach', item.get('impressions', 0))
            
            if total_reach > 0:
                hashtag_reaches.append(hashtag_reach)
                total_reaches.append(total_reach)
        
        if hashtag_reaches and total_reaches:
            avg_hashtag_reach = statistics.mean(hashtag_reaches)
            avg_total_reach = statistics.mean(total_reaches)
            
            if avg_total_reach > 0:
                hashtag_ratio = avg_hashtag_reach / avg_total_reach
                threshold = indicators.get('hashtag_reach_threshold', 0.15)
                
                if hashtag_ratio < threshold:
                    evidence.append(
                        ShadowBanEvidence(
                            method=DetectionMethod.HASHTAG_PERFORMANCE,
                            confidence=0.7,
                            description=f"Hashtag reach is {hashtag_ratio*100:.1f}% of total reach (expected >{threshold*100:.1f}%)",
                            data_points={
                                "hashtag_ratio": hashtag_ratio,
                                "threshold": threshold,
                                "avg_hashtag_reach": avg_hashtag_reach,
                                "avg_total_reach": avg_total_reach
                            },
                            detected_at=datetime.now()
                        )
                    )
                    confidence_factors.append(0.7)
        
        # Check for specific hashtag performance
        hashtag_performance = {}
        for item in hashtag_posts:
            hashtags = item.get('hashtags', [])
            hashtag_reach = item.get('hashtag_reach', 0)
            
            for hashtag in hashtags:
                if hashtag not in hashtag_performance:
                    hashtag_performance[hashtag] = []
                hashtag_performance[hashtag].append(hashtag_reach)
        
        # Identify potentially banned hashtags
        banned_hashtags = []
        for hashtag, reaches in hashtag_performance.items():
            if len(reaches) >= 3:  # Used at least 3 times
                avg_reach = statistics.mean(reaches)
                if avg_reach == 0:  # Consistently zero reach
                    banned_hashtags.append(hashtag)
        
        if banned_hashtags:
            evidence.append(
                ShadowBanEvidence(
                    method=DetectionMethod.HASHTAG_PERFORMANCE,
                    confidence=0.8,
                    description=f"Hashtags with zero reach detected: {', '.join(banned_hashtags[:5])}",
                    data_points={
                        "banned_hashtags": banned_hashtags,
                        "count": len(banned_hashtags)
                    },
                    detected_at=datetime.now()
                )
            )
            confidence_factors.append(0.8)
        
        # Compare with historical hashtag performance
        if historical_data:
            historical_hashtag_posts = [item for item in historical_data if item.get('hashtags')]
            if historical_hashtag_posts:
                historical_hashtag_reaches = [item.get('hashtag_reach', 0) for item in historical_hashtag_posts]
                historical_total_reaches = [item.get('reach', item.get('impressions', 0)) for item in historical_hashtag_posts]
                
                if historical_hashtag_reaches and historical_total_reaches:
                    hist_avg_hashtag = statistics.mean(historical_hashtag_reaches)
                    hist_avg_total = statistics.mean(historical_total_reaches)
                    
                    if hist_avg_total > 0 and avg_total_reach > 0:
                        hist_ratio = hist_avg_hashtag / hist_avg_total
                        current_ratio = avg_hashtag_reach / avg_total_reach
                        
                        ratio_drop = (hist_ratio - current_ratio) / max(hist_ratio, 0.01)
                        
                        if ratio_drop > 0.6:  # 60% drop in hashtag effectiveness
                            evidence.append(
                                ShadowBanEvidence(
                                    method=DetectionMethod.COMPARATIVE_ANALYSIS,
                                    confidence=0.9,
                                    description=f"Hashtag effectiveness dropped {ratio_drop*100:.1f}% compared to historical average",
                                    data_points={
                                        "current_ratio": current_ratio,
                                        "historical_ratio": hist_ratio,
                                        "drop_percentage": ratio_drop
                                    },
                                    detected_at=datetime.now()
                                )
                            )
                            confidence_factors.append(0.9)
        
        if not confidence_factors:
            return None
        
        overall_confidence = min(sum(confidence_factors), 1.0)
        severity = self._determine_severity(overall_confidence, ShadowBanType.HASHTAG_BAN)
        
        return ShadowBanTest(
            test_type=ShadowBanType.HASHTAG_BAN,
            severity=severity,
            confidence=overall_confidence,
            evidence=evidence,
            affected_features=["hashtag_discovery", "content_categorization"],
            platform_specific_data={
                "hashtag_ratio": hashtag_ratio if 'hashtag_ratio' in locals() else None,
                "banned_hashtags": banned_hashtags,
                "posts_with_hashtags": len(hashtag_posts)
            }
        )
    
    async def _test_reply_deboosting(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[ShadowBanTest]:
        """Test for reply deboosting (Twitter specific)"""
        if platform != PlatformType.TWITTER:
            return None
        
        evidence = []
        confidence_factors = []
        
        # Analyze reply visibility
        replies = [item for item in content_data if item.get('is_reply', False)]
        if not replies:
            return None
        
        # Check reply visibility metrics
        reply_visibilities = [item.get('reply_visibility', 1.0) for item in replies]
        avg_reply_visibility = statistics.mean(reply_visibilities)
        
        config = self.platform_configs.get(platform, {})
        indicators = config.get('shadow_ban_indicators', {})
        threshold = indicators.get('reply_visibility_threshold', 0.3)
        
        if avg_reply_visibility < threshold:
            evidence.append(
                ShadowBanEvidence(
                    method=DetectionMethod.VISIBILITY_TEST,
                    confidence=0.8,
                    description=f"Reply visibility is {avg_reply_visibility*100:.1f}% (expected >{threshold*100:.1f}%)",
                    data_points={
                        "avg_reply_visibility": avg_reply_visibility,
                        "threshold": threshold,
                        "replies_analyzed": len(replies)
                    },
                    detected_at=datetime.now()
                )
            )
            confidence_factors.append(0.8)
        
        # Check for replies with zero engagement
        zero_engagement_replies = sum(
            1 for item in replies
            if (item.get('likes', 0) + item.get('retweets', 0) + item.get('replies', 0)) == 0
        )
        
        if zero_engagement_replies >= len(replies) * 0.6:  # 60% of replies have no engagement
            evidence.append(
                ShadowBanEvidence(
                    method=DetectionMethod.ENGAGEMENT_PATTERN,
                    confidence=0.7,
                    description=f"{zero_engagement_replies}/{len(replies)} replies have zero engagement",
                    data_points={
                        "zero_engagement_replies": zero_engagement_replies,
                        "total_replies": len(replies),
                        "percentage": (zero_engagement_replies / len(replies)) * 100
                    },
                    detected_at=datetime.now()
                )
            )
            confidence_factors.append(0.7)
        
        # Compare reply performance with regular tweets
        regular_tweets = [item for item in content_data if not item.get('is_reply', False)]
        if regular_tweets:
            reply_avg_engagement = statistics.mean([
                item.get('likes', 0) + item.get('retweets', 0) + item.get('replies', 0)
                for item in replies
            ])
            regular_avg_engagement = statistics.mean([
                item.get('likes', 0) + item.get('retweets', 0) + item.get('replies', 0)
                for item in regular_tweets
            ])
            
            if regular_avg_engagement > 0:
                engagement_ratio = reply_avg_engagement / regular_avg_engagement
                
                if engagement_ratio < 0.2:  # Replies get 80% less engagement
                    evidence.append(
                        ShadowBanEvidence(
                            method=DetectionMethod.COMPARATIVE_ANALYSIS,
                            confidence=0.6,
                            description=f"Replies get {(1-engagement_ratio)*100:.1f}% less engagement than regular tweets",
                            data_points={
                                "reply_avg_engagement": reply_avg_engagement,
                                "regular_avg_engagement": regular_avg_engagement,
                                "engagement_ratio": engagement_ratio
                            },
                            detected_at=datetime.now()
                        )
                    )
                    confidence_factors.append(0.6)
        
        if not confidence_factors:
            return None
        
        overall_confidence = min(sum(confidence_factors), 1.0)
        severity = self._determine_severity(overall_confidence, ShadowBanType.REPLY_DEBOOSTING)
        
        return ShadowBanTest(
            test_type=ShadowBanType.REPLY_DEBOOSTING,
            severity=severity,
            confidence=overall_confidence,
            evidence=evidence,
            affected_features=["reply_visibility", "conversation_participation"],
            platform_specific_data={
                "avg_reply_visibility": avg_reply_visibility,
                "replies_analyzed": len(replies),
                "zero_engagement_ratio": zero_engagement_replies / len(replies) if replies else 0
            }
        )
    
    async def _test_timeline_suppression(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[ShadowBanTest]:
        """Test for timeline suppression"""
        evidence = []
        confidence_factors = []
        
        # Calculate timeline presence metrics
        follower_count = user_metrics.get('followers', 0)
        if follower_count == 0:
            return None
        
        # Analyze reach vs follower ratio
        reaches = [item.get('reach', item.get('impressions', 0)) for item in content_data]
        if not reaches:
            return None
        
        avg_reach = statistics.mean(reaches)
        reach_ratio = avg_reach / follower_count
        
        config = self.platform_configs.get(platform, {})
        indicators = config.get('shadow_ban_indicators', {})
        
        # Platform-specific timeline presence thresholds
        if platform == PlatformType.TWITTER:
            expected_ratio = 0.05  # 5% of followers typically see tweets
            threshold = indicators.get('timeline_presence_threshold', 0.2)
        elif platform == PlatformType.FACEBOOK:
            expected_ratio = 0.06  # 6% organic reach on Facebook
            threshold = indicators.get('timeline_visibility_threshold', 0.1)
        elif platform == PlatformType.INSTAGRAM:
            expected_ratio = 0.08  # 8% of followers see posts
            threshold = indicators.get('story_visibility_threshold', 0.4)
        elif platform == PlatformType.LINKEDIN:
            expected_ratio = 0.04  # 4% of connections see posts
            threshold = indicators.get('feed_visibility_threshold', 0.15)
        else:
            expected_ratio = 0.05
            threshold = 0.2
        
        timeline_presence_ratio = reach_ratio / expected_ratio
        
        if timeline_presence_ratio < threshold:
            evidence.append(
                ShadowBanEvidence(
                    method=DetectionMethod.TIMELINE_PRESENCE,
                    confidence=0.7,
                    description=f"Timeline presence is {timeline_presence_ratio*100:.1f}% of expected (threshold: {threshold*100:.1f}%)",
                    data_points={
                        "reach_ratio": reach_ratio,
                        "expected_ratio": expected_ratio,
                        "timeline_presence_ratio": timeline_presence_ratio,
                        "threshold": threshold,
                        "avg_reach": avg_reach,
                        "follower_count": follower_count
                    },
                    detected_at=datetime.now()
                )
            )
            confidence_factors.append(0.7)
        
        # Check for consistent low reach across posts
        low_reach_posts = sum(1 for reach in reaches if reach < follower_count * expected_ratio * 0.5)
        if low_reach_posts >= len(reaches) * 0.7:  # 70% of posts have very low reach
            evidence.append(
                ShadowBanEvidence(
                    method=DetectionMethod.REACH_ANALYSIS,
                    confidence=0.6,
                    description=f"{low_reach_posts}/{len(reaches)} posts have severely limited timeline reach",
                    data_points={
                        "low_reach_posts": low_reach_posts,
                        "total_posts": len(reaches),
                        "percentage": (low_reach_posts / len(reaches)) * 100
                    },
                    detected_at=datetime.now()
                )
            )
            confidence_factors.append(0.6)
        
        # Compare with historical timeline performance
        if historical_data:
            historical_reaches = [item.get('reach', item.get('impressions', 0)) for item in historical_data]
            if historical_reaches:
                hist_avg_reach = statistics.mean(historical_reaches)
                hist_reach_ratio = hist_avg_reach / follower_count
                
                ratio_drop = (hist_reach_ratio - reach_ratio) / max(hist_reach_ratio, 0.001)
                
                if ratio_drop > 0.5:  # 50% drop in timeline reach
                    evidence.append(
                        ShadowBanEvidence(
                            method=DetectionMethod.COMPARATIVE_ANALYSIS,
                            confidence=0.8,
                            description=f"Timeline reach dropped {ratio_drop*100:.1f}% compared to historical average",
                            data_points={
                                "current_reach_ratio": reach_ratio,
                                "historical_reach_ratio": hist_reach_ratio,
                                "drop_percentage": ratio_drop
                            },
                            detected_at=datetime.now()
                        )
                    )
                    confidence_factors.append(0.8)
        
        if not confidence_factors:
            return None
        
        overall_confidence = min(sum(confidence_factors), 1.0)
        severity = self._determine_severity(overall_confidence, ShadowBanType.TIMELINE_SUPPRESSION)
        
        return ShadowBanTest(
            test_type=ShadowBanType.TIMELINE_SUPPRESSION,
            severity=severity,
            confidence=overall_confidence,
            evidence=evidence,
            affected_features=["timeline_visibility", "follower_reach"],
            platform_specific_data={
                "reach_ratio": reach_ratio,
                "expected_ratio": expected_ratio,
                "timeline_presence_ratio": timeline_presence_ratio,
                "posts_analyzed": len(content_data)
            }
        )
    
    async def _test_discovery_ban(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[ShadowBanTest]:
        """Test for discovery ban (Instagram/TikTok specific)"""
        if platform not in [PlatformType.INSTAGRAM, PlatformType.TIKTOK]:
            return None
        
        evidence = []
        confidence_factors = []
        
        config = self.platform_configs.get(platform, {})
        indicators = config.get('shadow_ban_indicators', {})
        
        if platform == PlatformType.INSTAGRAM:
            # Check explore page visibility
            explore_reaches = [item.get('explore_reach', 0) for item in content_data]
            total_reaches = [item.get('reach', item.get('impressions', 0)) for item in content_data]
            
            if explore_reaches and total_reaches:
                total_explore = sum(explore_reaches)
                total_reach = sum(total_reaches)
                
                if total_reach > 0:
                    explore_ratio = total_explore / total_reach
                    threshold = indicators.get('explore_visibility_threshold', 0.02)
                    
                    if explore_ratio < threshold:
                        evidence.append(
                            ShadowBanEvidence(
                                method=DetectionMethod.DISCOVERY_BAN,
                                confidence=0.8,
                                description=f"Explore reach is {explore_ratio*100:.2f}% of total reach (expected >{threshold*100:.2f}%)",
                                data_points={
                                    "explore_ratio": explore_ratio,
                                    "threshold": threshold,
                                    "total_explore_reach": total_explore,
                                    "total_reach": total_reach
                                },
                                detected_at=datetime.now()
                            )
                        )
                        confidence_factors.append(0.8)
        
        elif platform == PlatformType.TIKTOK:
            # Check For You Page (FYP) visibility
            fyp_reaches = [item.get('fyp_reach', 0) for item in content_data]
            total_reaches = [item.get('reach', item.get('views', 0)) for item in content_data]
            
            if fyp_reaches and total_reaches:
                total_fyp = sum(fyp_reaches)
                total_reach = sum(total_reaches)
                
                if total_reach > 0:
                    fyp_ratio = total_fyp / total_reach
                    threshold = indicators.get('fyp_visibility_threshold', 0.05)
                    
                    if fyp_ratio < threshold:
                        evidence.append(
                            ShadowBanEvidence(
                                method=DetectionMethod.DISCOVERY_BAN,
                                confidence=0.9,
                                description=f"FYP reach is {fyp_ratio*100:.2f}% of total reach (expected >{threshold*100:.2f}%)",
                                data_points={
                                    "fyp_ratio": fyp_ratio,
                                    "threshold": threshold,
                                    "total_fyp_reach": total_fyp,
                                    "total_reach": total_reach
                                },
                                detected_at=datetime.now()
                            )
                        )
                        confidence_factors.append(0.9)
        
        # Check for new follower acquisition rate
        new_followers = [item.get('new_followers', 0) for item in content_data]
        if new_followers:
            avg_new_followers = statistics.mean(new_followers)
            total_reach = sum([item.get('reach', item.get('views', 0)) for item in content_data])
            
            if total_reach > 0:
                follower_conversion_rate = (sum(new_followers) / total_reach) * 100
                
                # Platform-specific conversion rate expectations
                expected_rate = 0.1 if platform == PlatformType.INSTAGRAM else 0.2  # TikTok typically higher
                
                if follower_conversion_rate < expected_rate * 0.3:  # Less than 30% of expected
                    evidence.append(
                        ShadowBanEvidence(
                            method=DetectionMethod.DISCOVERY_BAN,
                            confidence=0.6,
                            description=f"New follower conversion rate is {follower_conversion_rate:.3f}% (expected >{expected_rate*0.3:.3f}%)",
                            data_points={
                                "conversion_rate": follower_conversion_rate,
                                "expected_rate": expected_rate,
                                "total_new_followers": sum(new_followers),
                                "total_reach": total_reach
                            },
                            detected_at=datetime.now()
                        )
                    )
                    confidence_factors.append(0.6)
        
        if not confidence_factors:
            return None
        
        overall_confidence = min(sum(confidence_factors), 1.0)
        severity = self._determine_severity(overall_confidence, ShadowBanType.DISCOVERY_BAN)
        
        discovery_features = ["explore_page"] if platform == PlatformType.INSTAGRAM else ["for_you_page"]
        
        return ShadowBanTest(
            test_type=ShadowBanType.DISCOVERY_BAN,
            severity=severity,
            confidence=overall_confidence,
            evidence=evidence,
            affected_features=discovery_features + ["new_follower_acquisition"],
            platform_specific_data={
                "discovery_ratio": explore_ratio if 'explore_ratio' in locals() else fyp_ratio if 'fyp_ratio' in locals() else None,
                "conversion_rate": follower_conversion_rate if 'follower_conversion_rate' in locals() else None,
                "posts_analyzed": len(content_data)
            }
        )
    
    def _determine_severity(self, confidence: float, ban_type: ShadowBanType) -> ShadowBanSeverity:
        """Determine shadow ban severity based on confidence and type"""
        thresholds = self.detection_thresholds.get(ban_type, {})
        
        if confidence >= thresholds.get('complete_threshold', 0.95):
            return ShadowBanSeverity.COMPLETE
        elif confidence >= thresholds.get('heavy_threshold', 0.8):
            return ShadowBanSeverity.HEAVY
        elif confidence >= thresholds.get('moderate_threshold', 0.6):
            return ShadowBanSeverity.MODERATE
        elif confidence >= thresholds.get('light_threshold', 0.3):
            return ShadowBanSeverity.LIGHT
        else:
            return ShadowBanSeverity.NONE
    
    def _calculate_shadow_ban_score(self, detected_bans: List[ShadowBanTest]) -> float:
        """Calculate overall shadow ban score (0-1)"""
        if not detected_bans:
            return 0.0
        
        # Weight different ban types
        type_weights = {
            ShadowBanType.COMPLETE_SHADOW_BAN: 1.0,
            ShadowBanType.SEARCH_BAN: 0.8,
            ShadowBanType.HASHTAG_BAN: 0.7,
            ShadowBanType.DISCOVERY_BAN: 0.9,
            ShadowBanType.TIMELINE_SUPPRESSION: 0.8,
            ShadowBanType.REPLY_DEBOOSTING: 0.5,
            ShadowBanType.PARTIAL_SHADOW_BAN: 0.6
        }
        
        # Weight severity levels
        severity_weights = {
            ShadowBanSeverity.LIGHT: 0.3,
            ShadowBanSeverity.MODERATE: 0.6,
            ShadowBanSeverity.HEAVY: 0.8,
            ShadowBanSeverity.COMPLETE: 1.0
        }
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for ban in detected_bans:
            type_weight = type_weights.get(ban.test_type, 0.5)
            severity_weight = severity_weights.get(ban.severity, 0.3)
            
            weighted_score = ban.confidence * type_weight * severity_weight
            total_weighted_score += weighted_score
            total_weight += type_weight
        
        if total_weight == 0:
            return 0.0
        
        return min(total_weighted_score / total_weight, 1.0)
    
    def _calculate_visibility_score(
        self,
        content_data: List[Dict[str, Any]],
        detected_bans: List[ShadowBanTest],
        platform: PlatformType,
        user_metrics: Dict[str, Any]
    ) -> float:
        """Calculate overall visibility score (0-100)"""
        base_score = 100.0
        
        # Deduct points for detected shadow bans
        for ban in detected_bans:
            severity_deductions = {
                ShadowBanSeverity.LIGHT: 15,
                ShadowBanSeverity.MODERATE: 30,
                ShadowBanSeverity.HEAVY: 50,
                ShadowBanSeverity.COMPLETE: 70
            }
            
            deduction = severity_deductions.get(ban.severity, 10)
            base_score -= deduction * ban.confidence
        
        # Factor in actual performance metrics
        if content_data and user_metrics.get('followers', 0) > 0:
            reaches = [item.get('reach', item.get('impressions', 0)) for item in content_data]
            if reaches:
                avg_reach = statistics.mean(reaches)
                follower_count = user_metrics['followers']
                reach_ratio = avg_reach / follower_count
                
                # Expected reach ratios by platform
                expected_ratios = {
                    PlatformType.TWITTER: 0.05,
                    PlatformType.INSTAGRAM: 0.08,
                    PlatformType.FACEBOOK: 0.06,
                    PlatformType.LINKEDIN: 0.04,
                    PlatformType.TIKTOK: 0.15
                }
                
                expected_ratio = expected_ratios.get(platform, 0.05)
                performance_ratio = reach_ratio / expected_ratio
                
                if performance_ratio < 0.5:
                    base_score -= 20  # Poor performance
                elif performance_ratio < 0.8:
                    base_score -= 10
                elif performance_ratio > 1.5:
                    base_score += 10  # Good performance
        
        return max(base_score, 0.0)
    
    def _identify_affected_areas(self, detected_bans: List[ShadowBanTest]) -> List[str]:
        """Identify areas affected by shadow bans"""
        affected_areas = set()
        
        for ban in detected_bans:
            affected_areas.update(ban.affected_features)
        
        return list(affected_areas)
    
    def _calculate_detection_confidence(
        self,
        content_data: List[Dict[str, Any]],
        detected_bans: List[ShadowBanTest],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> float:
        """Calculate confidence in shadow ban detection"""
        base_confidence = min(len(content_data) * 8, 100)  # More content = higher confidence
        
        # Boost confidence with historical data
        if historical_data and len(historical_data) > 10:
            base_confidence *= 1.3
        elif not historical_data:
            base_confidence *= 0.7
        
        # Factor in detection confidence
        if detected_bans:
            avg_detection_confidence = statistics.mean([ban.confidence for ban in detected_bans])
            base_confidence = (base_confidence + avg_detection_confidence * 100) / 2
        
        # Adjust for data quality
        if len(content_data) < 8:
            base_confidence *= 0.6
        elif len(content_data) < 15:
            base_confidence *= 0.8
        
        return min(base_confidence, 100) / 100
    
    def _assess_shadow_ban_risk_level(
        self,
        overall_score: float,
        detected_bans: List[ShadowBanTest]
    ) -> RiskLevel:
        """Assess overall shadow ban risk level"""
        complete_bans = [b for b in detected_bans if b.severity == ShadowBanSeverity.COMPLETE]
        heavy_bans = [b for b in detected_bans if b.severity == ShadowBanSeverity.HEAVY]
        
        if complete_bans or overall_score >= 0.8:
            return RiskLevel.HIGH
        elif heavy_bans or overall_score >= 0.6:
            return RiskLevel.MEDIUM
        elif overall_score >= 0.3:
            return RiskLevel.LOW
        else:
            return RiskLevel.LOW
    
    def _generate_shadow_ban_recommendations(
        self,
        detected_bans: List[ShadowBanTest],
        platform: PlatformType,
        overall_score: float
    ) -> List[str]:
        """Generate shadow ban recovery recommendations"""
        recommendations = []
        
        ban_types = [ban.test_type for ban in detected_bans]
        
        if ShadowBanType.SEARCH_BAN in ban_types:
            recommendations.extend([
                "Avoid using banned or flagged keywords in your content",
                "Focus on creating original, high-quality content",
                "Reduce posting frequency temporarily"
            ])
        
        if ShadowBanType.HASHTAG_BAN in ban_types:
            recommendations.extend([
                "Stop using hashtags that show zero reach",
                "Research and use only verified, active hashtags",
                "Rotate hashtag usage to avoid repetitive patterns"
            ])
        
        if ShadowBanType.REPLY_DEBOOSTING in ban_types:
            recommendations.extend([
                "Reduce reply frequency and focus on quality responses",
                "Avoid controversial or sensitive topics in replies",
                "Engage more with original content creation"
            ])
        
        if ShadowBanType.TIMELINE_SUPPRESSION in ban_types:
            recommendations.extend([
                "Post during your audience's most active hours",
                "Create content that encourages immediate engagement",
                "Use platform-native features and formats"
            ])
        
        if ShadowBanType.DISCOVERY_BAN in ban_types:
            recommendations.extend([
                "Focus on building engagement with existing followers",
                "Create content using trending audio/formats",
                "Avoid reposting content from other platforms"
            ])
        
        # General recommendations based on severity
        if overall_score >= 0.7:
            recommendations.extend([
                "Consider taking a 48-72 hour break from posting",
                "Review and remove any potentially problematic content",
                "Focus on authentic engagement rather than growth tactics"
            ])
        
        return recommendations[:10]  # Limit to top 10
    
    def _generate_recovery_suggestions(
        self,
        detected_bans: List[ShadowBanTest],
        platform: PlatformType,
        visibility_score: float
    ) -> List[str]:
        """Generate specific recovery suggestions"""
        suggestions = []
        
        if visibility_score < 30:
            suggestions.extend([
                "Implement a content audit and remove low-performing posts",
                "Take a temporary break from posting (24-48 hours)",
                "Focus on creating evergreen, valuable content"
            ])
        elif visibility_score < 60:
            suggestions.extend([
                "Gradually increase posting frequency",
                "Monitor engagement patterns closely",
                "Diversify content types and formats"
            ])
        
        # Platform-specific recovery suggestions
        if platform == PlatformType.TWITTER:
            suggestions.extend([
                "Use Twitter Spaces to increase visibility",
                "Engage with trending topics naturally",
                "Focus on thread creation for better reach"
            ])
        elif platform == PlatformType.INSTAGRAM:
            suggestions.extend([
                "Use Instagram Stories and Reels more frequently",
                "Collaborate with other accounts in your niche",
                "Focus on building community through comments"
            ])
        elif platform == PlatformType.TIKTOK:
            suggestions.extend([
                "Create original content with trending sounds",
                "Post consistently at optimal times",
                "Engage with comments immediately after posting"
            ])
        
        return suggestions[:8]  # Limit to top 8
    
    def _generate_monitoring_recommendations(
        self,
        detected_bans: List[ShadowBanTest],
        platform: PlatformType
    ) -> List[str]:
        """Generate monitoring recommendations"""
        recommendations = [
            "Monitor reach and engagement metrics daily",
            "Track hashtag performance individually",
            "Test content visibility using secondary accounts",
            "Document any sudden changes in performance",
            "Set up alerts for significant metric drops"
        ]
        
        # Add platform-specific monitoring
        if platform == PlatformType.TWITTER:
            recommendations.extend([
                "Check if tweets appear in search results",
                "Monitor reply visibility in conversations",
                "Track timeline presence using analytics"
            ])
        elif platform == PlatformType.INSTAGRAM:
            recommendations.extend([
                "Test hashtag visibility in search",
                "Monitor Explore page appearances",
                "Track story completion rates"
            ])
        
        return recommendations[:8]
    
    async def _generate_shadow_ban_insights(
        self,
        detected_bans: List[ShadowBanTest],
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        user_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate platform-specific shadow ban insights"""
        insights = {
            "platform": platform.value,
            "shadow_ban_summary": {},
            "affected_features": [],
            "severity_breakdown": {},
            "recovery_outlook": {}
        }
        
        if detected_bans:
            # Shadow ban summary
            ban_types = [ban.test_type.value for ban in detected_bans]
            severities = [ban.severity.value for ban in detected_bans]
            
            insights["shadow_ban_summary"] = {
                "total_bans_detected": len(detected_bans),
                "ban_types": list(set(ban_types)),
                "highest_severity": max(severities) if severities else "none",
                "average_confidence": statistics.mean([ban.confidence for ban in detected_bans])
            }
            
            # Affected features
            all_features = []
            for ban in detected_bans:
                all_features.extend(ban.affected_features)
            insights["affected_features"] = list(set(all_features))
            
            # Severity breakdown
            severity_counts = {}
            for severity in severities:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            insights["severity_breakdown"] = severity_counts
            
            # Recovery outlook
            heavy_bans = len([b for b in detected_bans if b.severity in [ShadowBanSeverity.HEAVY, ShadowBanSeverity.COMPLETE]])
            if heavy_bans > 0:
                insights["recovery_outlook"] = {
                    "difficulty": "high",
                    "estimated_time": "2-4 weeks",
                    "success_probability": "medium"
                }
            else:
                insights["recovery_outlook"] = {
                    "difficulty": "medium",
                    "estimated_time": "1-2 weeks",
                    "success_probability": "high"
                }
        else:
            insights["shadow_ban_summary"] = {
                "status": "no_shadow_ban_detected",
                "account_health": "good"
            }
        
        return insights
    
    def _create_insufficient_data_analysis(
        self,
        platform: PlatformType,
        test_period_days: int
    ) -> ShadowBanAnalysis:
        """Create analysis when insufficient data is available"""
        return ShadowBanAnalysis(
            overall_shadow_ban_score=0.0,
            is_shadow_banned=False,
            detected_bans=[],
            risk_level=RiskLevel.LOW,
            visibility_score=50.0,  # Neutral score
            affected_areas=[],
            detection_confidence=0.0,
            recommendations=["Insufficient recent content for shadow ban analysis"],
            recovery_suggestions=["Post more content to enable comprehensive analysis"],
            monitoring_recommendations=["Monitor performance metrics as you post new content"],
            platform_insights={"platform": platform.value, "error": "insufficient_data"},
            analysis_timestamp=datetime.now(),
            test_period=(datetime.now() - timedelta(days=test_period_days), datetime.now())
        )
    
    def _create_error_analysis(
        self,
        platform: PlatformType,
        test_period_days: int,
        error_message: str
    ) -> ShadowBanAnalysis:
        """Create analysis when an error occurs"""
        return ShadowBanAnalysis(
            overall_shadow_ban_score=0.0,
            is_shadow_banned=False,
            detected_bans=[],
            risk_level=RiskLevel.LOW,
            visibility_score=0.0,
            affected_areas=[],
            detection_confidence=0.0,
            recommendations=[f"Analysis failed: {error_message}"],
            recovery_suggestions=["Retry analysis with different parameters"],
            monitoring_recommendations=["Check data quality and try again"],
            platform_insights={"platform": platform.value, "error": error_message},
            analysis_timestamp=datetime.now(),
            test_period=(datetime.now() - timedelta(days=test_period_days), datetime.now())
        )