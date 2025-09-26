"""
Penalty Detector for Social Media Algorithm Health Analysis

This module provides comprehensive penalty detection for social media accounts,
helping users identify algorithmic restrictions, shadow bans, and other penalties.
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


class PenaltyType(Enum):
    """Types of algorithmic penalties"""
    SHADOW_BAN = "shadow_ban"
    REACH_LIMITATION = "reach_limitation"
    ENGAGEMENT_THROTTLING = "engagement_throttling"
    CONTENT_SUPPRESSION = "content_suppression"
    HASHTAG_BAN = "hashtag_ban"
    LINK_PENALTY = "link_penalty"
    SPAM_FILTER = "spam_filter"
    QUALITY_FILTER = "quality_filter"
    TEMPORARY_RESTRICTION = "temporary_restriction"
    ACCOUNT_LIMITATION = "account_limitation"


class PenaltySeverity(Enum):
    """Severity levels of penalties"""
    NONE = "none"
    MILD = "mild"
    MODERATE = "moderate"
    SEVERE = "severe"
    CRITICAL = "critical"


class PenaltyStatus(Enum):
    """Status of penalty detection"""
    ACTIVE = "active"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    SUSPECTED = "suspected"
    MONITORING = "monitoring"


@dataclass
class PenaltyIndicator:
    """Individual penalty indicator"""
    penalty_type: PenaltyType
    severity: PenaltySeverity
    confidence: float
    evidence: List[str]
    detected_at: datetime
    platform_specific_data: Dict[str, Any]


@dataclass
class PenaltyAnalysis:
    """Comprehensive penalty analysis result"""
    overall_risk_score: float
    penalty_status: PenaltyStatus
    detected_penalties: List[PenaltyIndicator]
    risk_level: RiskLevel
    account_health_score: float
    trend_analysis: Dict[str, Any]
    recommendations: List[str]
    recovery_timeline: Optional[Dict[str, Any]]
    platform_insights: Dict[str, Any]
    analysis_period: Tuple[datetime, datetime]
    confidence_score: float


class PenaltyDetector:
    """
    Advanced penalty detection system for social media accounts.
    
    Analyzes content performance, engagement patterns, and reach metrics
    to identify potential algorithmic penalties and restrictions.
    """
    
    def __init__(self):
        """Initialize the penalty detector with platform-specific configurations"""
        self.platform_configs = self._load_platform_configs()
        self.penalty_thresholds = self._load_penalty_thresholds()
        
    def _load_platform_configs(self) -> Dict[PlatformType, Dict[str, Any]]:
        """Load platform-specific penalty detection configurations"""
        return {
            PlatformType.TWITTER: {
                "shadow_ban_indicators": {
                    "reach_drop_threshold": 0.7,  # 70% drop in reach
                    "engagement_drop_threshold": 0.6,
                    "search_visibility_threshold": 0.3,
                    "reply_visibility_threshold": 0.5
                },
                "penalty_patterns": {
                    "sudden_drop_window": 48,  # hours
                    "gradual_decline_window": 168,  # 1 week
                    "recovery_window": 336  # 2 weeks
                },
                "quality_thresholds": {
                    "min_engagement_rate": 0.02,
                    "min_reach_ratio": 0.03,
                    "spam_score_threshold": 0.7
                }
            },
            PlatformType.FACEBOOK: {
                "shadow_ban_indicators": {
                    "reach_drop_threshold": 0.8,
                    "engagement_drop_threshold": 0.7,
                    "organic_reach_threshold": 0.05,
                    "story_visibility_threshold": 0.4
                },
                "penalty_patterns": {
                    "sudden_drop_window": 72,
                    "gradual_decline_window": 240,
                    "recovery_window": 480
                },
                "quality_thresholds": {
                    "min_engagement_rate": 0.03,
                    "min_reach_ratio": 0.06,
                    "spam_score_threshold": 0.6
                }
            },
            PlatformType.INSTAGRAM: {
                "shadow_ban_indicators": {
                    "reach_drop_threshold": 0.6,
                    "engagement_drop_threshold": 0.5,
                    "hashtag_reach_threshold": 0.2,
                    "explore_visibility_threshold": 0.1
                },
                "penalty_patterns": {
                    "sudden_drop_window": 24,
                    "gradual_decline_window": 168,
                    "recovery_window": 336
                },
                "quality_thresholds": {
                    "min_engagement_rate": 0.04,
                    "min_reach_ratio": 0.08,
                    "spam_score_threshold": 0.5
                }
            },
            PlatformType.LINKEDIN: {
                "shadow_ban_indicators": {
                    "reach_drop_threshold": 0.8,
                    "engagement_drop_threshold": 0.7,
                    "feed_visibility_threshold": 0.3,
                    "connection_reach_threshold": 0.4
                },
                "penalty_patterns": {
                    "sudden_drop_window": 96,
                    "gradual_decline_window": 336,
                    "recovery_window": 672
                },
                "quality_thresholds": {
                    "min_engagement_rate": 0.025,
                    "min_reach_ratio": 0.04,
                    "spam_score_threshold": 0.8
                }
            },
            PlatformType.TIKTOK: {
                "shadow_ban_indicators": {
                    "reach_drop_threshold": 0.5,
                    "engagement_drop_threshold": 0.4,
                    "fyp_visibility_threshold": 0.1,
                    "hashtag_performance_threshold": 0.2
                },
                "penalty_patterns": {
                    "sudden_drop_window": 12,
                    "gradual_decline_window": 72,
                    "recovery_window": 168
                },
                "quality_thresholds": {
                    "min_engagement_rate": 0.03,
                    "min_reach_ratio": 0.15,
                    "spam_score_threshold": 0.4
                }
            }
        }
    
    def _load_penalty_thresholds(self) -> Dict[PenaltyType, Dict[str, float]]:
        """Load penalty detection thresholds"""
        return {
            PenaltyType.SHADOW_BAN: {
                "mild_threshold": 0.3,
                "moderate_threshold": 0.6,
                "severe_threshold": 0.8
            },
            PenaltyType.REACH_LIMITATION: {
                "mild_threshold": 0.2,
                "moderate_threshold": 0.5,
                "severe_threshold": 0.7
            },
            PenaltyType.ENGAGEMENT_THROTTLING: {
                "mild_threshold": 0.25,
                "moderate_threshold": 0.5,
                "severe_threshold": 0.75
            },
            PenaltyType.CONTENT_SUPPRESSION: {
                "mild_threshold": 0.3,
                "moderate_threshold": 0.6,
                "severe_threshold": 0.8
            },
            PenaltyType.HASHTAG_BAN: {
                "mild_threshold": 0.4,
                "moderate_threshold": 0.7,
                "severe_threshold": 0.9
            },
            PenaltyType.LINK_PENALTY: {
                "mild_threshold": 0.2,
                "moderate_threshold": 0.4,
                "severe_threshold": 0.6
            }
        }
    
    async def detect_penalties(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        follower_count: int,
        historical_data: Optional[List[Dict[str, Any]]] = None,
        analysis_days: int = 30
    ) -> PenaltyAnalysis:
        """
        Perform comprehensive penalty detection analysis
        
        Args:
            content_data: Recent content performance data
            platform: Social media platform
            follower_count: User's follower count
            historical_data: Historical performance data for comparison
            analysis_days: Number of days to analyze
            
        Returns:
            PenaltyAnalysis: Comprehensive penalty analysis results
        """
        try:
            logger.info(f"Starting penalty detection for {platform.value} with {len(content_data)} content items")
            
            # Filter recent content
            cutoff_date = datetime.now() - timedelta(days=analysis_days)
            recent_content = [
                item for item in content_data
                if datetime.fromisoformat(item.get('created_at', '')) > cutoff_date
            ]
            
            if not recent_content:
                logger.warning("No recent content found for penalty analysis")
                return self._create_empty_analysis(platform, analysis_days)
            
            # Detect individual penalties
            detected_penalties = []
            
            # Shadow ban detection
            shadow_ban_indicator = await self._detect_shadow_ban(
                recent_content, platform, follower_count, historical_data
            )
            if shadow_ban_indicator:
                detected_penalties.append(shadow_ban_indicator)
            
            # Reach limitation detection
            reach_penalty = await self._detect_reach_limitation(
                recent_content, platform, follower_count, historical_data
            )
            if reach_penalty:
                detected_penalties.append(reach_penalty)
            
            # Engagement throttling detection
            engagement_penalty = await self._detect_engagement_throttling(
                recent_content, platform, historical_data
            )
            if engagement_penalty:
                detected_penalties.append(engagement_penalty)
            
            # Content suppression detection
            content_penalty = await self._detect_content_suppression(
                recent_content, platform, historical_data
            )
            if content_penalty:
                detected_penalties.append(content_penalty)
            
            # Hashtag ban detection
            hashtag_penalty = await self._detect_hashtag_ban(
                recent_content, platform, historical_data
            )
            if hashtag_penalty:
                detected_penalties.append(hashtag_penalty)
            
            # Link penalty detection
            link_penalty = await self._detect_link_penalty(
                recent_content, platform, historical_data
            )
            if link_penalty:
                detected_penalties.append(link_penalty)
            
            # Calculate overall risk and health scores
            overall_risk_score = self._calculate_overall_risk_score(detected_penalties)
            account_health_score = self._calculate_account_health_score(
                recent_content, detected_penalties, platform, follower_count
            )
            
            # Determine penalty status
            penalty_status = self._determine_penalty_status(detected_penalties, recent_content)
            risk_level = self._assess_risk_level(overall_risk_score, detected_penalties)
            
            # Analyze trends
            trend_analysis = await self._analyze_penalty_trends(
                recent_content, detected_penalties, platform, historical_data
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                detected_penalties, trend_analysis, platform
            )
            
            # Estimate recovery timeline
            recovery_timeline = self._estimate_recovery_timeline(
                detected_penalties, platform, trend_analysis
            )
            
            # Generate platform insights
            platform_insights = await self._generate_platform_insights(
                detected_penalties, recent_content, platform
            )
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                recent_content, historical_data, detected_penalties
            )
            
            analysis_period = (cutoff_date, datetime.now())
            
            return PenaltyAnalysis(
                overall_risk_score=overall_risk_score,
                penalty_status=penalty_status,
                detected_penalties=detected_penalties,
                risk_level=risk_level,
                account_health_score=account_health_score,
                trend_analysis=trend_analysis,
                recommendations=recommendations,
                recovery_timeline=recovery_timeline,
                platform_insights=platform_insights,
                analysis_period=analysis_period,
                confidence_score=confidence_score
            )
            
        except Exception as e:
            logger.error(f"Error in penalty detection: {str(e)}")
            return self._create_empty_analysis(platform, analysis_days)
    
    async def _detect_shadow_ban(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        follower_count: int,
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[PenaltyIndicator]:
        """Detect potential shadow ban"""
        config = self.platform_configs.get(platform, {})
        indicators = config.get('shadow_ban_indicators', {})
        
        evidence = []
        confidence_factors = []
        
        # Calculate recent performance metrics
        recent_reach = [item.get('reach', 0) for item in content_data[-10:]]  # Last 10 posts
        recent_engagement = [
            item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
            for item in content_data[-10:]
        ]
        
        if not recent_reach or not recent_engagement:
            return None
        
        avg_recent_reach = statistics.mean(recent_reach)
        avg_recent_engagement = statistics.mean(recent_engagement)
        
        # Compare with historical data if available
        if historical_data:
            historical_reach = [item.get('reach', 0) for item in historical_data]
            historical_engagement = [
                item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
                for item in historical_data
            ]
            
            if historical_reach and historical_engagement:
                avg_historical_reach = statistics.mean(historical_reach)
                avg_historical_engagement = statistics.mean(historical_engagement)
                
                # Check for significant drops
                reach_drop_ratio = avg_recent_reach / max(avg_historical_reach, 1)
                engagement_drop_ratio = avg_recent_engagement / max(avg_historical_engagement, 1)
                
                reach_threshold = indicators.get('reach_drop_threshold', 0.7)
                engagement_threshold = indicators.get('engagement_drop_threshold', 0.6)
                
                if reach_drop_ratio < reach_threshold:
                    evidence.append(f"Reach dropped by {(1-reach_drop_ratio)*100:.1f}% compared to historical average")
                    confidence_factors.append(0.4)
                
                if engagement_drop_ratio < engagement_threshold:
                    evidence.append(f"Engagement dropped by {(1-engagement_drop_ratio)*100:.1f}% compared to historical average")
                    confidence_factors.append(0.3)
        
        # Check reach ratio against follower count
        expected_reach = follower_count * 0.05  # Assume 5% typical reach
        actual_reach_ratio = avg_recent_reach / max(expected_reach, 1)
        
        if actual_reach_ratio < 0.3:  # Less than 30% of expected reach
            evidence.append(f"Reach is only {actual_reach_ratio*100:.1f}% of expected based on follower count")
            confidence_factors.append(0.3)
        
        # Check for consistent low performance
        low_performance_count = sum(1 for reach in recent_reach if reach < expected_reach * 0.2)
        if low_performance_count >= len(recent_reach) * 0.7:  # 70% of posts underperforming
            evidence.append(f"{low_performance_count}/{len(recent_reach)} recent posts severely underperforming")
            confidence_factors.append(0.2)
        
        # Platform-specific checks
        if platform == PlatformType.TWITTER:
            # Check reply visibility (if data available)
            reply_visibility = sum(item.get('reply_visibility', 1) for item in content_data[-5:]) / 5
            if reply_visibility < indicators.get('reply_visibility_threshold', 0.5):
                evidence.append("Replies showing reduced visibility in conversations")
                confidence_factors.append(0.2)
        
        elif platform == PlatformType.INSTAGRAM:
            # Check hashtag reach
            hashtag_reach = [item.get('hashtag_reach', 0) for item in content_data[-5:]]
            if hashtag_reach and statistics.mean(hashtag_reach) < avg_recent_reach * 0.2:
                evidence.append("Hashtag reach significantly lower than total reach")
                confidence_factors.append(0.3)
        
        # Calculate overall confidence
        if not confidence_factors:
            return None
        
        overall_confidence = sum(confidence_factors)
        
        # Determine severity
        if overall_confidence >= 0.8:
            severity = PenaltySeverity.SEVERE
        elif overall_confidence >= 0.6:
            severity = PenaltySeverity.MODERATE
        elif overall_confidence >= 0.3:
            severity = PenaltySeverity.MILD
        else:
            return None  # Not confident enough to report
        
        return PenaltyIndicator(
            penalty_type=PenaltyType.SHADOW_BAN,
            severity=severity,
            confidence=min(overall_confidence, 1.0),
            evidence=evidence,
            detected_at=datetime.now(),
            platform_specific_data={
                "reach_drop_ratio": reach_drop_ratio if 'reach_drop_ratio' in locals() else None,
                "engagement_drop_ratio": engagement_drop_ratio if 'engagement_drop_ratio' in locals() else None,
                "actual_reach_ratio": actual_reach_ratio
            }
        )
    
    async def _detect_reach_limitation(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        follower_count: int,
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[PenaltyIndicator]:
        """Detect reach limitation penalties"""
        evidence = []
        confidence_factors = []
        
        # Calculate reach metrics
        recent_reach = [item.get('reach', 0) for item in content_data[-15:]]
        if not recent_reach:
            return None
        
        avg_reach = statistics.mean(recent_reach)
        expected_reach = follower_count * 0.05  # Platform average assumption
        reach_ratio = avg_reach / max(expected_reach, 1)
        
        # Check for consistently low reach
        if reach_ratio < 0.3:
            evidence.append(f"Average reach is only {reach_ratio*100:.1f}% of expected")
            confidence_factors.append(0.4)
        
        # Check reach consistency
        if len(recent_reach) > 5:
            reach_std = statistics.stdev(recent_reach)
            reach_cv = reach_std / max(avg_reach, 1)  # Coefficient of variation
            
            if reach_cv < 0.2:  # Very consistent low reach
                evidence.append("Reach is consistently limited across all content")
                confidence_factors.append(0.3)
        
        # Check for organic vs paid reach (if data available)
        organic_reach = [item.get('organic_reach', item.get('reach', 0)) for item in content_data[-10:]]
        if organic_reach:
            avg_organic_reach = statistics.mean(organic_reach)
            organic_ratio = avg_organic_reach / max(avg_reach, 1)
            
            if organic_ratio < 0.7:  # Less than 70% organic reach
                evidence.append(f"Organic reach is only {organic_ratio*100:.1f}% of total reach")
                confidence_factors.append(0.2)
        
        # Platform-specific checks
        config = self.platform_configs.get(platform, {})
        if platform == PlatformType.FACEBOOK:
            story_reach = [item.get('story_reach', 0) for item in content_data[-5:]]
            if story_reach and statistics.mean(story_reach) < avg_reach * 0.4:
                evidence.append("Story reach significantly lower than post reach")
                confidence_factors.append(0.2)
        
        if not confidence_factors:
            return None
        
        overall_confidence = sum(confidence_factors)
        
        if overall_confidence < 0.3:
            return None
        
        # Determine severity
        if overall_confidence >= 0.7:
            severity = PenaltySeverity.SEVERE
        elif overall_confidence >= 0.5:
            severity = PenaltySeverity.MODERATE
        else:
            severity = PenaltySeverity.MILD
        
        return PenaltyIndicator(
            penalty_type=PenaltyType.REACH_LIMITATION,
            severity=severity,
            confidence=min(overall_confidence, 1.0),
            evidence=evidence,
            detected_at=datetime.now(),
            platform_specific_data={
                "reach_ratio": reach_ratio,
                "avg_reach": avg_reach,
                "expected_reach": expected_reach
            }
        )
    
    async def _detect_engagement_throttling(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[PenaltyIndicator]:
        """Detect engagement throttling penalties"""
        evidence = []
        confidence_factors = []
        
        # Calculate engagement metrics
        recent_engagement_rates = []
        for item in content_data[-15:]:
            reach = item.get('reach', 0)
            engagement = item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
            if reach > 0:
                recent_engagement_rates.append((engagement / reach) * 100)
        
        if not recent_engagement_rates:
            return None
        
        avg_engagement_rate = statistics.mean(recent_engagement_rates)
        
        # Compare with platform benchmarks
        config = self.platform_configs.get(platform, {})
        min_engagement_rate = config.get('quality_thresholds', {}).get('min_engagement_rate', 0.02) * 100
        
        if avg_engagement_rate < min_engagement_rate:
            evidence.append(f"Engagement rate ({avg_engagement_rate:.2f}%) below platform minimum")
            confidence_factors.append(0.3)
        
        # Check engagement velocity (time to reach engagement)
        engagement_velocities = []
        for item in content_data[-10:]:
            created_at = datetime.fromisoformat(item.get('created_at'))
            hours_since = (datetime.now() - created_at).total_seconds() / 3600
            engagement = item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
            
            if hours_since > 0:
                velocity = engagement / hours_since
                engagement_velocities.append(velocity)
        
        if engagement_velocities:
            avg_velocity = statistics.mean(engagement_velocities)
            
            # Compare with historical data if available
            if historical_data:
                historical_velocities = []
                for item in historical_data[-20:]:
                    created_at = datetime.fromisoformat(item.get('created_at'))
                    hours_since = (datetime.now() - created_at).total_seconds() / 3600
                    engagement = item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
                    
                    if hours_since > 24:  # Only consider posts older than 24 hours
                        velocity = engagement / 24  # Normalize to 24-hour velocity
                        historical_velocities.append(velocity)
                
                if historical_velocities:
                    avg_historical_velocity = statistics.mean(historical_velocities)
                    velocity_ratio = avg_velocity / max(avg_historical_velocity, 1)
                    
                    if velocity_ratio < 0.5:  # 50% slower engagement
                        evidence.append(f"Engagement velocity {(1-velocity_ratio)*100:.1f}% slower than historical average")
                        confidence_factors.append(0.4)
        
        # Check for engagement pattern anomalies
        if len(recent_engagement_rates) > 5:
            engagement_std = statistics.stdev(recent_engagement_rates)
            if engagement_std < avg_engagement_rate * 0.2:  # Very consistent low engagement
                evidence.append("Engagement rates are consistently throttled")
                confidence_factors.append(0.3)
        
        if not confidence_factors:
            return None
        
        overall_confidence = sum(confidence_factors)
        
        if overall_confidence < 0.3:
            return None
        
        # Determine severity
        if overall_confidence >= 0.75:
            severity = PenaltySeverity.SEVERE
        elif overall_confidence >= 0.5:
            severity = PenaltySeverity.MODERATE
        else:
            severity = PenaltySeverity.MILD
        
        return PenaltyIndicator(
            penalty_type=PenaltyType.ENGAGEMENT_THROTTLING,
            severity=severity,
            confidence=min(overall_confidence, 1.0),
            evidence=evidence,
            detected_at=datetime.now(),
            platform_specific_data={
                "avg_engagement_rate": avg_engagement_rate,
                "min_threshold": min_engagement_rate,
                "avg_velocity": avg_velocity if 'avg_velocity' in locals() else None
            }
        )
    
    async def _detect_content_suppression(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[PenaltyIndicator]:
        """Detect content suppression penalties"""
        evidence = []
        confidence_factors = []
        
        # Check for content with external links
        link_posts = [item for item in content_data[-20:] if item.get('has_links', False)]
        non_link_posts = [item for item in content_data[-20:] if not item.get('has_links', False)]
        
        if link_posts and non_link_posts:
            link_avg_reach = statistics.mean([item.get('reach', 0) for item in link_posts])
            non_link_avg_reach = statistics.mean([item.get('reach', 0) for item in non_link_posts])
            
            if non_link_avg_reach > 0:
                link_penalty_ratio = link_avg_reach / non_link_avg_reach
                
                if link_penalty_ratio < 0.6:  # 40% less reach for posts with links
                    evidence.append(f"Posts with links get {(1-link_penalty_ratio)*100:.1f}% less reach")
                    confidence_factors.append(0.3)
        
        # Check for hashtag suppression
        hashtag_posts = [item for item in content_data[-20:] if len(item.get('hashtags', [])) > 5]
        low_hashtag_posts = [item for item in content_data[-20:] if len(item.get('hashtags', [])) <= 2]
        
        if hashtag_posts and low_hashtag_posts:
            hashtag_avg_reach = statistics.mean([item.get('reach', 0) for item in hashtag_posts])
            low_hashtag_avg_reach = statistics.mean([item.get('reach', 0) for item in low_hashtag_posts])
            
            if low_hashtag_avg_reach > 0:
                hashtag_ratio = hashtag_avg_reach / low_hashtag_avg_reach
                
                if hashtag_ratio < 0.7:  # Posts with many hashtags perform worse
                    evidence.append(f"Posts with many hashtags get {(1-hashtag_ratio)*100:.1f}% less reach")
                    confidence_factors.append(0.2)
        
        # Check for content type suppression
        content_types = {}
        for item in content_data[-15:]:
            content_type = item.get('type', 'post')
            if content_type not in content_types:
                content_types[content_type] = []
            content_types[content_type].append(item.get('reach', 0))
        
        if len(content_types) > 1:
            type_performance = {
                content_type: statistics.mean(reaches)
                for content_type, reaches in content_types.items()
                if reaches
            }
            
            if type_performance:
                max_performance = max(type_performance.values())
                suppressed_types = [
                    content_type for content_type, performance in type_performance.items()
                    if performance < max_performance * 0.5
                ]
                
                if suppressed_types:
                    evidence.append(f"Content types {', '.join(suppressed_types)} appear suppressed")
                    confidence_factors.append(0.2)
        
        # Check for keyword-based suppression (if keyword data available)
        sensitive_keywords = ['covid', 'vaccine', 'politics', 'election', 'crypto', 'investment']
        sensitive_posts = []
        regular_posts = []
        
        for item in content_data[-20:]:
            text = item.get('text', '').lower()
            if any(keyword in text for keyword in sensitive_keywords):
                sensitive_posts.append(item)
            else:
                regular_posts.append(item)
        
        if sensitive_posts and regular_posts:
            sensitive_avg_reach = statistics.mean([item.get('reach', 0) for item in sensitive_posts])
            regular_avg_reach = statistics.mean([item.get('reach', 0) for item in regular_posts])
            
            if regular_avg_reach > 0:
                sensitive_ratio = sensitive_avg_reach / regular_avg_reach
                
                if sensitive_ratio < 0.5:  # Sensitive content gets 50% less reach
                    evidence.append(f"Posts with sensitive keywords get {(1-sensitive_ratio)*100:.1f}% less reach")
                    confidence_factors.append(0.4)
        
        if not confidence_factors:
            return None
        
        overall_confidence = sum(confidence_factors)
        
        if overall_confidence < 0.2:
            return None
        
        # Determine severity
        if overall_confidence >= 0.6:
            severity = PenaltySeverity.MODERATE
        elif overall_confidence >= 0.4:
            severity = PenaltySeverity.MILD
        else:
            return None
        
        return PenaltyIndicator(
            penalty_type=PenaltyType.CONTENT_SUPPRESSION,
            severity=severity,
            confidence=min(overall_confidence, 1.0),
            evidence=evidence,
            detected_at=datetime.now(),
            platform_specific_data={
                "link_penalty_ratio": link_penalty_ratio if 'link_penalty_ratio' in locals() else None,
                "hashtag_ratio": hashtag_ratio if 'hashtag_ratio' in locals() else None,
                "sensitive_ratio": sensitive_ratio if 'sensitive_ratio' in locals() else None
            }
        )
    
    async def _detect_hashtag_ban(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[PenaltyIndicator]:
        """Detect hashtag ban penalties"""
        evidence = []
        confidence_factors = []
        
        # Analyze hashtag performance
        hashtag_performance = {}
        
        for item in content_data[-20:]:
            hashtags = item.get('hashtags', [])
            reach = item.get('reach', 0)
            hashtag_reach = item.get('hashtag_reach', 0)
            
            for hashtag in hashtags:
                if hashtag not in hashtag_performance:
                    hashtag_performance[hashtag] = {'total_reach': 0, 'hashtag_reach': 0, 'count': 0}
                
                hashtag_performance[hashtag]['total_reach'] += reach
                hashtag_performance[hashtag]['hashtag_reach'] += hashtag_reach
                hashtag_performance[hashtag]['count'] += 1
        
        # Identify potentially banned hashtags
        banned_hashtags = []
        for hashtag, data in hashtag_performance.items():
            if data['count'] >= 3:  # Used at least 3 times
                avg_total_reach = data['total_reach'] / data['count']
                avg_hashtag_reach = data['hashtag_reach'] / data['count']
                
                if avg_total_reach > 0:
                    hashtag_reach_ratio = avg_hashtag_reach / avg_total_reach
                    
                    if hashtag_reach_ratio < 0.1:  # Less than 10% of reach from hashtags
                        banned_hashtags.append(hashtag)
        
        if banned_hashtags:
            evidence.append(f"Hashtags appear banned or restricted: {', '.join(banned_hashtags[:5])}")
            confidence_factors.append(0.4)
        
        # Check for sudden drop in hashtag effectiveness
        if historical_data:
            historical_hashtag_performance = {}
            
            for item in historical_data[-30:]:
                hashtags = item.get('hashtags', [])
                hashtag_reach = item.get('hashtag_reach', 0)
                
                for hashtag in hashtags:
                    if hashtag not in historical_hashtag_performance:
                        historical_hashtag_performance[hashtag] = []
                    historical_hashtag_performance[hashtag].append(hashtag_reach)
            
            # Compare current vs historical hashtag performance
            performance_drops = []
            for hashtag in hashtag_performance:
                if hashtag in historical_hashtag_performance:
                    current_avg = hashtag_performance[hashtag]['hashtag_reach'] / hashtag_performance[hashtag]['count']
                    historical_avg = statistics.mean(historical_hashtag_performance[hashtag])
                    
                    if historical_avg > 0:
                        drop_ratio = current_avg / historical_avg
                        if drop_ratio < 0.3:  # 70% drop in hashtag performance
                            performance_drops.append((hashtag, drop_ratio))
            
            if performance_drops:
                worst_drops = sorted(performance_drops, key=lambda x: x[1])[:3]
                evidence.append(f"Significant hashtag performance drops detected: {', '.join([f'{h} ({(1-r)*100:.0f}% drop)' for h, r in worst_drops])}")
                confidence_factors.append(0.5)
        
        # Platform-specific hashtag analysis
        if platform == PlatformType.INSTAGRAM:
            # Check for hashtag reach vs total reach ratio
            posts_with_hashtags = [item for item in content_data[-15:] if item.get('hashtags')]
            if posts_with_hashtags:
                hashtag_reach_ratios = []
                for item in posts_with_hashtags:
                    total_reach = item.get('reach', 0)
                    hashtag_reach = item.get('hashtag_reach', 0)
                    if total_reach > 0:
                        hashtag_reach_ratios.append(hashtag_reach / total_reach)
                
                if hashtag_reach_ratios:
                    avg_hashtag_ratio = statistics.mean(hashtag_reach_ratios)
                    if avg_hashtag_ratio < 0.2:  # Less than 20% reach from hashtags
                        evidence.append(f"Hashtag reach is only {avg_hashtag_ratio*100:.1f}% of total reach")
                        confidence_factors.append(0.3)
        
        if not confidence_factors:
            return None
        
        overall_confidence = sum(confidence_factors)
        
        if overall_confidence < 0.3:
            return None
        
        # Determine severity
        if overall_confidence >= 0.8:
            severity = PenaltySeverity.SEVERE
        elif overall_confidence >= 0.6:
            severity = PenaltySeverity.MODERATE
        else:
            severity = PenaltySeverity.MILD
        
        return PenaltyIndicator(
            penalty_type=PenaltyType.HASHTAG_BAN,
            severity=severity,
            confidence=min(overall_confidence, 1.0),
            evidence=evidence,
            detected_at=datetime.now(),
            platform_specific_data={
                "banned_hashtags": banned_hashtags,
                "performance_drops": performance_drops if 'performance_drops' in locals() else [],
                "avg_hashtag_ratio": avg_hashtag_ratio if 'avg_hashtag_ratio' in locals() else None
            }
        )
    
    async def _detect_link_penalty(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[PenaltyIndicator]:
        """Detect link penalty"""
        evidence = []
        confidence_factors = []
        
        # Separate posts with and without links
        link_posts = [item for item in content_data[-20:] if item.get('has_links', False)]
        non_link_posts = [item for item in content_data[-20:] if not item.get('has_links', False)]
        
        if not link_posts or not non_link_posts:
            return None  # Need both types to compare
        
        # Compare performance
        link_avg_reach = statistics.mean([item.get('reach', 0) for item in link_posts])
        non_link_avg_reach = statistics.mean([item.get('reach', 0) for item in non_link_posts])
        
        link_avg_engagement = statistics.mean([
            item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
            for item in link_posts
        ])
        non_link_avg_engagement = statistics.mean([
            item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
            for item in non_link_posts
        ])
        
        # Calculate penalty ratios
        reach_penalty_ratio = link_avg_reach / max(non_link_avg_reach, 1)
        engagement_penalty_ratio = link_avg_engagement / max(non_link_avg_engagement, 1)
        
        # Check for significant penalties
        if reach_penalty_ratio < 0.7:  # 30% less reach
            evidence.append(f"Posts with links get {(1-reach_penalty_ratio)*100:.1f}% less reach")
            confidence_factors.append(0.4)
        
        if engagement_penalty_ratio < 0.8:  # 20% less engagement
            evidence.append(f"Posts with links get {(1-engagement_penalty_ratio)*100:.1f}% less engagement")
            confidence_factors.append(0.3)
        
        # Check for external domain penalties
        domain_performance = {}
        for item in link_posts:
            domains = item.get('external_domains', [])
            reach = item.get('reach', 0)
            
            for domain in domains:
                if domain not in domain_performance:
                    domain_performance[domain] = []
                domain_performance[domain].append(reach)
        
        # Identify poorly performing domains
        penalized_domains = []
        for domain, reaches in domain_performance.items():
            if len(reaches) >= 2:  # Domain used at least twice
                avg_domain_reach = statistics.mean(reaches)
                if avg_domain_reach < non_link_avg_reach * 0.5:  # 50% less than non-link posts
                    penalized_domains.append(domain)
        
        if penalized_domains:
            evidence.append(f"Specific domains appear penalized: {', '.join(penalized_domains[:3])}")
            confidence_factors.append(0.3)
        
        # Platform-specific link analysis
        config = self.platform_configs.get(platform, {})
        if platform == PlatformType.FACEBOOK:
            # Facebook heavily penalizes external links
            if reach_penalty_ratio < 0.5:  # 50% penalty is severe for Facebook
                evidence.append("Severe link penalty detected (typical for Facebook)")
                confidence_factors.append(0.2)
        
        elif platform == PlatformType.INSTAGRAM:
            # Instagram penalizes links in captions but not in bio/stories
            caption_links = [item for item in link_posts if item.get('link_in_caption', True)]
            if caption_links:
                caption_avg_reach = statistics.mean([item.get('reach', 0) for item in caption_links])
                caption_penalty_ratio = caption_avg_reach / max(non_link_avg_reach, 1)
                
                if caption_penalty_ratio < 0.6:
                    evidence.append("Links in captions heavily penalized")
                    confidence_factors.append(0.3)
        
        if not confidence_factors:
            return None
        
        overall_confidence = sum(confidence_factors)
        
        if overall_confidence < 0.3:
            return None
        
        # Determine severity based on penalty ratio
        if reach_penalty_ratio < 0.4 or engagement_penalty_ratio < 0.5:
            severity = PenaltySeverity.SEVERE
        elif reach_penalty_ratio < 0.6 or engagement_penalty_ratio < 0.7:
            severity = PenaltySeverity.MODERATE
        else:
            severity = PenaltySeverity.MILD
        
        return PenaltyIndicator(
            penalty_type=PenaltyType.LINK_PENALTY,
            severity=severity,
            confidence=min(overall_confidence, 1.0),
            evidence=evidence,
            detected_at=datetime.now(),
            platform_specific_data={
                "reach_penalty_ratio": reach_penalty_ratio,
                "engagement_penalty_ratio": engagement_penalty_ratio,
                "penalized_domains": penalized_domains,
                "link_posts_count": len(link_posts),
                "non_link_posts_count": len(non_link_posts)
            }
        )
    
    def _calculate_overall_risk_score(self, detected_penalties: List[PenaltyIndicator]) -> float:
        """Calculate overall penalty risk score (0-100)"""
        if not detected_penalties:
            return 0.0
        
        # Weight penalties by severity and confidence
        severity_weights = {
            PenaltySeverity.MILD: 1.0,
            PenaltySeverity.MODERATE: 2.0,
            PenaltySeverity.SEVERE: 3.0,
            PenaltySeverity.CRITICAL: 4.0
        }
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for penalty in detected_penalties:
            weight = severity_weights.get(penalty.severity, 1.0)
            score = penalty.confidence * weight * 25  # Scale to 0-100
            
            total_weighted_score += score
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        # Average and cap at 100
        return min(total_weighted_score / total_weight, 100.0)
    
    def _calculate_account_health_score(
        self,
        content_data: List[Dict[str, Any]],
        detected_penalties: List[PenaltyIndicator],
        platform: PlatformType,
        follower_count: int
    ) -> float:
        """Calculate overall account health score (0-100)"""
        base_score = 100.0
        
        # Deduct points for detected penalties
        for penalty in detected_penalties:
            severity_deductions = {
                PenaltySeverity.MILD: 10,
                PenaltySeverity.MODERATE: 20,
                PenaltySeverity.SEVERE: 35,
                PenaltySeverity.CRITICAL: 50
            }
            
            deduction = severity_deductions.get(penalty.severity, 10)
            base_score -= deduction * penalty.confidence
        
        # Factor in content performance
        if content_data:
            recent_content = content_data[-10:]
            avg_reach = statistics.mean([item.get('reach', 0) for item in recent_content])
            expected_reach = follower_count * 0.05
            
            reach_ratio = avg_reach / max(expected_reach, 1)
            if reach_ratio < 0.5:
                base_score -= 15  # Poor reach performance
            elif reach_ratio < 0.8:
                base_score -= 5
        
        return max(base_score, 0.0)
    
    def _determine_penalty_status(
        self,
        detected_penalties: List[PenaltyIndicator],
        content_data: List[Dict[str, Any]]
    ) -> PenaltyStatus:
        """Determine overall penalty status"""
        if not detected_penalties:
            return PenaltyStatus.RESOLVED
        
        # Check for severe penalties
        severe_penalties = [p for p in detected_penalties if p.severity in [PenaltySeverity.SEVERE, PenaltySeverity.CRITICAL]]
        if severe_penalties:
            return PenaltyStatus.ACTIVE
        
        # Check for recent improvement trends
        if len(content_data) >= 10:
            recent_performance = content_data[-5:]
            older_performance = content_data[-10:-5]
            
            recent_avg_reach = statistics.mean([item.get('reach', 0) for item in recent_performance])
            older_avg_reach = statistics.mean([item.get('reach', 0) for item in older_performance])
            
            if recent_avg_reach > older_avg_reach * 1.2:  # 20% improvement
                return PenaltyStatus.RECOVERING
        
        # Check penalty age
        recent_penalties = [p for p in detected_penalties if (datetime.now() - p.detected_at).days < 7]
        if recent_penalties:
            return PenaltyStatus.ACTIVE
        else:
            return PenaltyStatus.MONITORING
    
    def _assess_risk_level(
        self,
        overall_risk_score: float,
        detected_penalties: List[PenaltyIndicator]
    ) -> RiskLevel:
        """Assess overall risk level"""
        critical_penalties = [p for p in detected_penalties if p.severity == PenaltySeverity.CRITICAL]
        severe_penalties = [p for p in detected_penalties if p.severity == PenaltySeverity.SEVERE]
        
        if critical_penalties or overall_risk_score >= 80:
            return RiskLevel.HIGH
        elif severe_penalties or overall_risk_score >= 60:
            return RiskLevel.MEDIUM
        elif overall_risk_score >= 30:
            return RiskLevel.LOW
        else:
            return RiskLevel.LOW
    
    async def _analyze_penalty_trends(
        self,
        content_data: List[Dict[str, Any]],
        detected_penalties: List[PenaltyIndicator],
        platform: PlatformType,
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Analyze penalty trends over time"""
        trends = {
            "performance_trend": "stable",
            "penalty_progression": "stable",
            "recovery_indicators": []
        }
        
        if len(content_data) >= 10:
            # Analyze performance trend
            recent_reaches = [item.get('reach', 0) for item in content_data[-5:]]
            older_reaches = [item.get('reach', 0) for item in content_data[-10:-5]]
            
            recent_avg = statistics.mean(recent_reaches)
            older_avg = statistics.mean(older_reaches)
            
            if recent_avg > older_avg * 1.2:
                trends["performance_trend"] = "improving"
                trends["recovery_indicators"].append("Reach performance improving")
            elif recent_avg < older_avg * 0.8:
                trends["performance_trend"] = "declining"
            
            # Analyze engagement trend
            recent_engagement = [
                item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
                for item in content_data[-5:]
            ]
            older_engagement = [
                item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
                for item in content_data[-10:-5]
            ]
            
            recent_eng_avg = statistics.mean(recent_engagement)
            older_eng_avg = statistics.mean(older_engagement)
            
            if recent_eng_avg > older_eng_avg * 1.15:
                trends["recovery_indicators"].append("Engagement rates improving")
        
        # Analyze penalty severity progression
        if detected_penalties:
            severe_count = len([p for p in detected_penalties if p.severity in [PenaltySeverity.SEVERE, PenaltySeverity.CRITICAL]])
            moderate_count = len([p for p in detected_penalties if p.severity == PenaltySeverity.MODERATE])
            
            if severe_count > 0:
                trends["penalty_progression"] = "worsening"
            elif moderate_count > 2:
                trends["penalty_progression"] = "concerning"
        
        return trends
    
    def _generate_recommendations(
        self,
        detected_penalties: List[PenaltyIndicator],
        trend_analysis: Dict[str, Any],
        platform: PlatformType
    ) -> List[str]:
        """Generate actionable recommendations for penalty recovery"""
        recommendations = []
        
        # General recommendations based on detected penalties
        penalty_types = [p.penalty_type for p in detected_penalties]
        
        if PenaltyType.SHADOW_BAN in penalty_types:
            recommendations.extend([
                "Reduce posting frequency temporarily to avoid further penalties",
                "Focus on creating high-quality, engaging content",
                "Avoid using banned or flagged hashtags",
                "Engage authentically with your audience"
            ])
        
        if PenaltyType.LINK_PENALTY in penalty_types:
            recommendations.extend([
                "Reduce the number of external links in your posts",
                "Use platform-native features to share links (Stories, bio)",
                "Focus on creating valuable content without promotional links"
            ])
        
        if PenaltyType.HASHTAG_BAN in penalty_types:
            recommendations.extend([
                "Research and avoid banned or restricted hashtags",
                "Use a mix of popular and niche hashtags",
                "Rotate hashtags regularly to avoid repetitive patterns"
            ])
        
        if PenaltyType.ENGAGEMENT_THROTTLING in penalty_types:
            recommendations.extend([
                "Focus on creating content that encourages genuine engagement",
                "Post during your audience's most active hours",
                "Respond promptly to comments and messages"
            ])
        
        # Trend-based recommendations
        if trend_analysis.get("performance_trend") == "declining":
            recommendations.append("Consider taking a break from posting to reset algorithmic perception")
        elif trend_analysis.get("performance_trend") == "improving":
            recommendations.append("Continue current strategy as performance is recovering")
        
        # Platform-specific recommendations
        platform_recs = self._get_platform_specific_penalty_recommendations(platform, penalty_types)
        recommendations.extend(platform_recs)
        
        return recommendations[:12]  # Limit to top 12 recommendations
    
    def _get_platform_specific_penalty_recommendations(
        self,
        platform: PlatformType,
        penalty_types: List[PenaltyType]
    ) -> List[str]:
        """Get platform-specific penalty recovery recommendations"""
        recommendations = []
        
        if platform == PlatformType.TWITTER:
            recommendations.extend([
                "Avoid excessive tweeting or retweeting in short periods",
                "Use Twitter's native features like polls and Spaces",
                "Engage with trending topics naturally, not just for visibility"
            ])
        elif platform == PlatformType.INSTAGRAM:
            recommendations.extend([
                "Use Instagram Stories and Reels to maintain visibility",
                "Avoid using the same hashtags repeatedly",
                "Focus on building genuine community engagement"
            ])
        elif platform == PlatformType.FACEBOOK:
            recommendations.extend([
                "Share content that encourages meaningful conversations",
                "Use Facebook Groups to build community",
                "Avoid posting too frequently to prevent spam detection"
            ])
        elif platform == PlatformType.LINKEDIN:
            recommendations.extend([
                "Share professional, industry-relevant content",
                "Engage thoughtfully with other professionals' content",
                "Use LinkedIn's publishing platform for long-form content"
            ])
        elif platform == PlatformType.TIKTOK:
            recommendations.extend([
                "Create original content using trending sounds",
                "Avoid reposting content from other platforms",
                "Focus on authentic, entertaining content"
            ])
        
        return recommendations
    
    def _estimate_recovery_timeline(
        self,
        detected_penalties: List[PenaltyIndicator],
        platform: PlatformType,
        trend_analysis: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Estimate penalty recovery timeline"""
        if not detected_penalties:
            return None
        
        config = self.platform_configs.get(platform, {})
        recovery_window = config.get('penalty_patterns', {}).get('recovery_window', 336)  # Default 2 weeks
        
        # Adjust based on penalty severity
        max_severity = max([p.severity for p in detected_penalties], key=lambda x: [
            PenaltySeverity.MILD, PenaltySeverity.MODERATE, PenaltySeverity.SEVERE, PenaltySeverity.CRITICAL
        ].index(x))
        
        severity_multipliers = {
            PenaltySeverity.MILD: 0.5,
            PenaltySeverity.MODERATE: 1.0,
            PenaltySeverity.SEVERE: 1.5,
            PenaltySeverity.CRITICAL: 2.0
        }
        
        estimated_hours = recovery_window * severity_multipliers.get(max_severity, 1.0)
        
        # Adjust based on trends
        if trend_analysis.get("performance_trend") == "improving":
            estimated_hours *= 0.7  # Faster recovery if already improving
        elif trend_analysis.get("performance_trend") == "declining":
            estimated_hours *= 1.3  # Slower recovery if still declining
        
        estimated_days = int(estimated_hours / 24)
        
        return {
            "estimated_days": estimated_days,
            "estimated_hours": int(estimated_hours),
            "confidence": "medium" if len(detected_penalties) <= 2 else "low",
            "factors_affecting_recovery": [
                "Consistency in following recommendations",
                "Platform algorithm changes",
                "Content quality improvements",
                "Audience engagement patterns"
            ]
        }
    
    async def _generate_platform_insights(
        self,
        detected_penalties: List[PenaltyIndicator],
        content_data: List[Dict[str, Any]],
        platform: PlatformType
    ) -> Dict[str, Any]:
        """Generate platform-specific insights"""
        insights = {
            "platform": platform.value,
            "penalty_summary": {},
            "platform_specific_factors": {},
            "algorithm_health": {}
        }
        
        # Penalty summary
        if detected_penalties:
            penalty_counts = {}
            for penalty in detected_penalties:
                penalty_type = penalty.penalty_type.value
                if penalty_type not in penalty_counts:
                    penalty_counts[penalty_type] = 0
                penalty_counts[penalty_type] += 1
            
            insights["penalty_summary"] = {
                "total_penalties": len(detected_penalties),
                "penalty_types": penalty_counts,
                "most_severe": max([p.severity.value for p in detected_penalties]),
                "highest_confidence": max([p.confidence for p in detected_penalties])
            }
        
        # Platform-specific factors
        if platform == PlatformType.TWITTER:
            insights["platform_specific_factors"] = {
                "reply_visibility": "Check if replies are visible in conversations",
                "search_visibility": "Test if content appears in search results",
                "timeline_presence": "Monitor if content appears in followers' timelines"
            }
        elif platform == PlatformType.INSTAGRAM:
            insights["platform_specific_factors"] = {
                "hashtag_reach": "Monitor reach from hashtags vs total reach",
                "explore_visibility": "Check if content appears in Explore feed",
                "story_visibility": "Monitor story view rates"
            }
        elif platform == PlatformType.FACEBOOK:
            insights["platform_specific_factors"] = {
                "organic_reach": "Facebook heavily limits organic reach",
                "link_penalties": "External links are significantly penalized",
                "engagement_quality": "Focus on meaningful interactions"
            }
        
        # Algorithm health assessment
        if content_data:
            recent_performance = content_data[-10:]
            avg_reach = statistics.mean([item.get('reach', 0) for item in recent_performance])
            avg_engagement = statistics.mean([
                item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
                for item in recent_performance
            ])
            
            insights["algorithm_health"] = {
                "average_reach": avg_reach,
                "average_engagement": avg_engagement,
                "health_status": "poor" if detected_penalties else "good",
                "improvement_potential": "high" if len(detected_penalties) > 2 else "medium"
            }
        
        return insights
    
    def _calculate_confidence_score(
        self,
        content_data: List[Dict[str, Any]],
        historical_data: Optional[List[Dict[str, Any]]],
        detected_penalties: List[PenaltyIndicator]
    ) -> float:
        """Calculate confidence score for the penalty analysis"""
        base_confidence = min(len(content_data) * 5, 100)  # More content = higher confidence
        
        # Adjust based on historical data availability
        if historical_data and len(historical_data) > 10:
            base_confidence *= 1.2  # Boost confidence with historical comparison
        elif not historical_data:
            base_confidence *= 0.8  # Reduce confidence without historical data
        
        # Adjust based on penalty detection confidence
        if detected_penalties:
            avg_penalty_confidence = statistics.mean([p.confidence for p in detected_penalties])
            base_confidence = (base_confidence + avg_penalty_confidence * 100) / 2
        
        # Adjust based on data quality
        if len(content_data) < 10:
            base_confidence *= 0.7
        elif len(content_data) < 20:
            base_confidence *= 0.85
        
        return min(base_confidence, 100)
    
    def _create_empty_analysis(
        self,
        platform: PlatformType,
        analysis_days: int
    ) -> PenaltyAnalysis:
        """Create empty analysis when no data is available"""
        return PenaltyAnalysis(
            overall_risk_score=0.0,
            penalty_status=PenaltyStatus.MONITORING,
            detected_penalties=[],
            risk_level=RiskLevel.LOW,
            account_health_score=50.0,  # Neutral score
            trend_analysis={"error": "insufficient_data"},
            recommendations=["No recent content data available for penalty analysis"],
            recovery_timeline=None,
            platform_insights={"platform": platform.value, "error": "insufficient_data"},
            analysis_period=(datetime.now() - timedelta(days=analysis_days), datetime.now()),
            confidence_score=0.0
        )