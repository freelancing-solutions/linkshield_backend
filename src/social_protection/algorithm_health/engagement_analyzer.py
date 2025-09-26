"""
Engagement Analyzer for Social Media Algorithm Health Analysis

This module provides comprehensive engagement analysis for social media content,
helping users understand engagement patterns, quality, and algorithmic impact.
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


class EngagementType(Enum):
    """Types of engagement interactions"""
    LIKE = "like"
    COMMENT = "comment"
    SHARE = "share"
    SAVE = "save"
    CLICK = "click"
    VIEW = "view"
    REACTION = "reaction"
    MENTION = "mention"
    RETWEET = "retweet"
    QUOTE = "quote"


class EngagementQuality(Enum):
    """Quality levels of engagement"""
    EXCELLENT = "excellent"
    GOOD = "good"
    AVERAGE = "average"
    POOR = "poor"
    SUSPICIOUS = "suspicious"


class EngagementPattern(Enum):
    """Engagement pattern types"""
    ORGANIC = "organic"
    BOOSTED = "boosted"
    VIRAL = "viral"
    DECLINING = "declining"
    ARTIFICIAL = "artificial"
    SEASONAL = "seasonal"


@dataclass
class EngagementMetrics:
    """Container for engagement metrics"""
    total_engagement: int
    engagement_rate: float
    engagement_velocity: float  # Engagement per hour
    engagement_distribution: Dict[EngagementType, int]
    quality_score: float
    authenticity_score: float
    timestamp: datetime
    content_id: Optional[str] = None
    reach: Optional[int] = None
    impressions: Optional[int] = None


@dataclass
class EngagementAnalysis:
    """Comprehensive engagement analysis result"""
    overall_score: float
    quality: EngagementQuality
    pattern: EngagementPattern
    risk_level: RiskLevel
    metrics: List[EngagementMetrics]
    engagement_trends: Dict[str, Any]
    audience_insights: Dict[str, Any]
    recommendations: List[str]
    platform_benchmarks: Dict[str, float]
    analysis_period: Tuple[datetime, datetime]
    confidence_score: float


class EngagementAnalyzer:
    """
    Advanced engagement analysis system for social media content.
    
    Analyzes engagement patterns, quality, authenticity, and provides
    insights for improving content performance and audience interaction.
    """
    
    def __init__(self):
        """Initialize the engagement analyzer with platform-specific configurations"""
        self.platform_configs = self._load_platform_configs()
        self.engagement_weights = self._load_engagement_weights()
        
    def _load_platform_configs(self) -> Dict[PlatformType, Dict[str, Any]]:
        """Load platform-specific engagement configurations"""
        return {
            PlatformType.TWITTER: {
                "avg_engagement_rate": 0.045,  # 4.5% industry average
                "excellent_threshold": 0.09,
                "good_threshold": 0.06,
                "poor_threshold": 0.02,
                "velocity_window_hours": 24,
                "viral_threshold": 1000,
                "primary_engagements": [EngagementType.LIKE, EngagementType.RETWEET, EngagementType.COMMENT],
                "authenticity_factors": {
                    "comment_like_ratio": 0.3,
                    "retweet_like_ratio": 0.2,
                    "engagement_velocity_threshold": 100
                }
            },
            PlatformType.FACEBOOK: {
                "avg_engagement_rate": 0.063,
                "excellent_threshold": 0.12,
                "good_threshold": 0.08,
                "poor_threshold": 0.03,
                "velocity_window_hours": 48,
                "viral_threshold": 5000,
                "primary_engagements": [EngagementType.LIKE, EngagementType.SHARE, EngagementType.COMMENT],
                "authenticity_factors": {
                    "comment_like_ratio": 0.25,
                    "share_like_ratio": 0.15,
                    "engagement_velocity_threshold": 200
                }
            },
            PlatformType.INSTAGRAM: {
                "avg_engagement_rate": 0.083,
                "excellent_threshold": 0.15,
                "good_threshold": 0.10,
                "poor_threshold": 0.04,
                "velocity_window_hours": 24,
                "viral_threshold": 10000,
                "primary_engagements": [EngagementType.LIKE, EngagementType.COMMENT, EngagementType.SAVE],
                "authenticity_factors": {
                    "comment_like_ratio": 0.1,
                    "save_like_ratio": 0.05,
                    "engagement_velocity_threshold": 500
                }
            },
            PlatformType.LINKEDIN: {
                "avg_engagement_rate": 0.054,
                "excellent_threshold": 0.10,
                "good_threshold": 0.07,
                "poor_threshold": 0.025,
                "velocity_window_hours": 72,
                "viral_threshold": 1000,
                "primary_engagements": [EngagementType.LIKE, EngagementType.COMMENT, EngagementType.SHARE],
                "authenticity_factors": {
                    "comment_like_ratio": 0.2,
                    "share_like_ratio": 0.1,
                    "engagement_velocity_threshold": 50
                }
            },
            PlatformType.TIKTOK: {
                "avg_engagement_rate": 0.055,
                "excellent_threshold": 0.12,
                "good_threshold": 0.08,
                "poor_threshold": 0.03,
                "velocity_window_hours": 12,
                "viral_threshold": 50000,
                "primary_engagements": [EngagementType.LIKE, EngagementType.COMMENT, EngagementType.SHARE],
                "authenticity_factors": {
                    "comment_like_ratio": 0.05,
                    "share_like_ratio": 0.02,
                    "engagement_velocity_threshold": 1000
                }
            }
        }
    
    def _load_engagement_weights(self) -> Dict[EngagementType, float]:
        """Load engagement type weights for scoring"""
        return {
            EngagementType.LIKE: 1.0,
            EngagementType.COMMENT: 3.0,
            EngagementType.SHARE: 5.0,
            EngagementType.SAVE: 4.0,
            EngagementType.CLICK: 2.0,
            EngagementType.VIEW: 0.1,
            EngagementType.REACTION: 1.5,
            EngagementType.MENTION: 3.0,
            EngagementType.RETWEET: 4.0,
            EngagementType.QUOTE: 6.0
        }
    
    async def analyze_engagement(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        follower_count: int,
        analysis_days: int = 30
    ) -> EngagementAnalysis:
        """
        Perform comprehensive engagement analysis
        
        Args:
            content_data: List of content items with engagement metrics
            platform: Social media platform
            follower_count: User's follower count
            analysis_days: Number of days to analyze
            
        Returns:
            EngagementAnalysis: Comprehensive analysis results
        """
        try:
            logger.info(f"Starting engagement analysis for {platform.value} with {len(content_data)} content items")
            
            # Filter recent content
            cutoff_date = datetime.now() - timedelta(days=analysis_days)
            recent_content = [
                item for item in content_data
                if datetime.fromisoformat(item.get('created_at', '')) > cutoff_date
            ]
            
            if not recent_content:
                logger.warning("No recent content found for engagement analysis")
                return self._create_empty_analysis(platform, analysis_days)
            
            # Calculate engagement metrics for each content item
            metrics = []
            for item in recent_content:
                metric = await self._calculate_engagement_metrics(item, platform, follower_count)
                if metric:
                    metrics.append(metric)
            
            if not metrics:
                return self._create_empty_analysis(platform, analysis_days)
            
            # Analyze overall engagement performance
            overall_score = self._calculate_overall_score(metrics, platform)
            quality = self._assess_engagement_quality(overall_score, platform)
            pattern = self._identify_engagement_pattern(metrics, platform)
            risk_level = self._assess_risk_level(overall_score, quality, pattern)
            
            # Analyze engagement trends
            engagement_trends = await self._analyze_engagement_trends(metrics, platform)
            
            # Generate audience insights
            audience_insights = await self._generate_audience_insights(metrics, recent_content, platform)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                overall_score, quality, pattern, engagement_trends, platform
            )
            
            # Calculate platform benchmarks
            platform_benchmarks = self._calculate_platform_benchmarks(metrics, platform)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(metrics, len(recent_content))
            
            analysis_period = (
                min(m.timestamp for m in metrics),
                max(m.timestamp for m in metrics)
            )
            
            return EngagementAnalysis(
                overall_score=overall_score,
                quality=quality,
                pattern=pattern,
                risk_level=risk_level,
                metrics=metrics,
                engagement_trends=engagement_trends,
                audience_insights=audience_insights,
                recommendations=recommendations,
                platform_benchmarks=platform_benchmarks,
                analysis_period=analysis_period,
                confidence_score=confidence_score
            )
            
        except Exception as e:
            logger.error(f"Error in engagement analysis: {str(e)}")
            return self._create_empty_analysis(platform, analysis_days)
    
    async def _calculate_engagement_metrics(
        self,
        content_item: Dict[str, Any],
        platform: PlatformType,
        follower_count: int
    ) -> Optional[EngagementMetrics]:
        """Calculate engagement metrics for a single content item"""
        try:
            # Extract engagement data
            likes = content_item.get('likes', 0)
            comments = content_item.get('comments', 0)
            shares = content_item.get('shares', 0)
            saves = content_item.get('saves', 0)
            clicks = content_item.get('clicks', 0)
            views = content_item.get('views', 0)
            reach = content_item.get('reach', 0)
            impressions = content_item.get('impressions', reach)
            
            # Build engagement distribution
            engagement_distribution = {
                EngagementType.LIKE: likes,
                EngagementType.COMMENT: comments,
                EngagementType.SHARE: shares,
                EngagementType.SAVE: saves,
                EngagementType.CLICK: clicks,
                EngagementType.VIEW: views
            }
            
            # Platform-specific adjustments
            if platform == PlatformType.TWITTER:
                retweets = content_item.get('retweets', shares)
                quotes = content_item.get('quotes', 0)
                engagement_distribution[EngagementType.RETWEET] = retweets
                engagement_distribution[EngagementType.QUOTE] = quotes
            
            # Calculate total weighted engagement
            total_engagement = sum(
                count * self.engagement_weights.get(eng_type, 1.0)
                for eng_type, count in engagement_distribution.items()
            )
            
            # Calculate engagement rate
            base_metric = max(impressions, reach, follower_count * 0.1)  # Use best available metric
            engagement_rate = (total_engagement / max(base_metric, 1)) * 100
            
            # Calculate engagement velocity (engagement per hour since posting)
            post_time = datetime.fromisoformat(content_item.get('created_at'))
            hours_since_post = max((datetime.now() - post_time).total_seconds() / 3600, 1)
            engagement_velocity = total_engagement / hours_since_post
            
            # Calculate quality and authenticity scores
            quality_score = self._calculate_quality_score(engagement_distribution, platform)
            authenticity_score = self._calculate_authenticity_score(
                engagement_distribution, engagement_velocity, platform
            )
            
            return EngagementMetrics(
                total_engagement=int(total_engagement),
                engagement_rate=engagement_rate,
                engagement_velocity=engagement_velocity,
                engagement_distribution=engagement_distribution,
                quality_score=quality_score,
                authenticity_score=authenticity_score,
                timestamp=post_time,
                content_id=content_item.get('id'),
                reach=reach,
                impressions=impressions
            )
            
        except Exception as e:
            logger.error(f"Error calculating engagement metrics: {str(e)}")
            return None
    
    def _calculate_quality_score(
        self,
        engagement_distribution: Dict[EngagementType, int],
        platform: PlatformType
    ) -> float:
        """Calculate engagement quality score (0-100)"""
        config = self.platform_configs.get(platform, {})
        primary_engagements = config.get('primary_engagements', [])
        
        total_engagement = sum(engagement_distribution.values())
        if total_engagement == 0:
            return 0.0
        
        # Calculate quality based on engagement type distribution
        quality_score = 0.0
        
        # High-value engagements (comments, shares) get higher scores
        high_value_count = (
            engagement_distribution.get(EngagementType.COMMENT, 0) +
            engagement_distribution.get(EngagementType.SHARE, 0) +
            engagement_distribution.get(EngagementType.SAVE, 0) +
            engagement_distribution.get(EngagementType.QUOTE, 0)
        )
        
        medium_value_count = (
            engagement_distribution.get(EngagementType.LIKE, 0) +
            engagement_distribution.get(EngagementType.REACTION, 0) +
            engagement_distribution.get(EngagementType.RETWEET, 0)
        )
        
        low_value_count = (
            engagement_distribution.get(EngagementType.VIEW, 0) +
            engagement_distribution.get(EngagementType.CLICK, 0)
        )
        
        # Weighted quality calculation
        quality_score = (
            (high_value_count * 50) +
            (medium_value_count * 30) +
            (low_value_count * 10)
        ) / max(total_engagement, 1)
        
        # Normalize to 0-100 scale
        return min(quality_score, 100)
    
    def _calculate_authenticity_score(
        self,
        engagement_distribution: Dict[EngagementType, int],
        engagement_velocity: float,
        platform: PlatformType
    ) -> float:
        """Calculate engagement authenticity score (0-100)"""
        config = self.platform_configs.get(platform, {})
        authenticity_factors = config.get('authenticity_factors', {})
        
        authenticity_score = 100.0
        
        # Check engagement ratios for suspicious patterns
        likes = engagement_distribution.get(EngagementType.LIKE, 0)
        comments = engagement_distribution.get(EngagementType.COMMENT, 0)
        shares = engagement_distribution.get(EngagementType.SHARE, 0)
        
        if likes > 0:
            # Comment-to-like ratio check
            comment_ratio = comments / likes
            expected_comment_ratio = authenticity_factors.get('comment_like_ratio', 0.1)
            
            if comment_ratio > expected_comment_ratio * 3:  # Too many comments
                authenticity_score -= 20
            elif comment_ratio < expected_comment_ratio * 0.1:  # Too few comments
                authenticity_score -= 10
            
            # Share-to-like ratio check
            if platform in [PlatformType.FACEBOOK, PlatformType.LINKEDIN]:
                share_ratio = shares / likes
                expected_share_ratio = authenticity_factors.get('share_like_ratio', 0.1)
                
                if share_ratio > expected_share_ratio * 5:  # Too many shares
                    authenticity_score -= 15
        
        # Engagement velocity check
        velocity_threshold = authenticity_factors.get('engagement_velocity_threshold', 100)
        if engagement_velocity > velocity_threshold * 10:  # Suspiciously fast engagement
            authenticity_score -= 30
        elif engagement_velocity > velocity_threshold * 5:
            authenticity_score -= 15
        
        # Check for bot-like patterns (round numbers, suspicious timing)
        total_engagement = sum(engagement_distribution.values())
        if total_engagement > 100:
            # Check for suspiciously round numbers
            round_number_penalty = 0
            for count in engagement_distribution.values():
                if count > 50 and count % 100 == 0:  # Exact hundreds
                    round_number_penalty += 5
                elif count > 20 and count % 50 == 0:  # Exact fifties
                    round_number_penalty += 3
            
            authenticity_score -= min(round_number_penalty, 20)
        
        return max(authenticity_score, 0)
    
    def _calculate_overall_score(
        self,
        metrics: List[EngagementMetrics],
        platform: PlatformType
    ) -> float:
        """Calculate overall engagement score"""
        if not metrics:
            return 0.0
        
        # Weight recent metrics more heavily
        now = datetime.now()
        weighted_scores = []
        
        for metric in metrics:
            days_old = (now - metric.timestamp).days
            weight = max(1.0 - (days_old * 0.03), 0.1)  # Decay weight over time
            
            # Combine engagement rate, quality, and authenticity
            combined_score = (
                metric.engagement_rate * 0.4 +
                metric.quality_score * 0.3 +
                metric.authenticity_score * 0.3
            )
            
            weighted_scores.append(combined_score * weight)
        
        return sum(weighted_scores) / len(weighted_scores)
    
    def _assess_engagement_quality(
        self,
        overall_score: float,
        platform: PlatformType
    ) -> EngagementQuality:
        """Assess overall engagement quality"""
        config = self.platform_configs.get(platform, {})
        
        if overall_score >= 80:
            return EngagementQuality.EXCELLENT
        elif overall_score >= 60:
            return EngagementQuality.GOOD
        elif overall_score >= 40:
            return EngagementQuality.AVERAGE
        elif overall_score >= 20:
            return EngagementQuality.POOR
        else:
            return EngagementQuality.SUSPICIOUS
    
    def _identify_engagement_pattern(
        self,
        metrics: List[EngagementMetrics],
        platform: PlatformType
    ) -> EngagementPattern:
        """Identify engagement pattern type"""
        if len(metrics) < 3:
            return EngagementPattern.ORGANIC
        
        # Sort by timestamp
        sorted_metrics = sorted(metrics, key=lambda x: x.timestamp)
        engagement_rates = [m.engagement_rate for m in sorted_metrics]
        authenticity_scores = [m.authenticity_score for m in sorted_metrics]
        
        # Check for artificial patterns
        avg_authenticity = statistics.mean(authenticity_scores)
        if avg_authenticity < 50:
            return EngagementPattern.ARTIFICIAL
        
        # Check for viral content
        config = self.platform_configs.get(platform, {})
        viral_threshold = config.get('viral_threshold', 1000)
        max_engagement = max(m.total_engagement for m in metrics)
        
        if max_engagement > viral_threshold:
            return EngagementPattern.VIRAL
        
        # Check for boosted content (consistent high engagement)
        if len(engagement_rates) >= 5:
            recent_rates = engagement_rates[-5:]
            if all(rate > statistics.mean(engagement_rates) * 1.5 for rate in recent_rates):
                return EngagementPattern.BOOSTED
        
        # Check for declining pattern
        if len(engagement_rates) >= 5:
            first_half = engagement_rates[:len(engagement_rates)//2]
            second_half = engagement_rates[len(engagement_rates)//2:]
            
            if statistics.mean(second_half) < statistics.mean(first_half) * 0.7:
                return EngagementPattern.DECLINING
        
        # Check for seasonal patterns (would need more historical data)
        # For now, default to organic
        return EngagementPattern.ORGANIC
    
    def _assess_risk_level(
        self,
        overall_score: float,
        quality: EngagementQuality,
        pattern: EngagementPattern
    ) -> RiskLevel:
        """Assess risk level based on engagement analysis"""
        if quality == EngagementQuality.SUSPICIOUS or pattern == EngagementPattern.ARTIFICIAL:
            return RiskLevel.HIGH
        elif quality == EngagementQuality.POOR or pattern == EngagementPattern.DECLINING:
            return RiskLevel.MEDIUM
        elif overall_score >= 70:
            return RiskLevel.LOW
        else:
            return RiskLevel.MEDIUM
    
    async def _analyze_engagement_trends(
        self,
        metrics: List[EngagementMetrics],
        platform: PlatformType
    ) -> Dict[str, Any]:
        """Analyze engagement trends over time"""
        if len(metrics) < 3:
            return {"trend": "insufficient_data"}
        
        # Sort by timestamp
        sorted_metrics = sorted(metrics, key=lambda x: x.timestamp)
        
        # Calculate trends
        engagement_rates = [m.engagement_rate for m in sorted_metrics]
        quality_scores = [m.quality_score for m in sorted_metrics]
        authenticity_scores = [m.authenticity_score for m in sorted_metrics]
        
        trends = {
            "engagement_rate_trend": self._calculate_trend(engagement_rates),
            "quality_trend": self._calculate_trend(quality_scores),
            "authenticity_trend": self._calculate_trend(authenticity_scores),
            "average_engagement_rate": statistics.mean(engagement_rates),
            "engagement_rate_volatility": statistics.stdev(engagement_rates) if len(engagement_rates) > 1 else 0,
            "best_performing_period": self._identify_best_period(sorted_metrics),
            "engagement_distribution_trends": self._analyze_engagement_type_trends(sorted_metrics)
        }
        
        return trends
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for a series of values"""
        if len(values) < 3:
            return "stable"
        
        # Simple linear regression to determine trend
        n = len(values)
        x_values = list(range(n))
        
        x_mean = sum(x_values) / n
        y_mean = sum(values) / n
        
        numerator = sum((x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return "stable"
        
        slope = numerator / denominator
        
        if slope > 0.5:
            return "increasing"
        elif slope < -0.5:
            return "decreasing"
        else:
            return "stable"
    
    def _identify_best_period(self, sorted_metrics: List[EngagementMetrics]) -> Dict[str, Any]:
        """Identify the best performing time period"""
        if len(sorted_metrics) < 7:
            return {"period": "insufficient_data"}
        
        # Group by day of week and hour
        day_performance = {}
        hour_performance = {}
        
        for metric in sorted_metrics:
            day_of_week = metric.timestamp.strftime('%A')
            hour = metric.timestamp.hour
            
            if day_of_week not in day_performance:
                day_performance[day_of_week] = []
            day_performance[day_of_week].append(metric.engagement_rate)
            
            if hour not in hour_performance:
                hour_performance[hour] = []
            hour_performance[hour].append(metric.engagement_rate)
        
        # Find best performing day and hour
        best_day = max(day_performance.items(), key=lambda x: statistics.mean(x[1]))[0]
        best_hour = max(hour_performance.items(), key=lambda x: statistics.mean(x[1]))[0]
        
        return {
            "best_day": best_day,
            "best_hour": best_hour,
            "day_performance": {day: statistics.mean(rates) for day, rates in day_performance.items()},
            "hour_performance": {str(hour): statistics.mean(rates) for hour, rates in hour_performance.items()}
        }
    
    def _analyze_engagement_type_trends(
        self,
        sorted_metrics: List[EngagementMetrics]
    ) -> Dict[str, str]:
        """Analyze trends for different engagement types"""
        engagement_type_trends = {}
        
        # Collect data for each engagement type
        type_data = {}
        for metric in sorted_metrics:
            for eng_type, count in metric.engagement_distribution.items():
                if eng_type not in type_data:
                    type_data[eng_type] = []
                type_data[eng_type].append(count)
        
        # Calculate trends for each type
        for eng_type, values in type_data.items():
            if len(values) >= 3:
                engagement_type_trends[eng_type.value] = self._calculate_trend(values)
            else:
                engagement_type_trends[eng_type.value] = "stable"
        
        return engagement_type_trends
    
    async def _generate_audience_insights(
        self,
        metrics: List[EngagementMetrics],
        content_data: List[Dict[str, Any]],
        platform: PlatformType
    ) -> Dict[str, Any]:
        """Generate insights about audience behavior"""
        insights = {
            "engagement_patterns": {},
            "audience_quality": {},
            "interaction_preferences": {}
        }
        
        if not metrics:
            return insights
        
        # Analyze engagement patterns
        total_metrics = len(metrics)
        high_quality_posts = sum(1 for m in metrics if m.quality_score > 70)
        high_authenticity_posts = sum(1 for m in metrics if m.authenticity_score > 80)
        
        insights["engagement_patterns"] = {
            "high_quality_ratio": high_quality_posts / total_metrics,
            "high_authenticity_ratio": high_authenticity_posts / total_metrics,
            "average_engagement_velocity": statistics.mean([m.engagement_velocity for m in metrics]),
            "engagement_consistency": 1 - (statistics.stdev([m.engagement_rate for m in metrics]) / 
                                         max(statistics.mean([m.engagement_rate for m in metrics]), 1))
        }
        
        # Analyze audience quality
        avg_authenticity = statistics.mean([m.authenticity_score for m in metrics])
        insights["audience_quality"] = {
            "authenticity_score": avg_authenticity,
            "quality_assessment": "high" if avg_authenticity > 80 else "medium" if avg_authenticity > 60 else "low",
            "bot_risk_level": "low" if avg_authenticity > 80 else "medium" if avg_authenticity > 50 else "high"
        }
        
        # Analyze interaction preferences
        all_distributions = [m.engagement_distribution for m in metrics]
        total_by_type = {}
        
        for distribution in all_distributions:
            for eng_type, count in distribution.items():
                if eng_type not in total_by_type:
                    total_by_type[eng_type] = 0
                total_by_type[eng_type] += count
        
        total_engagement = sum(total_by_type.values())
        if total_engagement > 0:
            preferences = {
                eng_type.value: (count / total_engagement) * 100
                for eng_type, count in total_by_type.items()
            }
            
            # Find top 3 preferred engagement types
            top_preferences = sorted(preferences.items(), key=lambda x: x[1], reverse=True)[:3]
            
            insights["interaction_preferences"] = {
                "preferred_engagement_types": [pref[0] for pref in top_preferences],
                "engagement_distribution": preferences,
                "interaction_diversity": len([p for p in preferences.values() if p > 5])  # Types with >5% share
            }
        
        return insights
    
    def _generate_recommendations(
        self,
        overall_score: float,
        quality: EngagementQuality,
        pattern: EngagementPattern,
        engagement_trends: Dict[str, Any],
        platform: PlatformType
    ) -> List[str]:
        """Generate actionable recommendations for improving engagement"""
        recommendations = []
        
        # Score-based recommendations
        if overall_score < 40:
            recommendations.append("Your engagement is significantly below average. Focus on creating more interactive content.")
        elif overall_score < 60:
            recommendations.append("Your engagement has room for improvement. Consider experimenting with different content formats.")
        
        # Quality-based recommendations
        if quality == EngagementQuality.SUSPICIOUS:
            recommendations.append("Suspicious engagement patterns detected. Review your audience and avoid engagement manipulation.")
        elif quality == EngagementQuality.POOR:
            recommendations.append("Focus on creating higher-quality content that encourages meaningful interactions.")
        
        # Pattern-based recommendations
        if pattern == EngagementPattern.DECLINING:
            recommendations.append("Your engagement is declining. Analyze your recent content and adjust your strategy.")
        elif pattern == EngagementPattern.ARTIFICIAL:
            recommendations.append("Artificial engagement patterns detected. Focus on organic growth strategies.")
        
        # Trend-based recommendations
        if engagement_trends.get("engagement_rate_trend") == "decreasing":
            recommendations.append("Your engagement rate is decreasing. Try posting at different times or with different content types.")
        
        if engagement_trends.get("authenticity_trend") == "decreasing":
            recommendations.append("Engagement authenticity is declining. Focus on building genuine audience relationships.")
        
        # Best period recommendations
        best_period = engagement_trends.get("best_performing_period", {})
        if best_period.get("best_day") and best_period.get("best_hour"):
            recommendations.append(
                f"Your best engagement occurs on {best_period['best_day']} at {best_period['best_hour']}:00. "
                "Consider posting more content during this time."
            )
        
        # Platform-specific recommendations
        platform_recs = self._get_platform_specific_engagement_recommendations(platform, quality, pattern)
        recommendations.extend(platform_recs)
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _get_platform_specific_engagement_recommendations(
        self,
        platform: PlatformType,
        quality: EngagementQuality,
        pattern: EngagementPattern
    ) -> List[str]:
        """Get platform-specific engagement recommendations"""
        recommendations = []
        
        if platform == PlatformType.TWITTER:
            recommendations.extend([
                "Use Twitter polls and questions to increase engagement",
                "Engage with trending topics and hashtags",
                "Create Twitter threads for complex topics",
                "Respond quickly to comments and mentions"
            ])
        elif platform == PlatformType.INSTAGRAM:
            recommendations.extend([
                "Use Instagram Stories features like polls and questions",
                "Post high-quality visual content consistently",
                "Use relevant hashtags and location tags",
                "Collaborate with other creators in your niche"
            ])
        elif platform == PlatformType.FACEBOOK:
            recommendations.extend([
                "Create content that encourages sharing and discussion",
                "Use Facebook Groups to build community",
                "Post native videos for better reach",
                "Ask questions to prompt comments"
            ])
        elif platform == PlatformType.LINKEDIN:
            recommendations.extend([
                "Share professional insights and industry news",
                "Write detailed posts that provide value",
                "Engage with other professionals' content",
                "Use LinkedIn native features like polls and documents"
            ])
        elif platform == PlatformType.TIKTOK:
            recommendations.extend([
                "Use trending sounds and effects",
                "Create content that encourages duets and stitches",
                "Post consistently during peak hours",
                "Engage with comments through video responses"
            ])
        
        return recommendations
    
    def _calculate_platform_benchmarks(
        self,
        metrics: List[EngagementMetrics],
        platform: PlatformType
    ) -> Dict[str, float]:
        """Calculate platform-specific benchmarks"""
        config = self.platform_configs.get(platform, {})
        
        if not metrics:
            return {}
        
        avg_engagement_rate = statistics.mean([m.engagement_rate for m in metrics])
        avg_quality_score = statistics.mean([m.quality_score for m in metrics])
        avg_authenticity_score = statistics.mean([m.authenticity_score for m in metrics])
        
        return {
            "your_avg_engagement_rate": avg_engagement_rate,
            "platform_avg_engagement_rate": config.get('avg_engagement_rate', 0.05) * 100,
            "engagement_rate_percentile": self._calculate_percentile(
                avg_engagement_rate, config.get('avg_engagement_rate', 0.05) * 100
            ),
            "quality_score": avg_quality_score,
            "authenticity_score": avg_authenticity_score,
            "performance_vs_average": avg_engagement_rate / max(config.get('avg_engagement_rate', 0.05) * 100, 1)
        }
    
    def _calculate_percentile(self, value: float, average: float) -> float:
        """Calculate approximate percentile based on value vs average"""
        ratio = value / max(average, 0.01)
        
        if ratio >= 2.0:
            return 95.0
        elif ratio >= 1.5:
            return 85.0
        elif ratio >= 1.2:
            return 75.0
        elif ratio >= 1.0:
            return 60.0
        elif ratio >= 0.8:
            return 40.0
        elif ratio >= 0.6:
            return 25.0
        else:
            return 10.0
    
    def _calculate_confidence_score(
        self,
        metrics: List[EngagementMetrics],
        content_count: int
    ) -> float:
        """Calculate confidence score for the analysis"""
        base_confidence = min(content_count * 8, 100)  # More content = higher confidence
        
        # Adjust based on data quality
        if len(metrics) < 5:
            base_confidence *= 0.6
        elif len(metrics) < 10:
            base_confidence *= 0.8
        
        # Adjust based on time span
        if metrics:
            time_span = (max(m.timestamp for m in metrics) - min(m.timestamp for m in metrics)).days
            if time_span < 7:
                base_confidence *= 0.7
            elif time_span < 14:
                base_confidence *= 0.85
        
        return min(base_confidence, 100)
    
    def _create_empty_analysis(
        self,
        platform: PlatformType,
        analysis_days: int
    ) -> EngagementAnalysis:
        """Create empty analysis when no data is available"""
        return EngagementAnalysis(
            overall_score=0.0,
            quality=EngagementQuality.POOR,
            pattern=EngagementPattern.ORGANIC,
            risk_level=RiskLevel.HIGH,
            metrics=[],
            engagement_trends={"trend": "insufficient_data"},
            audience_insights={"error": "insufficient_data"},
            recommendations=["No recent engagement data available for analysis"],
            platform_benchmarks={},
            analysis_period=(datetime.now() - timedelta(days=analysis_days), datetime.now()),
            confidence_score=0.0
        )