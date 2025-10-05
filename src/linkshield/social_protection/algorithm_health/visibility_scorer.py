"""
Visibility Scorer for Social Media Algorithm Health Analysis

This module provides comprehensive visibility scoring and analysis for social media content,
helping users understand how platform algorithms affect their content reach and engagement.
"""

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import statistics
from ..types import PlatformType, RiskLevel
from ..logging_utils import get_logger

logger = get_logger("VisibilityScorer")


class VisibilityTrend(Enum):
    """Visibility trend indicators"""
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    VOLATILE = "volatile"
    UNKNOWN = "unknown"


class VisibilityFactor(Enum):
    """Factors affecting content visibility"""
    ENGAGEMENT_RATE = "engagement_rate"
    POSTING_TIME = "posting_time"
    CONTENT_TYPE = "content_type"
    HASHTAG_USAGE = "hashtag_usage"
    LINK_PRESENCE = "link_presence"
    CONTENT_LENGTH = "content_length"
    MEDIA_QUALITY = "media_quality"
    AUDIENCE_OVERLAP = "audience_overlap"
    ALGORITHM_CHANGES = "algorithm_changes"
    SHADOW_BAN = "shadow_ban"


@dataclass
class VisibilityMetrics:
    """Container for visibility metrics"""
    reach: int
    impressions: int
    engagement_rate: float
    visibility_score: float
    expected_reach: int
    reach_ratio: float
    timestamp: datetime
    platform: PlatformType
    content_id: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class VisibilityAnalysis:
    """Comprehensive visibility analysis result"""
    overall_score: float
    trend: VisibilityTrend
    risk_level: RiskLevel
    metrics: List[VisibilityMetrics]
    factors: Dict[VisibilityFactor, float]
    recommendations: List[str]
    platform_specific_insights: Dict[str, Any]
    analysis_period: Tuple[datetime, datetime]
    confidence_score: float


class VisibilityScorer:
    """
    Advanced visibility scoring system for social media content.
    
    Analyzes content reach, engagement patterns, and algorithmic visibility
    to provide actionable insights for content optimization.
    """
    
    def __init__(self):
        """Initialize the visibility scorer with platform-specific configurations"""
        self.platform_configs = self._load_platform_configs()
        self.baseline_metrics = {}
        
    def _load_platform_configs(self) -> Dict[PlatformType, Dict[str, Any]]:
        """Load platform-specific visibility configurations"""
        return {
            PlatformType.TWITTER: {
                "engagement_weight": 0.4,
                "reach_weight": 0.3,
                "timing_weight": 0.2,
                "content_weight": 0.1,
                "expected_reach_multiplier": 0.05,  # 5% of followers typically
                "peak_hours": [9, 12, 15, 18, 21],
                "optimal_hashtags": (1, 3),
                "link_penalty": 0.15
            },
            PlatformType.META_FACEBOOK: {
                "engagement_weight": 0.5,
                "reach_weight": 0.25,
                "timing_weight": 0.15,
                "content_weight": 0.1,
                "expected_reach_multiplier": 0.06,
                "peak_hours": [13, 15, 19, 21],
                "optimal_hashtags": (0, 2),
                "link_penalty": 0.2
            },
            PlatformType.META_INSTAGRAM: {
                "engagement_weight": 0.45,
                "reach_weight": 0.25,
                "timing_weight": 0.2,
                "content_weight": 0.1,
                "expected_reach_multiplier": 0.08,
                "peak_hours": [11, 13, 17, 19],
                "optimal_hashtags": (5, 15),
                "link_penalty": 0.1
            },
            PlatformType.LINKEDIN: {
                "engagement_weight": 0.35,
                "reach_weight": 0.3,
                "timing_weight": 0.25,
                "content_weight": 0.1,
                "expected_reach_multiplier": 0.04,
                "peak_hours": [8, 12, 17, 18],
                "optimal_hashtags": (3, 8),
                "link_penalty": 0.05
            },
            PlatformType.TIKTOK: {
                "engagement_weight": 0.6,
                "reach_weight": 0.2,
                "timing_weight": 0.1,
                "content_weight": 0.1,
                "expected_reach_multiplier": 0.15,
                "peak_hours": [18, 19, 20, 21, 22],
                "optimal_hashtags": (3, 8),
                "link_penalty": 0.25
            }
        }
    
    async def analyze_visibility(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType,
        follower_count: int,
        analysis_days: int = 30
    ) -> VisibilityAnalysis:
        """
        Perform comprehensive visibility analysis for content
        
        Args:
            content_data: List of content items with metrics
            platform: Social media platform
            follower_count: User's follower count
            analysis_days: Number of days to analyze
            
        Returns:
            VisibilityAnalysis: Comprehensive analysis results
        """
        try:
            logger.info(f"Starting visibility analysis for {platform.value} with {len(content_data)} content items")
            
            # Filter recent content
            cutoff_date = datetime.now() - timedelta(days=analysis_days)
            recent_content = [
                item for item in content_data
                if datetime.fromisoformat(item.get('created_at', '')) > cutoff_date
            ]
            
            if not recent_content:
                logger.warning("No recent content found for analysis")
                return self._create_empty_analysis(platform, analysis_days)
            
            # Calculate visibility metrics for each content item
            metrics = []
            for item in recent_content:
                metric = await self._calculate_content_visibility(item, platform, follower_count)
                if metric:
                    metrics.append(metric)
            
            if not metrics:
                return self._create_empty_analysis(platform, analysis_days)
            
            # Analyze overall visibility trends
            overall_score = self._calculate_overall_score(metrics, platform)
            trend = self._analyze_trend(metrics)
            risk_level = self._assess_risk_level(overall_score, trend)
            
            # Analyze visibility factors
            factors = await self._analyze_visibility_factors(recent_content, metrics, platform)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                overall_score, trend, factors, platform
            )
            
            # Platform-specific insights
            platform_insights = await self._generate_platform_insights(
                metrics, factors, platform
            )
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(metrics, len(recent_content))
            
            analysis_period = (
                min(m.timestamp for m in metrics),
                max(m.timestamp for m in metrics)
            )
            
            return VisibilityAnalysis(
                overall_score=overall_score,
                trend=trend,
                risk_level=risk_level,
                metrics=metrics,
                factors=factors,
                recommendations=recommendations,
                platform_specific_insights=platform_insights,
                analysis_period=analysis_period,
                confidence_score=confidence_score
            )
            
        except Exception as e:
            logger.error(f"Error in visibility analysis: {str(e)}")
            return self._create_empty_analysis(platform, analysis_days)
    
    async def _calculate_content_visibility(
        self,
        content_item: Dict[str, Any],
        platform: PlatformType,
        follower_count: int
    ) -> Optional[VisibilityMetrics]:
        """Calculate visibility metrics for a single content item"""
        try:
            config = self.platform_configs.get(platform, {})
            
            # Extract basic metrics
            reach = content_item.get('reach', 0)
            impressions = content_item.get('impressions', reach)
            likes = content_item.get('likes', 0)
            comments = content_item.get('comments', 0)
            shares = content_item.get('shares', 0)
            
            # Calculate engagement rate
            total_engagement = likes + comments + shares
            engagement_rate = (total_engagement / max(impressions, 1)) * 100
            
            # Calculate expected reach based on follower count
            expected_reach = int(follower_count * config.get('expected_reach_multiplier', 0.05))
            reach_ratio = reach / max(expected_reach, 1)
            
            # Calculate visibility score
            visibility_score = self._calculate_visibility_score(
                reach_ratio, engagement_rate, content_item, platform
            )
            
            return VisibilityMetrics(
                reach=reach,
                impressions=impressions,
                engagement_rate=engagement_rate,
                visibility_score=visibility_score,
                expected_reach=expected_reach,
                reach_ratio=reach_ratio,
                timestamp=datetime.fromisoformat(content_item.get('created_at')),
                platform=platform,
                content_id=content_item.get('id'),
                content_type=content_item.get('type', 'post')
            )
            
        except Exception as e:
            logger.error(f"Error calculating content visibility: {str(e)}")
            return None
    
    def _calculate_visibility_score(
        self,
        reach_ratio: float,
        engagement_rate: float,
        content_item: Dict[str, Any],
        platform: PlatformType
    ) -> float:
        """Calculate normalized visibility score (0-100)"""
        config = self.platform_configs.get(platform, {})
        
        # Base score from reach ratio
        reach_score = min(reach_ratio * 100, 100)
        
        # Engagement score
        engagement_score = min(engagement_rate * 10, 100)  # Scale engagement rate
        
        # Content factors
        content_score = self._calculate_content_factors_score(content_item, platform)
        
        # Timing factors
        timing_score = self._calculate_timing_score(content_item, platform)
        
        # Weighted final score
        final_score = (
            reach_score * config.get('reach_weight', 0.3) +
            engagement_score * config.get('engagement_weight', 0.4) +
            content_score * config.get('content_weight', 0.1) +
            timing_score * config.get('timing_weight', 0.2)
        )
        
        return min(max(final_score, 0), 100)
    
    def _calculate_content_factors_score(
        self,
        content_item: Dict[str, Any],
        platform: PlatformType
    ) -> float:
        """Calculate score based on content factors"""
        config = self.platform_configs.get(platform, {})
        score = 100.0
        
        # Check for external links (penalty)
        if content_item.get('has_links', False):
            score -= config.get('link_penalty', 0.1) * 100
        
        # Check hashtag usage
        hashtag_count = len(content_item.get('hashtags', []))
        optimal_range = config.get('optimal_hashtags', (1, 5))
        if not (optimal_range[0] <= hashtag_count <= optimal_range[1]):
            score -= 10
        
        # Content length factors
        content_length = len(content_item.get('text', ''))
        if platform == PlatformType.TWITTER and content_length > 240:
            score -= 5
        elif platform == PlatformType.LINKEDIN and content_length < 100:
            score -= 10
        
        return max(score, 0)
    
    def _calculate_timing_score(
        self,
        content_item: Dict[str, Any],
        platform: PlatformType
    ) -> float:
        """Calculate score based on posting timing"""
        config = self.platform_configs.get(platform, {})
        peak_hours = config.get('peak_hours', [12, 18])
        
        try:
            post_time = datetime.fromisoformat(content_item.get('created_at'))
            post_hour = post_time.hour
            
            if post_hour in peak_hours:
                return 100.0
            else:
                # Calculate distance from nearest peak hour
                distances = [abs(post_hour - peak) for peak in peak_hours]
                min_distance = min(distances)
                return max(100 - (min_distance * 10), 50)
                
        except Exception:
            return 75.0  # Default score if timing can't be determined
    
    def _calculate_overall_score(
        self,
        metrics: List[VisibilityMetrics],
        platform: PlatformType
    ) -> float:
        """Calculate overall visibility score"""
        if not metrics:
            return 0.0
        
        # Weight recent metrics more heavily
        now = datetime.now()
        weighted_scores = []
        
        for metric in metrics:
            days_old = (now - metric.timestamp).days
            weight = max(1.0 - (days_old * 0.05), 0.1)  # Decay weight over time
            weighted_scores.append(metric.visibility_score * weight)
        
        return sum(weighted_scores) / len(weighted_scores)
    
    def _analyze_trend(self, metrics: List[VisibilityMetrics]) -> VisibilityTrend:
        """Analyze visibility trend over time"""
        if len(metrics) < 3:
            return VisibilityTrend.UNKNOWN
        
        # Sort by timestamp
        sorted_metrics = sorted(metrics, key=lambda x: x.timestamp)
        scores = [m.visibility_score for m in sorted_metrics]
        
        # Calculate trend using linear regression slope
        n = len(scores)
        x_values = list(range(n))
        
        # Simple linear regression
        x_mean = sum(x_values) / n
        y_mean = sum(scores) / n
        
        numerator = sum((x_values[i] - x_mean) * (scores[i] - y_mean) for i in range(n))
        denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return VisibilityTrend.STABLE
        
        slope = numerator / denominator
        
        # Calculate volatility
        score_std = statistics.stdev(scores) if len(scores) > 1 else 0
        
        # Determine trend
        if score_std > 15:  # High volatility
            return VisibilityTrend.VOLATILE
        elif slope > 2:
            return VisibilityTrend.IMPROVING
        elif slope < -2:
            return VisibilityTrend.DECLINING
        else:
            return VisibilityTrend.STABLE
    
    def _assess_risk_level(
        self,
        overall_score: float,
        trend: VisibilityTrend
    ) -> RiskLevel:
        """Assess risk level based on score and trend"""
        if overall_score >= 80:
            return RiskLevel.LOW
        elif overall_score >= 60:
            if trend == VisibilityTrend.DECLINING:
                return RiskLevel.MEDIUM
            return RiskLevel.LOW
        elif overall_score >= 40:
            if trend in [VisibilityTrend.DECLINING, VisibilityTrend.VOLATILE]:
                return RiskLevel.HIGH
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.HIGH
    
    async def _analyze_visibility_factors(
        self,
        content_data: List[Dict[str, Any]],
        metrics: List[VisibilityMetrics],
        platform: PlatformType
    ) -> Dict[VisibilityFactor, float]:
        """Analyze factors affecting visibility"""
        factors = {}
        
        # Engagement rate factor
        avg_engagement = statistics.mean([m.engagement_rate for m in metrics])
        factors[VisibilityFactor.ENGAGEMENT_RATE] = min(avg_engagement * 10, 100)
        
        # Posting time factor
        factors[VisibilityFactor.POSTING_TIME] = self._analyze_timing_factor(content_data, platform)
        
        # Content type factor
        factors[VisibilityFactor.CONTENT_TYPE] = self._analyze_content_type_factor(content_data)
        
        # Hashtag usage factor
        factors[VisibilityFactor.HASHTAG_USAGE] = self._analyze_hashtag_factor(content_data, platform)
        
        # Link presence factor
        factors[VisibilityFactor.LINK_PRESENCE] = self._analyze_link_factor(content_data, platform)
        
        # Content length factor
        factors[VisibilityFactor.CONTENT_LENGTH] = self._analyze_length_factor(content_data, platform)
        
        # Shadow ban detection
        factors[VisibilityFactor.SHADOW_BAN] = self._detect_shadow_ban_indicators(metrics)
        
        return factors
    
    def _analyze_timing_factor(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType
    ) -> float:
        """Analyze posting timing effectiveness"""
        config = self.platform_configs.get(platform, {})
        peak_hours = config.get('peak_hours', [12, 18])
        
        peak_posts = 0
        total_posts = len(content_data)
        
        for item in content_data:
            try:
                post_time = datetime.fromisoformat(item.get('created_at'))
                if post_time.hour in peak_hours:
                    peak_posts += 1
            except Exception:
                continue
        
        return (peak_posts / max(total_posts, 1)) * 100
    
    def _analyze_content_type_factor(self, content_data: List[Dict[str, Any]]) -> float:
        """Analyze content type effectiveness"""
        type_performance = {}
        
        for item in content_data:
            content_type = item.get('type', 'post')
            engagement = item.get('likes', 0) + item.get('comments', 0) + item.get('shares', 0)
            
            if content_type not in type_performance:
                type_performance[content_type] = []
            type_performance[content_type].append(engagement)
        
        if not type_performance:
            return 50.0
        
        # Calculate average performance by type
        avg_performance = {}
        for content_type, engagements in type_performance.items():
            avg_performance[content_type] = statistics.mean(engagements)
        
        # Return score based on best performing type usage
        max_performance = max(avg_performance.values()) if avg_performance else 0
        return min(max_performance / 10, 100)  # Scale to 0-100
    
    def _analyze_hashtag_factor(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType
    ) -> float:
        """Analyze hashtag usage effectiveness"""
        config = self.platform_configs.get(platform, {})
        optimal_range = config.get('optimal_hashtags', (1, 5))
        
        optimal_posts = 0
        total_posts = len(content_data)
        
        for item in content_data:
            hashtag_count = len(item.get('hashtags', []))
            if optimal_range[0] <= hashtag_count <= optimal_range[1]:
                optimal_posts += 1
        
        return (optimal_posts / max(total_posts, 1)) * 100
    
    def _analyze_link_factor(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType
    ) -> float:
        """Analyze external link impact"""
        posts_with_links = sum(1 for item in content_data if item.get('has_links', False))
        total_posts = len(content_data)
        
        if posts_with_links == 0:
            return 100.0  # No links, no penalty
        
        link_ratio = posts_with_links / total_posts
        config = self.platform_configs.get(platform, {})
        penalty = config.get('link_penalty', 0.1)
        
        return max(100 - (link_ratio * penalty * 100), 0)
    
    def _analyze_length_factor(
        self,
        content_data: List[Dict[str, Any]],
        platform: PlatformType
    ) -> float:
        """Analyze content length effectiveness"""
        lengths = [len(item.get('text', '')) for item in content_data]
        
        if not lengths:
            return 50.0
        
        avg_length = statistics.mean(lengths)
        
        # Platform-specific optimal lengths
        optimal_ranges = {
            PlatformType.TWITTER: (100, 240),
            PlatformType.META_FACEBOOK: (100, 300),
            PlatformType.META_INSTAGRAM: (50, 200),
            PlatformType.LINKEDIN: (150, 500),
            PlatformType.TIKTOK: (50, 150)
        }
        
        optimal_range = optimal_ranges.get(platform, (100, 300))
        
        if optimal_range[0] <= avg_length <= optimal_range[1]:
            return 100.0
        elif avg_length < optimal_range[0]:
            return max(80 - ((optimal_range[0] - avg_length) / 10), 20)
        else:
            return max(80 - ((avg_length - optimal_range[1]) / 20), 20)
    
    def _detect_shadow_ban_indicators(self, metrics: List[VisibilityMetrics]) -> float:
        """Detect potential shadow ban indicators"""
        if len(metrics) < 5:
            return 100.0  # Not enough data
        
        # Check for sudden drops in reach
        recent_metrics = sorted(metrics, key=lambda x: x.timestamp)[-5:]
        reach_ratios = [m.reach_ratio for m in recent_metrics]
        
        # Look for consistent low reach ratios
        low_reach_count = sum(1 for ratio in reach_ratios if ratio < 0.3)
        
        if low_reach_count >= 3:
            return 20.0  # Potential shadow ban
        elif low_reach_count >= 2:
            return 50.0  # Possible issues
        else:
            return 100.0  # No indicators
    
    def _generate_recommendations(
        self,
        overall_score: float,
        trend: VisibilityTrend,
        factors: Dict[VisibilityFactor, float],
        platform: PlatformType
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Score-based recommendations
        if overall_score < 50:
            recommendations.append("Your content visibility is significantly below average. Consider reviewing your content strategy.")
        
        # Trend-based recommendations
        if trend == VisibilityTrend.DECLINING:
            recommendations.append("Your visibility is declining. Review recent algorithm changes and adjust your strategy.")
        elif trend == VisibilityTrend.VOLATILE:
            recommendations.append("Your visibility is inconsistent. Focus on maintaining consistent posting quality and timing.")
        
        # Factor-based recommendations
        if factors.get(VisibilityFactor.POSTING_TIME, 100) < 60:
            config = self.platform_configs.get(platform, {})
            peak_hours = config.get('peak_hours', [12, 18])
            recommendations.append(f"Post during peak hours ({', '.join(map(str, peak_hours))}) for better visibility.")
        
        if factors.get(VisibilityFactor.ENGAGEMENT_RATE, 100) < 40:
            recommendations.append("Focus on creating more engaging content to improve algorithmic ranking.")
        
        if factors.get(VisibilityFactor.HASHTAG_USAGE, 100) < 60:
            config = self.platform_configs.get(platform, {})
            optimal_range = config.get('optimal_hashtags', (1, 5))
            recommendations.append(f"Use {optimal_range[0]}-{optimal_range[1]} relevant hashtags per post.")
        
        if factors.get(VisibilityFactor.LINK_PRESENCE, 100) < 70:
            recommendations.append("Consider reducing external links or using platform-native features to share links.")
        
        if factors.get(VisibilityFactor.SHADOW_BAN, 100) < 50:
            recommendations.append("Potential shadow ban detected. Review content for policy violations and reduce posting frequency temporarily.")
        
        # Platform-specific recommendations
        platform_recs = self._get_platform_specific_recommendations(platform, factors)
        recommendations.extend(platform_recs)
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _get_platform_specific_recommendations(
        self,
        platform: PlatformType,
        factors: Dict[VisibilityFactor, float]
    ) -> List[str]:
        """Get platform-specific recommendations"""
        recommendations = []
        
        if platform == PlatformType.TWITTER:
            recommendations.extend([
                "Use Twitter Spaces and polls to increase engagement",
                "Reply to trending topics with relevant content",
                "Use Twitter threads for longer content"
            ])
        elif platform == PlatformType.META_INSTAGRAM:
            recommendations.extend([
                "Use Instagram Stories and Reels for better reach",
                "Post high-quality images with good lighting",
                "Engage with your audience through comments and DMs"
            ])
        elif platform == PlatformType.LINKEDIN:
            recommendations.extend([
                "Share professional insights and industry news",
                "Use LinkedIn native video for better engagement",
                "Participate in relevant LinkedIn groups"
            ])
        elif platform == PlatformType.TIKTOK:
            recommendations.extend([
                "Use trending sounds and effects",
                "Post consistently during peak hours",
                "Create content that encourages user interaction"
            ])
        
        return recommendations
    
    async def _generate_platform_insights(
        self,
        metrics: List[VisibilityMetrics],
        factors: Dict[VisibilityFactor, float],
        platform: PlatformType
    ) -> Dict[str, Any]:
        """Generate platform-specific insights"""
        insights = {
            "platform": platform.value,
            "analysis_summary": {},
            "performance_benchmarks": {},
            "optimization_opportunities": []
        }
        
        # Calculate performance benchmarks
        if metrics:
            insights["performance_benchmarks"] = {
                "average_reach_ratio": statistics.mean([m.reach_ratio for m in metrics]),
                "average_engagement_rate": statistics.mean([m.engagement_rate for m in metrics]),
                "average_visibility_score": statistics.mean([m.visibility_score for m in metrics]),
                "best_performing_content": max(metrics, key=lambda x: x.visibility_score).content_id,
                "total_content_analyzed": len(metrics)
            }
        
        # Analysis summary
        insights["analysis_summary"] = {
            "strongest_factor": max(factors.items(), key=lambda x: x[1])[0].value if factors else None,
            "weakest_factor": min(factors.items(), key=lambda x: x[1])[0].value if factors else None,
            "overall_health": "good" if statistics.mean(factors.values()) > 70 else "needs_improvement"
        }
        
        # Optimization opportunities
        weak_factors = [factor.value for factor, score in factors.items() if score < 60]
        insights["optimization_opportunities"] = weak_factors
        
        return insights
    
    def _calculate_confidence_score(
        self,
        metrics: List[VisibilityMetrics],
        content_count: int
    ) -> float:
        """Calculate confidence score for the analysis"""
        base_confidence = min(content_count * 10, 100)  # More content = higher confidence
        
        # Adjust based on data quality
        if len(metrics) < 5:
            base_confidence *= 0.7
        elif len(metrics) < 10:
            base_confidence *= 0.85
        
        # Adjust based on time span
        if metrics:
            time_span = (max(m.timestamp for m in metrics) - min(m.timestamp for m in metrics)).days
            if time_span < 7:
                base_confidence *= 0.8
            elif time_span < 14:
                base_confidence *= 0.9
        
        return min(base_confidence, 100)
    
    def _create_empty_analysis(
        self,
        platform: PlatformType,
        analysis_days: int
    ) -> VisibilityAnalysis:
        """Create empty analysis when no data is available"""
        return VisibilityAnalysis(
            overall_score=0.0,
            trend=VisibilityTrend.UNKNOWN,
            risk_level=RiskLevel.HIGH,
            metrics=[],
            factors={},
            recommendations=["No recent content data available for analysis"],
            platform_specific_insights={"platform": platform.value, "error": "insufficient_data"},
            analysis_period=(datetime.now() - timedelta(days=analysis_days), datetime.now()),
            confidence_score=0.0
        )