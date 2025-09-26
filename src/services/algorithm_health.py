#!/usr/bin/env python3
"""
LinkShield Backend Algorithm Health Service

Specialized service for monitoring and analyzing social media algorithm health,
including visibility scoring, engagement analysis, penalty detection,
and shadow ban detection across different platforms.
"""

import asyncio
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from src.config.settings import get_settings
from src.services.ai_service import AIService


class HealthStatus(Enum):
    """Algorithm health status levels."""
    EXCELLENT = "excellent"
    GOOD = "good"
    WARNING = "warning"
    POOR = "poor"
    CRITICAL = "critical"


class PenaltyType(Enum):
    """Types of algorithm penalties."""
    NONE = "none"
    SOFT_PENALTY = "soft_penalty"
    HARD_PENALTY = "hard_penalty"
    SHADOW_BAN = "shadow_ban"
    MANUAL_REVIEW = "manual_review"
    ACCOUNT_RESTRICTION = "account_restriction"


@dataclass
class VisibilityScore:
    """Result of visibility scoring analysis."""
    score: int  # 0-100
    status: HealthStatus
    reach_percentage: float
    impression_ratio: float
    visibility_factors: List[str]
    improvement_suggestions: List[str]
    platform_specific_metrics: Dict[str, Any]


@dataclass
class EngagementAnalysis:
    """Result of engagement analysis."""
    engagement_rate: float
    engagement_trend: str  # increasing, stable, decreasing
    engagement_quality: str  # high, medium, low
    anomalies_detected: List[str]
    benchmark_comparison: Dict[str, float]
    optimization_recommendations: List[str]


@dataclass
class PenaltyDetection:
    """Result of penalty detection analysis."""
    penalty_detected: bool
    penalty_type: PenaltyType
    confidence_score: float
    affected_metrics: List[str]
    penalty_indicators: List[str]
    recovery_timeline: Optional[str]
    recovery_actions: List[str]


@dataclass
class ShadowBanAnalysis:
    """Result of shadow ban detection."""
    shadow_ban_detected: bool
    shadow_ban_type: str  # content, hashtag, account, none
    detection_confidence: float
    affected_features: List[str]
    detection_methods: List[str]
    mitigation_strategies: List[str]


class AlgorithmHealthError(Exception):
    """Base algorithm health error."""
    pass


class VisibilityScorer:
    """
    Analyzes and scores content visibility across social media platforms.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Platform-specific visibility factors
        self.visibility_factors = {
            "twitter": {
                "optimal_posting_times": [9, 12, 15, 18],  # Hours
                "engagement_window": 2,  # Hours for initial engagement
                "hashtag_effectiveness": {"min": 1, "max": 3, "optimal": 2},
                "thread_penalty": 0.15,  # 15% reduction for threads
                "external_link_penalty": 0.25,  # 25% reduction for external links
                "retweet_boost": 1.3,  # 30% boost for retweets
                "reply_penalty": 0.8  # 20% reduction for replies
            },
            "facebook": {
                "optimal_posting_times": [13, 15, 19, 21],
                "engagement_window": 6,  # Hours
                "video_boost": 1.5,  # 50% boost for native video
                "external_link_penalty": 0.4,  # 60% reduction for external links
                "engagement_bait_penalty": 0.7,  # 30% reduction for engagement bait
                "friend_interaction_boost": 1.2,  # 20% boost for friend interactions
                "page_vs_profile_penalty": 0.6  # 40% reduction for page posts
            },
            "instagram": {
                "optimal_posting_times": [11, 13, 17, 19],
                "engagement_window": 4,  # Hours
                "hashtag_effectiveness": {"min": 5, "max": 30, "optimal": 11},
                "story_boost": 1.2,  # 20% boost for story engagement
                "reel_boost": 2.0,  # 100% boost for reels
                "carousel_boost": 1.3,  # 30% boost for carousel posts
                "shadowban_hashtag_penalty": 0.5  # 50% reduction for banned hashtags
            },
            "linkedin": {
                "optimal_posting_times": [8, 12, 17, 18],
                "engagement_window": 24,  # Hours (longer for professional content)
                "professional_content_boost": 1.4,  # 40% boost for professional content
                "external_link_penalty": 0.3,  # 70% reduction for external links
                "native_video_boost": 1.6,  # 60% boost for native video
                "comment_engagement_boost": 1.5  # 50% boost for comment engagement
            }
        }
        
        # Visibility benchmarks by platform
        self.visibility_benchmarks = {
            "twitter": {"excellent": 15, "good": 8, "warning": 3, "poor": 1},
            "facebook": {"excellent": 10, "good": 5, "warning": 2, "poor": 0.5},
            "instagram": {"excellent": 20, "good": 10, "warning": 4, "poor": 1},
            "linkedin": {"excellent": 8, "good": 4, "warning": 1.5, "poor": 0.5}
        }
    
    async def calculate_visibility_score(
        self,
        platform: str,
        metrics: Dict[str, Any],
        content_data: Optional[Dict[str, Any]] = None
    ) -> VisibilityScore:
        """
        Calculate visibility score based on platform metrics and content analysis.
        
        Args:
            platform: Social media platform
            metrics: Engagement and reach metrics
            content_data: Optional content analysis data
        
        Returns:
            VisibilityScore with detailed analysis
        """
        try:
            # Extract key metrics
            impressions = metrics.get("impressions", 0)
            reach = metrics.get("reach", 0)
            followers = metrics.get("followers", 1)  # Avoid division by zero
            engagement = metrics.get("engagement", 0)
            
            # Calculate base visibility metrics
            reach_percentage = (reach / followers * 100) if followers > 0 else 0
            impression_ratio = (impressions / followers) if followers > 0 else 0
            
            # Initialize scoring
            base_score = 50
            visibility_factors = []
            improvement_suggestions = []
            platform_specific_metrics = {}
            
            # Platform-specific analysis
            if platform in self.visibility_factors:
                platform_factors = self.visibility_factors[platform]
                platform_benchmarks = self.visibility_benchmarks[platform]
                
                # Analyze reach percentage against benchmarks
                if reach_percentage >= platform_benchmarks["excellent"]:
                    base_score += 30
                    visibility_factors.append("excellent_reach")
                elif reach_percentage >= platform_benchmarks["good"]:
                    base_score += 15
                    visibility_factors.append("good_reach")
                elif reach_percentage >= platform_benchmarks["warning"]:
                    base_score -= 10
                    visibility_factors.append("limited_reach")
                    improvement_suggestions.append("Optimize posting times and content format")
                else:
                    base_score -= 25
                    visibility_factors.append("poor_reach")
                    improvement_suggestions.append("Review content strategy and platform guidelines")
                
                # Analyze posting time optimization
                if content_data and "posted_at" in content_data:
                    posted_hour = datetime.fromisoformat(content_data["posted_at"]).hour
                    if posted_hour in platform_factors["optimal_posting_times"]:
                        base_score += 10
                        visibility_factors.append("optimal_posting_time")
                    else:
                        base_score -= 5
                        visibility_factors.append("suboptimal_posting_time")
                        improvement_suggestions.append(f"Post during optimal hours: {platform_factors['optimal_posting_times']}")
                
                # Platform-specific content analysis
                if content_data:
                    platform_score_adjustment = await self._analyze_platform_specific_content(
                        platform, content_data, platform_factors
                    )
                    base_score += platform_score_adjustment["score_adjustment"]
                    visibility_factors.extend(platform_score_adjustment["factors"])
                    improvement_suggestions.extend(platform_score_adjustment["suggestions"])
                    platform_specific_metrics = platform_score_adjustment["metrics"]
            
            # Normalize score
            final_score = max(0, min(100, base_score))
            
            # Determine status
            if final_score >= 80:
                status = HealthStatus.EXCELLENT
            elif final_score >= 65:
                status = HealthStatus.GOOD
            elif final_score >= 45:
                status = HealthStatus.WARNING
            elif final_score >= 25:
                status = HealthStatus.POOR
            else:
                status = HealthStatus.CRITICAL
            
            return VisibilityScore(
                score=final_score,
                status=status,
                reach_percentage=reach_percentage,
                impression_ratio=impression_ratio,
                visibility_factors=visibility_factors,
                improvement_suggestions=improvement_suggestions,
                platform_specific_metrics=platform_specific_metrics
            )
            
        except Exception as e:
            raise AlgorithmHealthError(f"Visibility scoring failed: {str(e)}")
    
    async def _analyze_platform_specific_content(
        self,
        platform: str,
        content_data: Dict[str, Any],
        platform_factors: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze platform-specific content factors."""
        score_adjustment = 0
        factors = []
        suggestions = []
        metrics = {}
        
        content_text = content_data.get("text", "")
        content_type = content_data.get("type", "text")
        
        if platform == "twitter":
            # Hashtag analysis
            hashtag_count = content_text.count('#')
            hashtag_config = platform_factors["hashtag_effectiveness"]
            
            if hashtag_config["min"] <= hashtag_count <= hashtag_config["max"]:
                if hashtag_count == hashtag_config["optimal"]:
                    score_adjustment += 10
                    factors.append("optimal_hashtag_count")
                else:
                    score_adjustment += 5
                    factors.append("good_hashtag_count")
            else:
                score_adjustment -= 10
                factors.append("suboptimal_hashtag_count")
                suggestions.append(f"Use {hashtag_config['optimal']} hashtags for optimal reach")
            
            # External link penalty
            if 'http' in content_text:
                penalty = int(platform_factors["external_link_penalty"] * 100)
                score_adjustment -= penalty
                factors.append("external_link_penalty")
                suggestions.append("Consider using Twitter Cards or native content")
            
            # Thread detection
            if any(indicator in content_text.lower() for indicator in ['thread', '1/', '2/']):
                penalty = int(platform_factors["thread_penalty"] * 100)
                score_adjustment -= penalty
                factors.append("thread_penalty")
            
            metrics["hashtag_count"] = hashtag_count
            metrics["has_external_link"] = 'http' in content_text
        
        elif platform == "facebook":
            # Video content boost
            if content_type == "video":
                boost = int((platform_factors["video_boost"] - 1) * 100)
                score_adjustment += boost
                factors.append("native_video_boost")
            
            # External link penalty
            if 'http' in content_text:
                penalty = int(platform_factors["external_link_penalty"] * 100)
                score_adjustment -= penalty
                factors.append("external_link_penalty")
                suggestions.append("Use Facebook's native sharing features")
            
            # Engagement bait detection
            engagement_bait = ['like if', 'share if', 'comment if', 'tag someone']
            if any(bait in content_text.lower() for bait in engagement_bait):
                penalty = int((1 - platform_factors["engagement_bait_penalty"]) * 100)
                score_adjustment -= penalty
                factors.append("engagement_bait_penalty")
                suggestions.append("Avoid engagement bait phrases")
            
            metrics["content_type"] = content_type
            metrics["has_external_link"] = 'http' in content_text
        
        elif platform == "instagram":
            # Hashtag analysis
            hashtag_count = content_text.count('#')
            hashtag_config = platform_factors["hashtag_effectiveness"]
            
            if hashtag_config["min"] <= hashtag_count <= hashtag_config["max"]:
                if hashtag_count == hashtag_config["optimal"]:
                    score_adjustment += 15
                    factors.append("optimal_hashtag_count")
                else:
                    score_adjustment += 8
                    factors.append("good_hashtag_count")
            else:
                score_adjustment -= 12
                factors.append("suboptimal_hashtag_count")
                suggestions.append(f"Use {hashtag_config['optimal']} hashtags for optimal reach")
            
            # Content type boosts
            if content_type == "reel":
                boost = int((platform_factors["reel_boost"] - 1) * 100)
                score_adjustment += boost
                factors.append("reel_boost")
            elif content_type == "carousel":
                boost = int((platform_factors["carousel_boost"] - 1) * 100)
                score_adjustment += boost
                factors.append("carousel_boost")
            
            metrics["hashtag_count"] = hashtag_count
            metrics["content_type"] = content_type
        
        elif platform == "linkedin":
            # Professional content detection (simplified)
            professional_keywords = [
                'business', 'career', 'professional', 'industry', 'leadership',
                'strategy', 'innovation', 'networking', 'skills', 'experience'
            ]
            
            professional_score = sum(1 for keyword in professional_keywords 
                                   if keyword in content_text.lower())
            
            if professional_score >= 3:
                boost = int((platform_factors["professional_content_boost"] - 1) * 100)
                score_adjustment += boost
                factors.append("professional_content_boost")
            
            # External link penalty
            if 'http' in content_text:
                penalty = int(platform_factors["external_link_penalty"] * 100)
                score_adjustment -= penalty
                factors.append("external_link_penalty")
                suggestions.append("Use LinkedIn's native document sharing")
            
            metrics["professional_score"] = professional_score
            metrics["has_external_link"] = 'http' in content_text
        
        return {
            "score_adjustment": score_adjustment,
            "factors": factors,
            "suggestions": suggestions,
            "metrics": metrics
        }


class EngagementAnalyzer:
    """
    Analyzes engagement patterns and quality across social media platforms.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Engagement benchmarks by platform (percentage rates)
        self.engagement_benchmarks = {
            "twitter": {"excellent": 3.0, "good": 1.5, "average": 0.5, "poor": 0.1},
            "facebook": {"excellent": 6.0, "good": 3.0, "average": 1.0, "poor": 0.3},
            "instagram": {"excellent": 8.0, "good": 4.0, "average": 1.5, "poor": 0.5},
            "linkedin": {"excellent": 4.0, "good": 2.0, "average": 0.8, "poor": 0.2}
        }
        
        # Engagement quality indicators
        self.quality_indicators = {
            "high_quality": ["meaningful_comments", "shares", "saves", "click_throughs"],
            "medium_quality": ["likes", "reactions", "brief_comments"],
            "low_quality": ["bot_likes", "spam_comments", "fake_engagement"]
        }
    
    async def analyze_engagement(
        self,
        platform: str,
        engagement_data: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> EngagementAnalysis:
        """
        Analyze engagement patterns and quality.
        
        Args:
            platform: Social media platform
            engagement_data: Current engagement metrics
            historical_data: Historical engagement data for trend analysis
        
        Returns:
            EngagementAnalysis with detailed insights
        """
        try:
            # Calculate engagement rate
            followers = engagement_data.get("followers", 1)
            total_engagement = engagement_data.get("total_engagement", 0)
            engagement_rate = (total_engagement / followers * 100) if followers > 0 else 0
            
            # Determine engagement quality
            engagement_quality = await self._assess_engagement_quality(engagement_data)
            
            # Analyze trends if historical data is available
            engagement_trend = "stable"
            if historical_data and len(historical_data) >= 3:
                engagement_trend = await self._analyze_engagement_trend(historical_data)
            
            # Detect anomalies
            anomalies_detected = await self._detect_engagement_anomalies(
                engagement_data, historical_data
            )
            
            # Compare against benchmarks
            benchmark_comparison = self._compare_against_benchmarks(platform, engagement_rate)
            
            # Generate optimization recommendations
            optimization_recommendations = await self._generate_optimization_recommendations(
                platform, engagement_data, engagement_quality, engagement_trend
            )
            
            return EngagementAnalysis(
                engagement_rate=engagement_rate,
                engagement_trend=engagement_trend,
                engagement_quality=engagement_quality,
                anomalies_detected=anomalies_detected,
                benchmark_comparison=benchmark_comparison,
                optimization_recommendations=optimization_recommendations
            )
            
        except Exception as e:
            raise AlgorithmHealthError(f"Engagement analysis failed: {str(e)}")
    
    async def _assess_engagement_quality(self, engagement_data: Dict[str, Any]) -> str:
        """Assess the quality of engagement based on interaction types."""
        high_quality_score = 0
        medium_quality_score = 0
        low_quality_score = 0
        
        # High quality engagement
        high_quality_score += engagement_data.get("comments", 0) * 3
        high_quality_score += engagement_data.get("shares", 0) * 5
        high_quality_score += engagement_data.get("saves", 0) * 4
        high_quality_score += engagement_data.get("click_throughs", 0) * 2
        
        # Medium quality engagement
        medium_quality_score += engagement_data.get("likes", 0) * 1
        medium_quality_score += engagement_data.get("reactions", 0) * 1
        
        # Low quality indicators (if detected)
        low_quality_score += engagement_data.get("bot_engagement", 0) * -2
        low_quality_score += engagement_data.get("spam_comments", 0) * -3
        
        total_score = high_quality_score + medium_quality_score + low_quality_score
        
        if high_quality_score > medium_quality_score * 2:
            return "high"
        elif medium_quality_score > high_quality_score and low_quality_score < total_score * 0.2:
            return "medium"
        else:
            return "low"
    
    async def _analyze_engagement_trend(self, historical_data: List[Dict[str, Any]]) -> str:
        """Analyze engagement trend from historical data."""
        if len(historical_data) < 3:
            return "stable"
        
        # Calculate engagement rates for recent periods
        engagement_rates = []
        for data in historical_data[-5:]:  # Last 5 data points
            followers = data.get("followers", 1)
            total_engagement = data.get("total_engagement", 0)
            rate = (total_engagement / followers * 100) if followers > 0 else 0
            engagement_rates.append(rate)
        
        # Calculate trend
        if len(engagement_rates) >= 3:
            recent_avg = statistics.mean(engagement_rates[-3:])
            older_avg = statistics.mean(engagement_rates[:-3]) if len(engagement_rates) > 3 else engagement_rates[0]
            
            change_percentage = ((recent_avg - older_avg) / older_avg * 100) if older_avg > 0 else 0
            
            if change_percentage > 10:
                return "increasing"
            elif change_percentage < -10:
                return "decreasing"
            else:
                return "stable"
        
        return "stable"
    
    async def _detect_engagement_anomalies(
        self,
        current_data: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]]
    ) -> List[str]:
        """Detect anomalies in engagement patterns."""
        anomalies = []
        
        if not historical_data or len(historical_data) < 3:
            return anomalies
        
        # Calculate historical averages
        historical_likes = [data.get("likes", 0) for data in historical_data]
        historical_comments = [data.get("comments", 0) for data in historical_data]
        historical_shares = [data.get("shares", 0) for data in historical_data]
        
        avg_likes = statistics.mean(historical_likes) if historical_likes else 0
        avg_comments = statistics.mean(historical_comments) if historical_comments else 0
        avg_shares = statistics.mean(historical_shares) if historical_shares else 0
        
        # Check for anomalies
        current_likes = current_data.get("likes", 0)
        current_comments = current_data.get("comments", 0)
        current_shares = current_data.get("shares", 0)
        
        # Sudden spike detection
        if current_likes > avg_likes * 3:
            anomalies.append("unusual_like_spike")
        if current_comments > avg_comments * 5:
            anomalies.append("unusual_comment_spike")
        if current_shares > avg_shares * 4:
            anomalies.append("unusual_share_spike")
        
        # Sudden drop detection
        if current_likes < avg_likes * 0.3 and avg_likes > 10:
            anomalies.append("significant_like_drop")
        if current_comments < avg_comments * 0.2 and avg_comments > 5:
            anomalies.append("significant_comment_drop")
        
        # Engagement ratio anomalies
        if current_likes > 0 and current_comments > 0:
            current_ratio = current_comments / current_likes
            historical_ratios = [
                data.get("comments", 0) / max(data.get("likes", 1), 1)
                for data in historical_data
            ]
            avg_ratio = statistics.mean(historical_ratios) if historical_ratios else 0
            
            if current_ratio > avg_ratio * 3:
                anomalies.append("unusual_comment_to_like_ratio")
        
        return anomalies
    
    def _compare_against_benchmarks(self, platform: str, engagement_rate: float) -> Dict[str, float]:
        """Compare engagement rate against platform benchmarks."""
        if platform not in self.engagement_benchmarks:
            return {"percentile": 50.0, "status": "unknown"}
        
        benchmarks = self.engagement_benchmarks[platform]
        
        if engagement_rate >= benchmarks["excellent"]:
            percentile = 95.0
            status = "excellent"
        elif engagement_rate >= benchmarks["good"]:
            percentile = 80.0
            status = "good"
        elif engagement_rate >= benchmarks["average"]:
            percentile = 50.0
            status = "average"
        elif engagement_rate >= benchmarks["poor"]:
            percentile = 20.0
            status = "below_average"
        else:
            percentile = 5.0
            status = "poor"
        
        return {
            "percentile": percentile,
            "status": status,
            "benchmark_excellent": benchmarks["excellent"],
            "benchmark_good": benchmarks["good"],
            "benchmark_average": benchmarks["average"]
        }
    
    async def _generate_optimization_recommendations(
        self,
        platform: str,
        engagement_data: Dict[str, Any],
        engagement_quality: str,
        engagement_trend: str
    ) -> List[str]:
        """Generate optimization recommendations based on analysis."""
        recommendations = []
        
        # Quality-based recommendations
        if engagement_quality == "low":
            recommendations.extend([
                "Focus on creating more engaging, conversation-starting content",
                "Ask questions to encourage meaningful comments",
                "Share behind-the-scenes or personal stories to increase connection"
            ])
        elif engagement_quality == "medium":
            recommendations.extend([
                "Encourage more shares by creating valuable, shareable content",
                "Use call-to-actions to drive specific engagement types",
                "Experiment with different content formats"
            ])
        
        # Trend-based recommendations
        if engagement_trend == "decreasing":
            recommendations.extend([
                "Analyze recent content performance to identify what's not working",
                "Refresh content strategy and try new formats",
                "Increase posting frequency temporarily to regain momentum",
                "Engage more actively with your audience's content"
            ])
        elif engagement_trend == "stable":
            recommendations.extend([
                "Test new content types to break through the plateau",
                "Collaborate with other creators or brands",
                "Optimize posting times based on audience activity"
            ])
        
        # Platform-specific recommendations
        if platform == "twitter":
            if engagement_data.get("retweets", 0) < engagement_data.get("likes", 0) * 0.1:
                recommendations.append("Create more retweetable content with quotes or insights")
        elif platform == "instagram":
            if engagement_data.get("saves", 0) < engagement_data.get("likes", 0) * 0.05:
                recommendations.append("Create more saveable content like tips, tutorials, or inspiration")
        elif platform == "linkedin":
            if engagement_data.get("comments", 0) < engagement_data.get("likes", 0) * 0.1:
                recommendations.append("Share professional insights that spark discussion")
        
        return recommendations


class PenaltyDetector:
    """
    Detects various types of algorithm penalties and restrictions.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Penalty detection thresholds
        self.penalty_thresholds = {
            "reach_drop": {"soft": 0.3, "hard": 0.1},  # 70% and 90% drops
            "engagement_drop": {"soft": 0.4, "hard": 0.2},  # 60% and 80% drops
            "impression_drop": {"soft": 0.35, "hard": 0.15},  # 65% and 85% drops
            "visibility_drop": {"soft": 0.25, "hard": 0.05}  # 75% and 95% drops
        }
        
        # Penalty indicators by platform
        self.penalty_indicators = {
            "twitter": [
                "sudden_reach_drop", "reduced_timeline_visibility", "limited_search_results",
                "restricted_trending", "reduced_notifications", "limited_replies_visibility"
            ],
            "facebook": [
                "reduced_news_feed_distribution", "limited_page_reach", "restricted_sharing",
                "reduced_organic_visibility", "limited_group_distribution"
            ],
            "instagram": [
                "hashtag_shadowban", "reduced_explore_visibility", "limited_story_reach",
                "restricted_reels_distribution", "reduced_profile_discoverability"
            ],
            "linkedin": [
                "reduced_feed_visibility", "limited_network_reach", "restricted_article_distribution",
                "reduced_connection_suggestions", "limited_group_visibility"
            ]
        }
    
    async def detect_penalties(
        self,
        platform: str,
        current_metrics: Dict[str, Any],
        historical_metrics: List[Dict[str, Any]],
        content_analysis: Optional[Dict[str, Any]] = None
    ) -> PenaltyDetection:
        """
        Detect algorithm penalties based on metrics and content analysis.
        
        Args:
            platform: Social media platform
            current_metrics: Current performance metrics
            historical_metrics: Historical performance data
            content_analysis: Optional content analysis results
        
        Returns:
            PenaltyDetection with penalty assessment
        """
        try:
            penalty_detected = False
            penalty_type = PenaltyType.NONE
            confidence_score = 0.0
            affected_metrics = []
            penalty_indicators = []
            recovery_timeline = None
            recovery_actions = []
            
            if len(historical_metrics) < 3:
                return PenaltyDetection(
                    penalty_detected=False,
                    penalty_type=PenaltyType.NONE,
                    confidence_score=0.0,
                    affected_metrics=[],
                    penalty_indicators=["insufficient_historical_data"],
                    recovery_timeline=None,
                    recovery_actions=["Collect more historical data for accurate penalty detection"]
                )
            
            # Calculate historical averages
            historical_avg = self._calculate_historical_averages(historical_metrics)
            
            # Analyze metric drops
            metric_analysis = await self._analyze_metric_drops(
                current_metrics, historical_avg, platform
            )
            
            # Determine penalty type and confidence
            if metric_analysis["severe_drops"] >= 2:
                penalty_detected = True
                penalty_type = PenaltyType.HARD_PENALTY
                confidence_score = min(0.95, 0.7 + len(metric_analysis["severe_drops"]) * 0.1)
                recovery_timeline = "2-4 weeks"
            elif metric_analysis["moderate_drops"] >= 3:
                penalty_detected = True
                penalty_type = PenaltyType.SOFT_PENALTY
                confidence_score = min(0.85, 0.6 + len(metric_analysis["moderate_drops"]) * 0.1)
                recovery_timeline = "1-2 weeks"
            elif metric_analysis["shadow_ban_indicators"] >= 2:
                penalty_detected = True
                penalty_type = PenaltyType.SHADOW_BAN
                confidence_score = min(0.9, 0.65 + len(metric_analysis["shadow_ban_indicators"]) * 0.1)
                recovery_timeline = "1-3 weeks"
            
            # Collect affected metrics and indicators
            affected_metrics = metric_analysis["affected_metrics"]
            penalty_indicators = metric_analysis["indicators"]
            
            # Content-based penalty detection
            if content_analysis:
                content_penalty_analysis = await self._analyze_content_penalties(
                    content_analysis, platform
                )
                
                if content_penalty_analysis["penalty_risk"] > 0.7:
                    if not penalty_detected:
                        penalty_detected = True
                        penalty_type = PenaltyType.MANUAL_REVIEW
                        confidence_score = content_penalty_analysis["penalty_risk"]
                        recovery_timeline = "1-2 weeks"
                    
                    penalty_indicators.extend(content_penalty_analysis["indicators"])
            
            # Generate recovery actions
            recovery_actions = await self._generate_recovery_actions(
                penalty_type, affected_metrics, platform
            )
            
            return PenaltyDetection(
                penalty_detected=penalty_detected,
                penalty_type=penalty_type,
                confidence_score=confidence_score,
                affected_metrics=affected_metrics,
                penalty_indicators=penalty_indicators,
                recovery_timeline=recovery_timeline,
                recovery_actions=recovery_actions
            )
            
        except Exception as e:
            raise AlgorithmHealthError(f"Penalty detection failed: {str(e)}")
    
    def _calculate_historical_averages(self, historical_metrics: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate averages from historical metrics."""
        metrics_keys = ["reach", "impressions", "engagement", "visibility_score"]
        averages = {}
        
        for key in metrics_keys:
            values = [metrics.get(key, 0) for metrics in historical_metrics if key in metrics]
            averages[key] = statistics.mean(values) if values else 0
        
        return averages
    
    async def _analyze_metric_drops(
        self,
        current_metrics: Dict[str, Any],
        historical_avg: Dict[str, float],
        platform: str
    ) -> Dict[str, Any]:
        """Analyze drops in key metrics."""
        severe_drops = []
        moderate_drops = []
        shadow_ban_indicators = []
        affected_metrics = []
        indicators = []
        
        for metric, current_value in current_metrics.items():
            if metric in historical_avg and historical_avg[metric] > 0:
                drop_ratio = current_value / historical_avg[metric]
                
                if metric in self.penalty_thresholds:
                    thresholds = self.penalty_thresholds[metric]
                    
                    if drop_ratio <= thresholds["hard"]:
                        severe_drops.append(metric)
                        affected_metrics.append(metric)
                        indicators.append(f"severe_{metric}_drop")
                    elif drop_ratio <= thresholds["soft"]:
                        moderate_drops.append(metric)
                        affected_metrics.append(metric)
                        indicators.append(f"moderate_{metric}_drop")
                
                # Shadow ban specific indicators
                if metric == "reach" and drop_ratio < 0.2:
                    shadow_ban_indicators.append("severe_reach_limitation")
                elif metric == "impressions" and drop_ratio < 0.15:
                    shadow_ban_indicators.append("impression_suppression")
        
        # Platform-specific shadow ban detection
        if platform == "instagram":
            hashtag_reach = current_metrics.get("hashtag_reach", 0)
            profile_visits = current_metrics.get("profile_visits", 0)
            
            if hashtag_reach < historical_avg.get("hashtag_reach", 0) * 0.1:
                shadow_ban_indicators.append("hashtag_shadowban")
                indicators.append("hashtag_visibility_blocked")
            
            if profile_visits < historical_avg.get("profile_visits", 0) * 0.3:
                shadow_ban_indicators.append("profile_discoverability_limited")
        
        return {
            "severe_drops": severe_drops,
            "moderate_drops": moderate_drops,
            "shadow_ban_indicators": shadow_ban_indicators,
            "affected_metrics": affected_metrics,
            "indicators": indicators
        }
    
    async def _analyze_content_penalties(
        self,
        content_analysis: Dict[str, Any],
        platform: str
    ) -> Dict[str, Any]:
        """Analyze content for penalty-triggering factors."""
        penalty_risk = 0.0
        indicators = []
        
        # Check for policy violations
        if "policy_violations" in content_analysis:
            violations = content_analysis["policy_violations"]
            penalty_risk += len(violations) * 0.2
            indicators.extend([f"policy_violation_{v}" for v in violations])
        
        # Check for spam indicators
        if "spam_score" in content_analysis:
            spam_score = content_analysis["spam_score"]
            if spam_score > 70:
                penalty_risk += 0.3
                indicators.append("high_spam_score")
            elif spam_score > 50:
                penalty_risk += 0.15
                indicators.append("moderate_spam_score")
        
        # Check for engagement bait
        if "engagement_bait_detected" in content_analysis:
            if content_analysis["engagement_bait_detected"]:
                penalty_risk += 0.25
                indicators.append("engagement_bait_detected")
        
        # Platform-specific content penalties
        if platform == "facebook" and "external_links" in content_analysis:
            if content_analysis["external_links"] > 1:
                penalty_risk += 0.2
                indicators.append("excessive_external_links")
        
        return {
            "penalty_risk": min(1.0, penalty_risk),
            "indicators": indicators
        }
    
    async def _generate_recovery_actions(
        self,
        penalty_type: PenaltyType,
        affected_metrics: List[str],
        platform: str
    ) -> List[str]:
        """Generate recovery actions based on penalty type."""
        actions = []
        
        if penalty_type == PenaltyType.HARD_PENALTY:
            actions.extend([
                "Immediately review and remove any policy-violating content",
                "Pause posting for 24-48 hours to allow algorithm reset",
                "Submit appeal through platform's official channels",
                "Focus on high-quality, policy-compliant content going forward"
            ])
        elif penalty_type == PenaltyType.SOFT_PENALTY:
            actions.extend([
                "Review recent content for policy compliance",
                "Reduce posting frequency temporarily",
                "Focus on engagement quality over quantity",
                "Avoid promotional or spammy content"
            ])
        elif penalty_type == PenaltyType.SHADOW_BAN:
            actions.extend([
                "Stop using potentially banned hashtags",
                "Vary content types and posting patterns",
                "Increase authentic engagement with other users",
                "Report the issue to platform support"
            ])
        elif penalty_type == PenaltyType.MANUAL_REVIEW:
            actions.extend([
                "Wait for manual review to complete",
                "Ensure all content complies with community guidelines",
                "Document the issue for potential appeal",
                "Continue posting compliant content"
            ])
        
        # Platform-specific recovery actions
        if platform == "instagram" and "reach" in affected_metrics:
            actions.append("Use location tags and engage with local community")
        elif platform == "twitter" and "visibility" in affected_metrics:
            actions.append("Engage authentically in Twitter conversations and threads")
        elif platform == "facebook" and "reach" in affected_metrics:
            actions.append("Focus on native content without external links")
        
        return actions


class ShadowBanDetector:
    """
    Specialized detector for shadow ban detection across platforms.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Shadow ban detection methods by platform
        self.detection_methods = {
            "twitter": [
                "search_visibility_test", "reply_visibility_test", "hashtag_visibility_test",
                "timeline_appearance_test", "notification_delivery_test"
            ],
            "instagram": [
                "hashtag_reach_test", "explore_visibility_test", "story_reach_test",
                "profile_discoverability_test", "comment_visibility_test"
            ],
            "facebook": [
                "news_feed_visibility_test", "page_reach_test", "group_visibility_test",
                "search_result_test", "notification_delivery_test"
            ],
            "linkedin": [
                "feed_visibility_test", "search_result_test", "connection_suggestion_test",
                "article_distribution_test", "notification_delivery_test"
            ]
        }
        
        # Shadow ban indicators
        self.shadow_ban_indicators = {
            "content_shadowban": ["hashtag_invisibility", "search_invisibility", "reduced_discoverability"],
            "hashtag_shadowban": ["hashtag_specific_invisibility", "hashtag_reach_drop"],
            "account_shadowban": ["profile_invisibility", "reduced_all_content_reach", "notification_blocking"]
        }
    
    async def detect_shadow_ban(
        self,
        platform: str,
        metrics: Dict[str, Any],
        test_results: Optional[Dict[str, Any]] = None
    ) -> ShadowBanAnalysis:
        """
        Detect shadow ban using multiple detection methods.
        
        Args:
            platform: Social media platform
            metrics: Performance metrics
            test_results: Optional test results from shadow ban detection tests
        
        Returns:
            ShadowBanAnalysis with detection results
        """
        try:
            shadow_ban_detected = False
            shadow_ban_type = "none"
            detection_confidence = 0.0
            affected_features = []
            detection_methods = []
            mitigation_strategies = []
            
            # Metric-based detection
            metric_indicators = await self._analyze_shadow_ban_metrics(platform, metrics)
            
            if metric_indicators["confidence"] > 0.7:
                shadow_ban_detected = True
                shadow_ban_type = metric_indicators["type"]
                detection_confidence = metric_indicators["confidence"]
                affected_features.extend(metric_indicators["affected_features"])
                detection_methods.append("metric_analysis")
            
            # Test-based detection (if available)
            if test_results:
                test_indicators = await self._analyze_test_results(platform, test_results)
                
                if test_indicators["confidence"] > detection_confidence:
                    shadow_ban_detected = True
                    shadow_ban_type = test_indicators["type"]
                    detection_confidence = test_indicators["confidence"]
                    affected_features = test_indicators["affected_features"]
                
                detection_methods.extend(test_indicators["methods"])
            
            # Generate mitigation strategies
            if shadow_ban_detected:
                mitigation_strategies = await self._generate_mitigation_strategies(
                    platform, shadow_ban_type, affected_features
                )
            
            return ShadowBanAnalysis(
                shadow_ban_detected=shadow_ban_detected,
                shadow_ban_type=shadow_ban_type,
                detection_confidence=detection_confidence,
                affected_features=affected_features,
                detection_methods=detection_methods,
                mitigation_strategies=mitigation_strategies
            )
            
        except Exception as e:
            raise AlgorithmHealthError(f"Shadow ban detection failed: {str(e)}")
    
    async def _analyze_shadow_ban_metrics(
        self,
        platform: str,
        metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze metrics for shadow ban indicators."""
        confidence = 0.0
        shadow_ban_type = "none"
        affected_features = []
        
        # Platform-specific metric analysis
        if platform == "instagram":
            hashtag_reach = metrics.get("hashtag_reach", 0)
            total_reach = metrics.get("reach", 1)
            hashtag_ratio = hashtag_reach / total_reach if total_reach > 0 else 0
            
            if hashtag_ratio < 0.1:  # Less than 10% reach from hashtags
                confidence += 0.4
                affected_features.append("hashtag_visibility")
                shadow_ban_type = "hashtag_shadowban"
            
            explore_reach = metrics.get("explore_reach", 0)
            explore_ratio = explore_reach / total_reach if total_reach > 0 else 0
            
            if explore_ratio < 0.05:  # Less than 5% reach from explore
                confidence += 0.3
                affected_features.append("explore_visibility")
                if shadow_ban_type == "none":
                    shadow_ban_type = "content_shadowban"
            
            profile_visits = metrics.get("profile_visits", 0)
            followers = metrics.get("followers", 1)
            visit_ratio = profile_visits / followers if followers > 0 else 0
            
            if visit_ratio < 0.02:  # Less than 2% of followers visiting profile
                confidence += 0.2
                affected_features.append("profile_discoverability")
        
        elif platform == "twitter":
            impressions = metrics.get("impressions", 0)
            followers = metrics.get("followers", 1)
            impression_ratio = impressions / followers if followers > 0 else 0
            
            if impression_ratio < 0.1:  # Less than 10% of followers see tweets
                confidence += 0.4
                affected_features.append("timeline_visibility")
                shadow_ban_type = "content_shadowban"
            
            search_impressions = metrics.get("search_impressions", 0)
            total_impressions = metrics.get("impressions", 1)
            search_ratio = search_impressions / total_impressions if total_impressions > 0 else 0
            
            if search_ratio < 0.05:  # Less than 5% impressions from search
                confidence += 0.3
                affected_features.append("search_visibility")
        
        elif platform == "facebook":
            organic_reach = metrics.get("organic_reach", 0)
            page_likes = metrics.get("page_likes", 1)
            reach_ratio = organic_reach / page_likes if page_likes > 0 else 0
            
            if reach_ratio < 0.05:  # Less than 5% organic reach
                confidence += 0.5
                affected_features.append("news_feed_visibility")
                shadow_ban_type = "content_shadowban"
        
        return {
            "confidence": min(1.0, confidence),
            "type": shadow_ban_type,
            "affected_features": affected_features
        }
    
    async def _analyze_test_results(
        self,
        platform: str,
        test_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze shadow ban test results."""
        confidence = 0.0
        shadow_ban_type = "none"
        affected_features = []
        methods = []
        
        available_methods = self.detection_methods.get(platform, [])
        
        for method in available_methods:
            if method in test_results:
                result = test_results[method]
                
                if result.get("shadow_ban_detected", False):
                    confidence += result.get("confidence", 0.2)
                    methods.append(method)
                    
                    if "hashtag" in method:
                        shadow_ban_type = "hashtag_shadowban"
                        affected_features.append("hashtag_visibility")
                    elif "search" in method:
                        affected_features.append("search_visibility")
                    elif "visibility" in method:
                        if shadow_ban_type == "none":
                            shadow_ban_type = "content_shadowban"
                        affected_features.append("content_visibility")
        
        return {
            "confidence": min(1.0, confidence),
            "type": shadow_ban_type,
            "affected_features": affected_features,
            "methods": methods
        }
    
    async def _generate_mitigation_strategies(
        self,
        platform: str,
        shadow_ban_type: str,
        affected_features: List[str]
    ) -> List[str]:
        """Generate mitigation strategies for shadow ban."""
        strategies = []
        
        # General strategies
        strategies.extend([
            "Temporarily reduce posting frequency",
            "Focus on high-quality, original content",
            "Increase authentic engagement with other users",
            "Avoid automated tools and services"
        ])
        
        # Type-specific strategies
        if shadow_ban_type == "hashtag_shadowban":
            strategies.extend([
                "Stop using potentially banned hashtags",
                "Research and use alternative hashtags",
                "Mix popular and niche hashtags",
                "Avoid overusing hashtags"
            ])
        elif shadow_ban_type == "content_shadowban":
            strategies.extend([
                "Review recent content for policy violations",
                "Diversify content types and formats",
                "Avoid repetitive or spammy content patterns",
                "Focus on community guidelines compliance"
            ])
        elif shadow_ban_type == "account_shadowban":
            strategies.extend([
                "Contact platform support",
                "Review account for policy violations",
                "Consider temporary account break",
                "Document the issue for appeal"
            ])
        
        # Platform-specific strategies
        if platform == "instagram":
            strategies.extend([
                "Use location tags to increase discoverability",
                "Post Instagram Stories regularly",
                "Engage with content in your niche",
                "Avoid third-party growth services"
            ])
        elif platform == "twitter":
            strategies.extend([
                "Participate in relevant conversations",
                "Use Twitter Spaces and live features",
                "Engage with trending topics appropriately",
                "Maintain consistent posting schedule"
            ])
        
        return strategies


class AlgorithmHealthService:
    """
    Main algorithm health service that coordinates all specialized analyzers.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.visibility_scorer = VisibilityScorer(ai_service)
        self.engagement_analyzer = EngagementAnalyzer(ai_service)
        self.penalty_detector = PenaltyDetector(ai_service)
        self.shadow_ban_detector = ShadowBanDetector(ai_service)
    
    async def comprehensive_health_analysis(
        self,
        platform: str,
        current_metrics: Dict[str, Any],
        historical_metrics: Optional[List[Dict[str, Any]]] = None,
        content_data: Optional[Dict[str, Any]] = None,
        test_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive algorithm health analysis.
        
        Args:
            platform: Social media platform
            current_metrics: Current performance metrics
            historical_metrics: Historical performance data
            content_data: Optional content analysis data
            test_results: Optional shadow ban test results
        
        Returns:
            Comprehensive algorithm health analysis
        """
        try:
            # Run all analyses concurrently
            analysis_tasks = [
                self.visibility_scorer.calculate_visibility_score(platform, current_metrics, content_data),
                self.engagement_analyzer.analyze_engagement(platform, current_metrics, historical_metrics),
                self.shadow_ban_detector.detect_shadow_ban(platform, current_metrics, test_results)
            ]
            
            # Add penalty detection if historical data is available
            if historical_metrics and len(historical_metrics) >= 3:
                analysis_tasks.append(
                    self.penalty_detector.detect_penalties(platform, current_metrics, historical_metrics, content_data)
                )
            
            # Execute all analyses
            results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
            # Process results
            visibility_analysis = results[0] if not isinstance(results[0], Exception) else None
            engagement_analysis = results[1] if not isinstance(results[1], Exception) else None
            shadow_ban_analysis = results[2] if not isinstance(results[2], Exception) else None
            penalty_analysis = results[3] if len(results) > 3 and not isinstance(results[3], Exception) else None
            
            # Calculate overall health score
            overall_health_score = await self._calculate_overall_health_score(
                visibility_analysis, engagement_analysis, penalty_analysis, shadow_ban_analysis
            )
            
            # Generate comprehensive recommendations
            recommendations = await self._generate_comprehensive_recommendations(
                visibility_analysis, engagement_analysis, penalty_analysis, shadow_ban_analysis
            )
            
            return {
                "overall_health_score": overall_health_score["score"],
                "health_status": overall_health_score["status"],
                "critical_issues": overall_health_score["critical_issues"],
                "recommendations": recommendations,
                "visibility_analysis": visibility_analysis.__dict__ if visibility_analysis else None,
                "engagement_analysis": engagement_analysis.__dict__ if engagement_analysis else None,
                "penalty_analysis": penalty_analysis.__dict__ if penalty_analysis else None,
                "shadow_ban_analysis": shadow_ban_analysis.__dict__ if shadow_ban_analysis else None,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": platform
            }
            
        except Exception as e:
            raise AlgorithmHealthError(f"Comprehensive health analysis failed: {str(e)}")
    
    async def _calculate_overall_health_score(
        self,
        visibility_analysis: Optional[VisibilityScore],
        engagement_analysis: Optional[EngagementAnalysis],
        penalty_analysis: Optional[PenaltyDetection],
        shadow_ban_analysis: Optional[ShadowBanAnalysis]
    ) -> Dict[str, Any]:
        """Calculate overall algorithm health score."""
        total_score = 0
        weight_sum = 0
        critical_issues = []
        
        # Visibility score (30% weight)
        if visibility_analysis:
            total_score += visibility_analysis.score * 0.3
            weight_sum += 0.3
            
            if visibility_analysis.status in [HealthStatus.POOR, HealthStatus.CRITICAL]:
                critical_issues.append(f"Poor visibility: {visibility_analysis.status.value}")
        
        # Engagement score (25% weight)
        if engagement_analysis:
            # Convert engagement quality to score
            engagement_score = {"high": 85, "medium": 65, "low": 35}.get(engagement_analysis.engagement_quality, 50)
            
            # Adjust based on trend
            if engagement_analysis.engagement_trend == "increasing":
                engagement_score += 10
            elif engagement_analysis.engagement_trend == "decreasing":
                engagement_score -= 15
            
            total_score += engagement_score * 0.25
            weight_sum += 0.25
            
            if engagement_analysis.engagement_quality == "low":
                critical_issues.append("Low engagement quality")
            if engagement_analysis.engagement_trend == "decreasing":
                critical_issues.append("Declining engagement trend")
        
        # Penalty impact (25% weight)
        if penalty_analysis:
            if penalty_analysis.penalty_detected:
                penalty_impact = {
                    PenaltyType.SOFT_PENALTY: 40,
                    PenaltyType.HARD_PENALTY: 20,
                    PenaltyType.SHADOW_BAN: 25,
                    PenaltyType.MANUAL_REVIEW: 50,
                    PenaltyType.ACCOUNT_RESTRICTION: 10
                }.get(penalty_analysis.penalty_type, 30)
                
                total_score += penalty_impact * 0.25
                critical_issues.append(f"Algorithm penalty detected: {penalty_analysis.penalty_type.value}")
            else:
                total_score += 80 * 0.25  # No penalty bonus
            
            weight_sum += 0.25
        
        # Shadow ban impact (20% weight)
        if shadow_ban_analysis:
            if shadow_ban_analysis.shadow_ban_detected:
                shadow_ban_impact = 30 - (shadow_ban_analysis.detection_confidence * 20)
                total_score += shadow_ban_impact * 0.2
                critical_issues.append(f"Shadow ban detected: {shadow_ban_analysis.shadow_ban_type}")
            else:
                total_score += 85 * 0.2  # No shadow ban bonus
            
            weight_sum += 0.2
        
        # Normalize score
        final_score = int(total_score / weight_sum) if weight_sum > 0 else 50
        
        # Determine status
        if final_score >= 80:
            status = HealthStatus.EXCELLENT
        elif final_score >= 65:
            status = HealthStatus.GOOD
        elif final_score >= 45:
            status = HealthStatus.WARNING
        elif final_score >= 25:
            status = HealthStatus.POOR
        else:
            status = HealthStatus.CRITICAL
        
        return {
            "score": final_score,
            "status": status,
            "critical_issues": critical_issues
        }
    
    async def _generate_comprehensive_recommendations(
        self,
        visibility_analysis: Optional[VisibilityScore],
        engagement_analysis: Optional[EngagementAnalysis],
        penalty_analysis: Optional[PenaltyDetection],
        shadow_ban_analysis: Optional[ShadowBanAnalysis]
    ) -> List[str]:
        """Generate comprehensive recommendations from all analyses."""
        recommendations = []
        
        # Priority order: penalties/shadow bans first, then engagement, then visibility
        if penalty_analysis and penalty_analysis.penalty_detected:
            recommendations.extend(penalty_analysis.recovery_actions[:3])  # Top 3 recovery actions
        
        if shadow_ban_analysis and shadow_ban_analysis.shadow_ban_detected:
            recommendations.extend(shadow_ban_analysis.mitigation_strategies[:3])  # Top 3 mitigation strategies
        
        if engagement_analysis:
            recommendations.extend(engagement_analysis.optimization_recommendations[:2])  # Top 2 engagement recommendations
        
        if visibility_analysis:
            recommendations.extend(visibility_analysis.improvement_suggestions[:2])  # Top 2 visibility suggestions
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:8]  # Return top 8 recommendations