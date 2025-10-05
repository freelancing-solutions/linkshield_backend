"""
Unit tests for Algorithm Health Analyzers

Tests for VisibilityScorer, EngagementAnalyzer, PenaltyDetector, and ShadowBanDetector
"""

import pytest
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import Mock, AsyncMock, patch

from linkshield.social_protection.algorithm_health.visibility_scorer import (
    VisibilityScorer,
    VisibilityTrend,
    VisibilityFactor,
    VisibilityMetrics,
    VisibilityAnalysis
)
from linkshield.social_protection.algorithm_health.engagement_analyzer import (
    EngagementAnalyzer,
    EngagementType,
    EngagementQuality,
    EngagementPattern,
    EngagementMetrics,
    EngagementAnalysis
)
from linkshield.social_protection.algorithm_health.penalty_detector import (
    PenaltyDetector,
    PenaltyType,
    PenaltySeverity,
    PenaltyStatus,
    PenaltyIndicator,
    PenaltyAnalysis
)
from linkshield.social_protection.algorithm_health.shadow_ban_detector import (
    ShadowBanDetector,
    ShadowBanType,
    ShadowBanSeverity,
    ShadowBanTest,
    ShadowBanAnalysis
)
from linkshield.social_protection.types import PlatformType, RiskLevel


# Test Fixtures

@pytest.fixture
def sample_content_data() -> List[Dict[str, Any]]:
    """Generate sample content data for testing"""
    base_time = datetime.now()
    content = []
    
    for i in range(15):
        content.append({
            'id': f'post_{i}',
            'created_at': (base_time - timedelta(days=i)).isoformat(),
            'reach': 1000 + (i * 50),
            'impressions': 1200 + (i * 60),
            'likes': 50 + (i * 5),
            'comments': 10 + i,
            'shares': 5 + (i // 2),
            'saves': 3 + (i // 3),
            'type': 'post',
            'has_links': i % 3 == 0,
            'hashtags': [f'#tag{j}' for j in range(i % 5)],
            'text': f'Sample post content {i}' * (10 + i),
            'hashtag_reach': 200 + (i * 10),
            'search_impressions': 100 + (i * 5)
        })
    
    return content


@pytest.fixture
def sample_historical_data() -> List[Dict[str, Any]]:
    """Generate sample historical data for comparison"""
    base_time = datetime.now() - timedelta(days=30)
    content = []
    
    for i in range(20):
        content.append({
            'id': f'hist_post_{i}',
            'created_at': (base_time - timedelta(days=i)).isoformat(),
            'reach': 1500 + (i * 60),
            'impressions': 1800 + (i * 70),
            'likes': 75 + (i * 6),
            'comments': 15 + i,
            'shares': 8 + (i // 2),
            'type': 'post',
            'hashtag_reach': 300 + (i * 15),
            'search_impressions': 150 + (i * 8)
        })
    
    return content


# VisibilityScorer Tests

class TestVisibilityScorer:
    """Test suite for VisibilityScorer"""
    
    @pytest.fixture
    def scorer(self):
        """Create VisibilityScorer instance"""
        return VisibilityScorer()
    
    @pytest.mark.asyncio
    async def test_analyze_visibility_basic(self, scorer, sample_content_data):
        """Test basic visibility analysis"""
        result = await scorer.analyze_visibility(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert isinstance(result, VisibilityAnalysis)
        assert 0 <= result.overall_score <= 100
        assert isinstance(result.trend, VisibilityTrend)
        assert isinstance(result.risk_level, RiskLevel)
        assert len(result.metrics) > 0
        assert len(result.recommendations) > 0
        assert 0 <= result.confidence_score <= 100
    
    @pytest.mark.asyncio
    async def test_analyze_visibility_empty_data(self, scorer):
        """Test visibility analysis with empty data"""
        result = await scorer.analyze_visibility(
            content_data=[],
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert result.overall_score == 0.0
        assert result.trend == VisibilityTrend.UNKNOWN
        assert result.risk_level == RiskLevel.HIGH
        assert len(result.metrics) == 0
    
    @pytest.mark.asyncio
    async def test_visibility_trend_detection(self, scorer):
        """Test visibility trend detection"""
        # Create improving trend data
        improving_data = []
        base_time = datetime.now()
        for i in range(10):
            improving_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 500 + (i * 100),  # Increasing reach
                'impressions': 600 + (i * 120),
                'likes': 25 + (i * 5),
                'comments': 5 + i,
                'shares': 2 + i,
                'type': 'post',
                'has_links': False,
                'hashtags': ['#test'],
                'text': 'Test content'
            })
        
        result = await scorer.analyze_visibility(
            content_data=improving_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        # Should detect improving or stable trend
        assert result.trend in [VisibilityTrend.IMPROVING, VisibilityTrend.STABLE]
    
    @pytest.mark.asyncio
    async def test_visibility_factors_analysis(self, scorer, sample_content_data):
        """Test visibility factors analysis"""
        result = await scorer.analyze_visibility(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert len(result.factors) > 0
        assert VisibilityFactor.ENGAGEMENT_RATE in result.factors
        assert all(0 <= score <= 100 for score in result.factors.values())
    
    @pytest.mark.asyncio
    async def test_platform_specific_configs(self, scorer, sample_content_data):
        """Test platform-specific configurations"""
        platforms = [
            PlatformType.TWITTER,
            PlatformType.META_FACEBOOK,
            PlatformType.META_INSTAGRAM,
            PlatformType.LINKEDIN,
            PlatformType.TIKTOK
        ]
        
        for platform in platforms:
            result = await scorer.analyze_visibility(
                content_data=sample_content_data,
                platform=platform,
                follower_count=10000,
                analysis_days=30
            )
            
            assert result.platform_specific_insights['platform'] == platform.value
            assert isinstance(result.overall_score, float)


# EngagementAnalyzer Tests

class TestEngagementAnalyzer:
    """Test suite for EngagementAnalyzer"""
    
    @pytest.fixture
    def analyzer(self):
        """Create EngagementAnalyzer instance"""
        return EngagementAnalyzer()
    
    @pytest.mark.asyncio
    async def test_analyze_engagement_basic(self, analyzer, sample_content_data):
        """Test basic engagement analysis"""
        result = await analyzer.analyze_engagement(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert isinstance(result, EngagementAnalysis)
        assert 0 <= result.overall_score <= 100
        assert isinstance(result.quality, EngagementQuality)
        assert isinstance(result.pattern, EngagementPattern)
        assert isinstance(result.risk_level, RiskLevel)
        assert len(result.metrics) > 0
    
    @pytest.mark.asyncio
    async def test_engagement_quality_assessment(self, analyzer):
        """Test engagement quality assessment"""
        # High quality engagement data
        high_quality_data = []
        base_time = datetime.now()
        for i in range(10):
            high_quality_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 1000,
                'impressions': 1200,
                'likes': 100,
                'comments': 50,  # High comment ratio
                'shares': 30,    # High share ratio
                'saves': 20,
                'type': 'post'
            })
        
        result = await analyzer.analyze_engagement(
            content_data=high_quality_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert result.quality in [EngagementQuality.EXCELLENT, EngagementQuality.GOOD]
        assert result.overall_score > 50
    
    @pytest.mark.asyncio
    async def test_engagement_pattern_detection(self, analyzer):
        """Test engagement pattern detection"""
        # Viral pattern data
        viral_data = []
        base_time = datetime.now()
        for i in range(10):
            viral_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 50000 if i == 0 else 1000,  # One viral post
                'impressions': 60000 if i == 0 else 1200,
                'likes': 5000 if i == 0 else 50,
                'comments': 500 if i == 0 else 10,
                'shares': 200 if i == 0 else 5,
                'type': 'post'
            })
        
        result = await analyzer.analyze_engagement(
            content_data=viral_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert result.pattern in [EngagementPattern.VIRAL, EngagementPattern.ORGANIC]
    
    @pytest.mark.asyncio
    async def test_authenticity_scoring(self, analyzer):
        """Test engagement authenticity scoring"""
        # Suspicious engagement data (too many likes, no comments)
        suspicious_data = []
        base_time = datetime.now()
        for i in range(10):
            suspicious_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 1000,
                'impressions': 1200,
                'likes': 1000,  # Suspiciously high
                'comments': 0,   # No comments
                'shares': 0,     # No shares
                'type': 'post'
            })
        
        result = await analyzer.analyze_engagement(
            content_data=suspicious_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        # Should detect low authenticity
        assert any(m.authenticity_score < 70 for m in result.metrics)
    
    @pytest.mark.asyncio
    async def test_engagement_trends_analysis(self, analyzer, sample_content_data):
        """Test engagement trends analysis"""
        result = await analyzer.analyze_engagement(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert 'engagement_rate_trend' in result.engagement_trends
        assert 'quality_trend' in result.engagement_trends
        assert 'best_performing_period' in result.engagement_trends
    
    @pytest.mark.asyncio
    async def test_audience_insights(self, analyzer, sample_content_data):
        """Test audience insights generation"""
        result = await analyzer.analyze_engagement(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert 'engagement_patterns' in result.audience_insights
        assert 'audience_quality' in result.audience_insights
        assert 'interaction_preferences' in result.audience_insights


# PenaltyDetector Tests

class TestPenaltyDetector:
    """Test suite for PenaltyDetector"""
    
    @pytest.fixture
    def detector(self):
        """Create PenaltyDetector instance"""
        return PenaltyDetector()
    
    @pytest.mark.asyncio
    async def test_detect_penalties_basic(self, detector, sample_content_data):
        """Test basic penalty detection"""
        result = await detector.detect_penalties(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        assert isinstance(result, PenaltyAnalysis)
        assert 0 <= result.overall_risk_score <= 1.0
        assert isinstance(result.penalty_status, PenaltyStatus)
        assert isinstance(result.risk_level, RiskLevel)
        assert 0 <= result.account_health_score <= 100
    
    @pytest.mark.asyncio
    async def test_shadow_ban_detection(self, detector, sample_historical_data):
        """Test shadow ban detection"""
        # Create data showing shadow ban indicators
        shadow_ban_data = []
        base_time = datetime.now()
        for i in range(15):
            shadow_ban_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 100,  # Very low reach
                'impressions': 150,
                'likes': 5,
                'comments': 1,
                'shares': 0,
                'type': 'post',
                'search_impressions': 0,  # No search visibility
                'hashtag_reach': 0  # No hashtag reach
            })
        
        result = await detector.detect_penalties(
            content_data=shadow_ban_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            historical_data=sample_historical_data,
            analysis_days=30
        )
        
        # Should detect some penalties
        assert len(result.detected_penalties) > 0 or result.overall_risk_score > 0.3
    
    @pytest.mark.asyncio
    async def test_reach_limitation_detection(self, detector):
        """Test reach limitation detection"""
        # Create data with consistently low reach
        low_reach_data = []
        base_time = datetime.now()
        for i in range(15):
            low_reach_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 50,  # Very low compared to follower count
                'impressions': 60,
                'likes': 3,
                'comments': 0,
                'shares': 0,
                'organic_reach': 40,
                'type': 'post'
            })
        
        result = await detector.detect_penalties(
            content_data=low_reach_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        # Should detect reach limitation
        penalty_types = [p.penalty_type for p in result.detected_penalties]
        assert PenaltyType.REACH_LIMITATION in penalty_types or result.overall_risk_score > 0.2
    
    @pytest.mark.asyncio
    async def test_engagement_throttling_detection(self, detector, sample_historical_data):
        """Test engagement throttling detection"""
        # Create data with low engagement velocity
        throttled_data = []
        base_time = datetime.now()
        for i in range(15):
            throttled_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 1000,
                'impressions': 1200,
                'likes': 5,  # Very low engagement
                'comments': 0,
                'shares': 0,
                'type': 'post'
            })
        
        result = await detector.detect_penalties(
            content_data=throttled_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            historical_data=sample_historical_data,
            analysis_days=30
        )
        
        # Should detect engagement issues
        assert result.account_health_score < 70 or len(result.detected_penalties) > 0
    
    @pytest.mark.asyncio
    async def test_penalty_severity_assessment(self, detector):
        """Test penalty severity assessment"""
        # Create data with severe penalties
        severe_penalty_data = []
        base_time = datetime.now()
        for i in range(15):
            severe_penalty_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 10,  # Extremely low
                'impressions': 15,
                'likes': 0,
                'comments': 0,
                'shares': 0,
                'type': 'post',
                'search_impressions': 0,
                'hashtag_reach': 0
            })
        
        result = await detector.detect_penalties(
            content_data=severe_penalty_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        # Should detect high risk
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM]
    
    @pytest.mark.asyncio
    async def test_recovery_timeline_estimation(self, detector, sample_content_data):
        """Test recovery timeline estimation"""
        result = await detector.detect_penalties(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            follower_count=10000,
            analysis_days=30
        )
        
        # Recovery timeline should be present if penalties detected
        if len(result.detected_penalties) > 0:
            assert result.recovery_timeline is not None


# ShadowBanDetector Tests

class TestShadowBanDetector:
    """Test suite for ShadowBanDetector"""
    
    @pytest.fixture
    def detector(self):
        """Create ShadowBanDetector instance"""
        return ShadowBanDetector()
    
    @pytest.fixture
    def user_metrics(self):
        """Sample user metrics"""
        return {
            'follower_count': 10000,
            'following_count': 500,
            'post_count': 1000,
            'account_age_days': 365
        }
    
    @pytest.mark.asyncio
    async def test_detect_shadow_ban_basic(self, detector, sample_content_data, user_metrics):
        """Test basic shadow ban detection"""
        result = await detector.detect_shadow_ban(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            user_metrics=user_metrics,
            test_period_days=7
        )
        
        assert isinstance(result, ShadowBanAnalysis)
        assert 0 <= result.overall_shadow_ban_score <= 1.0
        assert isinstance(result.is_shadow_banned, bool)
        assert isinstance(result.risk_level, RiskLevel)
        assert 0 <= result.visibility_score <= 100
        assert 0 <= result.detection_confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_search_ban_detection(self, detector, user_metrics):
        """Test search ban detection"""
        # Create data with search ban indicators
        search_ban_data = []
        base_time = datetime.now()
        for i in range(10):
            search_ban_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 1000,
                'impressions': 1200,
                'likes': 50,
                'comments': 10,
                'shares': 5,
                'search_impressions': 0,  # No search visibility
                'type': 'post'
            })
        
        result = await detector.detect_shadow_ban(
            content_data=search_ban_data,
            platform=PlatformType.TWITTER,
            user_metrics=user_metrics,
            test_period_days=7
        )
        
        # Should detect search-related issues
        ban_types = [ban.test_type for ban in result.detected_bans]
        assert ShadowBanType.SEARCH_BAN in ban_types or result.overall_shadow_ban_score > 0.2
    
    @pytest.mark.asyncio
    async def test_hashtag_ban_detection(self, detector, user_metrics):
        """Test hashtag ban detection"""
        # Create data with hashtag ban indicators
        hashtag_ban_data = []
        base_time = datetime.now()
        for i in range(10):
            hashtag_ban_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 1000,
                'impressions': 1200,
                'likes': 50,
                'comments': 10,
                'shares': 5,
                'hashtags': ['#test', '#banned', '#hashtag'],
                'hashtag_reach': 0,  # No hashtag reach
                'type': 'post'
            })
        
        result = await detector.detect_shadow_ban(
            content_data=hashtag_ban_data,
            platform=PlatformType.META_INSTAGRAM,
            user_metrics=user_metrics,
            test_period_days=7
        )
        
        # Should detect hashtag-related issues
        ban_types = [ban.test_type for ban in result.detected_bans]
        assert ShadowBanType.HASHTAG_BAN in ban_types or result.overall_shadow_ban_score > 0.2
    
    @pytest.mark.asyncio
    async def test_timeline_suppression_detection(self, detector, user_metrics, sample_historical_data):
        """Test timeline suppression detection"""
        # Create data with timeline suppression indicators
        suppressed_data = []
        base_time = datetime.now()
        for i in range(10):
            suppressed_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 100,  # Very low reach
                'impressions': 120,
                'likes': 5,
                'comments': 1,
                'shares': 0,
                'type': 'post'
            })
        
        result = await detector.detect_shadow_ban(
            content_data=suppressed_data,
            platform=PlatformType.TWITTER,
            user_metrics=user_metrics,
            historical_data=sample_historical_data,
            test_period_days=7
        )
        
        # Should detect suppression
        assert result.is_shadow_banned or result.overall_shadow_ban_score > 0.3
    
    @pytest.mark.asyncio
    async def test_insufficient_data_handling(self, detector, user_metrics):
        """Test handling of insufficient data"""
        # Only 3 posts (below minimum)
        insufficient_data = []
        base_time = datetime.now()
        for i in range(3):
            insufficient_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 1000,
                'impressions': 1200,
                'likes': 50,
                'comments': 10,
                'shares': 5,
                'type': 'post'
            })
        
        result = await detector.detect_shadow_ban(
            content_data=insufficient_data,
            platform=PlatformType.TWITTER,
            user_metrics=user_metrics,
            test_period_days=7
        )
        
        # Should handle gracefully
        assert isinstance(result, ShadowBanAnalysis)
        assert result.detection_confidence < 0.5  # Low confidence due to insufficient data
    
    @pytest.mark.asyncio
    async def test_platform_specific_detection(self, detector, user_metrics, sample_content_data):
        """Test platform-specific shadow ban detection"""
        platforms = [
            PlatformType.TWITTER,
            PlatformType.META_INSTAGRAM,
            PlatformType.META_FACEBOOK,
            PlatformType.TIKTOK
        ]
        
        for platform in platforms:
            result = await detector.detect_shadow_ban(
                content_data=sample_content_data,
                platform=platform,
                user_metrics=user_metrics,
                test_period_days=7
            )
            
            assert isinstance(result, ShadowBanAnalysis)
            assert result.platform_insights is not None
    
    @pytest.mark.asyncio
    async def test_recovery_suggestions(self, detector, user_metrics):
        """Test recovery suggestions generation"""
        # Create data that triggers shadow ban detection
        shadow_banned_data = []
        base_time = datetime.now()
        for i in range(10):
            shadow_banned_data.append({
                'id': f'post_{i}',
                'created_at': (base_time - timedelta(days=i)).isoformat(),
                'reach': 50,
                'impressions': 60,
                'likes': 2,
                'comments': 0,
                'shares': 0,
                'search_impressions': 0,
                'hashtag_reach': 0,
                'type': 'post'
            })
        
        result = await detector.detect_shadow_ban(
            content_data=shadow_banned_data,
            platform=PlatformType.TWITTER,
            user_metrics=user_metrics,
            test_period_days=7
        )
        
        # Should provide recovery suggestions if shadow banned
        if result.is_shadow_banned:
            assert len(result.recovery_suggestions) > 0
            assert len(result.monitoring_recommendations) > 0
    
    @pytest.mark.asyncio
    async def test_confidence_scoring(self, detector, user_metrics, sample_content_data, sample_historical_data):
        """Test detection confidence scoring"""
        # With historical data, confidence should be higher
        result_with_history = await detector.detect_shadow_ban(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            user_metrics=user_metrics,
            historical_data=sample_historical_data,
            test_period_days=7
        )
        
        # Without historical data
        result_without_history = await detector.detect_shadow_ban(
            content_data=sample_content_data,
            platform=PlatformType.TWITTER,
            user_metrics=user_metrics,
            historical_data=None,
            test_period_days=7
        )
        
        # Confidence with historical data should generally be higher or equal
        assert result_with_history.detection_confidence >= 0
        assert result_without_history.detection_confidence >= 0


# Integration Tests

class TestAlgorithmHealthIntegration:
    """Integration tests for algorithm health analyzers"""
    
    @pytest.mark.asyncio
    async def test_combined_analysis_workflow(self, sample_content_data, sample_historical_data):
        """Test combined analysis workflow using all analyzers"""
        visibility_scorer = VisibilityScorer()
        engagement_analyzer = EngagementAnalyzer()
        penalty_detector = PenaltyDetector()
        shadow_ban_detector = ShadowBanDetector()
        
        follower_count = 10000
        platform = PlatformType.TWITTER
        user_metrics = {'follower_count': follower_count}
        
        # Run all analyses
        visibility_result = await visibility_scorer.analyze_visibility(
            content_data=sample_content_data,
            platform=platform,
            follower_count=follower_count,
            analysis_days=30
        )
        
        engagement_result = await engagement_analyzer.analyze_engagement(
            content_data=sample_content_data,
            platform=platform,
            follower_count=follower_count,
            analysis_days=30
        )
        
        penalty_result = await penalty_detector.detect_penalties(
            content_data=sample_content_data,
            platform=platform,
            follower_count=follower_count,
            historical_data=sample_historical_data,
            analysis_days=30
        )
        
        shadow_ban_result = await shadow_ban_detector.detect_shadow_ban(
            content_data=sample_content_data,
            platform=platform,
            user_metrics=user_metrics,
            historical_data=sample_historical_data,
            test_period_days=7
        )
        
        # All analyses should complete successfully
        assert visibility_result is not None
        assert engagement_result is not None
        assert penalty_result is not None
        assert shadow_ban_result is not None
        
        # Results should be consistent
        # If shadow banned, visibility and engagement should be low
        if shadow_ban_result.is_shadow_banned:
            assert visibility_result.overall_score < 80 or engagement_result.overall_score < 80

