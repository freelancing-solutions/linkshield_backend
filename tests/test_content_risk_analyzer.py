"""
Comprehensive unit tests for ContentRiskAnalyzer.

Tests cover:
- Pattern-based analysis
- AI service integration
- Platform-specific rules
- Risk score calculation
- Error handling
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone

from src.social_protection.content_analyzer.content_risk_analyzer import (
    ContentRiskAnalyzer,
    ContentRiskResult
)
from src.services.ai_service import AIService


@pytest.fixture
def mock_ai_service():
    """Create a mock AI service."""
    ai_service = Mock(spec=AIService)
    ai_service.analyze_content = AsyncMock()
    return ai_service


@pytest.fixture
def analyzer(mock_ai_service):
    """Create ContentRiskAnalyzer with mocked AI service."""
    return ContentRiskAnalyzer(ai_service=mock_ai_service)


class TestPatternAnalysis:
    """Test pattern-based risk detection."""
    
    def test_engagement_killers_detection(self, analyzer):
        """Test detection of engagement killer patterns."""
        content = "Click here and follow for follow! Link in bio!"
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is True
        assert "engagement_killers" in result["pattern_results"]
        assert result["pattern_results"]["engagement_killers"]["match_count"] > 0
        assert result["total_pattern_risk_score"] > 0
    
    def test_algorithm_penalties_detection(self, analyzer):
        """Test detection of algorithm penalty patterns."""
        content = "Buy now! Limited time offer! Make money fast! Guaranteed results!"
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is True
        assert "algorithm_penalties" in result["pattern_results"]
        assert result["pattern_results"]["algorithm_penalties"]["match_count"] >= 3
        assert result["total_pattern_risk_score"] > 0
    
    def test_credibility_risks_detection(self, analyzer):
        """Test detection of credibility risk patterns."""
        content = "BREAKING: You won't believe what doctors hate! Secret revealed!"
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is True
        assert "credibility_risks" in result["pattern_results"]
        assert result["total_pattern_risk_score"] > 0
    
    def test_platform_violations_detection(self, analyzer):
        """Test detection of platform violation patterns."""
        content = "This contains hate speech and harassment content"
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is True
        assert "platform_violations" in result["pattern_results"]
        assert result["total_pattern_risk_score"] > 0
    
    def test_misinformation_indicators_detection(self, analyzer):
        """Test detection of misinformation indicators."""
        content = "Fake news! This is a conspiracy! Wake up sheeple! Do your own research!"
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is True
        assert "misinformation_indicators" in result["pattern_results"]
        assert result["total_pattern_risk_score"] > 0
    
    def test_phishing_indicators_detection(self, analyzer):
        """Test detection of phishing indicators."""
        content = "Verify your account immediately! Urgent action required! Click here now!"
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is True
        assert "phishing_indicators" in result["pattern_results"]
        assert result["total_pattern_risk_score"] > 0
    
    def test_scam_indicators_detection(self, analyzer):
        """Test detection of scam indicators."""
        content = "Congratulations! You've won! Claim your prize now! Free gift!"
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is True
        assert "scam_indicators" in result["pattern_results"]
        assert result["total_pattern_risk_score"] > 0
    
    def test_clean_content_no_patterns(self, analyzer):
        """Test that clean content doesn't trigger patterns."""
        content = "This is a normal, professional post about technology and innovation."
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is False
        assert result["total_pattern_risk_score"] == 0
        assert len(result["pattern_results"]) == 0
    
    def test_multiple_pattern_categories(self, analyzer):
        """Test content with multiple risk categories."""
        content = "Click here to buy now! Limited time! You won't believe this secret!"
        result = analyzer._analyze_patterns(content)
        
        assert result["patterns_detected"] is True
        assert len(result["pattern_results"]) >= 2
        assert result["total_pattern_risk_score"] > 0
    
    def test_pattern_recommendations_generated(self, analyzer):
        """Test that recommendations are generated for detected patterns."""
        content = "Follow for follow! Buy now! Breaking news!"
        result = analyzer._analyze_patterns(content)
        
        assert len(result["recommendations"]) > 0
        assert all(isinstance(rec, str) for rec in result["recommendations"])


class TestAIAnalysis:
    """Test AI-powered content analysis."""
    
    @pytest.mark.asyncio
    async def test_ai_analysis_threat_detected(self, analyzer, mock_ai_service):
        """Test AI analysis when threat is detected."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": True,
            "threat_types": ["phishing", "scam"],
            "confidence_score": 85,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 20},
                "sentiment_analysis": {"sentiment": "negative", "suspicious": True},
                "spam_analysis": {"is_spam": True, "confidence_score": 80}
            }
        }
        
        result = await analyzer._analyze_with_ai("Test content", "twitter")
        
        assert result["threat_detected"] is True
        assert result["ai_risk_score"] > 0
        assert len(result["threat_types"]) == 2
        assert len(result["ai_risk_factors"]) > 0
        assert len(result["ai_recommendations"]) > 0
    
    @pytest.mark.asyncio
    async def test_ai_analysis_no_threat(self, analyzer, mock_ai_service):
        """Test AI analysis when no threat is detected."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 10,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 80},
                "sentiment_analysis": {"sentiment": "positive", "suspicious": False},
                "spam_analysis": {"is_spam": False, "confidence_score": 5}
            }
        }
        
        result = await analyzer._analyze_with_ai("Test content", "twitter")
        
        assert result["threat_detected"] is False
        assert result["ai_risk_score"] == 0
        assert result["quality_score"] == 80
        assert result["is_spam"] is False
    
    @pytest.mark.asyncio
    async def test_ai_analysis_low_quality_content(self, analyzer, mock_ai_service):
        """Test AI analysis with low quality content."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 0,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 25},
                "sentiment_analysis": {"sentiment": "neutral", "suspicious": False},
                "spam_analysis": {"is_spam": False, "confidence_score": 0}
            }
        }
        
        result = await analyzer._analyze_with_ai("Test content", "twitter")
        
        assert result["quality_score"] == 25
        assert result["ai_risk_score"] >= 70  # Low quality triggers high risk
        assert "ai_low_quality_25" in result["ai_risk_factors"]
    
    @pytest.mark.asyncio
    async def test_ai_analysis_spam_detected(self, analyzer, mock_ai_service):
        """Test AI analysis when spam is detected."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 0,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 50},
                "sentiment_analysis": {"sentiment": "neutral", "suspicious": False},
                "spam_analysis": {"is_spam": True, "confidence_score": 75}
            }
        }
        
        result = await analyzer._analyze_with_ai("Test content", "twitter")
        
        assert result["is_spam"] is True
        assert result["ai_risk_score"] >= 75
        assert "ai_spam_detected" in result["ai_risk_factors"]
    
    @pytest.mark.asyncio
    async def test_ai_analysis_error_handling(self, analyzer, mock_ai_service):
        """Test AI analysis error handling."""
        mock_ai_service.analyze_content.side_effect = Exception("AI service error")
        
        result = await analyzer._analyze_with_ai("Test content", "twitter")
        
        assert result["ai_risk_score"] == 0
        assert result["threat_detected"] is False
        assert "error" in result
        assert result["confidence_score"] == 0


class TestPlatformRules:
    """Test platform-specific rule application."""
    
    def test_twitter_hashtag_limit(self, analyzer):
        """Test Twitter hashtag limit enforcement."""
        content = "Check out #tag1 #tag2 #tag3 #tag4 #tag5"
        result = analyzer._apply_platform_rules(content, "twitter", {})
        
        assert result["platform_risk_score"] > 0
        assert any("excessive_hashtags" in factor for factor in result["platform_risk_factors"])
    
    def test_twitter_mention_limit(self, analyzer):
        """Test Twitter mention limit enforcement."""
        content = "Hey @user1 @user2 @user3 @user4 check this out"
        result = analyzer._apply_platform_rules(content, "twitter", {})
        
        assert result["platform_risk_score"] > 0
        assert any("excessive_mentions" in factor for factor in result["platform_risk_factors"])
    
    def test_twitter_external_link_penalty(self, analyzer):
        """Test Twitter external link penalty."""
        content = "Check out this link: https://example.com"
        result = analyzer._apply_platform_rules(content, "twitter", {})
        
        assert result["platform_risk_score"] > 0
        assert "external_link_penalty" in result["platform_risk_factors"]
    
    def test_facebook_engagement_bait(self, analyzer):
        """Test Facebook engagement bait detection."""
        content = "Tag someone who needs to see this! Share if you agree!"
        result = analyzer._apply_platform_rules(content, "facebook", {})
        
        assert result["platform_risk_score"] > 0
        assert any("engagement_bait" in factor for factor in result["platform_risk_factors"])
    
    def test_facebook_clickbait(self, analyzer):
        """Test Facebook clickbait detection."""
        content = "You won't believe what happens next! Number 7 will shock you!"
        result = analyzer._apply_platform_rules(content, "facebook", {})
        
        assert result["platform_risk_score"] > 0
        assert "clickbait_detected" in result["platform_risk_factors"]
    
    def test_instagram_hashtag_limit(self, analyzer):
        """Test Instagram hashtag limit."""
        content = " ".join([f"#tag{i}" for i in range(35)])
        result = analyzer._apply_platform_rules(content, "instagram", {})
        
        assert result["platform_risk_score"] > 0
        assert any("excessive_hashtags" in factor for factor in result["platform_risk_factors"])
    
    def test_instagram_shadowban_risk(self, analyzer):
        """Test Instagram shadowban risk detection."""
        content = "Follow for follow! F4F L4L"
        result = analyzer._apply_platform_rules(content, "instagram", {})
        
        assert result["platform_risk_score"] > 0
        assert "shadowban_risk_hashtag" in result["platform_risk_factors"]
    
    def test_linkedin_professional_tone(self, analyzer):
        """Test LinkedIn professional tone check."""
        content = "This is so lol and omg amazing 😂🔥"
        result = analyzer._apply_platform_rules(content, "linkedin", {})
        
        assert result["platform_risk_score"] > 0
        assert "unprofessional_tone" in result["platform_risk_factors"]
    
    def test_linkedin_external_link_penalty(self, analyzer):
        """Test LinkedIn external link penalty."""
        content = "Read more at https://example.com"
        result = analyzer._apply_platform_rules(content, "linkedin", {})
        
        assert result["platform_risk_score"] > 0
        assert "external_link_penalty" in result["platform_risk_factors"]
    
    def test_tiktok_trend_hashtags(self, analyzer):
        """Test TikTok trend hashtag recommendation."""
        content = "Just a regular post without trending hashtags"
        result = analyzer._apply_platform_rules(content, "tiktok", {})
        
        assert result["platform_risk_score"] > 0
        assert "missing_trend_hashtags" in result["platform_risk_factors"]
    
    def test_platform_clean_content(self, analyzer):
        """Test platform rules with clean content."""
        content = "This is a normal post with good content"
        result = analyzer._apply_platform_rules(content, "twitter", {})
        
        assert result["platform_risk_score"] == 0
        assert len(result["platform_risk_factors"]) == 0


class TestRiskScoreCalculation:
    """Test risk score calculation logic."""
    
    def test_calculate_category_risk_score_platform_violations(self, analyzer):
        """Test risk score for platform violations."""
        score = analyzer._calculate_category_risk_score("platform_violations", 2, 2)
        assert score > 0
        assert score >= 40  # Base score for platform violations
    
    def test_calculate_category_risk_score_phishing(self, analyzer):
        """Test risk score for phishing indicators."""
        score = analyzer._calculate_category_risk_score("phishing_indicators", 3, 2)
        assert score > 0
        assert score >= 35  # Base score for phishing
    
    def test_calculate_category_risk_score_engagement_killers(self, analyzer):
        """Test risk score for engagement killers."""
        score = analyzer._calculate_category_risk_score("engagement_killers", 1, 1)
        assert score > 0
        assert score >= 15  # Base score for engagement killers
    
    def test_calculate_overall_risk_score_balanced(self, analyzer):
        """Test overall risk score calculation with balanced inputs."""
        score = analyzer._calculate_overall_risk_score(50, 50, 50)
        assert score == 50
    
    def test_calculate_overall_risk_score_high_pattern(self, analyzer):
        """Test overall risk score with high pattern score."""
        score = analyzer._calculate_overall_risk_score(80, 20, 20)
        assert 30 < score < 60  # Weighted average
    
    def test_calculate_overall_risk_score_high_ai(self, analyzer):
        """Test overall risk score with high AI score."""
        score = analyzer._calculate_overall_risk_score(20, 80, 20)
        assert 30 < score < 60  # Weighted average
    
    def test_calculate_overall_risk_score_capped_at_100(self, analyzer):
        """Test that overall risk score is capped at 100."""
        score = analyzer._calculate_overall_risk_score(100, 100, 100)
        assert score == 100
    
    def test_determine_risk_level_low(self, analyzer):
        """Test risk level determination for low risk."""
        assert analyzer._determine_risk_level(10) == "low"
        assert analyzer._determine_risk_level(24) == "low"
    
    def test_determine_risk_level_medium(self, analyzer):
        """Test risk level determination for medium risk."""
        assert analyzer._determine_risk_level(25) == "medium"
        assert analyzer._determine_risk_level(49) == "medium"
    
    def test_determine_risk_level_high(self, analyzer):
        """Test risk level determination for high risk."""
        assert analyzer._determine_risk_level(50) == "high"
        assert analyzer._determine_risk_level(74) == "high"
    
    def test_determine_risk_level_critical(self, analyzer):
        """Test risk level determination for critical risk."""
        assert analyzer._determine_risk_level(75) == "critical"
        assert analyzer._determine_risk_level(100) == "critical"
    
    def test_calculate_confidence_score_all_factors(self, analyzer):
        """Test confidence score with all factors present."""
        confidence = analyzer._calculate_confidence_score(True, 80, True)
        assert confidence > 0.5
        assert confidence <= 1.0
    
    def test_calculate_confidence_score_no_factors(self, analyzer):
        """Test confidence score with no factors."""
        confidence = analyzer._calculate_confidence_score(False, 0, False)
        assert confidence == 0.5  # Base confidence
    
    def test_calculate_confidence_score_capped_at_1(self, analyzer):
        """Test that confidence score is capped at 1.0."""
        confidence = analyzer._calculate_confidence_score(True, 100, True)
        assert confidence <= 1.0


class TestComprehensiveAnalysis:
    """Test the main analyze_content_risk method."""
    
    @pytest.mark.asyncio
    async def test_analyze_content_risk_clean_content(self, analyzer, mock_ai_service):
        """Test analysis of clean, safe content."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 5,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 85},
                "sentiment_analysis": {"sentiment": "positive", "suspicious": False},
                "spam_analysis": {"is_spam": False, "confidence_score": 0}
            }
        }
        
        content = "This is a professional post about technology innovation."
        result = await analyzer.analyze_content_risk(content, "twitter")
        
        assert isinstance(result, ContentRiskResult)
        assert result.risk_level == "low"
        assert result.risk_score < 25
        assert result.confidence_score > 0
    
    @pytest.mark.asyncio
    async def test_analyze_content_risk_high_risk_content(self, analyzer, mock_ai_service):
        """Test analysis of high-risk content."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": True,
            "threat_types": ["phishing", "scam"],
            "confidence_score": 90,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 15},
                "sentiment_analysis": {"sentiment": "negative", "suspicious": True},
                "spam_analysis": {"is_spam": True, "confidence_score": 85}
            }
        }
        
        content = "Click here NOW! Verify your account immediately! You've won a prize!"
        result = await analyzer.analyze_content_risk(content, "twitter")
        
        assert isinstance(result, ContentRiskResult)
        assert result.risk_level in ["high", "critical"]
        assert result.risk_score >= 50
        assert len(result.risk_factors) > 0
        assert len(result.recommendations) > 0
    
    @pytest.mark.asyncio
    async def test_analyze_content_risk_with_metadata(self, analyzer, mock_ai_service):
        """Test analysis with metadata."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 10,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 70},
                "sentiment_analysis": {"sentiment": "neutral", "suspicious": False},
                "spam_analysis": {"is_spam": False, "confidence_score": 5}
            }
        }
        
        content = "Test content"
        metadata = {"author": "test_user", "timestamp": "2024-01-01"}
        result = await analyzer.analyze_content_risk(content, "twitter", metadata)
        
        assert isinstance(result, ContentRiskResult)
        assert result.confidence_score > 0
    
    @pytest.mark.asyncio
    async def test_analyze_content_risk_platform_specific(self, analyzer, mock_ai_service):
        """Test that platform-specific analysis is applied."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 0,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 60},
                "sentiment_analysis": {"sentiment": "neutral", "suspicious": False},
                "spam_analysis": {"is_spam": False, "confidence_score": 0}
            }
        }
        
        content = "Check out https://example.com #tag1 #tag2 #tag3"
        result = await analyzer.analyze_content_risk(content, "twitter")
        
        assert "platform_rules" in result.platform_specific_risks
        assert result.platform_specific_risks["platform_rules"]["platform"] == "twitter"
    
    @pytest.mark.asyncio
    async def test_analyze_content_risk_aggregates_all_factors(self, analyzer, mock_ai_service):
        """Test that all risk factors are aggregated."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": True,
            "threat_types": ["spam"],
            "confidence_score": 60,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 40},
                "sentiment_analysis": {"sentiment": "neutral", "suspicious": False},
                "spam_analysis": {"is_spam": True, "confidence_score": 65}
            }
        }
        
        content = "Buy now! Limited time! Click here! #tag1 #tag2 #tag3 #tag4"
        result = await analyzer.analyze_content_risk(content, "twitter")
        
        # Should have risk factors from patterns, AI, and platform rules
        assert len(result.risk_factors) > 0
        assert len(result.recommendations) > 0
        assert "pattern_analysis" in result.platform_specific_risks
        assert "ai_analysis" in result.platform_specific_risks
        assert "platform_rules" in result.platform_specific_risks
    
    @pytest.mark.asyncio
    async def test_analyze_content_risk_error_handling(self, analyzer, mock_ai_service):
        """Test error handling in comprehensive analysis."""
        mock_ai_service.analyze_content.side_effect = Exception("Service error")
        
        content = "Test content"
        result = await analyzer.analyze_content_risk(content, "twitter")
        
        # Should return safe default assessment
        # Note: With clean content and AI error, pattern analysis returns 0, 
        # so overall score is low, not medium
        assert isinstance(result, ContentRiskResult)
        assert result.risk_level == "low"  # Clean content with no patterns
        assert result.risk_score >= 0
        assert result.confidence_score >= 0.0
    
    @pytest.mark.asyncio
    async def test_analyze_content_risk_timestamp(self, analyzer, mock_ai_service):
        """Test that analysis includes timestamp."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 0,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 70},
                "sentiment_analysis": {"sentiment": "neutral", "suspicious": False},
                "spam_analysis": {"is_spam": False, "confidence_score": 0}
            }
        }
        
        content = "Test content"
        result = await analyzer.analyze_content_risk(content, "twitter")
        
        assert result.analysis_timestamp is not None
        assert isinstance(result.analysis_timestamp, str)
        # Verify it's a valid ISO format timestamp
        datetime.fromisoformat(result.analysis_timestamp.replace('Z', '+00:00'))
    
    @pytest.mark.asyncio
    async def test_analyze_content_risk_deduplicates_factors(self, analyzer, mock_ai_service):
        """Test that duplicate risk factors are removed."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": True,
            "threat_types": ["spam", "spam"],  # Duplicate
            "confidence_score": 50,
            "detailed_analysis": {
                "quality_analysis": {"quality_score": 50},
                "sentiment_analysis": {"sentiment": "neutral", "suspicious": False},
                "spam_analysis": {"is_spam": True, "confidence_score": 50}
            }
        }
        
        content = "Buy now! Buy now! Buy now!"  # Repeated patterns
        result = await analyzer.analyze_content_risk(content, "twitter")
        
        # Check that risk factors don't have duplicates
        assert len(result.risk_factors) == len(set(result.risk_factors))
        assert len(result.recommendations) == len(set(result.recommendations))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
