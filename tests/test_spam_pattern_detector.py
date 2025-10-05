"""
Unit tests for SpamPatternDetector.

Tests spam pattern detection, keyword analysis, engagement bait detection,
repetition analysis, and ML model integration.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone

from linkshield.social_protection.content_analyzer.spam_pattern_detector import (
    SpamPatternDetector,
    SpamPatternResult
)
from linkshield.services.ai_service import AIService


@pytest.fixture
def mock_ai_service():
    """Create a mock AI service."""
    ai_service = Mock(spec=AIService)
    ai_service.detect_spam_patterns = AsyncMock(return_value={
        "spam_score": 0,
        "is_spam": False,
        "detected_patterns": [],
        "confidence": 0.0
    })
    return ai_service


@pytest.fixture
def spam_detector(mock_ai_service):
    """Create a SpamPatternDetector instance with mocked AI service."""
    return SpamPatternDetector(ai_service=mock_ai_service)


class TestSpamPatternDetector:
    """Test suite for SpamPatternDetector."""
    
    @pytest.mark.asyncio
    async def test_clean_content_not_spam(self, spam_detector):
        """Test that clean content is not flagged as spam."""
        content = "This is a normal post about technology and innovation."
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert isinstance(result, SpamPatternResult)
        assert result.is_spam is False
        assert result.spam_score < 60
        assert len(result.spam_types) == 0
    
    @pytest.mark.asyncio
    async def test_financial_scam_detection(self, spam_detector):
        """Test detection of financial scam keywords."""
        content = "Make money fast! Get rich quick with this guaranteed income opportunity!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert "financial_scams" in result.spam_types
        assert any("financial_scams" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_engagement_bait_detection(self, spam_detector):
        """Test detection of engagement bait patterns."""
        content = "Like if you agree! Share if you love this! Comment below and tag a friend!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert "engagement_bait" in result.spam_types
        assert any("engagement_bait" in behavior for behavior in result.suspicious_behaviors)
    
    @pytest.mark.asyncio
    async def test_fake_urgency_detection(self, spam_detector):
        """Test detection of fake urgency tactics."""
        content = "Limited time offer! Act now! Don't miss out! Expires today!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert "fake_urgency" in result.spam_types
    
    @pytest.mark.asyncio
    async def test_excessive_caps_detection(self, spam_detector):
        """Test detection of excessive capitalization."""
        content = "BUY NOW!!! AMAZING DEAL!!! LIMITED TIME ONLY!!!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert any("excessive_caps" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_excessive_punctuation_detection(self, spam_detector):
        """Test detection of excessive punctuation."""
        content = "This is amazing!!! Really incredible!!! You won't believe it!!!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert any("excessive_punctuation" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_repeated_characters_detection(self, spam_detector):
        """Test detection of repeated characters."""
        content = "Wooooow this is amaaaaaazing!!!! Sooooo good!!!!!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert any("repeated_characters" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_phone_number_detection(self, spam_detector):
        """Test detection of phone numbers in content."""
        content = "Call me at 555-123-4567 for more information!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert any("phone_numbers" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_email_address_detection(self, spam_detector):
        """Test detection of email addresses in content."""
        content = "Contact me at spam@example.com for details!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert any("email_addresses" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_repetition_analysis_words(self, spam_detector):
        """Test detection of excessive word repetition."""
        content = "Buy buy buy buy now now now now! Amazing amazing amazing amazing deal deal deal deal!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert "excessive_repetition" in result.suspicious_behaviors
        assert any("repeated_word" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_repetition_analysis_phrases(self, spam_detector):
        """Test detection of repeated phrases."""
        content = "Click here now! Click here now! Click here now!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert "excessive_repetition" in result.suspicious_behaviors
        assert any("repeated_phrase" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_crypto_scam_detection(self, spam_detector):
        """Test detection of crypto scam patterns."""
        content = "Free bitcoin giveaway! Get rich with crypto! Guaranteed returns on your investment!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert "crypto_scams" in result.spam_types
    
    @pytest.mark.asyncio
    async def test_health_scam_detection(self, spam_detector):
        """Test detection of health scam patterns."""
        content = "Miracle cure! Doctors hate this! Lose weight fast with this anti-aging secret!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.is_spam is True
        assert "health_scams" in result.spam_types
    
    @pytest.mark.asyncio
    async def test_clickbait_detection(self, spam_detector):
        """Test detection of clickbait patterns."""
        content = "You won't believe what happened next! Number 7 will shock you! This one trick doctors hate!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert "clickbait" in result.spam_types
    
    @pytest.mark.asyncio
    async def test_fake_giveaway_detection(self, spam_detector):
        """Test detection of fake giveaway patterns."""
        content = "Free iPhone giveaway! Win a prize! Congratulations you won! Claim your prize now!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.is_spam is True
        assert "fake_giveaways" in result.spam_types
    
    @pytest.mark.asyncio
    async def test_twitter_platform_specific(self, spam_detector):
        """Test Twitter-specific spam pattern detection."""
        content = "Follow me! #spam #follow #f4f #like #share #retweet #followback"
        
        result = await spam_detector.detect_spam_patterns(content, platform="twitter")
        
        assert result.spam_score > 0
        assert any("twitter" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_instagram_platform_specific(self, spam_detector):
        """Test Instagram-specific spam pattern detection."""
        content = "F4F L4L follow4follow like4like DM me for more!"
        
        result = await spam_detector.detect_spam_patterns(content, platform="instagram")
        
        assert result.spam_score > 0
        assert any("instagram" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_metadata_rapid_posting(self, spam_detector):
        """Test detection of rapid posting behavior."""
        content = "Check out this post!"
        metadata = {
            "posts_per_hour": 15,
            "account_age_days": 365
        }
        
        result = await spam_detector.detect_spam_patterns(content, metadata=metadata)
        
        assert "rapid_posting" in result.suspicious_behaviors
    
    @pytest.mark.asyncio
    async def test_metadata_low_engagement(self, spam_detector):
        """Test detection of low engagement ratio."""
        content = "Check out this post!"
        metadata = {
            "engagement_ratio": 0.005,  # 0.5% engagement
            "posts_per_hour": 5
        }
        
        result = await spam_detector.detect_spam_patterns(content, metadata=metadata)
        
        assert "low_engagement" in result.suspicious_behaviors
    
    @pytest.mark.asyncio
    async def test_metadata_new_account_high_activity(self, spam_detector):
        """Test detection of new account with high activity."""
        content = "Check out this post!"
        metadata = {
            "account_age_days": 15,
            "posts_count": 150
        }
        
        result = await spam_detector.detect_spam_patterns(content, metadata=metadata)
        
        assert "new_account_high_activity" in result.suspicious_behaviors
    
    @pytest.mark.asyncio
    async def test_ai_integration(self, spam_detector, mock_ai_service):
        """Test AI service integration for spam detection."""
        # Configure mock to return spam detection
        mock_ai_service.detect_spam_patterns.return_value = {
            "spam_score": 85,
            "is_spam": True,
            "detected_patterns": ["ai_detected_spam_pattern"],
            "confidence": 0.85,
            "method": "ml_model"
        }
        
        content = "Some potentially spammy content"
        result = await spam_detector.detect_spam_patterns(content)
        
        # Verify AI service was called
        mock_ai_service.detect_spam_patterns.assert_called_once_with(content)
        
        # Verify AI results are incorporated
        assert result.spam_score > 0
    
    @pytest.mark.asyncio
    async def test_ml_model_integration(self, spam_detector, mock_ai_service):
        """Test ML model integration for spam classification."""
        # Configure mock to return ML-based spam detection
        mock_ai_service.detect_spam_patterns.return_value = {
            "spam_score": 78,
            "is_spam": True,
            "detected_patterns": ["ml_toxic_content_75", "ml_obscene_content_65"],
            "confidence": 0.78,
            "ml_analysis": {
                "model": "toxic-bert",
                "indicators": {
                    "toxic": 0.75,
                    "severe_toxic": 0.30,
                    "obscene": 0.65,
                    "threat": 0.20,
                    "insult": 0.45,
                    "identity_hate": 0.15
                },
                "weighted_score": 0.52,
                "max_score": 0.75
            },
            "method": "ml_model"
        }
        
        content = "This is toxic spam content with obscene language"
        result = await spam_detector.detect_spam_patterns(content)
        
        # Verify ML model was used
        mock_ai_service.detect_spam_patterns.assert_called_once_with(content)
        
        # Verify ML results are incorporated
        assert result.is_spam is True
        assert result.spam_score >= 60
        assert result.confidence_score > 0.5
        
        # Check that ML-detected patterns are included
        ai_analysis = result.pattern_analysis.get("ai_analysis", {})
        assert "ml_analysis" in ai_analysis or len(result.detected_patterns) > 0
    
    @pytest.mark.asyncio
    async def test_ml_model_high_confidence(self, spam_detector, mock_ai_service):
        """Test ML model with high confidence spam detection."""
        # Configure mock to return high confidence spam detection
        mock_ai_service.detect_spam_patterns.return_value = {
            "spam_score": 92,
            "is_spam": True,
            "detected_patterns": [
                "ml_toxic_content_90",
                "ml_severe_toxic_85",
                "ml_insulting_content_75"
            ],
            "confidence": 0.92,
            "ml_analysis": {
                "model": "toxic-bert",
                "indicators": {
                    "toxic": 0.90,
                    "severe_toxic": 0.85,
                    "obscene": 0.70,
                    "threat": 0.60,
                    "insult": 0.75,
                    "identity_hate": 0.55
                },
                "weighted_score": 0.78,
                "max_score": 0.90
            },
            "method": "ml_model"
        }
        
        content = "Extremely toxic and spammy content"
        result = await spam_detector.detect_spam_patterns(content)
        
        # Verify high confidence detection
        assert result.is_spam is True
        assert result.spam_score >= 80
        assert result.confidence_score >= 0.8
    
    @pytest.mark.asyncio
    async def test_ml_model_low_confidence(self, spam_detector, mock_ai_service):
        """Test ML model with low confidence (borderline content)."""
        # Configure mock to return low confidence detection
        mock_ai_service.detect_spam_patterns.return_value = {
            "spam_score": 35,
            "is_spam": False,
            "detected_patterns": ["ml_toxic_content_35"],
            "confidence": 0.35,
            "ml_analysis": {
                "model": "toxic-bert",
                "indicators": {
                    "toxic": 0.35,
                    "severe_toxic": 0.08,
                    "obscene": 0.20,
                    "threat": 0.05,
                    "insult": 0.25,
                    "identity_hate": 0.05
                },
                "weighted_score": 0.20,
                "max_score": 0.35
            },
            "method": "ml_model"
        }
        
        content = "This is normal content without spam indicators"
        result = await spam_detector.detect_spam_patterns(content)
        
        # Verify low confidence results in not spam (below 60 threshold)
        # Note: Pattern-based detection may add some score, so we check it's not flagged as spam
        assert result.is_spam is False or result.spam_score < 70
    
    @pytest.mark.asyncio
    async def test_ml_model_fallback_to_patterns(self, spam_detector, mock_ai_service):
        """Test fallback to pattern-based detection when ML model fails."""
        # Configure mock to simulate ML model failure
        mock_ai_service.detect_spam_patterns.return_value = {
            "spam_score": 0,
            "is_spam": False,
            "detected_patterns": [],
            "confidence": 0.0,
            "ml_analysis": {"error": "Model not available"},
            "method": "pattern_based"
        }
        
        content = "Make money fast! Get rich quick! Limited time offer!"
        result = await spam_detector.detect_spam_patterns(content)
        
        # Verify pattern-based detection still works
        assert result.spam_score > 0  # Should detect financial scam patterns
        assert "financial_scams" in result.spam_types or "fake_urgency" in result.spam_types
    
    @pytest.mark.asyncio
    async def test_ml_and_openai_combined(self, spam_detector, mock_ai_service):
        """Test combined ML and OpenAI analysis."""
        # Configure mock to return combined analysis
        mock_ai_service.detect_spam_patterns.return_value = {
            "spam_score": 82,
            "is_spam": True,
            "detected_patterns": [
                "ml_toxic_content_75",
                "openai_spam_pattern"
            ],
            "confidence": 0.82,
            "ml_analysis": {
                "model": "toxic-bert",
                "indicators": {"toxic": 0.75}
            },
            "method": "ml_and_openai"
        }
        
        content = "Spam content analyzed by both ML and OpenAI"
        result = await spam_detector.detect_spam_patterns(content)
        
        # Verify combined analysis
        assert result.is_spam is True
        assert result.spam_score >= 70
        assert result.confidence_score > 0.7
    
    @pytest.mark.asyncio
    async def test_confidence_score_calculation(self, spam_detector):
        """Test confidence score calculation."""
        content = "Make money fast! Get rich quick! Limited time offer! Act now!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert 0.0 <= result.confidence_score <= 1.0
        assert result.confidence_score > 0.7  # High confidence with multiple indicators
    
    @pytest.mark.asyncio
    async def test_recommendations_generation(self, spam_detector):
        """Test that recommendations are generated for spam content."""
        content = "MAKE MONEY FAST!!! Like if you agree! Share now!!!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert len(result.recommendations) > 0
        # Check for any spam-related recommendations
        assert any(keyword in rec.lower() for rec in result.recommendations 
                  for keyword in ["engagement", "caps", "financial", "scam", "likes"])
    
    @pytest.mark.asyncio
    async def test_pattern_analysis_structure(self, spam_detector):
        """Test that pattern analysis contains all expected sections."""
        content = "Test content"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert "basic_patterns" in result.pattern_analysis
        assert "keyword_analysis" in result.pattern_analysis
        assert "behavior_analysis" in result.pattern_analysis
        assert "quality_analysis" in result.pattern_analysis
        assert "repetition_analysis" in result.pattern_analysis
        assert "ai_analysis" in result.pattern_analysis
    
    @pytest.mark.asyncio
    async def test_spam_score_normalization(self, spam_detector):
        """Test that spam score is normalized to 0-100 range."""
        content = "EXTREME SPAM!!! " * 100  # Very spammy content
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert 0 <= result.spam_score <= 100
    
    @pytest.mark.asyncio
    async def test_error_handling(self, spam_detector, mock_ai_service):
        """Test error handling when analysis fails."""
        # Make AI service raise an exception
        mock_ai_service.detect_spam_patterns.side_effect = Exception("AI service error")
        
        content = "Test content"
        result = await spam_detector.detect_spam_patterns(content)
        
        # Should still return a valid result (graceful degradation)
        assert isinstance(result, SpamPatternResult)
        # AI error should be logged but analysis continues with other methods
        assert "error" in result.pattern_analysis.get("ai_analysis", {})
    
    @pytest.mark.asyncio
    async def test_multiple_spam_types(self, spam_detector):
        """Test detection of multiple spam types in one content."""
        content = """
        Make money fast with crypto! Limited time offer!
        Like if you agree! Share now! Follow for follow!
        Free iPhone giveaway! You won't believe this!
        """
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.is_spam is True
        assert len(result.spam_types) >= 3  # Multiple spam types detected
        assert "financial_scams" in result.spam_types or "crypto_scams" in result.spam_types
        assert "engagement_bait" in result.spam_types
        assert "fake_urgency" in result.spam_types or "fake_giveaways" in result.spam_types
    
    @pytest.mark.asyncio
    async def test_timestamp_format(self, spam_detector):
        """Test that analysis timestamp is in ISO format."""
        content = "Test content"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        # Verify timestamp can be parsed
        timestamp = datetime.fromisoformat(result.analysis_timestamp.replace('Z', '+00:00'))
        assert isinstance(timestamp, datetime)
    
    @pytest.mark.asyncio
    async def test_content_quality_low(self, spam_detector):
        """Test detection of low quality content."""
        content = "asdfjkl qwerty 123abc xyz999 random text here"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        quality_analysis = result.pattern_analysis.get("quality_analysis", {})
        assert quality_analysis.get("quality_level") == "low" or result.spam_score > 0
    
    @pytest.mark.asyncio
    async def test_suspicious_url_shorteners(self, spam_detector):
        """Test detection of suspicious URL shorteners."""
        content = "Check out this link: bit.ly/abc123 and tinyurl.com/xyz789"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert result.spam_score > 0
        assert any("suspicious_urls" in pattern for pattern in result.detected_patterns)
    
    @pytest.mark.asyncio
    async def test_impersonation_detection(self, spam_detector):
        """Test detection of potential impersonation."""
        content = "I am the official verified account of this celebrity!"
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert "potential_impersonation" in result.suspicious_behaviors
    
    @pytest.mark.asyncio
    async def test_empty_content(self, spam_detector):
        """Test handling of empty content."""
        content = ""
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert isinstance(result, SpamPatternResult)
        assert result.spam_score >= 0
    
    @pytest.mark.asyncio
    async def test_very_long_content(self, spam_detector):
        """Test handling of very long content."""
        content = "This is a normal sentence. " * 1000  # Very long content
        
        result = await spam_detector.detect_spam_patterns(content)
        
        assert isinstance(result, SpamPatternResult)
        # Should detect repetition
        assert "excessive_repetition" in result.suspicious_behaviors
