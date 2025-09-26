"""
Unit tests for BotController analysis methods.

Tests the three new analysis methods added to BotController:
- analyze_account_safety()
- check_content_compliance()
- analyze_verified_followers()
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
from fastapi import HTTPException, status

from src.social_protection.controllers.bot_controller import BotController
from src.social_protection.types import PlatformType, RiskLevel
from src.models.user import User
from src.social_protection.data_models import ContentRiskAssessment


class TestBotControllerAnalysisMethods:
    """Test cases for BotController analysis methods."""
    
    @pytest.fixture
    def mock_services(self):
        """Create mock services for BotController."""
        return {
            'security_service': Mock(),
            'auth_service': Mock(),
            'email_service': Mock(),
            'social_scan_service': AsyncMock(),
            'content_risk_analyzer': AsyncMock(),
            'link_penalty_detector': AsyncMock(),
            'spam_pattern_detector': AsyncMock(),
            'community_notes_analyzer': AsyncMock(),
            'visibility_scorer': AsyncMock(),
            'engagement_analyzer': AsyncMock(),
            'penalty_detector': AsyncMock(),
            'shadow_ban_detector': AsyncMock()
        }
    
    @pytest.fixture
    def bot_controller(self, mock_services):
        """Create BotController instance with mocked services."""
        controller = BotController(**mock_services)
        # Mock the rate limiting method
        controller.check_rate_limit = AsyncMock(return_value=True)
        controller.log_operation = Mock()
        return controller
    
    @pytest.fixture
    def sample_user(self):
        """Create a sample user for testing."""
        user = Mock(spec=User)
        user.id = 123
        user.username = "testuser"
        return user


class TestAnalyzeAccountSafety(TestBotControllerAnalysisMethods):
    """Test cases for analyze_account_safety method."""
    
    @pytest.mark.asyncio
    async def test_analyze_account_safety_success(self, bot_controller, sample_user, mock_services):
        """Test successful account safety analysis."""
        # Setup mock scan result
        mock_scan_result = Mock()
        mock_risk_assessment = Mock()
        mock_risk_assessment.overall_risk_score = 0.3
        mock_risk_assessment.risk_level = RiskLevel.LOW
        mock_risk_assessment.risk_factors = [
            Mock(risk_type="suspicious_activity", severity="low", description="Low activity detected")
        ]
        mock_risk_assessment.recommendations = ["Monitor account regularly"]
        mock_scan_result.risk_assessment = mock_risk_assessment
        
        mock_services['social_scan_service'].create_profile_scan.return_value = mock_scan_result
        
        # Execute method
        result = await bot_controller.analyze_account_safety(
            user=sample_user,
            account_identifier="@testaccount",
            platform=PlatformType.TWITTER
        )
        
        # Verify result structure
        assert result["account_identifier"] == "testaccount"
        assert result["platform"] == "twitter"
        assert result["risk_score"] == 30.0  # 0.3 * 100
        assert result["risk_level"] == "low"
        assert len(result["risk_factors"]) == 1
        assert result["risk_factors"][0]["type"] == "suspicious_activity"
        assert len(result["recommendations"]) == 1
        assert "analysis_timestamp" in result
        assert "confidence_score" in result
        
        # Verify service calls
        mock_services['social_scan_service'].create_profile_scan.assert_called_once()
        bot_controller.log_operation.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analyze_account_safety_fallback_to_content_analyzer(self, bot_controller, sample_user, mock_services):
        """Test fallback to content analyzer when scan service fails."""
        # Setup scan service to fail
        mock_services['social_scan_service'].create_profile_scan.side_effect = Exception("Service unavailable")
        
        # Setup content analyzer mock
        mock_risk_result = Mock()
        mock_risk_result.overall_risk_score = 0.5
        mock_risk_result.risk_level = RiskLevel.MEDIUM
        mock_risk_result.risk_factors = [
            Mock(risk_type="content_risk", severity="medium", description="Medium risk content")
        ]
        mock_risk_result.recommendations = ["Review content policy"]
        
        mock_services['content_risk_analyzer'].analyze_content_risk.return_value = mock_risk_result
        
        # Execute method
        result = await bot_controller.analyze_account_safety(
            user=sample_user,
            account_identifier="testaccount",
            platform=PlatformType.TWITTER
        )
        
        # Verify fallback worked
        assert result["risk_score"] == 50.0
        assert result["risk_level"] == "medium"
        assert len(result["risk_factors"]) == 1
        
        # Verify content analyzer was called
        mock_services['content_risk_analyzer'].analyze_content_risk.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analyze_account_safety_rate_limit_exceeded(self, bot_controller, sample_user):
        """Test rate limit exceeded scenario."""
        # Setup rate limit to fail
        bot_controller.check_rate_limit = AsyncMock(return_value=False)
        
        # Execute and expect exception
        with pytest.raises(HTTPException) as exc_info:
            await bot_controller.analyze_account_safety(
                user=sample_user,
                account_identifier="testaccount",
                platform=PlatformType.TWITTER
            )
        
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "rate limit exceeded" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_analyze_account_safety_empty_identifier(self, bot_controller, sample_user):
        """Test empty account identifier validation."""
        with pytest.raises(HTTPException) as exc_info:
            await bot_controller.analyze_account_safety(
                user=sample_user,
                account_identifier="",
                platform=PlatformType.TWITTER
            )
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "required" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_analyze_account_safety_cleans_identifier(self, bot_controller, sample_user, mock_services):
        """Test that @ symbol is properly removed from identifier."""
        # Setup minimal mock
        mock_services['social_scan_service'].create_profile_scan.return_value = None
        mock_risk_result = Mock()
        mock_risk_result.overall_risk_score = 0.1
        mock_risk_result.risk_level = RiskLevel.LOW
        mock_risk_result.risk_factors = []
        mock_risk_result.recommendations = []
        mock_services['content_risk_analyzer'].analyze_content_risk.return_value = mock_risk_result
        
        # Execute with @ symbol
        result = await bot_controller.analyze_account_safety(
            user=sample_user,
            account_identifier="@testaccount",
            platform=PlatformType.TWITTER
        )
        
        # Verify @ was removed
        assert result["account_identifier"] == "testaccount"


class TestCheckContentCompliance(TestBotControllerAnalysisMethods):
    """Test cases for check_content_compliance method."""
    
    @pytest.mark.asyncio
    async def test_check_content_compliance_success(self, bot_controller, sample_user, mock_services):
        """Test successful content compliance check."""
        # Setup mock results
        mock_spam_result = Mock()
        mock_spam_result.spam_score = 0.2
        mock_spam_result.detected_patterns = [
            Mock(pattern_type="promotional", confidence=0.6)
        ]
        
        mock_risk_result = Mock()
        mock_risk_result.overall_risk_score = 0.1
        mock_risk_result.risk_factors = [
            Mock(risk_type="mild_concern", severity="low", description="Minor issue detected")
        ]
        
        mock_services['spam_pattern_detector'].detect_spam_patterns.return_value = mock_spam_result
        mock_services['content_risk_analyzer'].analyze_content_risk.return_value = mock_risk_result
        
        # Execute method
        result = await bot_controller.check_content_compliance(
            user=sample_user,
            content="This is test content for compliance checking",
            platform=PlatformType.TWITTER
        )
        
        # Verify result structure
        assert "content_preview" in result
        assert result["platform"] == "twitter"
        assert result["is_compliant"] is True  # Should be compliant with low scores
        assert result["compliance_score"] > 70.0  # Above threshold
        assert result["spam_score"] == 20.0  # 0.2 * 100
        assert result["risk_score"] == 10.0  # 0.1 * 100
        assert "violations" in result
        assert "recommendations" in result
        assert "analysis_timestamp" in result
        
        # Verify service calls
        mock_services['spam_pattern_detector'].detect_spam_patterns.assert_called_once()
        mock_services['content_risk_analyzer'].analyze_content_risk.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_content_compliance_non_compliant(self, bot_controller, sample_user, mock_services):
        """Test non-compliant content detection."""
        # Setup high risk scores
        mock_spam_result = Mock()
        mock_spam_result.spam_score = 0.8
        mock_spam_result.detected_patterns = [
            Mock(pattern_type="spam", confidence=0.9)
        ]
        
        mock_risk_result = Mock()
        mock_risk_result.overall_risk_score = 0.7
        mock_risk_result.risk_factors = [
            Mock(risk_type="policy_violation", severity="high", description="Policy violation detected")
        ]
        
        mock_services['spam_pattern_detector'].detect_spam_patterns.return_value = mock_spam_result
        mock_services['content_risk_analyzer'].analyze_content_risk.return_value = mock_risk_result
        
        # Execute method
        result = await bot_controller.check_content_compliance(
            user=sample_user,
            content="Spam content with violations",
            platform=PlatformType.TWITTER
        )
        
        # Verify non-compliant result
        assert result["is_compliant"] is False
        assert result["compliance_score"] < 70.0  # Below threshold
        assert len(result["violations"]) > 0
        assert any("spam" in rec.lower() for rec in result["recommendations"])
    
    @pytest.mark.asyncio
    async def test_check_content_compliance_empty_content(self, bot_controller, sample_user):
        """Test empty content validation."""
        with pytest.raises(HTTPException) as exc_info:
            await bot_controller.check_content_compliance(
                user=sample_user,
                content="",
                platform=PlatformType.TWITTER
            )
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "required" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_check_content_compliance_long_content_truncation(self, bot_controller, sample_user, mock_services):
        """Test that long content is properly truncated."""
        # Setup minimal mocks
        mock_services['spam_pattern_detector'].detect_spam_patterns.return_value = Mock(
            spam_score=0.1, detected_patterns=[]
        )
        mock_services['content_risk_analyzer'].analyze_content_risk.return_value = Mock(
            overall_risk_score=0.1, risk_factors=[]
        )
        
        # Create very long content
        long_content = "A" * 6000  # Exceeds 5000 char limit
        
        # Execute method
        result = await bot_controller.check_content_compliance(
            user=sample_user,
            content=long_content,
            platform=PlatformType.TWITTER
        )
        
        # Verify content was truncated in preview
        assert len(result["content_preview"]) <= 103  # 100 chars + "..."


class TestAnalyzeVerifiedFollowers(TestBotControllerAnalysisMethods):
    """Test cases for analyze_verified_followers method."""
    
    @pytest.mark.asyncio
    async def test_analyze_verified_followers_success(self, bot_controller, sample_user, mock_services):
        """Test successful verified followers analysis."""
        # Setup mock scan result
        mock_scan_result = Mock()
        mock_follower_analysis = Mock()
        mock_follower_analysis.verified_count = 25
        mock_follower_analysis.high_value_count = 5
        mock_follower_analysis.categories = {
            "verified": 25,
            "business": 10,
            "influencer": 8,
            "regular": 100
        }
        mock_follower_analysis.networking_opportunities = [
            "Connect with @influencer1",
            "Engage with @business2"
        ]
        mock_scan_result.follower_analysis = mock_follower_analysis
        
        mock_services['social_scan_service'].create_profile_scan.return_value = mock_scan_result
        
        # Execute method
        result = await bot_controller.analyze_verified_followers(
            user=sample_user,
            account_identifier="testaccount",
            platform=PlatformType.TWITTER
        )
        
        # Verify result structure
        assert result["account_identifier"] == "testaccount"
        assert result["platform"] == "twitter"
        assert result["verified_followers_count"] == 25
        assert result["high_value_count"] == 5
        assert result["total_analyzed"] == 143  # Sum of categories
        assert result["quality_score"] > 0  # Should have some quality score
        assert "follower_categories" in result
        assert "networking_opportunities" in result
        assert len(result["insights"]) <= 3
        assert len(result["recommendations"]) <= 3
        
        # Verify service calls
        mock_services['social_scan_service'].create_profile_scan.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analyze_verified_followers_no_verified(self, bot_controller, sample_user, mock_services):
        """Test analysis when no verified followers are found."""
        # Setup scan service to fail (fallback scenario)
        mock_services['social_scan_service'].create_profile_scan.side_effect = Exception("Service unavailable")
        
        # Execute method
        result = await bot_controller.analyze_verified_followers(
            user=sample_user,
            account_identifier="testaccount",
            platform=PlatformType.TWITTER
        )
        
        # Verify fallback result
        assert result["verified_followers_count"] == 0
        assert result["high_value_count"] == 0
        assert "No verified followers detected" in result["insights"]
        assert any("quality content" in rec.lower() for rec in result["recommendations"])
    
    @pytest.mark.asyncio
    async def test_analyze_verified_followers_default_account(self, bot_controller, sample_user, mock_services):
        """Test using default account when none specified."""
        # Setup fallback scenario
        mock_services['social_scan_service'].create_profile_scan.side_effect = Exception("Service unavailable")
        
        # Execute without account identifier
        result = await bot_controller.analyze_verified_followers(
            user=sample_user,
            account_identifier=None,
            platform=PlatformType.TWITTER
        )
        
        # Verify it used user's username
        assert result["account_identifier"] == "testuser"
    
    @pytest.mark.asyncio
    async def test_analyze_verified_followers_rate_limit(self, bot_controller, sample_user):
        """Test rate limit for follower analysis."""
        # Setup rate limit to fail
        bot_controller.check_rate_limit = AsyncMock(return_value=False)
        
        # Execute and expect exception
        with pytest.raises(HTTPException) as exc_info:
            await bot_controller.analyze_verified_followers(
                user=sample_user,
                account_identifier="testaccount",
                platform=PlatformType.TWITTER
            )
        
        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "rate limit exceeded" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_analyze_verified_followers_quality_score_calculation(self, bot_controller, sample_user, mock_services):
        """Test quality score calculation logic."""
        # Setup scan result with specific numbers for quality calculation
        mock_scan_result = Mock()
        mock_follower_analysis = Mock()
        mock_follower_analysis.verified_count = 10
        mock_follower_analysis.high_value_count = 5
        mock_follower_analysis.categories = {
            "verified": 10,
            "business": 5,
            "regular": 85
        }
        mock_follower_analysis.networking_opportunities = []
        mock_scan_result.follower_analysis = mock_follower_analysis
        
        mock_services['social_scan_service'].create_profile_scan.return_value = mock_scan_result
        
        # Execute method
        result = await bot_controller.analyze_verified_followers(
            user=sample_user,
            account_identifier="testaccount",
            platform=PlatformType.TWITTER
        )
        
        # Verify quality score calculation
        # Formula: (verified_count + high_value_count * 2) / total * 100
        # (10 + 5 * 2) / 100 * 100 = 20.0
        expected_quality = (10 + 5 * 2) / 100 * 100
        assert result["quality_score"] == expected_quality


class TestBotControllerMethodsIntegration(TestBotControllerAnalysisMethods):
    """Integration tests for BotController methods."""
    
    @pytest.mark.asyncio
    async def test_all_methods_return_compatible_format(self, bot_controller, sample_user, mock_services):
        """Test that all three methods return BotResponse-compatible format."""
        # Setup minimal mocks for all services
        mock_services['social_scan_service'].create_profile_scan.return_value = None
        mock_services['content_risk_analyzer'].analyze_content_risk.return_value = Mock(
            overall_risk_score=0.1, risk_level=RiskLevel.LOW, risk_factors=[], recommendations=[]
        )
        mock_services['spam_pattern_detector'].detect_spam_patterns.return_value = Mock(
            spam_score=0.1, detected_patterns=[]
        )
        
        # Test all three methods
        account_result = await bot_controller.analyze_account_safety(
            user=sample_user, account_identifier="test", platform=PlatformType.TWITTER
        )
        
        compliance_result = await bot_controller.check_content_compliance(
            user=sample_user, content="test content", platform=PlatformType.TWITTER
        )
        
        followers_result = await bot_controller.analyze_verified_followers(
            user=sample_user, account_identifier="test", platform=PlatformType.TWITTER
        )
        
        # Verify all results have required fields for BotResponse compatibility
        for result in [account_result, compliance_result, followers_result]:
            assert "platform" in result
            assert "analysis_timestamp" in result
            assert "confidence_score" in result
            assert isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_error_handling_consistency(self, bot_controller, sample_user, mock_services):
        """Test that all methods handle errors consistently."""
        # Setup all services to fail
        mock_services['social_scan_service'].create_profile_scan.side_effect = Exception("Service error")
        mock_services['content_risk_analyzer'].analyze_content_risk.side_effect = Exception("Analyzer error")
        mock_services['spam_pattern_detector'].detect_spam_patterns.side_effect = Exception("Detector error")
        
        # Test that all methods raise HTTPException with 500 status
        with pytest.raises(HTTPException) as exc_info:
            await bot_controller.analyze_account_safety(
                user=sample_user, account_identifier="test", platform=PlatformType.TWITTER
            )
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        
        with pytest.raises(HTTPException) as exc_info:
            await bot_controller.check_content_compliance(
                user=sample_user, content="test", platform=PlatformType.TWITTER
            )
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        
        with pytest.raises(HTTPException) as exc_info:
            await bot_controller.analyze_verified_followers(
                user=sample_user, platform=PlatformType.TWITTER
            )
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR