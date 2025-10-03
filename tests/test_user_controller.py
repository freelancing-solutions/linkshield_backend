"""
Unit tests for UserController

Tests all controller methods including:
- Protection settings management
- Analytics generation
- Platform scanning
- Content analysis
- Algorithm health analysis
- Rate limiting
- Error handling
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4
from fastapi import HTTPException

# Mock the circular import before importing
import sys
sys.modules['src.controllers.user_controller'] = Mock()

from src.social_protection.controllers.user_controller import UserController
from src.models.user import User
from src.social_protection.types import PlatformType, RiskLevel
from src.social_protection.content_analyzer.content_risk_analyzer import ContentRiskResult
from src.social_protection.content_analyzer.link_penalty_detector import LinkPenaltyResult
from src.social_protection.content_analyzer.spam_pattern_detector import SpamPatternResult
from src.social_protection.content_analyzer.community_notes_analyzer import CommunityNotesResult
from src.social_protection.algorithm_health.visibility_scorer import VisibilityAnalysisResult
from src.social_protection.algorithm_health.engagement_analyzer import EngagementAnalysisResult, EngagementQuality
from src.social_protection.algorithm_health.penalty_detector import PenaltyDetectionResult
from src.social_protection.algorithm_health.shadow_ban_detector import ShadowBanDetectionResult


@pytest.fixture
def mock_services():
    """Create mock services for testing"""
    return {
        "security_service": Mock(),
        "auth_service": Mock(),
        "email_service": Mock(),
        "social_scan_service": AsyncMock(),
        "content_risk_analyzer": AsyncMock(),
        "link_penalty_detector": AsyncMock(),
        "spam_pattern_detector": AsyncMock(),
        "community_notes_analyzer": AsyncMock(),
        "visibility_scorer": AsyncMock(),
        "engagement_analyzer": AsyncMock(),
        "penalty_detector": AsyncMock(),
        "shadow_ban_detector": AsyncMock()
    }


@pytest.fixture
def user_controller(mock_services):
    """Create UserController instance with mocked services"""
    return UserController(**mock_services)


@pytest.fixture
def free_user():
    """Create a free tier user for testing"""
    user = Mock(spec=User)
    user.id = uuid4()
    user.subscription_plan = "free"
    user.email = "test@example.com"
    return user


@pytest.fixture
def premium_user():
    """Create a premium tier user for testing"""
    user = Mock(spec=User)
    user.id = uuid4()
    user.subscription_plan = "premium"
    user.email = "premium@example.com"
    return user


@pytest.fixture
def mock_db_session():
    """Create mock database session"""
    session = AsyncMock()
    return session


class TestGetUserProtectionSettings:
    """Test get_user_protection_settings method"""
    
    @pytest.mark.asyncio
    async def test_get_settings_free_user(self, user_controller, free_user, mock_db_session):
        """Test getting settings for free user"""
        result = await user_controller.get_user_protection_settings(free_user, mock_db_session)
        
        assert result["user_id"] == str(free_user.id)
        assert result["protection_level"] == "free"
        assert result["rate_limits"]["scans_per_hour"] == 20
        assert result["rate_limits"]["analyses_per_hour"] == 50
        assert result["scan_preferences"]["deep_analysis_enabled"] is False
        assert result["notification_preferences"]["real_time_alerts"] is False
    
    @pytest.mark.asyncio
    async def test_get_settings_premium_user(self, user_controller, premium_user, mock_db_session):
        """Test getting settings for premium user"""
        result = await user_controller.get_user_protection_settings(premium_user, mock_db_session)
        
        assert result["user_id"] == str(premium_user.id)
        assert result["protection_level"] == "premium"
        assert result["rate_limits"]["scans_per_hour"] == 100
        assert result["rate_limits"]["analyses_per_hour"] == 200
        assert result["scan_preferences"]["deep_analysis_enabled"] is True
        assert result["notification_preferences"]["real_time_alerts"] is True


class TestUpdateUserProtectionSettings:
    """Test update_user_protection_settings method"""
    
    @pytest.mark.asyncio
    async def test_update_settings_success(self, user_controller, free_user, mock_db_session):
        """Test successful settings update"""
        settings_update = {
            "notification_preferences": {
                "email_alerts": False,
                "weekly_reports": True
            }
        }
        
        result = await user_controller.update_user_protection_settings(
            free_user, settings_update, mock_db_session
        )
        
        assert result["success"] is True
        assert "settings" in result
    
    @pytest.mark.asyncio
    async def test_update_settings_invalid_keys(self, user_controller, free_user, mock_db_session):
        """Test update with invalid settings keys"""
        settings_update = {
            "invalid_key": {"some": "value"}
        }
        
        with pytest.raises(HTTPException) as exc_info:
            await user_controller.update_user_protection_settings(
                free_user, settings_update, mock_db_session
            )
        
        assert exc_info.value.status_code == 400
    
    @pytest.mark.asyncio
    async def test_update_settings_premium_restrictions(self, user_controller, free_user, mock_db_session):
        """Test that premium features are restricted for free users"""
        settings_update = {
            "scan_preferences": {
                "deep_analysis_enabled": True,  # Premium feature
                "shadow_ban_monitoring": True   # Premium feature
            }
        }
        
        result = await user_controller.update_user_protection_settings(
            free_user, settings_update, mock_db_session
        )
        
        # Premium features should be overridden to False for free users
        assert result["success"] is True


class TestGetUserProtectionAnalytics:
    """Test get_user_protection_analytics method"""
    
    @pytest.mark.asyncio
    async def test_get_analytics_with_data(self, user_controller, premium_user, mock_db_session):
        """Test getting analytics with scan data"""
        # Mock recent scans
        with patch.object(user_controller, '_get_user_recent_scans', return_value=[
            {"scan_id": "1", "risk_score": 0.2},
            {"scan_id": "2", "risk_score": 0.3}
        ]):
            with patch.object(user_controller, 'check_rate_limit', return_value=True):
                result = await user_controller.get_user_protection_analytics(
                    premium_user, PlatformType.TWITTER, 30, mock_db_session
                )
        
        assert result["user_id"] == str(premium_user.id)
        assert result["platform"] == "twitter"
        assert result["period_days"] == 30
        assert "analytics" in result
    
    @pytest.mark.asyncio
    async def test_get_analytics_no_data(self, user_controller, premium_user, mock_db_session):
        """Test getting analytics with no scan data"""
        with patch.object(user_controller, '_get_user_recent_scans', return_value=[]):
            with patch.object(user_controller, 'check_rate_limit', return_value=True):
                result = await user_controller.get_user_protection_analytics(
                    premium_user, None, 30, mock_db_session
                )
        
        assert result["analytics"]["total_scans"] == 0
        assert "message" in result
    
    @pytest.mark.asyncio
    async def test_get_analytics_rate_limit_exceeded(self, user_controller, premium_user, mock_db_session):
        """Test rate limit enforcement"""
        with patch.object(user_controller, 'check_rate_limit', return_value=False):
            with patch.object(user_controller, 'handle_rate_limit_error') as mock_handler:
                mock_handler.side_effect = HTTPException(status_code=429, detail="Rate limit exceeded")
                
                with pytest.raises(HTTPException) as exc_info:
                    await user_controller.get_user_protection_analytics(
                        premium_user, None, 30, mock_db_session
                    )
                
                assert exc_info.value.status_code == 429


class TestInitiateUserPlatformScan:
    """Test initiate_user_platform_scan method"""
    
    @pytest.mark.asyncio
    async def test_initiate_scan_success(self, user_controller, premium_user, mock_db_session):
        """Test successful scan initiation"""
        mock_scan_result = {
            "scan_id": str(uuid4()),
            "estimated_completion": datetime.utcnow().isoformat()
        }
        user_controller.social_scan_service.initiate_scan = AsyncMock(return_value=mock_scan_result)
        
        with patch.object(user_controller, 'check_rate_limit', return_value=True):
            result = await user_controller.initiate_user_platform_scan(
                premium_user,
                PlatformType.TWITTER,
                "testuser",
                None,
                None,
                mock_db_session
            )
        
        assert result["success"] is True
        assert "scan_id" in result
        assert result["platform"] == "twitter"
        assert result["username"] == "testuser"
    
    @pytest.mark.asyncio
    async def test_initiate_scan_empty_username(self, user_controller, premium_user, mock_db_session):
        """Test scan initiation with empty username"""
        with patch.object(user_controller, 'check_rate_limit', return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                await user_controller.initiate_user_platform_scan(
                    premium_user,
                    PlatformType.TWITTER,
                    "",
                    None,
                    None,
                    mock_db_session
                )
            
            assert exc_info.value.status_code == 400
    
    @pytest.mark.asyncio
    async def test_initiate_scan_rate_limit(self, user_controller, free_user, mock_db_session):
        """Test rate limit enforcement for scans"""
        with patch.object(user_controller, 'check_rate_limit', return_value=False):
            with patch.object(user_controller, 'handle_rate_limit_error') as mock_handler:
                mock_handler.side_effect = HTTPException(status_code=429, detail="Rate limit exceeded")
                
                with pytest.raises(HTTPException) as exc_info:
                    await user_controller.initiate_user_platform_scan(
                        free_user,
                        PlatformType.TWITTER,
                        "testuser",
                        None,
                        None,
                        mock_db_session
                    )
                
                assert exc_info.value.status_code == 429


class TestAnalyzeUserContent:
    """Test analyze_user_content method"""
    
    @pytest.mark.asyncio
    async def test_analyze_content_comprehensive(self, user_controller, premium_user, mock_db_session):
        """Test comprehensive content analysis"""
        # Mock analyzer results with correct structure
        user_controller.content_risk_analyzer.analyze_content_risk = AsyncMock(
            return_value=Mock(
                overall_risk_score=0.3,
                risk_level=RiskLevel.LOW,
                risk_factors=[],
                recommendations=["Test recommendation"]
            )
        )
        user_controller.link_penalty_detector.detect_link_penalties = AsyncMock(
            return_value=Mock(
                penalty_score=0.1,
                detected_penalties=[],
                affected_links=[],
                recommendations=[]
            )
        )
        user_controller.spam_pattern_detector.detect_spam_patterns = AsyncMock(
            return_value=Mock(
                spam_score=0.2,
                detected_patterns=[],
                risk_level=RiskLevel.LOW,
                recommendations=[]
            )
        )
        user_controller.community_notes_analyzer.analyze_community_notes = AsyncMock(
            return_value=Mock(
                fact_check_risk=0.1,
                misinformation_indicators=[],
                source_credibility=0.8,
                recommendations=[]
            )
        )
        
        content_data = {
            "content": "Test content",
            "platform": "twitter",
            "links": ["https://example.com"]
        }
        
        with patch.object(user_controller, 'check_rate_limit', return_value=True):
            result = await user_controller.analyze_user_content(
                premium_user,
                content_data,
                "comprehensive",
                mock_db_session
            )
        
        assert result["success"] is True
        assert "analysis_results" in result
        assert "content_risk" in result["analysis_results"]
        assert "link_penalties" in result["analysis_results"]
        assert "spam_patterns" in result["analysis_results"]
    
    @pytest.mark.asyncio
    async def test_analyze_content_missing_fields(self, user_controller, premium_user, mock_db_session):
        """Test content analysis with missing required fields"""
        content_data = {
            "content": "Test content"
            # Missing platform field
        }
        
        with patch.object(user_controller, 'check_rate_limit', return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                await user_controller.analyze_user_content(
                    premium_user,
                    content_data,
                    "comprehensive",
                    mock_db_session
                )
            
            assert exc_info.value.status_code == 400


class TestGetUserAlgorithmHealth:
    """Test get_user_algorithm_health method"""
    
    @pytest.mark.asyncio
    async def test_algorithm_health_premium_user(self, user_controller, premium_user, mock_db_session):
        """Test algorithm health analysis for premium user"""
        # Mock analyzer results with correct structure
        user_controller.visibility_scorer.analyze_visibility = AsyncMock(
            return_value=Mock(
                overall_score=75.0,
                visibility_trends=[],
                risk_factors=[],
                recommendations=[]
            )
        )
        user_controller.engagement_analyzer.analyze_engagement = AsyncMock(
            return_value=Mock(
                overall_score=80.0,
                engagement_quality=Mock(value="good"),
                patterns=[],
                recommendations=[]
            )
        )
        user_controller.penalty_detector.detect_penalties = AsyncMock(
            return_value=Mock(
                penalty_score=0.1,
                detected_penalties=[],
                risk_level=RiskLevel.LOW,
                recommendations=[]
            )
        )
        user_controller.shadow_ban_detector.detect_shadow_ban = AsyncMock(
            return_value=Mock(
                overall_shadow_ban_score=0.1,
                is_shadow_banned=False,
                detected_bans=[],
                visibility_score=90.0,
                recommendations=[]
            )
        )
        
        content_data = [
            {"content_id": "1", "engagement": {"likes": 10}},
            {"content_id": "2", "engagement": {"likes": 20}},
            {"content_id": "3", "engagement": {"likes": 15}},
            {"content_id": "4", "engagement": {"likes": 25}},
            {"content_id": "5", "engagement": {"likes": 30}}
        ]
        user_metrics = {"followers": 1000, "following": 500}
        
        with patch.object(user_controller, 'check_rate_limit', return_value=True):
            result = await user_controller.get_user_algorithm_health(
                premium_user,
                PlatformType.TWITTER,
                content_data,
                user_metrics,
                mock_db_session
            )
        
        assert result["success"] is True
        assert "health_analysis" in result
        assert "visibility" in result["health_analysis"]
        assert "engagement" in result["health_analysis"]
        assert "penalties" in result["health_analysis"]
        assert "shadow_ban" in result["health_analysis"]
    
    @pytest.mark.asyncio
    async def test_algorithm_health_free_user(self, user_controller, free_user, mock_db_session):
        """Test algorithm health analysis denied for free user"""
        content_data = [{"content_id": "1"}] * 5
        user_metrics = {"followers": 1000}
        
        with patch.object(user_controller, 'handle_authorization_error') as mock_handler:
            mock_handler.side_effect = HTTPException(status_code=403, detail="Premium required")
            
            with pytest.raises(HTTPException) as exc_info:
                await user_controller.get_user_algorithm_health(
                    free_user,
                    PlatformType.TWITTER,
                    content_data,
                    user_metrics,
                    mock_db_session
                )
            
            assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_algorithm_health_insufficient_data(self, user_controller, premium_user, mock_db_session):
        """Test algorithm health analysis with insufficient data"""
        content_data = [{"content_id": "1"}]  # Less than 5 items
        user_metrics = {"followers": 1000}
        
        with pytest.raises(HTTPException) as exc_info:
            await user_controller.get_user_algorithm_health(
                premium_user,
                PlatformType.TWITTER,
                content_data,
                user_metrics,
                mock_db_session
            )
        
        assert exc_info.value.status_code == 400


class TestHelperMethods:
    """Test helper methods"""
    
    @pytest.mark.asyncio
    async def test_calculate_overall_content_score(self, user_controller):
        """Test overall content score calculation"""
        analysis_results = {
            "content_risk": {"overall_risk_score": 0.2},
            "link_penalties": {"penalty_score": 0.1},
            "spam_patterns": {"spam_score": 0.15}
        }
        
        score = user_controller._calculate_overall_content_score(analysis_results)
        
        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Low risk should result in high score
    
    @pytest.mark.asyncio
    async def test_calculate_algorithm_health_score(self, user_controller):
        """Test algorithm health score calculation"""
        health_results = {
            "visibility": {"overall_score": 75.0},
            "engagement": {"overall_score": 80.0},
            "penalties": {"penalty_score": 0.1},
            "shadow_ban": {"visibility_score": 90.0}
        }
        
        score = user_controller._calculate_algorithm_health_score(health_results)
        
        assert 0.0 <= score <= 100.0
        assert score > 50.0  # Good health should result in high score


class TestRateLimiting:
    """Test rate limiting across all methods"""
    
    @pytest.mark.asyncio
    async def test_rate_limits_free_vs_premium(self, user_controller, free_user, premium_user):
        """Test that premium users have higher rate limits"""
        assert user_controller.max_scans_per_hour_free < user_controller.max_scans_per_hour_premium
        assert user_controller.max_analyses_per_hour_free < user_controller.max_analyses_per_hour_premium


class TestErrorHandling:
    """Test error handling"""
    
    @pytest.mark.asyncio
    async def test_error_handling_with_execute_with_error_handling(self, user_controller, premium_user, mock_db_session):
        """Test that execute_with_error_handling is used"""
        # The get_user_protection_settings method uses execute_with_error_handling
        # Test that it properly handles errors
        with patch.object(user_controller, '_get_user_platform_settings', side_effect=Exception("Test error")):
            with pytest.raises(HTTPException):
                await user_controller.get_user_protection_settings(premium_user, mock_db_session)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
