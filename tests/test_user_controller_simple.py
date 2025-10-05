"""
Simplified unit tests for UserController

Tests core functionality without complex imports.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from uuid import uuid4
from fastapi import HTTPException


class TestUserControllerBasics:
    """Test basic UserController functionality"""
    
    def test_rate_limit_configuration(self):
        """Test that rate limits are properly configured"""
        # Import here to avoid circular import issues
        import sys
        sys.modules['src.controllers.user_controller'] = Mock()
        
        from linkshield.social_protection.controllers.user_controller import UserController
        
        # Create mock services
        mock_services = {
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
        
        controller = UserController(**mock_services)
        
        # Verify rate limits are configured
        assert hasattr(controller, 'max_scans_per_hour_free')
        assert hasattr(controller, 'max_scans_per_hour_premium')
        assert hasattr(controller, 'max_analyses_per_hour_free')
        assert hasattr(controller, 'max_analyses_per_hour_premium')
        
        # Verify premium has higher limits
        assert controller.max_scans_per_hour_premium > controller.max_scans_per_hour_free
        assert controller.max_analyses_per_hour_premium > controller.max_analyses_per_hour_free
    
    def test_all_analyzers_injected(self):
        """Test that all required analyzers are injected"""
        import sys
        sys.modules['src.controllers.user_controller'] = Mock()
        
        from linkshield.social_protection.controllers.user_controller import UserController
        
        mock_services = {
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
        
        controller = UserController(**mock_services)
        
        # Verify all analyzers are present
        assert hasattr(controller, 'content_risk_analyzer')
        assert hasattr(controller, 'link_penalty_detector')
        assert hasattr(controller, 'spam_pattern_detector')
        assert hasattr(controller, 'community_notes_analyzer')
        assert hasattr(controller, 'visibility_scorer')
        assert hasattr(controller, 'engagement_analyzer')
        assert hasattr(controller, 'penalty_detector')
        assert hasattr(controller, 'shadow_ban_detector')
        assert hasattr(controller, 'social_scan_service')
    
    @pytest.mark.asyncio
    async def test_get_settings_returns_dict(self):
        """Test that get_user_protection_settings returns a dictionary"""
        import sys
        sys.modules['src.controllers.user_controller'] = Mock()
        
        from linkshield.social_protection.controllers.user_controller import UserController
        
        mock_services = {
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
        
        controller = UserController(**mock_services)
        
        # Create mock user
        user = Mock()
        user.id = uuid4()
        user.subscription_plan = "free"
        
        # Create mock db session
        db = AsyncMock()
        
        # Call method
        result = await controller.get_user_protection_settings(user, db)
        
        # Verify result structure
        assert isinstance(result, dict)
        assert "user_id" in result
        assert "protection_level" in result
        assert "rate_limits" in result
        assert "scan_preferences" in result
        assert "notification_preferences" in result


class TestUserControllerErrorHandling:
    """Test error handling in UserController"""
    
    @pytest.mark.asyncio
    async def test_invalid_settings_update_raises_400(self):
        """Test that invalid settings update raises 400 error"""
        import sys
        sys.modules['src.controllers.user_controller'] = Mock()
        
        from linkshield.social_protection.controllers.user_controller import UserController
        
        mock_services = {
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
        
        controller = UserController(**mock_services)
        
        user = Mock()
        user.id = uuid4()
        user.subscription_plan = "free"
        
        db = AsyncMock()
        
        # Try to update with invalid keys
        invalid_settings = {"invalid_key": "value"}
        
        with pytest.raises(HTTPException) as exc_info:
            await controller.update_user_protection_settings(user, invalid_settings, db)
        
        assert exc_info.value.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
