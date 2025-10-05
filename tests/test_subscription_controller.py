#!/usr/bin/env python3
"""
Unit tests for SubscriptionController class.

Tests the API controller layer for subscription management including:
- Subscription creation, retrieval, and updates
- Usage checking and plan listing
- Error handling and response formatting
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import uuid

from linkshield.controllers.subscription_controller import SubscriptionController
from linkshield.services.subscription_service import SubscriptionService
from linkshield.models.subscription import UserSubscription
from linkshield.models.user import User


class TestSubscriptionController:
    """Test suite for SubscriptionController functionality."""

    @pytest.fixture
    def mock_subscription_service(self):
        """Create a mock SubscriptionService."""
        return Mock(spec=SubscriptionService)

    @pytest.fixture
    def subscription_controller(self, mock_subscription_service):
        """Create SubscriptionController instance with mock service."""
        return SubscriptionController(mock_subscription_service)

    @pytest.fixture
    def test_user(self):
        """Create a test user."""
        user = User(
            id=uuid.uuid4(),
            email="test@example.com",
            username="testuser",
            is_active=True,
            is_verified=True
        )
        return user

    @pytest.fixture
    def test_subscription(self, test_user):
        """Create a test subscription."""
        subscription = UserSubscription(
            id=uuid.uuid4(),
            user_id=test_user.id,
            plan_name="pro",
            status="active",
            billing_interval="monthly",
            current_period_start=datetime.utcnow(),
            current_period_end=datetime.utcnow() + timedelta(days=30),
            daily_checks_used=0,
            monthly_checks_used=0,
            last_usage_reset=datetime.utcnow(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        return subscription

    async def test_create_subscription_success(self, subscription_controller, mock_subscription_service, test_user):
        """Test creating a subscription successfully."""
        # Mock the service method
        mock_subscription_service.create_subscription.return_value = test_subscription
        
        # Call the controller method
        result = await subscription_controller.create_subscription(
            user_id=test_user.id,
            plan_name="pro",
            billing_interval="monthly",
            trial_days=14
        )
        
        # Verify the service was called correctly
        mock_subscription_service.create_subscription.assert_called_once_with(
            user_id=test_user.id,
            plan_name="pro",
            billing_interval="monthly",
            trial_days=14
        )
        
        # Verify the result
        assert result == test_subscription

    async def test_create_subscription_error(self, subscription_controller, mock_subscription_service, test_user):
        """Test creating a subscription with error."""
        # Mock the service method to raise an error
        mock_subscription_service.create_subscription.side_effect = ValueError("Plan not found")
        
        # Verify the error is propagated
        with pytest.raises(ValueError, match="Plan not found"):
            await subscription_controller.create_subscription(
                user_id=test_user.id,
                plan_name="invalid",
                billing_interval="monthly"
            )

    async def test_get_subscription_success(self, subscription_controller, mock_subscription_service, test_user, test_subscription):
        """Test getting a subscription successfully."""
        # Mock the service method
        mock_subscription_service.get_subscription.return_value = test_subscription
        
        # Call the controller method
        result = await subscription_controller.get_subscription(test_user.id)
        
        # Verify the service was called correctly
        mock_subscription_service.get_subscription.assert_called_once_with(test_user.id)
        
        # Verify the result
        assert result == test_subscription

    async def test_get_subscription_not_found(self, subscription_controller, mock_subscription_service, test_user):
        """Test getting a non-existent subscription."""
        # Mock the service method to raise an error
        mock_subscription_service.get_subscription.side_effect = ValueError("Subscription not found")
        
        # Verify the error is propagated
        with pytest.raises(ValueError, match="Subscription not found"):
            await subscription_controller.get_subscription(test_user.id)

    async def test_update_subscription_success(self, subscription_controller, mock_subscription_service, test_user, test_subscription):
        """Test updating a subscription successfully."""
        # Mock the service method
        mock_subscription_service.update_subscription.return_value = test_subscription
        
        # Call the controller method
        result = await subscription_controller.update_subscription(
            user_id=test_user.id,
            new_plan_name="enterprise",
            billing_interval="yearly"
        )
        
        # Verify the service was called correctly
        mock_subscription_service.update_subscription.assert_called_once_with(
            user_id=test_user.id,
            new_plan_name="enterprise",
            billing_interval="yearly"
        )
        
        # Verify the result
        assert result == test_subscription

    async def test_update_subscription_error(self, subscription_controller, mock_subscription_service, test_user):
        """Test updating a subscription with error."""
        # Mock the service method to raise an error
        mock_subscription_service.update_subscription.side_effect = ValueError("Invalid plan")
        
        # Verify the error is propagated
        with pytest.raises(ValueError, match="Invalid plan"):
            await subscription_controller.update_subscription(
                user_id=test_user.id,
                new_plan_name="invalid",
                billing_interval="monthly"
            )

    async def test_cancel_subscription_success(self, subscription_controller, mock_subscription_service, test_user, test_subscription):
        """Test cancelling a subscription successfully."""
        # Mock the service method
        mock_subscription_service.cancel_subscription.return_value = test_subscription
        
        # Call the controller method
        result = await subscription_controller.cancel_subscription(
            user_id=test_user.id,
            cancel_at_period_end=True,
            reason="Test cancellation"
        )
        
        # Verify the service was called correctly
        mock_subscription_service.cancel_subscription.assert_called_once_with(
            user_id=test_user.id,
            cancel_at_period_end=True,
            reason="Test cancellation"
        )
        
        # Verify the result
        assert result == test_subscription

    async def test_cancel_subscription_error(self, subscription_controller, mock_subscription_service, test_user):
        """Test cancelling a subscription with error."""
        # Mock the service method to raise an error
        mock_subscription_service.cancel_subscription.side_effect = ValueError("Subscription not found")
        
        # Verify the error is propagated
        with pytest.raises(ValueError, match="Subscription not found"):
            await subscription_controller.cancel_subscription(
                user_id=test_user.id,
                cancel_at_period_end=True,
                reason="Test cancellation"
            )

    async def test_get_subscription_usage_success(self, subscription_controller, mock_subscription_service, test_user):
        """Test getting subscription usage successfully."""
        # Mock the service method
        mock_usage_data = {
            "has_subscription": True,
            "plan_name": "pro",
            "daily_used": 50,
            "daily_limit": 1000,
            "monthly_used": 500,
            "monthly_limit": 10000,
            "has_daily_limit": True,
            "has_monthly_limit": True,
            "daily_remaining": 950,
            "monthly_remaining": 9500,
            "is_over_limit": False
        }
        mock_subscription_service.get_subscription_usage.return_value = mock_usage_data
        
        # Call the controller method
        result = await subscription_controller.get_subscription_usage(test_user.id)
        
        # Verify the service was called correctly
        mock_subscription_service.get_subscription_usage.assert_called_once_with(test_user.id)
        
        # Verify the result
        assert result == mock_usage_data

    async def test_get_subscription_usage_no_subscription(self, subscription_controller, mock_subscription_service, test_user):
        """Test getting subscription usage when no subscription exists."""
        # Mock the service method to return free plan usage
        mock_usage_data = {
            "has_subscription": False,
            "plan_name": "free",
            "daily_used": 0,
            "daily_limit": 100,
            "monthly_used": 0,
            "monthly_limit": 1000,
            "has_daily_limit": True,
            "has_monthly_limit": True,
            "daily_remaining": 100,
            "monthly_remaining": 1000,
            "is_over_limit": False
        }
        mock_subscription_service.get_subscription_usage.return_value = mock_usage_data
        
        # Call the controller method
        result = await subscription_controller.get_subscription_usage(test_user.id)
        
        # Verify the service was called correctly
        mock_subscription_service.get_subscription_usage.assert_called_once_with(test_user.id)
        
        # Verify the result
        assert result == mock_usage_data

    async def test_get_available_plans_success(self, subscription_controller, mock_subscription_service):
        """Test getting available subscription plans successfully."""
        # Mock the service method
        mock_plans = [
            {"name": "free", "display_name": "Free", "monthly_price": 0.0},
            {"name": "basic", "display_name": "Basic", "monthly_price": 9.99},
            {"name": "pro", "display_name": "Pro", "monthly_price": 29.99},
            {"name": "enterprise", "display_name": "Enterprise", "monthly_price": 99.99}
        ]
        mock_subscription_service.get_available_plans.return_value = mock_plans
        
        # Call the controller method
        result = await subscription_controller.get_available_plans()
        
        # Verify the service was called correctly
        mock_subscription_service.get_available_plans.assert_called_once()
        
        # Verify the result
        assert result == mock_plans

    async def test_reset_usage_success(self, subscription_controller, mock_subscription_service, test_subscription):
        """Test resetting subscription usage successfully."""
        # Mock the service method
        mock_subscription_service.reset_usage.return_value = test_subscription
        
        # Call the controller method
        result = await subscription_controller.reset_usage(test_subscription.id)
        
        # Verify the service was called correctly
        mock_subscription_service.reset_usage.assert_called_once_with(test_subscription.id)
        
        # Verify the result
        assert result == test_subscription

    async def test_reset_usage_error(self, subscription_controller, mock_subscription_service):
        """Test resetting subscription usage with error."""
        # Mock the service method to raise an error
        mock_subscription_service.reset_usage.side_effect = ValueError("Subscription not found")
        
        # Verify the error is propagated
        with pytest.raises(ValueError, match="Subscription not found"):
            await subscription_controller.reset_usage(uuid.uuid4())

    async def test_increment_usage_success(self, subscription_controller, mock_subscription_service, test_user):
        """Test incrementing subscription usage successfully."""
        # Mock the service method
        mock_subscription_service.increment_usage.return_value = True
        
        # Call the controller method
        result = await subscription_controller.increment_usage(test_user.id, 5)
        
        # Verify the service was called correctly
        mock_subscription_service.increment_usage.assert_called_once_with(test_user.id, 5)
        
        # Verify the result
        assert result is True

    async def test_increment_usage_over_limit(self, subscription_controller, mock_subscription_service, test_user):
        """Test incrementing subscription usage when over limit."""
        # Mock the service method
        mock_subscription_service.increment_usage.return_value = False
        
        # Call the controller method
        result = await subscription_controller.increment_usage(test_user.id, 5)
        
        # Verify the service was called correctly
        mock_subscription_service.increment_usage.assert_called_once_with(test_user.id, 5)
        
        # Verify the result
        assert result is False

    async def test_increment_usage_error(self, subscription_controller, mock_subscription_service, test_user):
        """Test incrementing subscription usage with error."""
        # Mock the service method to raise an error
        mock_subscription_service.increment_usage.side_effect = ValueError("Subscription not found")
        
        # Verify the error is propagated
        with pytest.raises(ValueError, match="Subscription not found"):
            await subscription_controller.increment_usage(test_user.id, 5)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])