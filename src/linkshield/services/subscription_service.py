#!/usr/bin/env python3
"""
LinkShield Backend Subscription Service

Service layer for subscription management, including:
- Subscription creation, upgrade, and cancellation
- Usage tracking and limit enforcement
- Plan validation and billing integration
"""

import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Dict, Any, Optional, List, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import selectinload

from linkshield.models.subscription import (
    UserSubscription,
    SubscriptionPlan as SubscriptionPlanModel,
    SubscriptionStatus,
    BillingInterval,
    UsageRecord,
    UsageType
)
from linkshield.models.user import User

from linkshield.config.settings import get_settings
from linkshield.services.paddle_client import PaddleClientService
from linkshield.exceptions.subscription_exceptions import (
    SubscriptionError,
    PaymentProcessingError,
    PlanNotFoundError,
    SubscriptionNotFoundError,
    PaddleIntegrationError,
    SubscriptionAlreadyExistsError
)
import logging
logger = logging.getLogger(__name__)

# Subscription plans configuration
# Bot-specific subscription plans configuration with enhanced limits
SUBSCRIPTION_PLANS = {
    "free": {
        "display_name": "Free Plan",
        "description": "Basic link checking for personal use",
        "monthly_price": Decimal("0.00"),
        "yearly_price": Decimal("0.00"),
        "daily_check_limit": 10,
        "monthly_check_limit": 100,
        "api_rate_limit": 10,  # requests per hour
        "max_projects": 1,
        "max_team_members_per_project": 1,
        "max_alerts_per_project": 3,
        "monitoring_frequency_minutes": 60,
        "scan_depth_limit": 2,
        "max_links_per_scan": 10,
        "ai_analysis_enabled": False,
        "bulk_checking_enabled": False,
        "api_access_enabled": False,  # No bot access for free users
        "priority_support": False,
        "custom_branding": False,
        "trial_days": 0,
        # Bot-specific limits
        "bot_access_enabled": False,
        "bot_monthly_requests": 0,
        "bot_platforms_allowed": 0,
        "bot_analysis_types": [],
        "bot_features": [],
        "bot_concurrent_requests": 0,
        "bot_priority": "none"
    },
    "basic": {
        "display_name": "Basic Plan",
        "description": "Enhanced features for small teams",
        "monthly_price": Decimal("9.99"),
        "yearly_price": Decimal("99.99"),
        "daily_check_limit": 100,
        "monthly_check_limit": 1000,
        "api_rate_limit": 50,
        "max_projects": 3,
        "max_team_members_per_project": 5,
        "max_alerts_per_project": 10,
        "monitoring_frequency_minutes": 30,
        "scan_depth_limit": 5,
        "max_links_per_scan": 50,
        "ai_analysis_enabled": True,
        "bulk_checking_enabled": True,
        "api_access_enabled": True,
        "priority_support": False,
        "custom_branding": False,
        "trial_days": 14,
        # Bot-specific limits
        "bot_access_enabled": True,
        "bot_monthly_requests": 100,
        "bot_platforms_allowed": 1,
        "bot_analysis_types": ["account_safety"],
        "bot_features": ["basic_analysis"],
        "bot_concurrent_requests": 1,
        "bot_priority": "low"
    },
    "pro": {
        "display_name": "Pro Plan",
        "description": "Advanced features for growing businesses",
        "monthly_price": Decimal("29.99"),
        "yearly_price": Decimal("299.99"),
        "daily_check_limit": 500,
        "monthly_check_limit": 5000,
        "api_rate_limit": 200,
        "max_projects": 10,
        "max_team_members_per_project": 15,
        "max_alerts_per_project": 25,
        "monitoring_frequency_minutes": 15,
        "scan_depth_limit": 10,
        "max_links_per_scan": 200,
        "ai_analysis_enabled": True,
        "bulk_checking_enabled": True,
        "api_access_enabled": True,
        "priority_support": True,
        "custom_branding": True,
        "trial_days": 14,
        # Bot-specific limits
        "bot_access_enabled": True,
        "bot_monthly_requests": 500,
        "bot_platforms_allowed": 3,
        "bot_analysis_types": ["account_safety", "content_compliance", "verified_followers"],
        "bot_features": ["basic_analysis", "detailed_reports", "export_data"],
        "bot_concurrent_requests": 3,
        "bot_priority": "normal"
    },
    "enterprise": {
        "display_name": "Enterprise Plan",
        "description": "Full-featured solution for large organizations",
        "monthly_price": Decimal("99.99"),
        "yearly_price": Decimal("999.99"),
        "daily_check_limit": -1,  # unlimited
        "monthly_check_limit": -1,  # unlimited
        "api_rate_limit": 1000,
        "max_projects": -1,  # unlimited
        "max_team_members_per_project": -1,  # unlimited
        "max_alerts_per_project": -1,  # unlimited
        "monitoring_frequency_minutes": 5,
        "scan_depth_limit": -1,  # unlimited
        "max_links_per_scan": -1,  # unlimited
        "ai_analysis_enabled": True,
        "bulk_checking_enabled": True,
        "api_access_enabled": True,
        "priority_support": True,
        "custom_branding": True,
        "trial_days": 30,
        # Bot-specific limits
        "bot_access_enabled": True,
        "bot_monthly_requests": 5000,
        "bot_platforms_allowed": 10,
        "bot_analysis_types": ["account_safety", "content_compliance", "verified_followers", "advanced_analytics"],
        "bot_features": ["basic_analysis", "detailed_reports", "export_data", "api_access", "custom_alerts"],
        "bot_concurrent_requests": 10,
        "bot_priority": "high"
    }
}


class SubscriptionService:
    """
    Service for managing user subscriptions, usage tracking, and plan enforcement.
    """

    def __init__(self, db_session: AsyncSession):
        """
        Initialize subscription service with database session and Paddle client.
        
        Args:
            db_session: Async database session for database operations
        """
        self.db = db_session
        self.settings = get_settings()
        self.paddle_client = PaddleClientService()

    async def create_subscription(
        self,
        user_id: uuid.UUID,
        plan_name: str,
        billing_interval: BillingInterval,
        trial_days: Optional[int] = None,
        customer_email: Optional[str] = None,
        customer_name: Optional[str] = None
    ) -> UserSubscription:
        """
        Create a new subscription for a user with Paddle integration.
        
        Args:
            user_id: ID of the user to create subscription for
            plan_name: Name of the subscription plan
            billing_interval: Billing interval (monthly/yearly)
            trial_days: Optional trial period in days
            customer_email: Customer email for Paddle (required for paid plans)
            customer_name: Customer name for Paddle
            
        Returns:
            UserSubscription: The created subscription
            
        Raises:
            ValueError: If plan name is invalid or user already has active subscription
            PaymentProcessingError: If Paddle subscription creation fails
        """
        # Validate plan name
        if plan_name not in SUBSCRIPTION_PLANS:
            raise ValueError(f"Invalid plan name: {plan_name}")
        
        # Check if user already has active subscription
        existing_sub = await self._get_active_subscription(user_id)
        if existing_sub:
            raise ValueError("User already has an active subscription")
        
        # Get plan configuration
        plan_config = SUBSCRIPTION_PLANS[plan_name]
        
        # Calculate trial period if applicable
        now = datetime.now(timezone.utc)
        trial_start = None
        trial_end = None
        is_trial = False
        
        if trial_days is None:
            trial_days = plan_config.get("trial_days", 0)
        
        if trial_days > 0:
            trial_start = now
            trial_end = now + timedelta(days=trial_days)
            is_trial = True
        
        # Calculate billing period
        period_start = now
        if billing_interval == BillingInterval.MONTHLY:
            period_end = now + timedelta(days=30)
        elif billing_interval == BillingInterval.YEARLY:
            period_end = now + timedelta(days=365)
        else:
            period_end = now + timedelta(days=30)  # Default to monthly
        
        paddle_subscription_id = None
        paddle_customer_id = None
        
        # For paid plans, create Paddle subscription
        if plan_name != "free":
            if not customer_email:
                raise ValueError("Customer email is required for paid plans")
            
            try:
                # Sync products to Paddle first to ensure they exist
                price_mapping = await self.paddle_client.sync_products_to_paddle()
                
                # Get the appropriate price ID based on plan and billing interval
                price_key = f"{plan_name}_{billing_interval.value.lower()}"
                price_id = price_mapping.get(price_key)
                
                if not price_id:
                    raise PaymentProcessingError(f"Price not found for plan {plan_name} and billing interval {billing_interval}")
                
                # Create or get customer in Paddle
                customer = await self.paddle_client.create_customer(
                    email=customer_email,
                    name=customer_name,
                    user_id=user_id
                )
                paddle_customer_id = customer.id
                
                # Create subscription in Paddle
                subscription = await self.paddle_client.create_subscription(
                    customer_id=paddle_customer_id,
                    price_id=price_id,
                    trial_days=trial_days
                )
                paddle_subscription_id = subscription.id
                
                logger.info(f"Created Paddle subscription {paddle_subscription_id} for user {user_id}")
                
            except Exception as e:
                logger.error(f"Failed to create Paddle subscription: {e}")
                raise PaymentProcessingError(f"Failed to create payment subscription: {str(e)}")
        
        # Create local subscription record
        subscription = UserSubscription(
            user_id=user_id,
            plan_id=await self._get_or_create_plan_id(plan_name, plan_config),
            status=SubscriptionStatus.ACTIVE if not is_trial else SubscriptionStatus.TRIAL,
            billing_interval=billing_interval,
            current_period_start=period_start,
            current_period_end=period_end,
            next_billing_date=period_end,
            trial_start=trial_start,
            trial_end=trial_end,
            is_trial=is_trial,
            daily_checks_used=0,
            monthly_checks_used=0,
            last_usage_reset=now,
            paddle_subscription_id=paddle_subscription_id,
            paddle_customer_id=paddle_customer_id
        )
        
        self.db.add(subscription)
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Created subscription for user {user_id}: {plan_name} plan")
        return subscription

    async def upgrade_subscription(
        self,
        subscription_id: uuid.UUID,
        new_plan_name: str,
        billing_interval: Optional[BillingInterval] = None
    ) -> UserSubscription:
        """
        Upgrade a user's subscription to a higher plan with Paddle integration.
        
        Args:
            subscription_id: ID of the subscription to upgrade
            new_plan_name: Name of the new subscription plan
            billing_interval: Optional new billing interval
            
        Returns:
            UserSubscription: The upgraded subscription
            
        Raises:
            ValueError: If new plan is invalid or not an upgrade
            PaymentProcessingError: If Paddle subscription update fails
        """
        # Validate new plan
        if new_plan_name not in SUBSCRIPTION_PLANS:
            raise ValueError(f"Invalid plan name: {new_plan_name}")
        
        # Get current subscription
        subscription = await self.db.get(UserSubscription, subscription_id)
        if not subscription:
            raise ValueError("Subscription not found")
        
        # Get current and new plan configurations
        current_plan_config = SUBSCRIPTION_PLANS.get(subscription.plan.name, {})
        new_plan_config = SUBSCRIPTION_PLANS[new_plan_name]
        
        # Validate upgrade (new plan should have higher limits)
        if (new_plan_config.get("monthly_check_limit", 0) < 
            current_plan_config.get("monthly_check_limit", 0)):
            raise ValueError("Cannot downgrade subscription through upgrade method")
        
        # Handle Paddle subscription update for paid plans
        if (subscription.paddle_subscription_id and 
            new_plan_name != "free" and 
            subscription.plan.name != "free"):
            
            try:
                # Sync products to Paddle first to ensure they exist
                price_mapping = await self.paddle_client.sync_products_to_paddle()
                
                # Get the appropriate price ID based on plan and billing interval
                new_billing_interval = billing_interval or subscription.billing_interval
                price_key = f"{new_plan_name}_{new_billing_interval.value.lower()}"
                price_id = price_mapping.get(price_key)
                
                if not price_id:
                    raise PaymentProcessingError(f"Price not found for plan {new_plan_name} and billing interval {new_billing_interval}")
                
                # Update subscription in Paddle
                # Note: Paddle subscription updates typically require creating a new subscription
                # and cancelling the old one, or using Paddle's update subscription API
                # For now, we'll log this and handle through webhooks
                logger.info(f"Paddle subscription update required for {subscription.paddle_subscription_id} "
                          f"from {subscription.plan.name} to {new_plan_name}")
                
                # In a real implementation, we would call Paddle's API to update the subscription
                # This might involve creating a new subscription and cancelling the old one
                
            except Exception as e:
                logger.error(f"Failed to update Paddle subscription: {e}")
                raise PaymentProcessingError(f"Failed to update payment subscription: {str(e)}")
        
        # Update local subscription record
        subscription.plan_id = await self._get_or_create_plan_id(new_plan_name, new_plan_config)
        if billing_interval:
            subscription.billing_interval = billing_interval
        
        # Update billing period if needed
        now = datetime.now(timezone.utc)
        if subscription.current_period_end < now:
            if subscription.billing_interval == BillingInterval.MONTHLY:
                subscription.current_period_end = now + timedelta(days=30)
            else:
                subscription.current_period_end = now + timedelta(days=365)
        
        subscription.next_billing_date = subscription.current_period_end
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Upgraded subscription {subscription_id} to {new_plan_name} plan")
        return subscription

    async def cancel_subscription(
        self,
        subscription_id: uuid.UUID,
        cancel_at_period_end: bool = True,
        reason: Optional[str] = None
    ) -> UserSubscription:
        """
        Cancel a user's subscription.
        
        Args:
            subscription_id: ID of the subscription to cancel
            cancel_at_period_end: Whether to cancel at period end or immediately
            reason: Optional cancellation reason
            
        Returns:
            UserSubscription: The cancelled subscription
            
        Raises:
            ValueError: If subscription not found
        """
        subscription = await self.db.get(UserSubscription, subscription_id)
        if not subscription:
            raise ValueError("Subscription not found")
        
        # Handle Paddle cancellation for paid plans
        if subscription.plan.name != "free" and subscription.paddle_subscription_id:
            try:
                # Cancel subscription in Paddle
                effective_from = "next_billing_period" if cancel_at_period_end else "immediately"
                await self.paddle_client.cancel_subscription(
                    subscription.paddle_subscription_id,
                    effective_from=effective_from
                )
                logger.info(f"Cancelled Paddle subscription {subscription.paddle_subscription_id}")
            except Exception as e:
                logger.error(f"Failed to cancel Paddle subscription: {e}")
                # Continue with local cancellation even if Paddle cancellation fails
        
        if cancel_at_period_end:
            subscription.cancel_at_period_end = True
            subscription.cancellation_reason = reason
            subscription.status = SubscriptionStatus.ACTIVE  # Keep active until period end
        else:
            subscription.status = SubscriptionStatus.CANCELLED
            subscription.cancelled_at = datetime.now(timezone.utc)
            subscription.cancellation_reason = reason
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Cancelled subscription {subscription_id}")
        return subscription

    async def check_usage_limits(
        self,
        user_id: uuid.UUID,
        usage_type: UsageType = UsageType.LINK_CHECK
    ) -> Dict[str, Any]:
        """
        Check if user has reached usage limits for their subscription.
        
        Args:
            user_id: ID of the user to check
            usage_type: Type of usage to check
            
        Returns:
            Dict containing usage information and limit status
        """
        subscription = await self._get_active_subscription(user_id)
        if not subscription:
            # Use free plan limits for users without subscription
            plan_config = SUBSCRIPTION_PLANS["free"]
            return {
                "has_subscription": False,
                "plan_name": "free",
                "daily_used": 0,
                "daily_limit": plan_config["daily_check_limit"],
                "monthly_used": 0,
                "monthly_limit": plan_config["monthly_check_limit"],
                "has_daily_limit": plan_config["daily_check_limit"] > 0,
                "has_monthly_limit": plan_config["monthly_check_limit"] > 0,
                "daily_remaining": plan_config["daily_check_limit"],
                "monthly_remaining": plan_config["monthly_check_limit"],
                "is_over_limit": False
            }
        
        # Reset daily usage if needed
        await self._reset_usage_if_needed(subscription)
        
        plan_config = SUBSCRIPTION_PLANS.get(subscription.plan.name, SUBSCRIPTION_PLANS["free"])
        
        daily_limit = plan_config["daily_check_limit"]
        monthly_limit = plan_config["monthly_check_limit"]
        
        # Check if limits are unlimited (-1)
        has_daily_limit = daily_limit != -1
        has_monthly_limit = monthly_limit != -1
        
        daily_remaining = daily_limit - subscription.daily_checks_used if has_daily_limit else float('inf')
        monthly_remaining = monthly_limit - subscription.monthly_checks_used if has_monthly_limit else float('inf')
        
        is_over_daily = has_daily_limit and subscription.daily_checks_used >= daily_limit
        is_over_monthly = has_monthly_limit and subscription.monthly_checks_used >= monthly_limit
        is_over_limit = is_over_daily or is_over_monthly
        
        return {
            "has_subscription": True,
            "plan_name": subscription.plan.name,
            "daily_used": subscription.daily_checks_used,
            "daily_limit": daily_limit,
            "monthly_used": subscription.monthly_checks_used,
            "monthly_limit": monthly_limit,
            "has_daily_limit": has_daily_limit,
            "has_monthly_limit": has_monthly_limit,
            "daily_remaining": daily_remaining,
            "monthly_remaining": monthly_remaining,
            "is_over_limit": is_over_limit
        }

    async def increment_usage(
        self,
        user_id: uuid.UUID,
        usage_type: UsageType = UsageType.LINK_CHECK,
        quantity: int = 1
    ) -> None:
        """
        Increment usage counters for a user's subscription.
        
        Args:
            user_id: ID of the user
            usage_type: Type of usage to increment
            quantity: Amount to increment by
        """
        subscription = await self._get_active_subscription(user_id)
        if not subscription:
            # No subscription, nothing to increment
            return
        
        # Reset usage if needed
        await self._reset_usage_if_needed(subscription)
        
        # Increment counters
        subscription.daily_checks_used += quantity
        subscription.monthly_checks_used += quantity
        
        # Create usage record
        usage_record = UsageRecord(
            subscription_id=subscription.id,
            usage_type=usage_type,
            quantity=quantity,
            usage_date=datetime.now(timezone.utc)
        )
        
        self.db.add(usage_record)
        await self.db.commit()
        
        logger.debug(f"Incremented usage for user {user_id}: {quantity} {usage_type.value}")

    async def create_usage_record(
        self,
        subscription_id: uuid.UUID,
        usage_type: UsageType,
        quantity: int = 1,
        usage_date: Optional[datetime] = None
    ) -> UsageRecord:
        """
        Create a detailed usage record for a subscription.
        
        Args:
            subscription_id: ID of the subscription
            usage_type: Type of usage
            quantity: Amount of usage
            usage_date: Optional specific date of usage
            
        Returns:
            UsageRecord: The created usage record
        """
        if usage_date is None:
            usage_date = datetime.now(timezone.utc)
        
        usage_record = UsageRecord(
            subscription_id=subscription_id,
            usage_type=usage_type,
            quantity=quantity,
            usage_date=usage_date
        )
        
        self.db.add(usage_record)
        await self.db.commit()
        await self.db.refresh(usage_record)
        
        return usage_record

    async def get_subscription_plans(self) -> List[Dict[str, Any]]:
        """
        Get all available subscription plans.
        
        Returns:
            List of plan configurations
        """
        plans = []
        for plan_name, plan_config in SUBSCRIPTION_PLANS.items():
            plan_data = {
                "name": plan_name,
                "display_name": plan_config["display_name"],
                "description": plan_config["description"],
                "monthly_price": float(plan_config["monthly_price"]),
                "yearly_price": float(plan_config["yearly_price"]),
                "currency": "USD",
                "daily_check_limit": plan_config["daily_check_limit"],
                "monthly_check_limit": plan_config["monthly_check_limit"],
                "api_rate_limit": plan_config["api_rate_limit"],
                "max_projects": plan_config["max_projects"],
                "max_team_members_per_project": plan_config["max_team_members_per_project"],
                "max_alerts_per_project": plan_config["max_alerts_per_project"],
                "monitoring_frequency_minutes": plan_config["monitoring_frequency_minutes"],
                "scan_depth_limit": plan_config["scan_depth_limit"],
                "max_links_per_scan": plan_config["max_links_per_scan"],
                "ai_analysis_enabled": plan_config["ai_analysis_enabled"],
                "bulk_checking_enabled": plan_config["bulk_checking_enabled"],
                "api_access_enabled": plan_config["api_access_enabled"],
                "priority_support": plan_config["priority_support"],
                "custom_branding": plan_config["custom_branding"],
                "trial_days": plan_config["trial_days"]
            }
            plans.append(plan_data)
        
        return plans

    async def _get_active_subscription(self, user_id: uuid.UUID) -> Optional[UserSubscription]:
        """
        Get active subscription for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            UserSubscription if found, None otherwise
        """
        stmt = select(UserSubscription).where(
            and_(
                UserSubscription.user_id == user_id,
                or_(
                    UserSubscription.status == SubscriptionStatus.ACTIVE,
                    UserSubscription.status == SubscriptionStatus.TRIAL
                )
            )
        ).options(selectinload(UserSubscription.plan))
        
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def _reset_usage_if_needed(self, subscription: UserSubscription) -> None:
        """
        Reset daily usage counters if a new day has started.
        
        Args:
            subscription: The subscription to check
        """
        now = datetime.now(timezone.utc)
        
        # Check if we need to reset daily usage
        if subscription.last_usage_reset.date() < now.date():
            subscription.daily_checks_used = 0
            subscription.last_usage_reset = now
            
            # Check if we need to reset monthly usage (first day of month)
            if now.day == 1:
                subscription.monthly_checks_used = 0
            
            await self.db.commit()

    async def _get_or_create_plan_id(self, plan_name: str, plan_config: Dict[str, Any]) -> uuid.UUID:
        """
        Get or create a subscription plan in the database.
        
        Args:
            plan_name: Name of the plan
            plan_config: Plan configuration
            
        Returns:
            UUID of the plan
        """
        # Try to find existing plan
        stmt = select(SubscriptionPlanModel).where(SubscriptionPlanModel.name == plan_name)
        result = await self.db.execute(stmt)
        existing_plan = result.scalar_one_or_none()
        
        if existing_plan:
            return existing_plan.id
        
        # Create new plan
        new_plan = SubscriptionPlanModel(
            name=plan_name,
            display_name=plan_config["display_name"],
            description=plan_config["description"],
            plan_type=plan_name.upper(),
            monthly_price=plan_config["monthly_price"],
            yearly_price=plan_config["yearly_price"],
            currency="USD",
            daily_check_limit=plan_config["daily_check_limit"],
            monthly_check_limit=plan_config["monthly_check_limit"],
            api_rate_limit=plan_config["api_rate_limit"],
            max_projects=plan_config["max_projects"],
            max_team_members_per_project=plan_config["max_team_members_per_project"],
            max_alerts_per_project=plan_config["max_alerts_per_project"],
            monitoring_frequency_minutes=plan_config["monitoring_frequency_minutes"],
            scan_depth_limit=plan_config["scan_depth_limit"],
            max_links_per_scan=plan_config["max_links_per_scan"],
            ai_analysis_enabled=plan_config["ai_analysis_enabled"],
            bulk_checking_enabled=plan_config["bulk_checking_enabled"],
            api_access_enabled=plan_config["api_access_enabled"],
            priority_support=plan_config["priority_support"],
            custom_branding=plan_config["custom_branding"],
            trial_days=plan_config["trial_days"]
        )
        
        self.db.add(new_plan)
        await self.db.commit()
        await self.db.refresh(new_plan)
        
        return new_plan.id

    async def update_subscription_paddle_id(
        self,
        subscription_id: uuid.UUID,
        paddle_subscription_id: str,
        paddle_plan_id: str,
        status: str
    ) -> UserSubscription:
        """
        Update subscription with Paddle subscription ID and plan ID.
        
        Args:
            subscription_id: Local subscription ID
            paddle_subscription_id: Paddle subscription ID
            paddle_plan_id: Paddle plan ID
            status: Subscription status from Paddle
            
        Returns:
            Updated UserSubscription
            
        Raises:
            ValueError: If subscription not found
        """
        stmt = select(UserSubscription).where(UserSubscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()
        
        if not subscription:
            raise ValueError(f"Subscription {subscription_id} not found")
        
        subscription.paddle_subscription_id = paddle_subscription_id
        subscription.paddle_plan_id = paddle_plan_id
        
        # Map Paddle status to our status
        status_mapping = {
            "active": SubscriptionStatus.ACTIVE,
            "trialing": SubscriptionStatus.TRIAL,
            "past_due": SubscriptionStatus.PAST_DUE,
            "paused": SubscriptionStatus.PAUSED,
            "canceled": SubscriptionStatus.CANCELLED
        }
        
        if status.lower() in status_mapping:
            subscription.status = status_mapping[status.lower()]
        
        subscription.updated_at = datetime.now(timezone.utc)
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Updated subscription {subscription_id} with Paddle ID {paddle_subscription_id}")
        
        return subscription

    async def update_subscription_from_webhook(
        self,
        subscription_id: uuid.UUID,
        paddle_plan_id: str,
        status: str,
        update_reason: str
    ) -> UserSubscription:
        """
        Update subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            paddle_plan_id: Paddle plan ID
            status: Subscription status from Paddle
            update_reason: Reason for the update
            
        Returns:
            Updated UserSubscription
            
        Raises:
            ValueError: If subscription not found
        """
        stmt = select(UserSubscription).where(UserSubscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()
        
        if not subscription:
            raise ValueError(f"Subscription {subscription_id} not found")
        
        subscription.paddle_plan_id = paddle_plan_id
        
        # Map Paddle status to our status
        status_mapping = {
            "active": SubscriptionStatus.ACTIVE,
            "trialing": SubscriptionStatus.TRIAL,
            "past_due": SubscriptionStatus.PAST_DUE,
            "paused": SubscriptionStatus.PAUSED,
            "canceled": SubscriptionStatus.CANCELLED
        }
        
        if status.lower() in status_mapping:
            subscription.status = status_mapping[status.lower()]
        
        subscription.updated_at = datetime.now(timezone.utc)
        subscription.update_reason = update_reason
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Updated subscription {subscription_id} from webhook: {update_reason}")
        
        return subscription

    async def cancel_subscription_from_webhook(
        self,
        subscription_id: uuid.UUID,
        cancel_at_period_end: bool,
        cancellation_reason: str
    ) -> UserSubscription:
        """
        Cancel subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            cancel_at_period_end: Whether to cancel at period end
            cancellation_reason: Reason for cancellation
            
        Returns:
            Cancelled UserSubscription
            
        Raises:
            ValueError: If subscription not found
        """
        stmt = select(UserSubscription).where(UserSubscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()
        
        if not subscription:
            raise ValueError(f"Subscription {subscription_id} not found")
        
        subscription.cancel_at_period_end = cancel_at_period_end
        subscription.cancellation_reason = cancellation_reason
        subscription.cancelled_at = datetime.now(timezone.utc)
        
        if not cancel_at_period_end:
            subscription.status = SubscriptionStatus.CANCELLED
        
        subscription.updated_at = datetime.now(timezone.utc)
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Cancelled subscription {subscription_id} from webhook: {cancellation_reason}")
        
        return subscription

    async def activate_subscription(
        self,
        subscription_id: uuid.UUID,
        activation_reason: str
    ) -> UserSubscription:
        """
        Activate subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            activation_reason: Reason for activation
            
        Returns:
            Activated UserSubscription
            
        Raises:
            ValueError: If subscription not found
        """
        stmt = select(UserSubscription).where(UserSubscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()
        
        if not subscription:
            raise ValueError(f"Subscription {subscription_id} not found")
        
        subscription.status = SubscriptionStatus.ACTIVE
        subscription.activated_at = datetime.now(timezone.utc)
        subscription.activation_reason = activation_reason
        subscription.updated_at = datetime.now(timezone.utc)
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Activated subscription {subscription_id}: {activation_reason}")
        
        return subscription

    async def pause_subscription(
        self,
        subscription_id: uuid.UUID,
        pause_reason: str
    ) -> UserSubscription:
        """
        Pause subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            pause_reason: Reason for pausing
            
        Returns:
            Paused UserSubscription
            
        Raises:
            ValueError: If subscription not found
        """
        stmt = select(UserSubscription).where(UserSubscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()
        
        if not subscription:
            raise ValueError(f"Subscription {subscription_id} not found")
        
        subscription.status = SubscriptionStatus.PAUSED
        subscription.paused_at = datetime.now(timezone.utc)
        subscription.pause_reason = pause_reason
        subscription.updated_at = datetime.now(timezone.utc)
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Paused subscription {subscription_id}: {pause_reason}")
        
        return subscription

    async def resume_subscription(
        self,
        subscription_id: uuid.UUID,
        resume_reason: str
    ) -> UserSubscription:
        """
        Resume subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            resume_reason: Reason for resuming
            
        Returns:
            Resumed UserSubscription
            
        Raises:
            ValueError: If subscription not found
        """
        stmt = select(UserSubscription).where(UserSubscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()
        
        if not subscription:
            raise ValueError(f"Subscription {subscription_id} not found")
        
        subscription.status = SubscriptionStatus.ACTIVE
        subscription.resumed_at = datetime.now(timezone.utc)
        subscription.resume_reason = resume_reason
        subscription.updated_at = datetime.now(timezone.utc)
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        logger.info(f"Resumed subscription {subscription_id}: {resume_reason}")
        
        return subscription

    async def record_payment(
        self,
        subscription_id: uuid.UUID,
        transaction_id: str,
        amount: float,
        currency: str,
        status: str,
        payment_method: str,
        failure_reason: Optional[str] = None,
        refund_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record payment from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            transaction_id: Payment transaction ID
            amount: Payment amount
            currency: Payment currency
            status: Payment status
            payment_method: Payment method
            failure_reason: Reason for payment failure (optional)
            refund_reason: Reason for refund (optional)
            
        Returns:
            Dict containing payment record details
            
        Raises:
            ValueError: If subscription not found
        """
        stmt = select(UserSubscription).where(UserSubscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()
        
        if not subscription:
            raise ValueError(f"Subscription {subscription_id} not found")
        
        # For now, we'll just log the payment and update subscription status
        # In a full implementation, you'd create a PaymentRecord model
        
        logger.info(
            f"Payment recorded for subscription {subscription_id}: "
            f"transaction_id={transaction_id}, amount={amount} {currency}, "
            f"status={status}, method={payment_method}"
        )
        
        # Update subscription based on payment status
        if status.lower() == "completed":
            subscription.status = SubscriptionStatus.ACTIVE
            subscription.last_payment_at = datetime.now(timezone.utc)
        elif status.lower() == "failed":
            subscription.status = SubscriptionStatus.PAST_DUE
            subscription.payment_failure_reason = failure_reason
        elif status.lower() == "refunded":
            subscription.status = SubscriptionStatus.CANCELLED
            subscription.refund_reason = refund_reason
        
        subscription.updated_at = datetime.now(timezone.utc)
        
        await self.db.commit()
        await self.db.refresh(subscription)
        
        return {
            "subscription_id": str(subscription_id),
            "transaction_id": transaction_id,
            "amount": amount,
            "currency": currency,
            "status": status,
            "payment_method": payment_method,
            "failure_reason": failure_reason,
            "refund_reason": refund_reason,
            "recorded_at": datetime.now(timezone.utc).isoformat()
        }