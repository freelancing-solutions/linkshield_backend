#!/usr/bin/env python3
"""
LinkShield Backend Subscription Controller

API controller for subscription management endpoints.
Handles HTTP requests for subscription operations.
"""

import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.controllers.base_controller import BaseController
from src.services.subscription_service import SubscriptionService
from src.models.subscription import BillingInterval, UsageType
from src.config.database import get_db
from src.config.security import get_current_user
from src.models.user import User
from src.config.logging import logger


class SubscriptionController(BaseController):
    """
    Controller for handling subscription-related API requests.
    """

    def __init__(self, subscription_service: SubscriptionService):
        """
        Initialize subscription controller.
        
        Args:
            subscription_service: Subscription service instance
        """
        self.subscription_service = subscription_service

    async def create_subscription(
        self,
        user: User,
        plan_name: str,
        billing_interval: BillingInterval,
        trial_days: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Create a new subscription for the authenticated user.
        
        Args:
            user: Authenticated user
            plan_name: Name of the subscription plan
            billing_interval: Billing interval (monthly/yearly)
            trial_days: Optional trial period in days
            
        Returns:
            Dict containing subscription details
            
        Raises:
            HTTPException: If subscription creation fails
        """
        try:
            subscription = await self.subscription_service.create_subscription(
                user_id=user.id,
                plan_name=plan_name,
                billing_interval=billing_interval,
                trial_days=trial_days
            )
            
            return {
                "id": str(subscription.id),
                "user_id": str(subscription.user_id),
                "plan_name": subscription.plan.name,
                "status": subscription.status.value,
                "billing_interval": subscription.billing_interval.value,
                "current_period_start": subscription.current_period_start.isoformat(),
                "current_period_end": subscription.current_period_end.isoformat(),
                "is_trial": subscription.is_trial,
                "trial_end": subscription.trial_end.isoformat() if subscription.trial_end else None,
                "created_at": subscription.created_at.isoformat()
            }
            
        except ValueError as e:
            logger.warning(f"Subscription creation failed for user {user.id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error creating subscription for user {user.id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create subscription"
            )

    async def get_subscription(self, user: User) -> Dict[str, Any]:
        """
        Get the current user's active subscription.
        
        Args:
            user: Authenticated user
            
        Returns:
            Dict containing subscription details
            
        Raises:
            HTTPException: If subscription not found
        """
        try:
            subscription = await self.subscription_service._get_active_subscription(user.id)
            
            if not subscription:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No active subscription found"
                )
            
            return {
                "id": str(subscription.id),
                "user_id": str(subscription.user_id),
                "plan_name": subscription.plan.name,
                "status": subscription.status.value,
                "billing_interval": subscription.billing_interval.value,
                "current_period_start": subscription.current_period_start.isoformat(),
                "current_period_end": subscription.current_period_end.isoformat(),
                "next_billing_date": subscription.next_billing_date.isoformat() if subscription.next_billing_date else None,
                "is_trial": subscription.is_trial,
                "trial_start": subscription.trial_start.isoformat() if subscription.trial_start else None,
                "trial_end": subscription.trial_end.isoformat() if subscription.trial_end else None,
                "cancel_at_period_end": subscription.cancel_at_period_end,
                "cancelled_at": subscription.cancelled_at.isoformat() if subscription.cancelled_at else None,
                "daily_checks_used": subscription.daily_checks_used,
                "monthly_checks_used": subscription.monthly_checks_used,
                "last_usage_reset": subscription.last_usage_reset.isoformat(),
                "created_at": subscription.created_at.isoformat(),
                "updated_at": subscription.updated_at.isoformat(),
                "plan_details": subscription.plan.to_dict()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error getting subscription for user {user.id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve subscription"
            )

    async def update_subscription(
        self,
        user: User,
        subscription_id: uuid.UUID,
        new_plan_name: str,
        billing_interval: Optional[BillingInterval] = None
    ) -> Dict[str, Any]:
        """
        Update a user's subscription (upgrade/downgrade).
        
        Args:
            user: Authenticated user
            subscription_id: ID of the subscription to update
            new_plan_name: Name of the new subscription plan
            billing_interval: Optional new billing interval
            
        Returns:
            Dict containing updated subscription details
            
        Raises:
            HTTPException: If subscription update fails
        """
        try:
            # Verify user owns the subscription
            subscription = await self.subscription_service._get_active_subscription(user.id)
            if not subscription or subscription.id != subscription_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Subscription not found"
                )
            
            updated_subscription = await self.subscription_service.upgrade_subscription(
                subscription_id=subscription_id,
                new_plan_name=new_plan_name,
                billing_interval=billing_interval
            )
            
            return {
                "id": str(updated_subscription.id),
                "user_id": str(updated_subscription.user_id),
                "plan_name": updated_subscription.plan.name,
                "status": updated_subscription.status.value,
                "billing_interval": updated_subscription.billing_interval.value,
                "current_period_start": updated_subscription.current_period_start.isoformat(),
                "current_period_end": updated_subscription.current_period_end.isoformat(),
                "next_billing_date": updated_subscription.next_billing_date.isoformat() if updated_subscription.next_billing_date else None,
                "updated_at": updated_subscription.updated_at.isoformat()
            }
            
        except ValueError as e:
            logger.warning(f"Subscription update failed for user {user.id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error updating subscription {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update subscription"
            )

    async def update_subscription_paddle_id(
        self,
        subscription_id: uuid.UUID,
        paddle_subscription_id: str,
        paddle_plan_id: str,
        status: str
    ) -> Dict[str, Any]:
        """
        Update subscription with Paddle subscription ID and plan ID.
        
        Args:
            subscription_id: Local subscription ID
            paddle_subscription_id: Paddle subscription ID
            paddle_plan_id: Paddle plan ID
            status: Subscription status from Paddle
            
        Returns:
            Dict containing updated subscription details
            
        Raises:
            HTTPException: If subscription update fails
        """
        try:
            updated_subscription = await self.subscription_service.update_subscription_paddle_id(
                subscription_id=subscription_id,
                paddle_subscription_id=paddle_subscription_id,
                paddle_plan_id=paddle_plan_id,
                status=status
            )
            
            return {
                "id": str(updated_subscription.id),
                "paddle_subscription_id": updated_subscription.paddle_subscription_id,
                "paddle_plan_id": updated_subscription.paddle_plan_id,
                "status": updated_subscription.status.value,
                "updated_at": updated_subscription.updated_at.isoformat()
            }
            
        except ValueError as e:
            logger.warning(f"Subscription Paddle ID update failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error updating subscription Paddle ID {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update subscription Paddle ID"
            )

    async def update_subscription_from_webhook(
        self,
        subscription_id: uuid.UUID,
        paddle_plan_id: str,
        status: str,
        update_reason: str
    ) -> Dict[str, Any]:
        """
        Update subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            paddle_plan_id: Paddle plan ID
            status: Subscription status from Paddle
            update_reason: Reason for the update
            
        Returns:
            Dict containing updated subscription details
            
        Raises:
            HTTPException: If subscription update fails
        """
        try:
            updated_subscription = await self.subscription_service.update_subscription_from_webhook(
                subscription_id=subscription_id,
                paddle_plan_id=paddle_plan_id,
                status=status,
                update_reason=update_reason
            )
            
            return {
                "id": str(updated_subscription.id),
                "paddle_plan_id": updated_subscription.paddle_plan_id,
                "status": updated_subscription.status.value,
                "updated_at": updated_subscription.updated_at.isoformat(),
                "update_reason": update_reason
            }
            
        except ValueError as e:
            logger.warning(f"Subscription webhook update failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error updating subscription from webhook {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update subscription from webhook"
            )

    async def cancel_subscription_from_webhook(
        self,
        subscription_id: uuid.UUID,
        cancel_at_period_end: bool,
        cancellation_reason: str
    ) -> Dict[str, Any]:
        """
        Cancel subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            cancel_at_period_end: Whether to cancel at period end
            cancellation_reason: Reason for cancellation
            
        Returns:
            Dict containing cancellation details
            
        Raises:
            HTTPException: If subscription cancellation fails
        """
        try:
            cancelled_subscription = await self.subscription_service.cancel_subscription_from_webhook(
                subscription_id=subscription_id,
                cancel_at_period_end=cancel_at_period_end,
                cancellation_reason=cancellation_reason
            )
            
            return {
                "id": str(cancelled_subscription.id),
                "status": cancelled_subscription.status.value,
                "cancel_at_period_end": cancelled_subscription.cancel_at_period_end,
                "cancelled_at": cancelled_subscription.cancelled_at.isoformat() if cancelled_subscription.cancelled_at else None,
                "cancellation_reason": cancelled_subscription.cancellation_reason,
                "cancellation_source": "paddle_webhook"
            }
            
        except ValueError as e:
            logger.warning(f"Subscription webhook cancellation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error cancelling subscription from webhook {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to cancel subscription from webhook"
            )

    async def activate_subscription(
        self,
        subscription_id: uuid.UUID,
        activation_reason: str
    ) -> Dict[str, Any]:
        """
        Activate subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            activation_reason: Reason for activation
            
        Returns:
            Dict containing activated subscription details
            
        Raises:
            HTTPException: If subscription activation fails
        """
        try:
            activated_subscription = await self.subscription_service.activate_subscription(
                subscription_id=subscription_id,
                activation_reason=activation_reason
            )
            
            return {
                "id": str(activated_subscription.id),
                "status": activated_subscription.status.value,
                "activated_at": activated_subscription.activated_at.isoformat() if activated_subscription.activated_at else None,
                "activation_reason": activation_reason
            }
            
        except ValueError as e:
            logger.warning(f"Subscription activation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error activating subscription {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to activate subscription"
            )

    async def pause_subscription(
        self,
        subscription_id: uuid.UUID,
        pause_reason: str
    ) -> Dict[str, Any]:
        """
        Pause subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            pause_reason: Reason for pausing
            
        Returns:
            Dict containing paused subscription details
            
        Raises:
            HTTPException: If subscription pausing fails
        """
        try:
            paused_subscription = await self.subscription_service.pause_subscription(
                subscription_id=subscription_id,
                pause_reason=pause_reason
            )
            
            return {
                "id": str(paused_subscription.id),
                "status": paused_subscription.status.value,
                "paused_at": paused_subscription.paused_at.isoformat() if paused_subscription.paused_at else None,
                "pause_reason": pause_reason
            }
            
        except ValueError as e:
            logger.warning(f"Subscription pausing failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error pausing subscription {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to pause subscription"
            )

    async def resume_subscription(
        self,
        subscription_id: uuid.UUID,
        resume_reason: str
    ) -> Dict[str, Any]:
        """
        Resume subscription from webhook event.
        
        Args:
            subscription_id: Local subscription ID
            resume_reason: Reason for resuming
            
        Returns:
            Dict containing resumed subscription details
            
        Raises:
            HTTPException: If subscription resuming fails
        """
        try:
            resumed_subscription = await self.subscription_service.resume_subscription(
                subscription_id=subscription_id,
                resume_reason=resume_reason
            )
            
            return {
                "id": str(resumed_subscription.id),
                "status": resumed_subscription.status.value,
                "resumed_at": resumed_subscription.resumed_at.isoformat() if resumed_subscription.resumed_at else None,
                "resume_reason": resume_reason
            }
            
        except ValueError as e:
            logger.warning(f"Subscription resuming failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error resuming subscription {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to resume subscription"
            )

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
            HTTPException: If payment recording fails
        """
        try:
            payment_record = await self.subscription_service.record_payment(
                subscription_id=subscription_id,
                transaction_id=transaction_id,
                amount=amount,
                currency=currency,
                status=status,
                payment_method=payment_method,
                failure_reason=failure_reason,
                refund_reason=refund_reason
            )
            
            return {
                "id": str(payment_record.id),
                "subscription_id": str(payment_record.subscription_id),
                "transaction_id": payment_record.transaction_id,
                "amount": payment_record.amount,
                "currency": payment_record.currency,
                "status": payment_record.status,
                "payment_method": payment_record.payment_method,
                "failure_reason": payment_record.failure_reason,
                "refund_reason": payment_record.refund_reason,
                "created_at": payment_record.created_at.isoformat()
            }
            
        except ValueError as e:
            logger.warning(f"Payment recording failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Unexpected error recording payment for subscription {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to record payment"
            )

    async def cancel_subscription(
        self,
        user: User,
        subscription_id: uuid.UUID,
        cancel_at_period_end: bool = True,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Cancel a user's subscription.
        
        Args:
            user: Authenticated user
            subscription_id: ID of the subscription to cancel
            cancel_at_period_end: Whether to cancel at period end or immediately
            reason: Optional cancellation reason
            
        Returns:
            Dict containing cancellation details
            
        Raises:
            HTTPException: If subscription cancellation fails
        """
        try:
            # Verify user owns the subscription
            subscription = await self.subscription_service._get_active_subscription(user.id)
            if not subscription or subscription.id != subscription_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Subscription not found"
                )
            
            cancelled_subscription = await self.subscription_service.cancel_subscription(
                subscription_id=subscription_id,
                cancel_at_period_end=cancel_at_period_end,
                reason=reason
            )
            
            return {
                "id": str(cancelled_subscription.id),
                "status": cancelled_subscription.status.value,
                "cancel_at_period_end": cancelled_subscription.cancel_at_period_end,
                "cancelled_at": cancelled_subscription.cancelled_at.isoformat() if cancelled_subscription.cancelled_at else None,
                "cancellation_reason": cancelled_subscription.cancellation_reason,
                "current_period_end": cancelled_subscription.current_period_end.isoformat(),
                "updated_at": cancelled_subscription.updated_at.isoformat()
            }
            
        except ValueError as e:
            logger.warning(f"Subscription cancellation failed for user {user.id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error cancelling subscription {subscription_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to cancel subscription"
            )

    async def get_subscription_usage(self, user: User) -> Dict[str, Any]:
        """
        Get usage information for the current user's subscription.
        
        Args:
            user: Authenticated user
            
        Returns:
            Dict containing usage information and limits
        """
        try:
            usage_info = await self.subscription_service.check_usage_limits(user.id)
            
            return {
                "has_subscription": usage_info["has_subscription"],
                "plan_name": usage_info["plan_name"],
                "daily_used": usage_info["daily_used"],
                "daily_limit": usage_info["daily_limit"],
                "monthly_used": usage_info["monthly_used"],
                "monthly_limit": usage_info["monthly_limit"],
                "has_daily_limit": usage_info["has_daily_limit"],
                "has_monthly_limit": usage_info["has_monthly_limit"],
                "daily_remaining": usage_info["daily_remaining"],
                "monthly_remaining": usage_info["monthly_remaining"],
                "is_over_limit": usage_info["is_over_limit"]
            }
            
        except Exception as e:
            logger.error(f"Unexpected error getting usage for user {user.id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve usage information"
            )

    async def get_available_plans(self) -> List[Dict[str, Any]]:
        """
        Get all available subscription plans.
        
        Returns:
            List of available subscription plans
        """
        try:
            plans = await self.subscription_service.get_subscription_plans()
            return plans
            
        except Exception as e:
            logger.error(f"Unexpected error getting subscription plans: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve subscription plans"
            )


# Dependency injection for subscription controller
def get_subscription_controller(db: AsyncSession = Depends(get_db)) -> SubscriptionController:
    """
    Get subscription controller instance with database dependency.
    
    Args:
        db: Async database session
        
    Returns:
        SubscriptionController instance
    """
    subscription_service = SubscriptionService(db)
    return SubscriptionController(subscription_service)