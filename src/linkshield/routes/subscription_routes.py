#!/usr/bin/env python3
"""
LinkShield Backend Subscription Routes

API endpoints for subscription management, including:
- Creating, retrieving, updating, and cancelling subscriptions
- Checking subscription usage
- Getting available subscription plans
"""
import logging
from datetime import datetime
from typing import Optional, List
import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from linkshield.authentication.dependencies import get_current_user
from linkshield.config.database import get_db
from linkshield.controllers.depends import get_subscription_controller
from linkshield.services.subscription_service import SubscriptionService
from linkshield.controllers.subscription_controller import SubscriptionController
from linkshield.schemas.subscription import (
    SubscriptionCreate,
    SubscriptionUpdate,
    SubscriptionCancel,
    SubscriptionResponse,
    SubscriptionUsageResponse,
    SubscriptionCancellationResponse,
    SubscriptionListResponse,
    ErrorResponse
)
from linkshield.models.user import User
logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/subscriptions",
    tags=["subscriptions"],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        429: {"description": "Rate limit exceeded"}
    }
)





@router.post(
    "/",
    response_model=SubscriptionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request or plan not found"},
        409: {"model": ErrorResponse, "description": "User already has an active subscription"}
    }
)
async def create_subscription(
    subscription_data: SubscriptionCreate,
    current_user: User = Depends(get_current_user),
    subscription_controller: SubscriptionController = Depends(get_subscription_controller)
):
    """
    Create a new subscription for the authenticated user.
    
    This endpoint allows users to subscribe to a plan with optional trial period.
    """
    try:
        subscription = await subscription_controller.create_subscription(
            user=current_user,
            plan_name=subscription_data.plan_name,
            billing_interval=subscription_data.billing_interval,
            trial_days=subscription_data.trial_days
        )
        return subscription
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create subscription: {str(e)}"
        )


@router.get(
    "/me",
    response_model=SubscriptionResponse,
    responses={
        404: {"model": ErrorResponse, "description": "Subscription not found"}
    }
)
async def get_subscription(
    current_user: User = Depends(get_current_user),
    subscription_controller: SubscriptionController = Depends(get_subscription_controller)
):
    """
    Get the current user's subscription details.
    
    Returns detailed information about the authenticated user's subscription,
    including plan details, usage statistics, and billing information.
    """
    try:
        subscription = await subscription_controller.get_subscription(current_user.id)
        return subscription
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve subscription: {str(e)}"
        )


@router.put(
    "/me",
    response_model=SubscriptionResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request or plan not found"},
        404: {"model": ErrorResponse, "description": "Subscription not found"}
    }
)
async def update_subscription(
    subscription_data: SubscriptionUpdate,
    current_user: User = Depends(get_current_user),
    subscription_controller: SubscriptionController = Depends(get_subscription_controller)
):
    """
    Update the current user's subscription plan.
    
    Allows users to upgrade or downgrade their subscription plan.
    Changes take effect at the next billing cycle.
    """
    try:
        subscription = await subscription_controller.update_subscription(
            user=current_user,
            new_plan_name=subscription_data.new_plan_name,
            billing_interval=subscription_data.billing_interval,
            subscription_id=subscription_data.subscription_id
        )
        return subscription
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update subscription: {str(e)}"
        )


@router.delete(
    "/me",
    response_model=SubscriptionCancellationResponse,
    responses={
        404: {"model": ErrorResponse, "description": "Subscription not found"}
    }
)
async def cancel_subscription(
    cancel_data: Optional[SubscriptionCancel] = None,
    current_user: User = Depends(get_current_user),
    subscription_controller: SubscriptionController = Depends(get_subscription_controller)
):
    """
    Cancel the current user's subscription.
    
    Cancellation can be immediate or at the end of the billing period.
    Users can optionally provide a reason for cancellation.
    """
    try:
        cancel_at_period_end = True
        reason = None
        
        if cancel_data:
            cancel_at_period_end = cancel_data.cancel_at_period_end
            reason = cancel_data.reason
        
        result = await subscription_controller.cancel_subscription(
            user=current_user,
            cancel_at_period_end=cancel_at_period_end,
            reason=reason,
            subscription_id=cancel_data.subscription_id if cancel_data else None
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel subscription: {str(e)}"
        )


@router.get(
    "/me/usage",
    response_model=SubscriptionUsageResponse,
    responses={
        404: {"model": ErrorResponse, "description": "Subscription not found"}
    }
)
async def get_subscription_usage(
    current_user: User = Depends(get_current_user),
    subscription_controller: SubscriptionController = Depends(get_subscription_controller)
):
    """
    Get the current user's subscription usage information.
    
    Returns usage statistics including daily and monthly limits,
    current usage, and remaining checks available.
    """
    try:
        usage = await subscription_controller.get_subscription_usage(current_user.id)
        return usage
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve subscription usage: {str(e)}"
        )


@router.get(
    "/plans",
    response_model=SubscriptionListResponse,
    responses={
        500: {"model": ErrorResponse, "description": "Internal server error"}
    }
)
async def get_available_plans(
    subscription_controller: SubscriptionController = Depends(get_subscription_controller)
):
    """
    Get all available subscription plans.
    
    Returns a list of all subscription plans available for purchase,
    including detailed feature comparisons and pricing information.
    """
    try:
        plans = await subscription_controller.get_available_plans()
        return SubscriptionListResponse(plans=plans)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve subscription plans: {str(e)}"
        )


@router.post(
    "/{subscription_id}/reset-usage",
    response_model=SubscriptionResponse,
    responses={
        403: {"model": ErrorResponse, "description": "Forbidden - admin access required"},
        404: {"model": ErrorResponse, "description": "Subscription not found"}
    }
)
async def reset_subscription_usage(
    subscription_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    subscription_controller: SubscriptionController = Depends(get_subscription_controller)
):
    """
    Reset subscription usage counters (Admin only).
    
    This endpoint is restricted to administrators and allows resetting
    daily and monthly usage counters for a specific subscription.
    """
    # Check if current user is admin
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required to reset subscription usage"
        )
    
    try:
        subscription = await subscription_controller.reset_usage(subscription_id)
        return subscription
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset subscription usage: {str(e)}"
        )