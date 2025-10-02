#!/usr/bin/env python3
"""
Paddle Webhook Routes

API endpoints for handling Paddle subscription and payment webhook events.
This module processes webhook notifications from Paddle for:
- Subscription lifecycle events (created, updated, canceled)
- Payment events (completed, failed)
- Customer events (created, updated)
"""

import logging
from typing import Dict, Any, Optional
import json

from fastapi import APIRouter, Request, HTTPException, Header, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from src.database import get_db
from src.services.paddle_client import PaddleClientService
from src.services.subscription_service import SubscriptionService
from src.controllers.subscription_controller import SubscriptionController
from src.schemas.subscription import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/webhooks/paddle",
    tags=["paddle-webhooks"],
    responses={
        400: {"model": ErrorResponse, "description": "Invalid webhook payload or signature"},
        401: {"description": "Unauthorized - invalid webhook signature"},
        500: {"model": ErrorResponse, "description": "Internal server error processing webhook"}
    }
)


def get_paddle_client_service() -> PaddleClientService:
    """Dependency to get PaddleClientService instance."""
    return PaddleClientService()


def get_subscription_service(db: Session = Depends(get_db)) -> SubscriptionService:
    """Dependency to get SubscriptionService instance."""
    return SubscriptionService(db)


def get_subscription_controller(
    subscription_service: SubscriptionService = Depends(get_subscription_service)
) -> SubscriptionController:
    """Dependency to get SubscriptionController instance."""
    return SubscriptionController(subscription_service)


@router.post("/subscription", status_code=status.HTTP_200_OK)
async def handle_paddle_subscription_webhook(
    request: Request,
    paddle_client_service: PaddleClientService = Depends(get_paddle_client_service),
    subscription_controller: SubscriptionController = Depends(get_subscription_controller),
    paddle_signature: Optional[str] = Header(None, alias="Paddle-Signature"),
):
    """
    Handle Paddle subscription webhook events.
    
    Processes subscription lifecycle events including:
    - subscription.created: New subscription created
    - subscription.updated: Subscription plan or status changed
    - subscription.canceled: Subscription canceled
    - subscription.activated: Subscription activated
    - subscription.paused: Subscription paused
    - subscription.resumed: Subscription resumed
    
    Webhook signature verification is performed for security.
    """
    try:
        # Get raw payload
        payload = await request.body()
        
        # Verify webhook signature
        if paddle_signature:
            is_valid = await paddle_client_service.verify_webhook_signature(
                payload=payload,
                signature=paddle_signature
            )
            if not is_valid:
                logger.warning("Paddle webhook signature verification failed")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature"
                )
        
        # Parse JSON payload
        try:
            event_data = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Paddle webhook payload: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON payload"
            )
        
        # Log received webhook
        event_type = event_data.get('alert_name')
        logger.info(f"Received Paddle webhook: {event_type}")
        
        # Process different subscription event types
        if event_type == 'subscription_created':
            await _handle_subscription_created(event_data, subscription_controller)
        elif event_type == 'subscription_updated':
            await _handle_subscription_updated(event_data, subscription_controller)
        elif event_type == 'subscription_cancelled':
            await _handle_subscription_cancelled(event_data, subscription_controller)
        elif event_type == 'subscription_activated':
            await _handle_subscription_activated(event_data, subscription_controller)
        elif event_type == 'subscription_paused':
            await _handle_subscription_paused(event_data, subscription_controller)
        elif event_type == 'subscription_resumed':
            await _handle_subscription_resumed(event_data, subscription_controller)
        else:
            logger.warning(f"Unhandled Paddle subscription event type: {event_type}")
        
        return JSONResponse(
            content={"status": "success", "message": "Webhook processed successfully"},
            status_code=status.HTTP_200_OK
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing Paddle subscription webhook: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process webhook: {str(e)}"
        )


@router.post("/transaction", status_code=status.HTTP_200_OK)
async def handle_paddle_transaction_webhook(
    request: Request,
    paddle_client_service: PaddleClientService = Depends(get_paddle_client_service),
    subscription_controller: SubscriptionController = Depends(get_subscription_controller),
    paddle_signature: Optional[str] = Header(None, alias="Paddle-Signature"),
):
    """
    Handle Paddle transaction webhook events.
    
    Processes payment and transaction events including:
    - payment_succeeded: Payment completed successfully
    - payment_failed: Payment failed
    - payment_refunded: Payment refunded
    - subscription_payment_succeeded: Subscription payment succeeded
    - subscription_payment_failed: Subscription payment failed
    - subscription_payment_refunded: Subscription payment refunded
    
    Webhook signature verification is performed for security.
    """
    try:
        # Get raw payload
        payload = await request.body()
        
        # Verify webhook signature
        if paddle_signature:
            is_valid = await paddle_client_service.verify_webhook_signature(
                payload=payload,
                signature=paddle_signature
            )
            if not is_valid:
                logger.warning("Paddle webhook signature verification failed")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature"
                )
        
        # Parse JSON payload
        try:
            event_data = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Paddle webhook payload: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON payload"
            )
        
        # Log received webhook
        event_type = event_data.get('alert_name')
        logger.info(f"Received Paddle transaction webhook: {event_type}")
        
        # Process different transaction event types
        if event_type in ['payment_succeeded', 'subscription_payment_succeeded']:
            await _handle_payment_succeeded(event_data, subscription_controller)
        elif event_type in ['payment_failed', 'subscription_payment_failed']:
            await _handle_payment_failed(event_data, subscription_controller)
        elif event_type in ['payment_refunded', 'subscription_payment_refunded']:
            await _handle_payment_refunded(event_data, subscription_controller)
        else:
            logger.warning(f"Unhandled Paddle transaction event type: {event_type}")
        
        return JSONResponse(
            content={"status": "success", "message": "Webhook processed successfully"},
            status_code=status.HTTP_200_OK
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing Paddle transaction webhook: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process webhook: {str(e)}"
        )


async def _handle_subscription_created(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle subscription.created webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        paddle_subscription_id = event_data.get('subscription_id')
        user_id = event_data.get('user_id')
        plan_id = event_data.get('plan_id')
        status = event_data.get('status')
        
        logger.info(f"Processing subscription created: {subscription_id} for user {user_id}")
        
        # Update local subscription with Paddle subscription ID
        # This links our local subscription record with Paddle's record
        await subscription_controller.update_subscription_paddle_id(
            subscription_id=subscription_id,
            paddle_subscription_id=paddle_subscription_id,
            paddle_plan_id=plan_id,
            status=status
        )
        
    except Exception as e:
        logger.error(f"Error handling subscription created event: {e}")
        raise


async def _handle_subscription_updated(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle subscription.updated webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        new_plan_id = event_data.get('plan_id')
        status = event_data.get('status')
        
        logger.info(f"Processing subscription updated: {subscription_id}")
        
        # Update subscription plan and status
        await subscription_controller.update_subscription_from_webhook(
            subscription_id=subscription_id,
            paddle_plan_id=new_plan_id,
            status=status,
            update_reason="paddle_webhook"
        )
        
    except Exception as e:
        logger.error(f"Error handling subscription updated event: {e}")
        raise


async def _handle_subscription_cancelled(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle subscription.cancelled webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        cancel_at_period_end = event_data.get('cancel_at_period_end', False)
        
        logger.info(f"Processing subscription cancelled: {subscription_id}")
        
        # Cancel subscription
        await subscription_controller.cancel_subscription_from_webhook(
            subscription_id=subscription_id,
            cancel_at_period_end=cancel_at_period_end,
            cancellation_reason="paddle_webhook"
        )
        
    except Exception as e:
        logger.error(f"Error handling subscription cancelled event: {e}")
        raise


async def _handle_subscription_activated(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle subscription.activated webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        
        logger.info(f"Processing subscription activated: {subscription_id}")
        
        # Activate subscription
        await subscription_controller.activate_subscription(
            subscription_id=subscription_id,
            activation_reason="paddle_webhook"
        )
        
    except Exception as e:
        logger.error(f"Error handling subscription activated event: {e}")
        raise


async def _handle_subscription_paused(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle subscription.paused webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        
        logger.info(f"Processing subscription paused: {subscription_id}")
        
        # Pause subscription
        await subscription_controller.pause_subscription(
            subscription_id=subscription_id,
            pause_reason="paddle_webhook"
        )
        
    except Exception as e:
        logger.error(f"Error handling subscription paused event: {e}")
        raise


async def _handle_subscription_resumed(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle subscription.resumed webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        
        logger.info(f"Processing subscription resumed: {subscription_id}")
        
        # Resume subscription
        await subscription_controller.resume_subscription(
            subscription_id=subscription_id,
            resume_reason="paddle_webhook"
        )
        
    except Exception as e:
        logger.error(f"Error handling subscription resumed event: {e}")
        raise


async def _handle_payment_succeeded(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle payment succeeded webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        transaction_id = event_data.get('transaction_id')
        amount = event_data.get('amount')
        currency = event_data.get('currency')
        
        logger.info(f"Processing payment succeeded: {transaction_id} for subscription {subscription_id}")
        
        # Record successful payment
        await subscription_controller.record_payment(
            subscription_id=subscription_id,
            transaction_id=transaction_id,
            amount=amount,
            currency=currency,
            status="succeeded",
            payment_method="paddle"
        )
        
    except Exception as e:
        logger.error(f"Error handling payment succeeded event: {e}")
        raise


async def _handle_payment_failed(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle payment failed webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        transaction_id = event_data.get('transaction_id')
        amount = event_data.get('amount')
        currency = event_data.get('currency')
        failure_reason = event_data.get('failure_reason', 'unknown')
        
        logger.warning(f"Processing payment failed: {transaction_id} for subscription {subscription_id}, reason: {failure_reason}")
        
        # Record failed payment
        await subscription_controller.record_payment(
            subscription_id=subscription_id,
            transaction_id=transaction_id,
            amount=amount,
            currency=currency,
            status="failed",
            payment_method="paddle",
            failure_reason=failure_reason
        )
        
    except Exception as e:
        logger.error(f"Error handling payment failed event: {e}")
        raise


async def _handle_payment_refunded(
    event_data: Dict[str, Any],
    subscription_controller: SubscriptionController
) -> None:
    """Handle payment refunded webhook event."""
    try:
        subscription_id = event_data.get('subscription_id')
        transaction_id = event_data.get('transaction_id')
        amount = event_data.get('amount')
        currency = event_data.get('currency')
        refund_reason = event_data.get('refund_reason', 'unknown')
        
        logger.info(f"Processing payment refunded: {transaction_id} for subscription {subscription_id}")
        
        # Record refund
        await subscription_controller.record_payment(
            subscription_id=subscription_id,
            transaction_id=transaction_id,
            amount=amount,
            currency=currency,
            status="refunded",
            payment_method="paddle",
            refund_reason=refund_reason
        )
        
    except Exception as e:
        logger.error(f"Error handling payment refunded event: {e}")
        raise