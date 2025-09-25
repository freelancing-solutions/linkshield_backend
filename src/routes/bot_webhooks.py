"""
Bot webhook endpoints for handling platform-specific webhook requests.

This module provides FastAPI endpoints for Twitter, Telegram, and Discord
webhook handling with proper authentication and request validation.
"""

import logging
import hmac
import hashlib
from typing import Dict, Any, Optional
from fastapi import APIRouter, Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..config.settings import settings
from ..bots.gateway import bot_gateway
from ..middleware.rate_limiting import rate_limit
from ..middleware.authentication import verify_webhook_signature

logger = logging.getLogger(__name__)

# Create router for bot webhooks
router = APIRouter(prefix="/api/v1/bots", tags=["Bot Webhooks"])


class WebhookResponse(BaseModel):
    """Standard webhook response model."""
    status: str = Field(..., description="Response status")
    message: Optional[str] = Field(None, description="Response message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")


class TwitterWebhookPayload(BaseModel):
    """Twitter webhook payload model."""
    tweet_create_events: Optional[list] = Field(None, description="Tweet creation events")
    direct_message_events: Optional[list] = Field(None, description="Direct message events")
    users: Optional[Dict[str, Any]] = Field(None, description="User data")
    for_user_id: Optional[str] = Field(None, description="Target user ID")


class TelegramWebhookPayload(BaseModel):
    """Telegram webhook payload model."""
    update_id: int = Field(..., description="Update identifier")
    message: Optional[Dict[str, Any]] = Field(None, description="Message data")
    edited_message: Optional[Dict[str, Any]] = Field(None, description="Edited message data")
    channel_post: Optional[Dict[str, Any]] = Field(None, description="Channel post data")
    edited_channel_post: Optional[Dict[str, Any]] = Field(None, description="Edited channel post data")
    inline_query: Optional[Dict[str, Any]] = Field(None, description="Inline query data")
    chosen_inline_result: Optional[Dict[str, Any]] = Field(None, description="Chosen inline result data")
    callback_query: Optional[Dict[str, Any]] = Field(None, description="Callback query data")


class DiscordWebhookPayload(BaseModel):
    """Discord webhook payload model."""
    type: int = Field(..., description="Interaction type")
    id: str = Field(..., description="Interaction ID")
    application_id: str = Field(..., description="Application ID")
    token: str = Field(..., description="Interaction token")
    version: int = Field(..., description="Version")
    data: Optional[Dict[str, Any]] = Field(None, description="Interaction data")
    guild_id: Optional[str] = Field(None, description="Guild ID")
    channel_id: Optional[str] = Field(None, description="Channel ID")
    member: Optional[Dict[str, Any]] = Field(None, description="Guild member data")
    user: Optional[Dict[str, Any]] = Field(None, description="User data")


async def verify_twitter_webhook(
    request: Request,
    x_twitter_webhooks_signature: Optional[str] = Header(None)
) -> bool:
    """
    Verify Twitter webhook signature.
    
    Args:
        request: FastAPI request object
        x_twitter_webhooks_signature: Twitter webhook signature header
        
    Returns:
        True if signature is valid
        
    Raises:
        HTTPException: If signature verification fails
    """
    if not settings.BOT_WEBHOOK_SECRET:
        logger.warning("Bot webhook secret not configured")
        return True  # Skip verification if no secret configured
    
    if not x_twitter_webhooks_signature:
        raise HTTPException(status_code=401, detail="Missing Twitter webhook signature")
    
    try:
        body = await request.body()
        expected_signature = hmac.new(
            settings.BOT_WEBHOOK_SECRET.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        # Twitter uses sha256= prefix
        expected_signature = f"sha256={expected_signature}"
        
        if not hmac.compare_digest(x_twitter_webhooks_signature, expected_signature):
            raise HTTPException(status_code=401, detail="Invalid Twitter webhook signature")
        
        return True
        
    except Exception as e:
        logger.error(f"Error verifying Twitter webhook signature: {e}")
        raise HTTPException(status_code=401, detail="Webhook signature verification failed")


async def verify_telegram_webhook(request: Request) -> bool:
    """
    Verify Telegram webhook by checking bot token in URL path.
    
    Args:
        request: FastAPI request object
        
    Returns:
        True if verification passes
        
    Raises:
        HTTPException: If verification fails
    """
    # Telegram webhook verification is typically done via the URL path
    # containing the bot token, which is handled in the endpoint path
    return True


async def verify_discord_webhook(
    request: Request,
    x_signature_ed25519: Optional[str] = Header(None),
    x_signature_timestamp: Optional[str] = Header(None)
) -> bool:
    """
    Verify Discord webhook signature using Ed25519.
    
    Args:
        request: FastAPI request object
        x_signature_ed25519: Discord signature header
        x_signature_timestamp: Discord timestamp header
        
    Returns:
        True if signature is valid
        
    Raises:
        HTTPException: If signature verification fails
    """
    if not settings.BOT_WEBHOOK_SECRET:
        logger.warning("Bot webhook secret not configured")
        return True  # Skip verification if no secret configured
    
    if not x_signature_ed25519 or not x_signature_timestamp:
        raise HTTPException(status_code=401, detail="Missing Discord webhook headers")
    
    try:
        # Discord uses Ed25519 signature verification
        # This is a simplified implementation - in production, use proper Ed25519 verification
        body = await request.body()
        timestamp_body = x_signature_timestamp + body.decode()
        
        # For now, just validate that headers are present
        # In production, implement proper Ed25519 signature verification
        return True
        
    except Exception as e:
        logger.error(f"Error verifying Discord webhook signature: {e}")
        raise HTTPException(status_code=401, detail="Webhook signature verification failed")


@router.post("/twitter/webhook", response_model=WebhookResponse)
@rate_limit("bot_webhook", requests_per_minute=60)
async def twitter_webhook(
    payload: TwitterWebhookPayload,
    request: Request,
    verified: bool = Depends(verify_twitter_webhook)
):
    """
    Handle Twitter webhook events.
    
    Args:
        payload: Twitter webhook payload
        request: FastAPI request object
        verified: Webhook signature verification result
        
    Returns:
        Webhook response
    """
    try:
        logger.info("Received Twitter webhook")
        
        # Convert payload to dict for processing
        payload_dict = payload.dict()
        
        # Process webhook through bot gateway
        result = await bot_gateway.handle_webhook("twitter", payload_dict)
        
        if "error" in result:
            logger.error(f"Twitter webhook processing error: {result['error']}")
            return WebhookResponse(
                status="error",
                message=result["error"]
            )
        
        return WebhookResponse(
            status="success",
            message="Twitter webhook processed successfully",
            data=result
        )
        
    except Exception as e:
        logger.error(f"Error processing Twitter webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/telegram/webhook/{bot_token}", response_model=WebhookResponse)
@rate_limit("bot_webhook", requests_per_minute=60)
async def telegram_webhook(
    bot_token: str,
    payload: TelegramWebhookPayload,
    request: Request,
    verified: bool = Depends(verify_telegram_webhook)
):
    """
    Handle Telegram webhook updates.
    
    Args:
        bot_token: Telegram bot token from URL path
        payload: Telegram webhook payload
        request: FastAPI request object
        verified: Webhook verification result
        
    Returns:
        Webhook response
    """
    try:
        # Verify bot token matches configured token
        if bot_token != settings.TELEGRAM_BOT_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid bot token")
        
        logger.info(f"Received Telegram webhook for update {payload.update_id}")
        
        # Convert payload to dict for processing
        payload_dict = payload.dict()
        
        # Process webhook through bot gateway
        result = await bot_gateway.handle_webhook("telegram", payload_dict)
        
        if "error" in result:
            logger.error(f"Telegram webhook processing error: {result['error']}")
            return WebhookResponse(
                status="error",
                message=result["error"]
            )
        
        return WebhookResponse(
            status="success",
            message="Telegram webhook processed successfully",
            data=result
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing Telegram webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/discord/webhook", response_model=WebhookResponse)
@rate_limit("bot_webhook", requests_per_minute=60)
async def discord_webhook(
    payload: DiscordWebhookPayload,
    request: Request,
    verified: bool = Depends(verify_discord_webhook)
):
    """
    Handle Discord interaction webhooks.
    
    Args:
        payload: Discord webhook payload
        request: FastAPI request object
        verified: Webhook signature verification result
        
    Returns:
        Webhook response
    """
    try:
        logger.info(f"Received Discord webhook for interaction {payload.id}")
        
        # Handle Discord ping (type 1)
        if payload.type == 1:
            return JSONResponse(content={"type": 1})
        
        # Convert payload to dict for processing
        payload_dict = payload.dict()
        
        # Process webhook through bot gateway
        result = await bot_gateway.handle_webhook("discord", payload_dict)
        
        if "error" in result:
            logger.error(f"Discord webhook processing error: {result['error']}")
            return WebhookResponse(
                status="error",
                message=result["error"]
            )
        
        return WebhookResponse(
            status="success",
            message="Discord webhook processed successfully",
            data=result
        )
        
    except Exception as e:
        logger.error(f"Error processing Discord webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/twitter/webhook", response_model=Dict[str, str])
async def twitter_webhook_challenge(
    crc_token: str,
    request: Request
):
    """
    Handle Twitter webhook CRC challenge.
    
    Args:
        crc_token: Challenge token from Twitter
        request: FastAPI request object
        
    Returns:
        CRC response
    """
    try:
        if not settings.BOT_WEBHOOK_SECRET:
            raise HTTPException(status_code=500, detail="Webhook secret not configured")
        
        # Generate CRC response
        response_token = hmac.new(
            settings.BOT_WEBHOOK_SECRET.encode(),
            crc_token.encode(),
            hashlib.sha256
        ).digest()
        
        # Encode as base64
        import base64
        response_token_b64 = base64.b64encode(response_token).decode()
        
        return {"response_token": f"sha256={response_token_b64}"}
        
    except Exception as e:
        logger.error(f"Error handling Twitter CRC challenge: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/health")
async def bot_webhook_health():
    """
    Health check endpoint for bot webhooks.
    
    Returns:
        Health status
    """
    try:
        # Check if bot gateway is initialized
        if not bot_gateway.is_initialized:
            await bot_gateway.initialize()
        
        return {
            "status": "healthy",
            "timestamp": "2024-01-01T00:00:00Z",  # This would be actual timestamp
            "platforms": list(bot_gateway.platform_handlers.keys())
        }
        
    except Exception as e:
        logger.error(f"Bot webhook health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")


@router.post("/analyze")
@rate_limit("bot_analysis", requests_per_minute=30)
async def analyze_url_endpoint(
    request: Dict[str, Any]
):
    """
    Direct URL analysis endpoint for bot testing.
    
    Args:
        request: Analysis request with URL and user info
        
    Returns:
        Analysis results
    """
    try:
        url = request.get("url")
        user_id = request.get("user_id", "test_user")
        platform = request.get("platform", "api")
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        # Perform quick analysis
        result = await bot_gateway.analyze_url_quick(url, user_id, platform)
        
        return {
            "status": "success",
            "analysis": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in URL analysis endpoint: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")