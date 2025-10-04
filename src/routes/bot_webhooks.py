"""
Bot Webhook Routes.

This module provides FastAPI routes for handling webhook requests from
Discord, Telegram, and Twitter platforms. Includes signature verification
and proper error handling.
"""

import logging
from typing import Dict, Any
from fastapi import APIRouter, Request, HTTPException, Header, BackgroundTasks
from fastapi.responses import JSONResponse
import json

from src.config.settings import settings
from src.bots.registration import bot_registration_manager
from src.bots.gateway import bot_gateway
from src.bots.lifecycle import bot_lifecycle_manager
from src.bots.error_handler import bot_error_handler
from src.auth.bot_auth import verify_webhook_signature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/bots", tags=["Bot Webhooks"])


@router.post("/discord/webhook")
async def discord_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_signature_ed25519: str = Header(None),
    x_signature_timestamp: str = Header(None)
):
    """
    Handle Discord webhook interactions.
    
    Processes Discord slash commands, message components, and other interactions.
    Includes signature verification for security.
    """
    try:
        # Get raw payload for signature verification
        payload = await request.body()
        
        # Verify webhook signature if secret is configured
        if settings.DISCORD_WEBHOOK_SECRET and x_signature_ed25519:
            is_valid = await bot_registration_manager.verify_webhook_signature(
                platform="discord",
                payload=payload,
                signature=x_signature_ed25519,
                timestamp=x_signature_timestamp
            )
            
            if not is_valid:
                logger.warning("Discord webhook signature verification failed")
                raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse JSON payload
        try:
            interaction_data = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Discord webhook payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Handle PING interaction (Discord verification)
        if interaction_data.get("type") == 1:
            return {"type": 1}  # PONG response
        
        # Process interaction through bot gateway
        response = await bot_gateway.handle_webhook("discord", interaction_data)
        
        # Update metrics
        success = "error" not in response
        bot_lifecycle_manager.update_metrics(success, 0.0)  # Response time would be calculated elsewhere
        
        # Log interaction
        background_tasks.add_task(
            _log_webhook_interaction,
            platform="discord",
            interaction_data=interaction_data,
            response=response,
            success=success
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Discord webhook error: {e}")
        bot_lifecycle_manager.record_platform_error("discord")
        
        # Return appropriate Discord error response
        return {
            "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
            "data": {
                "content": "❌ An error occurred while processing your request. Please try again later.",
                "flags": 64  # EPHEMERAL
            }
        }


@router.post("/telegram/webhook")
async def telegram_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_telegram_bot_api_secret_token: str = Header(None)
):
    """
    Handle Telegram webhook updates.
    
    Processes Telegram messages, commands, callback queries, and other updates.
    Includes secret token verification for security.
    """
    try:
        # Get raw payload
        payload = await request.body()
        
        # Verify secret token if configured
        if settings.TELEGRAM_WEBHOOK_SECRET and x_telegram_bot_api_secret_token:
            if x_telegram_bot_api_secret_token != settings.TELEGRAM_WEBHOOK_SECRET:
                logger.warning("Telegram webhook secret token verification failed")
                raise HTTPException(status_code=401, detail="Invalid secret token")
        
        # Parse JSON payload
        try:
            update_data = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Telegram webhook payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Process update through bot gateway
        response = await bot_gateway.handle_webhook("telegram", update_data)
        
        # Update metrics
        success = "error" not in response
        bot_lifecycle_manager.update_metrics(success, 0.0)
        
        # Log interaction
        background_tasks.add_task(
            _log_webhook_interaction,
            platform="telegram",
            interaction_data=update_data,
            response=response,
            success=success
        )
        
        # Telegram expects 200 OK response
        return JSONResponse(content={"ok": True}, status_code=200)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Telegram webhook error: {e}")
        bot_lifecycle_manager.record_platform_error("telegram")
        
        # Return 200 OK to prevent Telegram from retrying
        return JSONResponse(content={"ok": False, "error": str(e)}, status_code=200)


@router.post("/twitter/webhook")
async def twitter_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_twitter_webhooks_signature: str = Header(None)
):
    """
    Handle Twitter webhook events.
    
    Processes Twitter mentions, direct messages, and other Account Activity API events.
    Includes signature verification for security.
    """
    try:
        # Get raw payload
        payload = await request.body()
        
        # Verify webhook signature if secret is configured
        if settings.TWITTER_WEBHOOK_SECRET and x_twitter_webhooks_signature:
            is_valid = await bot_registration_manager.verify_webhook_signature(
                platform="twitter",
                payload=payload,
                signature=x_twitter_webhooks_signature
            )
            
            if not is_valid:
                logger.warning("Twitter webhook signature verification failed")
                raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse JSON payload
        try:
            event_data = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Twitter webhook payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
        # Process event through bot gateway
        response = await bot_gateway.handle_webhook("twitter", event_data)
        
        # Update metrics
        success = "error" not in response
        bot_lifecycle_manager.update_metrics(success, 0.0)
        
        # Log interaction
        background_tasks.add_task(
            _log_webhook_interaction,
            platform="twitter",
            interaction_data=event_data,
            response=response,
            success=success
        )
        
        return JSONResponse(content=response, status_code=200)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Twitter webhook error: {e}")
        bot_lifecycle_manager.record_platform_error("twitter")
        
        return JSONResponse(
            content={"error": "Internal server error"},
            status_code=500
        )


@router.get("/discord/webhook")
async def discord_webhook_verification(request: Request):
    """
    Handle Discord webhook verification (if needed).
    
    Some Discord webhook setups may require GET endpoint verification.
    """
    return {"message": "Discord webhook endpoint active"}


@router.get("/telegram/webhook")
async def telegram_webhook_verification(request: Request):
    """
    Handle Telegram webhook verification.
    
    Provides endpoint verification for Telegram webhook setup.
    """
    return {"message": "Telegram webhook endpoint active"}


@router.get("/twitter/webhook")
async def twitter_webhook_verification(request: Request):
    """
    Handle Twitter webhook verification (CRC challenge).
    
    Twitter requires CRC challenge response for webhook verification.
    """
    crc_token = request.query_params.get("crc_token")
    
    if not crc_token:
        raise HTTPException(status_code=400, detail="Missing crc_token parameter")
    
    if not settings.TWITTER_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Twitter webhook secret not configured")
    
    # Generate CRC response
    import hmac
    import hashlib
    import base64
    
    signature = hmac.new(
        settings.TWITTER_WEBHOOK_SECRET.encode('utf-8'),
        crc_token.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    response_token = base64.b64encode(signature).decode('utf-8')
    
    return {"response_token": f"sha256={response_token}"}


@router.get("/status")
async def bot_status():
    """
    Get bot service status.
    
    Returns comprehensive status information for all bot platforms.
    """
    try:
        status = await bot_lifecycle_manager.get_status()
        return JSONResponse(content=status, status_code=200)
        
    except Exception as e:
        logger.error(f"Error getting bot status: {e}")
        return JSONResponse(
            content={"error": "Failed to get bot status"},
            status_code=500
        )


@router.get("/health")
async def bot_health():
    """
    Get bot service health status.
    
    Returns health information for monitoring systems.
    """
    try:
        health = await bot_lifecycle_manager.get_health_status()
        status_code = 200 if health["healthy"] else 503
        
        return JSONResponse(content=health, status_code=status_code)
        
    except Exception as e:
        logger.error(f"Error getting bot health: {e}")
        return JSONResponse(
            content={
                "healthy": False,
                "error": "Failed to get health status"
            },
            status_code=503
        )


@router.post("/commands/register")
async def register_bot_commands():
    """
    Manually trigger bot command registration.
    
    Useful for updating commands without restarting the service.
    """
    try:
        results = await bot_registration_manager.register_all_commands()
        
        return JSONResponse(
            content={
                "message": "Command registration completed",
                "results": results
            },
            status_code=200
        )
        
    except Exception as e:
        logger.error(f"Error registering bot commands: {e}")
        return JSONResponse(
            content={"error": "Failed to register commands"},
            status_code=500
        )


@router.post("/platforms/{platform}/restart")
async def restart_platform(platform: str):
    """
    Restart a specific bot platform.
    
    Args:
        platform: Platform name (discord, telegram, twitter)
    """
    try:
        if platform not in ["discord", "telegram", "twitter"]:
            raise HTTPException(status_code=400, detail="Invalid platform")
        
        await bot_lifecycle_manager.restart_platform(platform)
        
        return JSONResponse(
            content={"message": f"Platform {platform} restart initiated"},
            status_code=200
        )
        
    except Exception as e:
        logger.error(f"Error restarting platform {platform}: {e}")
        return JSONResponse(
            content={"error": f"Failed to restart platform {platform}"},
            status_code=500
        )


@router.get("/platforms/{platform}/info")
async def get_platform_info(platform: str):
    """
    Get information about a specific bot platform.
    
    Args:
        platform: Platform name (discord, telegram, twitter)
    """
    try:
        if platform not in ["discord", "telegram", "twitter"]:
            raise HTTPException(status_code=400, detail="Invalid platform")
        
        # Get bot info
        bot_info = await bot_registration_manager.get_bot_info(platform)
        
        # Get platform configuration
        config = await bot_registration_manager.bot_configuration_manager.get_platform_config(platform)
        
        # Get platform status
        status = await bot_lifecycle_manager.get_status()
        platform_status = status.get("platform_statuses", {}).get(platform, "unknown")
        
        return JSONResponse(
            content={
                "platform": platform,
                "status": platform_status,
                "bot_info": bot_info,
                "config": {
                    "enabled": config.get("enabled", False) if config else False,
                    "features": config.get("features", {}) if config else {},
                    "limits": config.get("limits", {}) if config else {}
                },
                "health": status.get("platform_health", {}).get(platform, {})
            },
            status_code=200
        )
        
    except Exception as e:
        logger.error(f"Error getting platform info for {platform}: {e}")
        return JSONResponse(
            content={"error": f"Failed to get platform info for {platform}"},
            status_code=500
        )


# Background task functions

async def _log_webhook_interaction(
    platform: str,
    interaction_data: Dict[str, Any],
    response: Dict[str, Any],
    success: bool
):
    """
    Log webhook interaction for analytics and debugging.
    
    Args:
        platform: Platform name
        interaction_data: Original interaction data
        response: Response data
        success: Whether the interaction was successful
    """
    try:
        # Extract relevant information for logging
        log_data = {
            "platform": platform,
            "timestamp": interaction_data.get("timestamp") or "unknown",
            "success": success,
            "response_type": response.get("type", "unknown")
        }
        
        # Platform-specific logging
        if platform == "discord":
            log_data.update({
                "interaction_type": interaction_data.get("type"),
                "command_name": interaction_data.get("data", {}).get("name"),
                "user_id": interaction_data.get("member", {}).get("user", {}).get("id") or 
                         interaction_data.get("user", {}).get("id"),
                "guild_id": interaction_data.get("guild_id")
            })
        elif platform == "telegram":
            log_data.update({
                "update_id": interaction_data.get("update_id"),
                "message_id": interaction_data.get("message", {}).get("message_id"),
                "user_id": interaction_data.get("message", {}).get("from", {}).get("id"),
                "chat_id": interaction_data.get("message", {}).get("chat", {}).get("id")
            })
        elif platform == "twitter":
            log_data.update({
                "event_type": "tweet" if "tweet_create_events" in interaction_data else "dm",
                "user_id": interaction_data.get("for_user_id")
            })
        
        # Log the interaction
        if success:
            logger.info(f"Bot interaction successful: {log_data}")
        else:
            logger.warning(f"Bot interaction failed: {log_data}")
        
        # Store analytics data if enabled
        if settings.BOT_ENABLE_ANALYTICS:
            # This would store analytics data in database
            # Implementation depends on analytics requirements
            pass
            
    except Exception as e:
        logger.error(f"Error logging webhook interaction: {e}")


# Error handlers for webhook routes - these should be handled at the app level
# Removing router.exception_handler as it's not available on APIRouter