"""
Bot Authentication Routes.

This module provides FastAPI routes for linking social media platform accounts
to authenticated user accounts, enabling subscription-based bot access.
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.authentication.dependencies import get_current_user
from src.config.settings import settings
from src.database.connection import get_db
from src.models.user import User
from src.models.bot import BotUser, BotPlatform
from src.services.bot_subscription_validator import BotSubscriptionValidator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/bot-auth", tags=["Bot Authentication"])

# In-memory store for auth tokens (in production, use Redis)
_auth_tokens: Dict[str, Dict[str, Any]] = {}

# ------------------------------------------------------------------
# Request/Response Models
# ------------------------------------------------------------------

class LinkAccountRequest(BaseModel):
    """Request model for linking a platform account."""
    platform: str = Field(..., description="Platform name (twitter, telegram, discord)")
    platform_user_id: str = Field(..., description="Platform-specific user ID")
    username: Optional[str] = Field(None, description="Platform username")
    display_name: Optional[str] = Field(None, description="Platform display name")


class AuthTokenRequest(BaseModel):
    """Request model for generating auth token."""
    platform: str = Field(..., description="Platform name")
    platform_user_id: str = Field(..., description="Platform-specific user ID")


class AuthTokenResponse(BaseModel):
    """Response model for auth token generation."""
    auth_token: str = Field(..., description="Authentication token")
    auth_url: str = Field(..., description="URL for user to complete authentication")
    expires_at: datetime = Field(..., description="Token expiration time")


class AuthStatusResponse(BaseModel):
    """Response model for auth status check."""
    status: str = Field(..., description="Authentication status")
    linked: bool = Field(..., description="Whether account is linked")
    message: str = Field(..., description="Status message")


class UnlinkAccountRequest(BaseModel):
    """Request model for unlinking a platform account."""
    platform: str = Field(..., description="Platform name")
    platform_user_id: str = Field(..., description="Platform-specific user ID")


class LinkedPlatformInfo(BaseModel):
    """Information about a linked platform account."""
    platform: str
    username: Optional[str]
    display_name: Optional[str]
    linked_at: datetime
    last_used: Optional[datetime]
    total_analyses: int


class LinkedPlatformsResponse(BaseModel):
    """Response model for linked platforms list."""
    linked_platforms: List[LinkedPlatformInfo]
    platform_limit: int
    can_add_more: bool


# ------------------------------------------------------------------
# Dependency Injection
# ------------------------------------------------------------------

def get_bot_subscription_validator(db: Session = Depends(get_db)) -> BotSubscriptionValidator:
    """Get bot subscription validator instance."""
    return BotSubscriptionValidator(db)


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@router.post("/generate-token", response_model=AuthTokenResponse)
async def generate_auth_token(
    request: AuthTokenRequest,
    validator: BotSubscriptionValidator = Depends(get_bot_subscription_validator)
):
    """
    Generate an authentication token for platform account linking.
    
    This endpoint is called by bot platforms when a user wants to link
    their platform account to their LinkShield account.
    """
    try:
        # Validate platform
        if request.platform not in ["twitter", "telegram", "discord"]:
            raise HTTPException(status_code=400, detail="Invalid platform")
        
        # Generate secure token
        auth_token = secrets.token_urlsafe(32)
        
        # Set expiration (10 minutes)
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        # Store token data
        _auth_tokens[auth_token] = {
            "platform": request.platform,
            "platform_user_id": request.platform_user_id,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at,
            "status": "pending"
        }
        
        # Generate auth URL
        auth_url = f"{settings.FRONTEND_URL}/bot-auth?token={auth_token}"
        
        logger.info(f"Generated auth token for {request.platform} user {request.platform_user_id}")
        
        return AuthTokenResponse(
            auth_token=auth_token,
            auth_url=auth_url,
            expires_at=expires_at
        )
        
    except Exception as e:
        logger.error(f"Error generating auth token: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate auth token")


@router.get("/status/{auth_token}", response_model=AuthStatusResponse)
async def check_auth_status(auth_token: str):
    """
    Check the status of an authentication token.
    
    Used by bot platforms to poll for authentication completion.
    """
    try:
        # Check if token exists
        if auth_token not in _auth_tokens:
            raise HTTPException(status_code=404, detail="Auth token not found")
        
        token_data = _auth_tokens[auth_token]
        
        # Check if token expired
        if datetime.utcnow() > token_data["expires_at"]:
            # Clean up expired token
            del _auth_tokens[auth_token]
            return AuthStatusResponse(
                status="expired",
                linked=False,
                message="Authentication token has expired"
            )
        
        # Return current status
        status = token_data["status"]
        linked = status == "completed"
        
        if status == "pending":
            message = "Waiting for user authentication"
        elif status == "completed":
            message = "Account successfully linked"
        else:
            message = "Authentication failed"
        
        return AuthStatusResponse(
            status=status,
            linked=linked,
            message=message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking auth status: {e}")
        raise HTTPException(status_code=500, detail="Failed to check auth status")


@router.post("/link")
async def link_platform_account(
    request: LinkAccountRequest,
    auth_token: str,
    current_user: User = Depends(get_current_user),
    validator: BotSubscriptionValidator = Depends(get_bot_subscription_validator)
):
    """
    Link a platform account to the authenticated user.
    
    This endpoint is called from the frontend when a user completes
    the authentication flow.
    """
    try:
        # Validate auth token
        if auth_token not in _auth_tokens:
            raise HTTPException(status_code=404, detail="Invalid or expired auth token")
        
        token_data = _auth_tokens[auth_token]
        
        # Check if token expired
        if datetime.utcnow() > token_data["expires_at"]:
            del _auth_tokens[auth_token]
            raise HTTPException(status_code=400, detail="Auth token has expired")
        
        # Verify token matches request
        if (token_data["platform"] != request.platform or 
            token_data["platform_user_id"] != request.platform_user_id):
            raise HTTPException(status_code=400, detail="Token data mismatch")
        
        # Check if user can add more platforms
        user_bot_count = len(current_user.bot_users)
        bot_limits = current_user.get_bot_feature_limits()
        max_platforms = bot_limits.get("max_platforms", 0)
        
        if max_platforms > 0 and user_bot_count >= max_platforms:
            raise HTTPException(
                status_code=403, 
                detail=f"Platform limit reached. Your plan allows {max_platforms} platform accounts."
            )
        
        # Validate platform
        try:
            platform_enum = BotPlatform(request.platform)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid platform")
        
        # Link bot user to authenticated user
        success, error_message = await validator.link_bot_user_to_user(
            platform=platform_enum,
            platform_user_id=request.platform_user_id,
            user_id=str(current_user.id)
        )
        
        if not success:
            raise HTTPException(status_code=400, detail=error_message)
        
        # Update token status
        token_data["status"] = "completed"
        token_data["completed_at"] = datetime.utcnow()
        token_data["user_id"] = str(current_user.id)
        
        logger.info(f"Successfully linked {request.platform} account {request.platform_user_id} to user {current_user.id}")
        
        return {
            "success": True,
            "message": "Platform account linked successfully",
            "platform": request.platform,
            "username": request.username
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error linking platform account: {e}")
        raise HTTPException(status_code=500, detail="Failed to link platform account")


@router.delete("/unlink")
async def unlink_platform_account(
    request: UnlinkAccountRequest,
    current_user: User = Depends(get_current_user),
    validator: BotSubscriptionValidator = Depends(get_bot_subscription_validator)
):
    """
    Unlink a platform account from the authenticated user.
    """
    try:
        # Validate platform
        try:
            platform_enum = BotPlatform(request.platform)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid platform")
        
        # Unlink bot user
        success, error_message = await validator.unlink_bot_user(
            platform=platform_enum,
            platform_user_id=request.platform_user_id,
            user_id=str(current_user.id)
        )
        
        if not success:
            raise HTTPException(status_code=400, detail=error_message)
        
        # Get remaining platforms
        remaining_platforms = [
            bot_user.platform.value for bot_user in current_user.bot_users
            if bot_user.platform != platform_enum or bot_user.platform_user_id != request.platform_user_id
        ]
        
        logger.info(f"Successfully unlinked {request.platform} account {request.platform_user_id} from user {current_user.id}")
        
        return {
            "success": True,
            "message": "Platform account unlinked successfully",
            "remaining_platforms": remaining_platforms
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error unlinking platform account: {e}")
        raise HTTPException(status_code=500, detail="Failed to unlink platform account")


@router.get("/linked-platforms", response_model=LinkedPlatformsResponse)
async def get_linked_platforms(
    current_user: User = Depends(get_current_user)
):
    """
    Get all platform accounts linked to the authenticated user.
    """
    try:
        # Get bot feature limits
        bot_limits = current_user.get_bot_feature_limits()
        platform_limit = bot_limits.get("max_platforms", 0)
        
        # Build linked platforms list
        linked_platforms = []
        for bot_user in current_user.bot_users:
            linked_platforms.append(LinkedPlatformInfo(
                platform=bot_user.platform.value,
                username=bot_user.username,
                display_name=bot_user.display_name,
                linked_at=bot_user.created_at,
                last_used=bot_user.last_analysis_at,
                total_analyses=bot_user.total_analyses
            ))
        
        # Check if user can add more platforms
        can_add_more = platform_limit == 0 or len(linked_platforms) < platform_limit
        
        return LinkedPlatformsResponse(
            linked_platforms=linked_platforms,
            platform_limit=platform_limit,
            can_add_more=can_add_more
        )
        
    except Exception as e:
        logger.error(f"Error getting linked platforms: {e}")
        raise HTTPException(status_code=500, detail="Failed to get linked platforms")


@router.get("/limits")
async def get_bot_limits(
    current_user: User = Depends(get_current_user)
):
    """
    Get bot feature limits for the authenticated user.
    """
    try:
        # Check if user can access bot features
        if not current_user.can_access_bot_feature("basic_analysis"):
            raise HTTPException(
                status_code=403,
                detail="Your subscription plan does not include bot access. Please upgrade to Basic or higher."
            )
        
        # Get bot feature limits
        bot_limits = current_user.get_bot_feature_limits()
        
        # Get current usage
        current_usage = {
            "linked_platforms": len(current_user.bot_users),
            "monthly_requests": sum(bot_user.monthly_request_count for bot_user in current_user.bot_users)
        }
        
        return {
            "limits": bot_limits,
            "current_usage": current_usage,
            "subscription_plan": current_user.subscription_plan.value
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting bot limits: {e}")
        raise HTTPException(status_code=500, detail="Failed to get bot limits")


# ------------------------------------------------------------------
# Background Tasks
# ------------------------------------------------------------------

async def cleanup_expired_tokens():
    """
    Background task to clean up expired auth tokens.
    Should be called periodically.
    """
    try:
        current_time = datetime.utcnow()
        expired_tokens = [
            token for token, data in _auth_tokens.items()
            if current_time > data["expires_at"]
        ]
        
        for token in expired_tokens:
            del _auth_tokens[token]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired auth tokens")
            
    except Exception as e:
        logger.error(f"Error cleaning up expired tokens: {e}")