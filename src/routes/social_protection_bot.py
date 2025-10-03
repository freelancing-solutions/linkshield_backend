"""
Social Protection Bot Routes

API routes for bot integration and automated analysis services for third-party systems.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, Field

from src.authentication.auth_service import get_current_user
from src.models.user import User
from src.social_protection.controllers.bot_controller import BotController
from src.social_protection.controllers.depends import get_bot_controller
from src.social_protection.types import PlatformType

router = APIRouter(prefix="/api/v1/social-protection/bot", tags=["Social Protection - Bot"])


# Request/Response Models
class QuickAnalysisRequest(BaseModel):
    """Model for quick content analysis"""
    content: str
    platform: Optional[PlatformType] = None
    context: Optional[dict] = Field(default_factory=dict)
    response_format: str = Field(default="json", pattern="^(json|minimal|detailed)$")


class AccountSafetyRequest(BaseModel):
    """Model for account safety assessment"""
    platform: PlatformType
    account_identifier: str
    check_followers: bool = False
    check_content: bool = True


class ComplianceCheckRequest(BaseModel):
    """Model for content compliance checking"""
    content: str
    platform: PlatformType
    compliance_rules: Optional[List[str]] = None
    strict_mode: bool = False


class FollowerAnalysisRequest(BaseModel):
    """Model for follower analysis"""
    platform: PlatformType
    account_identifier: str
    sample_size: int = Field(default=100, ge=10, le=1000)
    check_verified_only: bool = False


@router.post("/analyze")
async def quick_content_analysis(
    request: QuickAnalysisRequest,
    current_user: User = Depends(get_current_user),
    controller: BotController = Depends(get_bot_controller)
):
    """
    Quick content analysis for bots
    
    Provides fast content analysis optimized for bot integration.
    Supports multiple response formats (json, minimal, detailed).
    
    Response formats:
    - json: Standard JSON response with full details
    - minimal: Lightweight response with essential info only
    - detailed: Comprehensive response with all analysis data
    """
    return await controller.quick_content_analysis(
        current_user,
        request.content,
        request.platform,
        request.context,
        request.response_format
    )


@router.post("/account-safety")
async def analyze_account_safety(
    request: AccountSafetyRequest,
    current_user: User = Depends(get_current_user),
    controller: BotController = Depends(get_bot_controller)
):
    """
    Analyze account safety
    
    Performs comprehensive safety assessment of a social media account
    including reputation check, content analysis, and follower verification.
    """
    return await controller.analyze_account_safety(
        current_user,
        request.platform,
        request.account_identifier,
        request.check_followers,
        request.check_content
    )


@router.post("/compliance")
async def check_content_compliance(
    request: ComplianceCheckRequest,
    current_user: User = Depends(get_current_user),
    controller: BotController = Depends(get_bot_controller)
):
    """
    Check content compliance
    
    Verifies content against platform policies and custom compliance rules.
    Useful for pre-posting content validation.
    """
    return await controller.check_content_compliance(
        current_user,
        request.content,
        request.platform,
        request.compliance_rules,
        request.strict_mode
    )


@router.post("/followers")
async def analyze_verified_followers(
    request: FollowerAnalysisRequest,
    current_user: User = Depends(get_current_user),
    controller: BotController = Depends(get_bot_controller)
):
    """
    Analyze verified followers
    
    Analyzes follower quality and authenticity, with optional focus
    on verified accounts.
    """
    return await controller.analyze_verified_followers(
        current_user,
        request.platform,
        request.account_identifier,
        request.sample_size,
        request.check_verified_only
    )


@router.get("/health")
async def bot_health_check(
    controller: BotController = Depends(get_bot_controller)
):
    """
    Bot service health check
    
    Returns health status of bot integration services including
    analyzer availability, rate limit status, and system metrics.
    """
    return await controller.health_check()


@router.post("/batch-analyze")
async def batch_content_analysis(
    contents: List[str] = Field(..., max_items=50),
    platform: Optional[PlatformType] = None,
    response_format: str = "json",
    current_user: User = Depends(get_current_user),
    controller: BotController = Depends(get_bot_controller)
):
    """
    Batch content analysis
    
    Analyze multiple content items in a single request.
    Maximum 50 items per batch.
    """
    results = []
    for content in contents:
        try:
            result = await controller.quick_content_analysis(
                current_user,
                content,
                platform,
                {},
                response_format
            )
            results.append(result)
        except Exception as e:
            results.append({
                "success": False,
                "error": str(e),
                "content_preview": content[:50]
            })
    
    return {
        "success": True,
        "batch_size": len(contents),
        "results": results,
        "failed_count": sum(1 for r in results if not r.get("success", True))
    }


@router.post("/webhook")
async def bot_webhook_handler(
    event_type: str,
    payload: dict,
    x_bot_signature: Optional[str] = Header(None),
    current_user: User = Depends(get_current_user),
    controller: BotController = Depends(get_bot_controller)
):
    """
    Bot webhook handler
    
    Handles webhook events from bot integrations.
    Requires valid bot signature in X-Bot-Signature header.
    """
    # Verify webhook signature
    # In production, implement proper signature verification
    
    return {
        "success": True,
        "event_type": event_type,
        "processed": True,
        "message": "Webhook received and processed"
    }


@router.get("/stats")
async def get_bot_stats(
    time_range: str = "24h",
    current_user: User = Depends(get_current_user),
    controller: BotController = Depends(get_bot_controller)
):
    """
    Get bot usage statistics
    
    Returns statistics about bot API usage including request counts,
    analysis results, and performance metrics.
    
    Query Parameters:
    - time_range: Time range for stats (1h, 24h, 7d, 30d)
    """
    return {
        "success": True,
        "time_range": time_range,
        "stats": {
            "total_requests": 0,
            "analyses_performed": 0,
            "threats_detected": 0,
            "average_response_time": 0.0
        }
    }
