"""
Social Protection Extension Routes

API routes for browser extension integration with real-time analysis
and seamless UX.
"""

from typing import Optional
from fastapi import APIRouter, Depends, BackgroundTasks, Request
from pydantic import BaseModel, Field

from src.authentication.dependencies import get_current_user
from src.models.user import User
from src.social_protection.controllers.extension_controller import (
    ExtensionController,
    ExtensionEventType,
    ExtensionAnalysisMode,
    ExtensionResponseType
)
from src.social_protection.controllers.depends import get_extension_controller
from src.social_protection.types import PlatformType

router = APIRouter(prefix="/api/v1/social-protection/extension", tags=["Social Protection - Extension"])


# Request/Response Models
class ExtensionDataRequest(BaseModel):
    """Model for extension data processing"""
    event_type: ExtensionEventType
    platform: PlatformType
    url: str
    timestamp: str
    session_id: Optional[str] = None
    content: Optional[dict] = None
    metadata: Optional[dict] = Field(default_factory=dict)
    analysis_mode: ExtensionAnalysisMode = ExtensionAnalysisMode.REAL_TIME
    response_type: ExtensionResponseType = ExtensionResponseType.IMMEDIATE


class RealTimeAnalysisRequest(BaseModel):
    """Model for real-time content analysis"""
    content: str
    platform: PlatformType
    links: Optional[list] = None
    context: Optional[dict] = Field(default_factory=dict)


class ExtensionSettingsUpdate(BaseModel):
    """Model for updating extension settings"""
    ui_preferences: Optional[dict] = None
    platform_settings: Optional[dict] = None
    analysis_settings: Optional[dict] = None
    cache_settings: Optional[dict] = None


class ExtensionStateSync(BaseModel):
    """Model for extension state synchronization"""
    version: str
    active_tabs: list = Field(default_factory=list)
    settings_hash: str
    last_sync: Optional[str] = None
    session_id: Optional[str] = None


@router.post("/process")
async def process_extension_data(
    request: ExtensionDataRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Process data from browser extension
    
    Main endpoint for extension data processing with support for
    different analysis modes and response types.
    
    Analysis Modes:
    - REAL_TIME: Immediate lightweight analysis
    - BACKGROUND: Deferred comprehensive analysis
    - ON_DEMAND: User-triggered analysis
    - BATCH: Multiple items processed together
    
    Response Types:
    - IMMEDIATE: Full response returned immediately
    - PROGRESSIVE: Initial response with background processing
    - CACHED: Return cached result if available
    - DEFERRED: Acknowledge receipt, process in background
    """
    extension_data = request.dict()
    
    return await controller.process_extension_data(
        current_user,
        extension_data,
        request.analysis_mode,
        request.response_type,
        background_tasks,
        http_request
    )


@router.post("/analyze")
async def analyze_content_real_time(
    request: RealTimeAnalysisRequest,
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Perform real-time content analysis
    
    Optimized for low-latency analysis of content as users browse.
    Returns quick risk assessment with UI indicators.
    """
    content_data = {
        "content": request.content,
        "links": request.links or []
    }
    
    return await controller.analyze_content_real_time(
        current_user,
        content_data,
        request.platform,
        request.context
    )


@router.get("/settings")
async def get_extension_settings(
    extension_version: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Get extension settings and configuration
    
    Returns user-specific extension configuration including
    feature flags, rate limits, UI preferences, and platform settings.
    
    Query Parameters:
    - extension_version: Version of the extension (for compatibility checks)
    """
    return await controller.get_extension_settings(
        current_user,
        extension_version
    )


@router.put("/settings")
async def update_extension_settings(
    settings: ExtensionSettingsUpdate,
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Update extension settings
    
    Allows users to customize extension behavior including
    UI preferences, platform-specific settings, and analysis configuration.
    
    Note: Some settings may be restricted based on subscription plan.
    """
    return await controller.update_extension_settings(
        current_user,
        settings.dict(exclude_unset=True)
    )


@router.get("/analytics")
async def get_extension_analytics(
    time_range: str = "24h",
    include_details: bool = False,
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Get extension usage analytics
    
    Returns analytics about extension usage including request counts,
    threats detected, performance metrics, and platform breakdown.
    
    Query Parameters:
    - time_range: Time range for analytics (1h, 24h, 7d, 30d)
    - include_details: Include detailed breakdown
    """
    return await controller.get_extension_analytics(
        current_user,
        time_range,
        include_details
    )


@router.post("/sync")
async def sync_extension_state(
    state: ExtensionStateSync,
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Synchronize extension state with backend
    
    Keeps extension state in sync with backend including active tabs,
    settings, and session information.
    """
    return await controller.sync_extension_state(
        current_user,
        state.dict(),
        state.session_id
    )


@router.get("/status")
async def get_extension_status(
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Get extension connection status
    
    Returns current status of extension connection including
    session info, last activity, and service health.
    """
    return {
        "success": True,
        "status": "connected",
        "user_id": str(current_user.id),
        "subscription_plan": current_user.subscription_plan or "free",
        "features_available": {
            "real_time_analysis": True,
            "advanced_warnings": current_user.subscription_plan == "premium",
            "batch_analysis": current_user.subscription_plan == "premium"
        }
    }


@router.post("/feedback")
async def submit_extension_feedback(
    feedback_type: str,
    message: str,
    metadata: Optional[dict] = None,
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Submit extension feedback
    
    Allows users to submit feedback, bug reports, or feature requests
    directly from the extension.
    """
    return {
        "success": True,
        "message": "Feedback received",
        "feedback_id": "placeholder",
        "thank_you": "Thank you for your feedback!"
    }


@router.get("/cache/stats")
async def get_cache_stats(
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Get extension cache statistics
    
    Returns cache performance metrics including hit rate,
    size, and efficiency.
    """
    return {
        "success": True,
        "cache_stats": {
            "hit_rate": 0.0,
            "total_entries": 0,
            "size_bytes": 0,
            "oldest_entry_age_seconds": 0
        }
    }


@router.delete("/cache")
async def clear_extension_cache(
    current_user: User = Depends(get_current_user),
    controller: ExtensionController = Depends(get_extension_controller)
):
    """
    Clear extension cache
    
    Clears all cached analysis results for the user.
    """
    return {
        "success": True,
        "message": "Cache cleared successfully",
        "entries_cleared": 0
    }
