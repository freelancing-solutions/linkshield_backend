"""
Social Protection Crisis Routes

API routes for crisis detection and management for brand protection.
"""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from linkshield.authentication.dependencies import get_current_user
from linkshield.config.database import get_db
from linkshield.models.user import User
from linkshield.social_protection.controllers.crisis_controller import CrisisController
from linkshield.social_protection.controllers.depends import get_crisis_controller

router = APIRouter(prefix="/api/v1/social-protection/crisis", tags=["Social Protection - Crisis"])


# Request/Response Models
class CrisisEvaluationRequest(BaseModel):
    """Model for crisis evaluation"""
    brand: str = Field(..., min_length=1, max_length=256)
    window_seconds: int = Field(default=3600, ge=300, le=86400)


class AlertStatusUpdate(BaseModel):
    """Model for updating alert status"""
    resolved: bool
    resolution_notes: Optional[str] = Field(None, max_length=1000)


@router.post("/evaluate")
async def evaluate_brand_crisis(
    request: CrisisEvaluationRequest,
    current_user: User = Depends(get_current_user),
    controller: CrisisController = Depends(get_crisis_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Evaluate a brand for crisis indicators
    
    Analyzes brand mentions and sentiment over a specified time window
    to detect potential crisis situations.
    
    Request Body:
    - brand: Brand name to evaluate
    - window_seconds: Time window in seconds (300-86400, default 3600)
    
    Returns crisis evaluation including:
    - Crisis detection status
    - Crisis score (0-1)
    - Severity level (OK, WARNING, HIGH, CRITICAL)
    - Signal breakdown (volume, sentiment, keywords, etc.)
    - Actionable recommendations
    """
    return await controller.evaluate_brand_crisis(
        current_user,
        request.brand,
        request.window_seconds,
        db
    )


@router.get("/alerts")
async def get_crisis_alerts(
    brand: Optional[str] = None,
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    controller: CrisisController = Depends(get_crisis_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve crisis alerts with optional filtering
    
    Query Parameters:
    - brand: Filter by brand name
    - severity: Filter by severity (OK, WARNING, HIGH, CRITICAL)
    - resolved: Filter by resolution status (true/false)
    - limit: Maximum number of alerts to return (1-100, default 50)
    - offset: Pagination offset (default 0)
    
    Returns paginated list of crisis alerts with filtering applied.
    """
    return await controller.get_crisis_alerts(
        current_user,
        brand,
        severity,
        resolved,
        limit,
        offset,
        db
    )


@router.get("/history")
async def get_crisis_history(
    brand: str,
    days: int = Query(default=30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    controller: CrisisController = Depends(get_crisis_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get historical crisis data for a brand
    
    Query Parameters:
    - brand: Brand name (required)
    - days: Number of days of history (1-365, default 30)
    
    Returns:
    - Historical timeline of crisis alerts
    - Summary statistics (total alerts, severity breakdown, etc.)
    - Trend analysis
    """
    return await controller.get_crisis_history(
        current_user,
        brand,
        days,
        db
    )


@router.put("/alerts/{alert_id}")
async def update_crisis_alert_status(
    alert_id: UUID,
    update: AlertStatusUpdate,
    current_user: User = Depends(get_current_user),
    controller: CrisisController = Depends(get_crisis_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Update the status of a crisis alert
    
    Path Parameters:
    - alert_id: UUID of the alert to update
    
    Request Body:
    - resolved: Whether the crisis is resolved
    - resolution_notes: Optional notes about the resolution
    
    Allows marking alerts as resolved or reopening them.
    """
    return await controller.update_crisis_status(
        current_user,
        alert_id,
        update.resolved,
        update.resolution_notes,
        db
    )


@router.get("/alerts/{alert_id}/recommendations")
async def get_crisis_recommendations(
    alert_id: UUID,
    current_user: User = Depends(get_current_user),
    controller: CrisisController = Depends(get_crisis_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get actionable recommendations for a crisis alert
    
    Path Parameters:
    - alert_id: UUID of the alert
    
    Returns prioritized list of actionable recommendations based on
    crisis severity and detected signals.
    """
    return await controller.get_crisis_recommendations(
        current_user,
        alert_id,
        db
    )


@router.get("/brands")
async def get_monitored_brands(
    current_user: User = Depends(get_current_user),
    controller: CrisisController = Depends(get_crisis_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get list of brands being monitored
    
    Returns list of brands with active monitoring including
    current status and recent alert counts.
    """
    # This would query the database for brands with recent alerts
    # For now, return a placeholder
    return {
        "success": True,
        "brands": [],
        "total_count": 0
    }


@router.get("/dashboard")
async def get_crisis_dashboard(
    current_user: User = Depends(get_current_user),
    controller: CrisisController = Depends(get_crisis_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get crisis management dashboard summary
    
    Returns comprehensive dashboard view including:
    - Active crisis alerts
    - Recent evaluations
    - Severity distribution
    - Trending brands
    - Quick stats
    """
    return {
        "success": True,
        "dashboard": {
            "active_alerts": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "warning_alerts": 0,
            "brands_monitored": 0,
            "recent_evaluations": []
        }
    }


@router.get("/stats")
async def get_crisis_stats(
    time_range: str = "30d",
    current_user: User = Depends(get_current_user),
    controller: CrisisController = Depends(get_crisis_controller),
    db: AsyncSession = Depends(get_db)
):
    """
    Get crisis detection statistics
    
    Query Parameters:
    - time_range: Time range for stats (7d, 30d, 90d)
    
    Returns statistics about crisis detection including
    alert counts, severity distribution, and resolution rates.
    """
    return {
        "success": True,
        "time_range": time_range,
        "stats": {
            "total_alerts": 0,
            "resolved_alerts": 0,
            "average_resolution_time_hours": 0.0,
            "severity_distribution": {
                "CRITICAL": 0,
                "HIGH": 0,
                "WARNING": 0,
                "OK": 0
            }
        }
    }
