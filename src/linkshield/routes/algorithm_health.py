#!/usr/bin/env python3
"""
Algorithm Health Routes

FastAPI router for social media algorithm health monitoring including:
- Visibility scoring and analysis
- Engagement pattern analysis
- Penalty detection and monitoring
- Shadow ban detection and assessment

Note: All business logic is implemented in UserController.
Routes handle only HTTP concerns and delegate to controller methods.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Depends, Query, Path, BackgroundTasks, status, HTTPException
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, field_validator

from linkshield.config.settings import get_settings
from linkshield.models.user import User
from linkshield.social_protection.types import PlatformType, RiskLevel
from linkshield.social_protection.algorithm_health.visibility_scorer import VisibilityTrend, VisibilityFactor
from linkshield.social_protection.algorithm_health.engagement_analyzer import EngagementType, EngagementQuality, EngagementPattern
from linkshield.social_protection.algorithm_health.penalty_detector import PenaltyType, PenaltySeverity, PenaltyStatus
from linkshield.social_protection.algorithm_health.shadow_ban_detector import ShadowBanType, ShadowBanSeverity, DetectionMethod
from linkshield.social_protection.controllers.depends import get_user_controller
from linkshield.authentication.dependencies import get_current_user


# Initialize router
router = APIRouter(prefix="/api/v1/social/algorithm-health", tags=["Algorithm Health"])
security = HTTPBearer()
settings = get_settings()


# Request/Response Models

class VisibilityAnalysisRequest(BaseModel):
    """Request model for visibility analysis."""
    account_id: str = Field(..., description="Social media account identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    content_ids: List[str] = Field(..., description="List of content IDs to analyze")
    time_range_hours: int = Field(24, ge=1, le=168, description="Analysis time range in hours")
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_id": "user123",
                "platform": "twitter",
                "content_ids": ["tweet_1", "tweet_2", "tweet_3"],
                "time_range_hours": 24
            }
        }


class VisibilityMetricsResponse(BaseModel):
    """Response model for visibility metrics."""
    account_id: str
    platform: PlatformType
    visibility_score: float = Field(..., ge=0.0, le=100.0)
    trend: VisibilityTrend
    factors: List[VisibilityFactor]
    reach_metrics: Dict[str, Any]
    impression_data: Dict[str, Any]
    analysis_timestamp: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_id": "user123",
                "platform": "twitter",
                "visibility_score": 75.5,
                "trend": "stable",
                "factors": ["content_quality", "engagement_rate"],
                "reach_metrics": {"organic_reach": 1500, "total_reach": 2000},
                "impression_data": {"impressions": 5000, "unique_views": 3000},
                "analysis_timestamp": "2024-01-25T10:30:00Z"
            }
        }


class EngagementAnalysisRequest(BaseModel):
    """Request model for engagement analysis."""
    account_id: str = Field(..., description="Social media account identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    content_ids: Optional[List[str]] = Field(None, description="Specific content IDs to analyze")
    engagement_types: List[EngagementType] = Field(default_factory=list, description="Types of engagement to analyze")
    time_range_hours: int = Field(24, ge=1, le=168, description="Analysis time range in hours")
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_id": "user123",
                "platform": "twitter",
                "content_ids": ["tweet_1", "tweet_2"],
                "engagement_types": ["like", "retweet", "reply"],
                "time_range_hours": 48
            }
        }


class EngagementAnalysisResponse(BaseModel):
    """Response model for engagement analysis."""
    account_id: str
    platform: PlatformType
    overall_quality: EngagementQuality
    patterns: List[EngagementPattern]
    engagement_metrics: Dict[str, Any]
    quality_score: float = Field(..., ge=0.0, le=100.0)
    anomalies: List[Dict[str, Any]]
    recommendations: List[str]
    analysis_timestamp: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_id": "user123",
                "platform": "twitter",
                "overall_quality": "high",
                "patterns": ["consistent_engagement", "peak_hours_activity"],
                "engagement_metrics": {"avg_likes": 50, "avg_retweets": 15},
                "quality_score": 82.3,
                "anomalies": [],
                "recommendations": ["Post during peak hours", "Increase visual content"],
                "analysis_timestamp": "2024-01-25T10:30:00Z"
            }
        }


class PenaltyDetectionRequest(BaseModel):
    """Request model for penalty detection."""
    account_id: str = Field(..., description="Social media account identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    check_types: List[PenaltyType] = Field(default_factory=list, description="Types of penalties to check")
    historical_analysis: bool = Field(False, description="Include historical penalty analysis")
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_id": "user123",
                "platform": "twitter",
                "check_types": ["reach_limit", "engagement_throttle"],
                "historical_analysis": True
            }
        }


class PenaltyDetectionResponse(BaseModel):
    """Response model for penalty detection."""
    account_id: str
    platform: PlatformType
    penalties_detected: List[Dict[str, Any]]
    overall_status: PenaltyStatus
    severity_level: PenaltySeverity
    affected_metrics: List[str]
    recovery_timeline: Optional[Dict[str, Any]]
    recommendations: List[str]
    analysis_timestamp: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_id": "user123",
                "platform": "twitter",
                "penalties_detected": [
                    {
                        "type": "reach_limit",
                        "severity": "moderate",
                        "detected_at": "2024-01-24T15:00:00Z",
                        "confidence": 0.85
                    }
                ],
                "overall_status": "penalty_detected",
                "severity_level": "moderate",
                "affected_metrics": ["organic_reach", "impression_rate"],
                "recovery_timeline": {"estimated_days": 7, "confidence": 0.7},
                "recommendations": ["Reduce posting frequency", "Focus on quality content"],
                "analysis_timestamp": "2024-01-25T10:30:00Z"
            }
        }


class ShadowBanDetectionRequest(BaseModel):
    """Request model for shadow ban detection."""
    account_id: str = Field(..., description="Social media account identifier")
    platform: PlatformType = Field(..., description="Social media platform")
    detection_methods: List[DetectionMethod] = Field(default_factory=list, description="Detection methods to use")
    comprehensive_check: bool = Field(False, description="Perform comprehensive multi-method check")
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_id": "user123",
                "platform": "twitter",
                "detection_methods": ["visibility_drop", "engagement_analysis"],
                "comprehensive_check": True
            }
        }


class ShadowBanDetectionResponse(BaseModel):
    """Response model for shadow ban detection."""
    account_id: str
    platform: PlatformType
    shadow_ban_detected: bool
    ban_types: List[ShadowBanType]
    severity: ShadowBanSeverity
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    detection_methods_used: List[DetectionMethod]
    evidence: List[Dict[str, Any]]
    recovery_suggestions: List[str]
    monitoring_recommendations: List[str]
    analysis_timestamp: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_id": "user123",
                "platform": "twitter",
                "shadow_ban_detected": True,
                "ban_types": ["search_suggestion"],
                "severity": "moderate",
                "confidence_score": 0.78,
                "detection_methods_used": ["visibility_drop", "engagement_analysis"],
                "evidence": [
                    {
                        "method": "visibility_drop",
                        "metric": "search_visibility",
                        "drop_percentage": 65,
                        "timeframe": "7_days"
                    }
                ],
                "recovery_suggestions": ["Appeal to platform", "Modify content strategy"],
                "monitoring_recommendations": ["Daily visibility checks", "Engagement tracking"],
                "analysis_timestamp": "2024-01-25T10:30:00Z"
            }
        }


class BatchAnalysisRequest(BaseModel):
    """Request model for batch algorithm health analysis."""
    account_ids: List[str] = Field(..., min_items=1, max_items=50, description="List of account IDs")
    platform: PlatformType = Field(..., description="Social media platform")
    analysis_types: List[str] = Field(..., description="Types of analysis to perform")
    priority: str = Field("normal", description="Analysis priority level")
    
    @field_validator('analysis_types')
    def validate_analysis_types(cls, v):
        valid_types = ["visibility", "engagement", "penalty", "shadow_ban"]
        for analysis_type in v:
            if analysis_type not in valid_types:
                raise ValueError(f"Invalid analysis type: {analysis_type}")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "account_ids": ["user123", "user456", "user789"],
                "platform": "twitter",
                "analysis_types": ["visibility", "penalty"],
                "priority": "high"
            }
        }


class BatchAnalysisResponse(BaseModel):
    """Response model for batch analysis."""
    batch_id: str
    total_accounts: int
    completed_analyses: int
    failed_analyses: int
    status: str
    results: List[Dict[str, Any]]
    started_at: datetime
    completed_at: Optional[datetime]
    
    class Config:
        json_schema_extra = {
            "example": {
                "batch_id": "batch_123",
                "total_accounts": 3,
                "completed_analyses": 3,
                "failed_analyses": 0,
                "status": "completed",
                "results": [
                    {
                        "account_id": "user123",
                        "visibility_score": 75.5,
                        "penalties_detected": 0,
                        "status": "healthy"
                    }
                ],
                "started_at": "2024-01-25T10:00:00Z",
                "completed_at": "2024-01-25T10:15:00Z"
            }
        }


# Visibility Scoring Endpoints

@router.post("/visibility/analyze", response_model=VisibilityMetricsResponse)
async def analyze_visibility(
    request: VisibilityAnalysisRequest,
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Analyze content visibility and reach metrics for a social media account.
    
    This endpoint provides comprehensive visibility analysis including:
    - Visibility score calculation
    - Trend analysis
    - Reach and impression metrics
    - Visibility factors identification
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.analyze_visibility(
            user=current_user,
            account_id=request.account_id,
            platform=request.platform,
            content_ids=request.content_ids,
            time_range_hours=request.time_range_hours
        )
        
        return VisibilityMetricsResponse(
            account_id=request.account_id,
            platform=request.platform,
            visibility_score=result["visibility_score"],
            trend=result["trend"],
            factors=result["factors"],
            reach_metrics=result["reach_metrics"],
            impression_data=result["impression_data"],
            analysis_timestamp=datetime.fromisoformat(result["analysis_timestamp"])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Visibility analysis failed: {str(e)}"
        )


@router.get("/visibility/trends/{account_id}")
async def get_visibility_trends(
    account_id: str = Path(..., description="Account ID"),
    platform: PlatformType = Query(..., description="Social media platform"),
    days: int = Query(7, ge=1, le=30, description="Number of days for trend analysis"),
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Get visibility trends for an account over a specified time period.
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.get_visibility_trends(
            user=current_user,
            account_id=account_id,
            platform=platform,
            days=days
        )
        
        return {
            "account_id": account_id,
            "platform": platform,
            "time_period_days": days,
            "trends": result["trends"],
            "generated_at": datetime.utcnow()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Trend analysis failed: {str(e)}"
        )


# Engagement Analysis Endpoints

@router.post("/engagement/analyze", response_model=EngagementAnalysisResponse)
async def analyze_engagement(
    request: EngagementAnalysisRequest,
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Analyze engagement patterns and quality for a social media account.
    
    This endpoint provides comprehensive engagement analysis including:
    - Engagement quality assessment
    - Pattern identification
    - Anomaly detection
    - Optimization recommendations
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.analyze_engagement(
            user=current_user,
            account_id=request.account_id,
            platform=request.platform,
            content_ids=request.content_ids,
            engagement_types=request.engagement_types,
            time_range_hours=request.time_range_hours
        )
        
        return EngagementAnalysisResponse(
            account_id=request.account_id,
            platform=request.platform,
            overall_quality=result["overall_quality"],
            patterns=result["patterns"],
            engagement_metrics=result["engagement_metrics"],
            quality_score=result["quality_score"],
            anomalies=result["anomalies"],
            recommendations=result["recommendations"],
            analysis_timestamp=datetime.fromisoformat(result["analysis_timestamp"])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Engagement analysis failed: {str(e)}"
        )


@router.get("/engagement/patterns/{account_id}")
async def get_engagement_patterns(
    account_id: str = Path(..., description="Account ID"),
    platform: PlatformType = Query(..., description="Social media platform"),
    pattern_type: Optional[str] = Query(None, description="Specific pattern type to analyze"),
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Get engagement patterns for an account.
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.get_engagement_patterns(
            user=current_user,
            account_id=account_id,
            platform=platform,
            pattern_type=pattern_type
        )
        
        return {
            "account_id": account_id,
            "platform": platform,
            "patterns": result["patterns"],
            "generated_at": datetime.utcnow()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pattern analysis failed: {str(e)}"
        )


# Penalty Detection Endpoints

@router.post("/penalty/detect", response_model=PenaltyDetectionResponse)
async def detect_penalties(
    request: PenaltyDetectionRequest,
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Detect algorithmic penalties affecting a social media account.
    
    This endpoint provides comprehensive penalty detection including:
    - Multiple penalty type detection
    - Severity assessment
    - Recovery timeline estimation
    - Mitigation recommendations
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.detect_penalties(
            user=current_user,
            account_id=request.account_id,
            platform=request.platform,
            check_types=request.check_types,
            historical_analysis=request.historical_analysis
        )
        
        return PenaltyDetectionResponse(
            account_id=request.account_id,
            platform=request.platform,
            penalties_detected=result["penalties_detected"],
            overall_status=result["overall_status"],
            severity_level=result["severity_level"],
            affected_metrics=result["affected_metrics"],
            recovery_timeline=result["recovery_timeline"],
            recommendations=result["recommendations"],
            analysis_timestamp=datetime.fromisoformat(result["analysis_timestamp"])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Penalty detection failed: {str(e)}"
        )


@router.get("/penalty/monitor/{account_id}")
async def monitor_penalties(
    account_id: str = Path(..., description="Account ID"),
    platform: PlatformType = Query(..., description="Social media platform"),
    continuous: bool = Query(False, description="Enable continuous monitoring"),
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Monitor an account for ongoing penalties and changes.
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.monitor_penalties(
            user=current_user,
            account_id=account_id,
            platform=platform,
            continuous=continuous
        )
        
        return {
            "account_id": account_id,
            "platform": platform,
            "monitoring_active": continuous,
            "current_status": result["monitoring_result"],
            "last_check": datetime.utcnow()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Penalty monitoring failed: {str(e)}"
        )


# Shadow Ban Detection Endpoints

@router.post("/shadow-ban/detect", response_model=ShadowBanDetectionResponse)
async def detect_shadow_ban(
    request: ShadowBanDetectionRequest,
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Detect shadow bans affecting a social media account.
    
    This endpoint provides comprehensive shadow ban detection including:
    - Multiple detection methods
    - Ban type identification
    - Confidence scoring
    - Recovery recommendations
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.detect_shadow_ban(
            user=current_user,
            account_id=request.account_id,
            platform=request.platform,
            detection_methods=request.detection_methods,
            comprehensive_check=request.comprehensive_check
        )
        
        return ShadowBanDetectionResponse(
            account_id=request.account_id,
            platform=request.platform,
            shadow_ban_detected=result["shadow_ban_detected"],
            ban_types=result["ban_types"],
            severity=result["severity"],
            confidence_score=result["confidence_score"],
            detection_methods_used=result["detection_methods_used"],
            evidence=result["evidence"],
            recovery_suggestions=result["recovery_suggestions"],
            monitoring_recommendations=result["monitoring_recommendations"],
            analysis_timestamp=datetime.fromisoformat(result["analysis_timestamp"])
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Shadow ban detection failed: {str(e)}"
        )


@router.get("/shadow-ban/monitor/{account_id}")
async def monitor_shadow_ban(
    account_id: str = Path(..., description="Account ID"),
    platform: PlatformType = Query(..., description="Social media platform"),
    alert_threshold: float = Query(0.7, ge=0.0, le=1.0, description="Alert confidence threshold"),
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Monitor an account for shadow ban indicators.
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.monitor_shadow_ban(
            user=current_user,
            account_id=account_id,
            platform=platform,
            alert_threshold=alert_threshold
        )
        
        return {
            "account_id": account_id,
            "platform": platform,
            "monitoring_active": True,
            "alert_threshold": alert_threshold,
            "current_status": result["monitoring_result"],
            "last_check": datetime.utcnow()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Shadow ban monitoring failed: {str(e)}"
        )


# Batch Analysis Endpoints

@router.post("/batch/analyze", response_model=BatchAnalysisResponse)
async def batch_analyze(
    request: BatchAnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Perform batch algorithm health analysis for multiple accounts.
    
    This endpoint allows analyzing multiple accounts simultaneously for:
    - Visibility metrics
    - Engagement patterns
    - Penalty detection
    - Shadow ban detection
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.batch_analyze_algorithm_health(
            user=current_user,
            request=request,
            background_tasks=background_tasks
        )
        
        return BatchAnalysisResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch analysis initialization failed: {str(e)}"
        )


@router.get("/batch/status/{batch_id}")
async def get_batch_status(
    batch_id: str = Path(..., description="Batch analysis ID"),
    current_user: User = Depends(get_current_user),
    user_controller = Depends(get_user_controller)
):
    """
    Get the status of a batch analysis operation.
    """
    try:
        # Delegate to controller for business logic
        result = await user_controller.get_batch_analysis_status(
            user=current_user,
            batch_id=batch_id
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch status retrieval failed: {str(e)}"
        )


# Health Check Endpoint

@router.get("/health")
async def algorithm_health_check():
    """
    Health check endpoint for algorithm health service.
    """
    return {
        "service": "algorithm_health",
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "version": "1.0.0"
    }