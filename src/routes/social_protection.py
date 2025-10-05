#!/usr/bin/env python3
"""
Social Protection Routes (DEPRECATED)

⚠️ DEPRECATION WARNING ⚠️
These routes are deprecated and will be removed in a future version.

Please migrate to the new specialized routes:
- /api/v1/social-protection/user/* - For user dashboard operations
- /api/v1/social-protection/bot/* - For bot integration
- /api/v1/social-protection/extension/* - For browser extension integration
- /api/v1/social-protection/crisis/* - For crisis detection

FastAPI router for social media protection functionality including:
- Extension data processing
- Social profile scanning
- Content risk assessment
- Real-time monitoring
"""

import uuid
import warnings
from datetime import datetime
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Depends, Query, Path, BackgroundTasks, status, Response
from fastapi.security import HTTPBearer
from pydantic import BaseModel, HttpUrl, Field

from src.config.settings import get_settings
from src.models.user import User
from src.social_protection.data_models import ContentType
from src.social_protection.types import (
    PlatformType, ScanStatus, RiskLevel
)
from src.models.social_protection import AssessmentType
from src.social_protection.controllers.social_protection_controller import SocialProtectionController
from src.controllers.depends import get_social_protection_controller
from src.authentication.dependencies import get_current_user


# Initialize router
router = APIRouter(
    prefix="/api/v1/social-protection", 
    tags=["Social Protection (Deprecated)"],
    deprecated=True
)
security = HTTPBearer()
settings = get_settings()

# Deprecation warning
warnings.warn(
    "The /api/v1/social-protection routes are deprecated. "
    "Please use the new specialized routes: /user/*, /bot/*, /extension/*, /crisis/*",
    DeprecationWarning,
    stacklevel=2
)


def add_deprecation_headers(response: Response):
    """Add deprecation headers to response"""
    response.headers["X-API-Deprecated"] = "true"
    response.headers["X-API-Deprecation-Date"] = "2025-10-03"
    response.headers["X-API-Sunset-Date"] = "2026-01-01"
    response.headers["X-API-Migration-Guide"] = "https://docs.linkshield.com/migration/social-protection"
    response.headers["Warning"] = '299 - "This API endpoint is deprecated. Please migrate to the new specialized endpoints."'
    return response


# Request/Response Models

class ExtensionDataRequest(BaseModel):
    """Request model for processing extension data."""
    data: Dict[str, Any] = Field(..., description="Raw data from browser extension")
    project_id: Optional[uuid.UUID] = Field(None, description="Optional project ID for organization")
    
    class Config:
        json_schema_extra = {
            "example": {
                "data": {
                    "url": "https://example.com/profile",
                    "content_type": "social_profile",
                    "platform": "twitter",
                    "content": "Profile content data...",
                    "metadata": {
                        "timestamp": "2024-01-01T00:00:00Z",
                        "user_agent": "Mozilla/5.0..."
                    }
                },
                "project_id": "123e4567-e89b-12d3-a456-426614174000"
            }
        }


class ExtensionDataResponse(BaseModel):
    """Response model for extension data processing."""
    processing_id: str
    risk_level: Optional[RiskLevel]
    confidence_score: Optional[float]
    alerts: List[Dict[str, Any]]
    requires_deep_analysis: bool
    processed_at: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "processing_id": "proc_123456789",
                "risk_level": "medium",
                "confidence_score": 0.75,
                "alerts": [
                    {
                        "type": "suspicious_content",
                        "message": "Potentially harmful content detected",
                        "severity": "medium"
                    }
                ],
                "requires_deep_analysis": True,
                "processed_at": "2024-01-01T00:00:00Z"
            }
        }


class SocialScanRequest(BaseModel):
    """Request model for initiating social media scans."""
    platform: PlatformType = Field(..., description="Social media platform")
    profile_url: str = Field(..., description="URL of the profile to scan", min_length=1, max_length=2048)
    project_id: Optional[uuid.UUID] = Field(None, description="Optional project ID for organization")
    scan_depth: str = Field(default="basic", description="Depth of scan (basic, detailed, comprehensive)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "platform": "twitter",
                "profile_url": "https://twitter.com/example_user",
                "project_id": "123e4567-e89b-12d3-a456-426614174000",
                "scan_depth": "detailed"
            }
        }


class SocialScanResponse(BaseModel):
    """Response model for social media scans."""
    id: uuid.UUID
    platform: PlatformType
    profile_url: str
    status: ScanStatus
    scan_depth: str
    risk_level: Optional[RiskLevel]
    confidence_score: Optional[float]
    findings: Optional[Dict[str, Any]]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class ContentAssessmentRequest(BaseModel):
    """Request model for content risk assessment."""
    content_type: ContentType = Field(..., description="Type of content being assessed")
    content_data: Dict[str, Any] = Field(..., description="Content data and metadata")
    project_id: Optional[uuid.UUID] = Field(None, description="Optional project ID for organization")
    assessment_type: AssessmentType = Field(default=AssessmentType.CONTENT_RISK, description="Type of assessment")
    
    class Config:
        json_schema_extra = {
            "example": {
                "content_type": "text",
                "content_data": {
                    "text": "Content to be assessed...",
                    "source_url": "https://example.com/post",
                    "metadata": {
                        "author": "user123",
                        "timestamp": "2024-01-01T00:00:00Z"
                    }
                },
                "project_id": "123e4567-e89b-12d3-a456-426614174000",
                "assessment_type": "automated"
            }
        }


class ContentAssessmentResponse(BaseModel):
    """Response model for content risk assessment."""
    id: uuid.UUID
    content_type: ContentType
    assessment_type: AssessmentType
    risk_level: Optional[RiskLevel]
    confidence_score: Optional[float]
    risk_factors: Optional[List[str]]
    recommendations: Optional[List[str]]
    created_at: datetime
    
    class Config:
        from_attributes = True


# Extension Data Processing Endpoints

@router.post(
    "/extension/process",
    response_model=ExtensionDataResponse,
    status_code=status.HTTP_200_OK,
    summary="Process extension data (DEPRECATED)",
    description="⚠️ DEPRECATED: Use /api/v1/social-protection/extension/process instead. Process data received from browser extension for real-time analysis",
    deprecated=True,
    operation_id="process_extension_data_deprecated"
)
async def process_extension_data_deprecated(
    request: ExtensionDataRequest,
    response: Response,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    controller: SocialProtectionController = Depends(get_social_protection_controller)
) -> ExtensionDataResponse:
    """Process data from browser extension.
    
    ⚠️ DEPRECATED: This endpoint is deprecated. Please use:
    POST /api/v1/social-protection/extension/process
    """
    add_deprecation_headers(response)
    
    result = await controller.process_extension_data(
        data=request.data,
        user=current_user,
        project_id=request.project_id,
        background_tasks=background_tasks
    )
    
    return ExtensionDataResponse(
        processing_id=result.get("processing_id", ""),
        risk_level=result.get("risk_level"),
        confidence_score=result.get("confidence_score"),
        alerts=result.get("alerts", []),
        requires_deep_analysis=result.get("requires_deep_analysis", False),
        processed_at=datetime.utcnow()
    )


# Social Media Scanning Endpoints

@router.post(
    "/scans",
    response_model=SocialScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate social media scan",
    description="Start a comprehensive scan of a social media profile"
)
async def initiate_social_scan(
    request: SocialScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    controller: SocialProtectionController = Depends(get_social_protection_controller)
) -> SocialScanResponse:
    """Initiate a social media profile scan."""
    scan = await controller.initiate_social_scan(
        platform=request.platform,
        profile_url=request.profile_url,
        user=current_user,
        project_id=request.project_id,
        scan_depth=request.scan_depth,
        background_tasks=background_tasks
    )
    
    return SocialScanResponse.model_validate(scan)


@router.get(
    "/scans/{scan_id}",
    response_model=SocialScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Get scan status",
    description="Retrieve the current status and results of a social media scan"
)
async def get_scan_status(
    scan_id: uuid.UUID = Path(..., description="ID of the scan to retrieve"),
    current_user: User = Depends(get_current_user),
    controller: SocialProtectionController = Depends(get_social_protection_controller)
) -> SocialScanResponse:
    """Get the status of a social media scan."""
    scan = await controller.get_scan_status(scan_id=scan_id, user=current_user)
    return SocialScanResponse.model_validate(scan)


@router.get(
    "/scans",
    response_model=List[SocialScanResponse],
    status_code=status.HTTP_200_OK,
    summary="List user scans",
    description="Retrieve a list of social media scans for the current user"
)
async def list_user_scans(
    project_id: Optional[uuid.UUID] = Query(None, description="Filter by project ID"),
    platform: Optional[PlatformType] = Query(None, description="Filter by platform"),
    status: Optional[ScanStatus] = Query(None, description="Filter by scan status"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: User = Depends(get_current_user),
    controller: SocialProtectionController = Depends(get_social_protection_controller)
) -> List[SocialScanResponse]:
    """List social media scans for the current user."""
    scans = await controller.get_user_scans(
        user=current_user,
        project_id=project_id,
        platform=platform,
        status=status,
        limit=limit,
        offset=offset
    )
    
    return [SocialScanResponse.model_validate(scan) for scan in scans]


# Content Risk Assessment Endpoints

@router.post(
    "/assessments",
    response_model=ContentAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create content assessment",
    description="Create a risk assessment for specific content"
)
async def create_content_assessment(
    request: ContentAssessmentRequest,
    current_user: User = Depends(get_current_user),
    controller: SocialProtectionController = Depends(get_social_protection_controller)
) -> ContentAssessmentResponse:
    """Create a content risk assessment."""
    assessment = await controller.create_content_assessment(
        content_type=request.content_type,
        content_data=request.content_data,
        user=current_user,
        project_id=request.project_id,
        assessment_type=request.assessment_type
    )
    
    return ContentAssessmentResponse.model_validate(assessment)


@router.get(
    "/assessments",
    response_model=List[ContentAssessmentResponse],
    status_code=status.HTTP_200_OK,
    summary="List user assessments",
    description="Retrieve a list of content risk assessments for the current user"
)
async def list_user_assessments(
    project_id: Optional[uuid.UUID] = Query(None, description="Filter by project ID"),
    content_type: Optional[ContentType] = Query(None, description="Filter by content type"),
    risk_level: Optional[RiskLevel] = Query(None, description="Filter by risk level"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: User = Depends(get_current_user),
    controller: SocialProtectionController = Depends(get_social_protection_controller)
) -> List[ContentAssessmentResponse]:
    """List content risk assessments for the current user."""
    assessments = await controller.get_user_assessments(
        user=current_user,
        project_id=project_id,
        content_type=content_type,
        risk_level=risk_level,
        limit=limit,
        offset=offset
    )
    
    return [ContentAssessmentResponse.model_validate(assessment) for assessment in assessments]


# Health and Status Endpoints

@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Social protection health check",
    description="Check the health status of social protection services including analyzers, platform adapters, and core services"
)
async def health_check(
    controller: SocialProtectionController = Depends(get_social_protection_controller)
) -> Dict[str, Any]:
    """
    Comprehensive health check for social protection services.
    
    Checks the operational status of:
    - Core services (extension processor, scan service)
    - Content analyzers (risk, spam, link penalty, community notes)
    - Algorithm health analyzers (visibility, engagement, penalty, shadow ban)
    - Platform adapters (Twitter, Meta, TikTok, LinkedIn, Telegram, Discord)
    - Crisis detection system
    
    Returns:
        Dict with status, timestamp, and detailed service health information
        
    Status Codes:
        200: All services healthy or degraded but operational
        503: Critical services unavailable
    """
    return await controller.get_health_status()