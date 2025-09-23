#!/usr/bin/env python3
"""
LinkShield Backend URL Check Routes

API routes for URL analysis, security scanning, and threat detection.
"""

import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Depends, Query, Path, BackgroundTasks
from fastapi.security import HTTPBearer
from pydantic import BaseModel, HttpUrl, Field

from src.config.settings import get_settings
from src.models.url_check import CheckStatus, ThreatLevel, ScanType
from src.models.user import User

from src.authentication.dependencies import get_current_user, get_optional_user
from src.controllers.url_check_controller import URLCheckController
from src.controllers.depends import get_url_check_controller


# Initialize router
router = APIRouter(prefix="/api/v1/url-check", tags=["URL Analysis"])
security = HTTPBearer()
settings = get_settings()


# Request/Response Models
class URLCheckRequest(BaseModel):
    """
    URL check request model.
    """
    url: str = Field(..., description="URL to analyze", min_length=1, max_length=2048)
    scan_types: Optional[List[ScanType]] = Field(
        default=[ScanType.SECURITY, ScanType.REPUTATION, ScanType.CONTENT],
        description="Types of scans to perform"
    )
    priority: bool = Field(default=False, description="Whether to prioritize this scan")
    callback_url: Optional[HttpUrl] = Field(None, description="Webhook URL for async results")


class URLCheckResponse(BaseModel):
    """
    URL check response model.
    """
    id: uuid.UUID
    original_url: str
    normalized_url: str
    domain: str
    status: CheckStatus
    threat_level: Optional[ThreatLevel]
    confidence_score: Optional[int]
    scan_started_at: Optional[datetime]
    scan_completed_at: Optional[datetime]
    analysis_results: Optional[Dict[str, Any]]
    error_message: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class ScanResultResponse(BaseModel):
    """
    Scan result response model.
    """
    id: uuid.UUID
    scan_type: ScanType
    provider: str
    threat_detected: bool
    threat_types: List[str]
    confidence_score: int
    metadata: Dict[str, Any]
    created_at: datetime
    
    class Config:
        from_attributes = True


class URLReputationResponse(BaseModel):
    """
    URL reputation response model.
    """
    domain: str
    reputation_score: int
    total_checks: int
    malicious_count: int
    last_threat_level: Optional[ThreatLevel]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    
    class Config:
        from_attributes = True


class BulkURLCheckRequest(BaseModel):
    """
    Bulk URL check request model.
    """
    urls: List[str] = Field(..., description="URLs to analyze")
    scan_types: Optional[List[ScanType]] = Field(
        default=[ScanType.SECURITY, ScanType.REPUTATION],
        description="Types of scans to perform"
    )
    callback_url: Optional[HttpUrl] = Field(None, description="Webhook URL for async results")


class URLHistoryResponse(BaseModel):
    """
    URL history response model.
    """
    checks: List[URLCheckResponse]
    total_count: int
    page: int
    page_size: int


# API Routes
@router.post("/check", response_model=URLCheckResponse, summary="Analyze URL for threats")
async def check_url(
    request: URLCheckRequest,
    background_tasks: BackgroundTasks,
    controller: URLCheckController = Depends(get_url_check_controller),
    user: Optional[User] = Depends(get_optional_user) ):
    """
    Analyze a URL for security threats, malware, phishing, and other risks.

    Performs comprehensive analysis including:
    - Security scanning using multiple threat intelligence providers
    - AI-powered content analysis
    - Reputation checking based on historical data
    - Technical analysis of URL structure

    Args:
        request (URLCheckRequest): The request body containing the URL and scan options.
        background_tasks (BackgroundTasks): FastAPI background task manager.
        controller (URLCheckController): Dependency-injected controller.
        user (Optional[User]): The authenticated user, if any.

    Returns:
        URLCheckResponse: The result of the URL analysis.

    Rate Limits:
        - Authenticated users: 100 checks per hour
        - Anonymous users: 10 checks per hour

    Scan Types:
        - SECURITY: Malware and threat detection
        - REPUTATION: Historical reputation analysis
        - CONTENT: AI-powered content analysis
        - TECHNICAL: URL structure and hosting analysis

    Notes:
        Delegates business logic to URLCheckController.
    """
    return await controller.check_url(url=request.url, user=user, scan_types=request.scan_types,
                                      priority=request.priority, callback_url=request.callback_url)

@router.post("/bulk-check", response_model=List[URLCheckResponse], summary="Analyze multiple URLs")
async def bulk_check_urls(request: BulkURLCheckRequest, background_tasks: BackgroundTasks,
    controller: URLCheckController = Depends(get_url_check_controller), user: User = Depends(get_current_user)):
    """
    Analyze multiple URLs in a single request.

    Args:
        request (BulkURLCheckRequest): The request body containing a list of URLs and scan options.
        background_tasks (BackgroundTasks): FastAPI background task manager.
        controller (URLCheckController): Dependency-injected controller.
        user (User): The authenticated user (required).

    Returns:
        List[URLCheckResponse]: List of results for each URL.

    Limitations:
        - Maximum 100 URLs per request
        - Requires authentication
        - Higher rate limits apply

    Notes:
        Delegates business logic to URLCheckController.
    """
    return await controller.bulk_check_urls(urls=request.urls,scan_types=request.scan_types,
                                            callback_url=request.callback_url, user=user)

@router.get("/check/{check_id}", response_model=URLCheckResponse, summary="Get URL check results")
async def get_url_check(check_id: uuid.UUID = Path(..., description="URL check ID"),
                        controller: URLCheckController = Depends(get_url_check_controller),
                        user: Optional[User] = Depends(get_optional_user)):
    """
    Retrieve results of a specific URL check.

    Args:
        check_id (uuid.UUID): The unique identifier for the URL check.
        controller (URLCheckController): Dependency-injected controller.
        user (Optional[User]): The authenticated user, if any.

    Returns:
        URLCheckResponse: The result of the URL analysis.

    Notes:
        Delegates business logic to URLCheckController.
    """
    return await controller.get_url_check(check_id=check_id, user=user)

@router.get("/check/{check_id}/results", response_model=List[ScanResultResponse], summary="Get detailed scan results")
async def get_scan_results(check_id: uuid.UUID = Path(..., description="URL check ID"),
                           controller: URLCheckController = Depends(get_url_check_controller),
                           user: Optional[User] = Depends(get_optional_user)):
    """
    Get detailed scan results for a URL check.

    Args:
        check_id (uuid.UUID): The unique identifier for the URL check.
        controller (URLCheckController): Dependency-injected controller.
        user (Optional[User]): The authenticated user, if any.

    Returns:
        List[ScanResultResponse]: List of scan results from different providers.

    Notes:
        Delegates business logic to URLCheckController.
    """
    return await controller.get_scan_results(check_id=check_id, user=user)

@router.get("/history", response_model=URLHistoryResponse, summary="Get URL check history")
async def get_url_history(
    url: Optional[str] = Query(None, description="Filter by specific URL"),
    domain: Optional[str] = Query(None, description="Filter by domain"),
    threat_level: Optional[ThreatLevel] = Query(None, description="Filter by threat level"),
    status: Optional[CheckStatus] = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    controller: URLCheckController = Depends(get_url_check_controller),
    user: User = Depends(get_current_user)
):
    """
    Get URL check history for the authenticated user.

    Args:
        url (Optional[str]): Filter by specific URL.
        domain (Optional[str]): Filter by domain.
        threat_level (Optional[ThreatLevel]): Filter by threat level.
        status (Optional[CheckStatus]): Filter by status.
        page (int): Page number (default 1).
        page_size (int): Number of items per page (default 20, max 100).
        controller (URLCheckController): Dependency-injected controller.
        user (User): The authenticated user (required).

    Returns:
        URLHistoryResponse: Paginated list of URL checks.

    Notes:
        Delegates business logic to URLCheckController.
    """
    return await controller.get_url_history(url=url, domain=domain, threat_level=threat_level, status=status, page=page, page_size=page_size, user=user)

@router.get("/reputation/{domain}", response_model=URLReputationResponse, summary="Get domain reputation")
async def get_domain_reputation(
    domain: str = Path(..., description="Domain to check"),
    controller: URLCheckController = Depends(get_url_check_controller),
    user: Optional[User] = Depends(get_optional_user)
):
    """
    Get reputation information for a specific domain.

    Args:
        domain (str): The domain to check.
        controller (URLCheckController): Dependency-injected controller.
        user (Optional[User]): The authenticated user, if any.

    Returns:
        URLReputationResponse: Reputation data for the domain.

    Notes:
        Delegates business logic to URLCheckController.
    """
    return await controller.get_domain_reputation(domain, user)

@router.get("/stats", summary="Get URL check statistics")
async def get_url_check_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to include in stats"),
    user: User = Depends(get_current_user),
    controller: URLCheckController = Depends(get_url_check_controller)
):
    """
    Get URL check statistics for the authenticated user.

    Args:
        days (int): Number of days to include in statistics (default 30, max 365).
        user (User): The authenticated user (required).
        controller (URLCheckController): Dependency-injected controller.

    Returns:
        dict: Statistics for the user's URL checks.

    Notes:
        Delegates business logic to URLCheckController.
    """
    return await controller.get_url_check_statistics(days, user)
