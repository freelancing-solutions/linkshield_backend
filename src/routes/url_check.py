#!/usr/bin/env python3
"""
LinkShield Backend URL Check Routes

API routes for URL analysis, security scanning, and threat detection.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, HttpUrl, Field, validator
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from src.config.database import get_db
from src.config.settings import get_settings
from src.models.url_check import URLCheck, ScanResult, URLReputation, CheckStatus, ThreatLevel, ScanType
from src.models.user import User
from src.services.url_analysis_service import URLAnalysisService, URLAnalysisError, InvalidURLError
from src.services.ai_service import AIService
from src.services.security_service import SecurityService, AuthenticationError, RateLimitError
from src.authentication.auth_service import AuthService


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
    
    @validator('url')
    def validate_url(cls, v):
        if not v or not v.strip():
            raise ValueError("URL cannot be empty")
        
        # Basic URL validation
        v = v.strip()
        if not (v.startswith('http://') or v.startswith('https://') or '.' in v):
            raise ValueError("Invalid URL format")
        
        return v


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
    urls: List[str] = Field(..., min_items=1, max_items=100, description="URLs to analyze")
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


# Dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> Optional[User]:
    """
    Get current authenticated user.
    """
    try:
        auth_service = AuthService(db)
        security_service = SecurityService(db)
        
        # Verify JWT token
        token_data = security_service.verify_jwt_token(credentials.credentials)
        user_id = token_data.get("user_id")
        session_id = token_data.get("session_id")
        
        if not user_id or not session_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Validate session
        is_valid, session = security_service.validate_session(session_id, user_id)
        if not is_valid:
            raise HTTPException(status_code=401, detail="Session expired")
        
        # Get user
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        return user
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Authentication failed")


async def get_optional_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security), db: Session = Depends(get_db)) -> Optional[User]:
    """
    Get current user if authenticated, otherwise None.
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


async def check_rate_limits(user: Optional[User], db: Session = Depends(get_db)) -> None:
    """
    Check rate limits for user.
    """
    security_service = SecurityService(db)
    
    identifier = str(user.id) if user else "anonymous"
    
    # Check API request rate limit
    is_allowed, limit_info = security_service.check_rate_limit(identifier, "api_requests", "127.0.0.1")
    if not is_allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {limit_info['retry_after']:.0f} seconds",
            headers={"Retry-After": str(int(limit_info['retry_after']))}
        )


# API Routes
@router.post("/check", response_model=URLCheckResponse, summary="Analyze URL for threats")
async def check_url(
    request: URLCheckRequest,
    background_tasks: BackgroundTasks,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Analyze a URL for security threats, malware, phishing, and other risks.
    
    This endpoint performs comprehensive analysis including:
    - Security scanning using multiple threat intelligence providers
    - AI-powered content analysis
    - Reputation checking based on historical data
    - Technical analysis of URL structure
    
    **Rate Limits:**
    - Authenticated users: 100 checks per hour
    - Anonymous users: 10 checks per hour
    
    **Scan Types:**
    - `SECURITY`: Malware and threat detection
    - `REPUTATION`: Historical reputation analysis
    - `CONTENT`: AI-powered content analysis
    - `TECHNICAL`: URL structure and hosting analysis
    """
    try:
        # Check rate limits
        await check_rate_limits(user, db)
        
        # Additional rate limit for URL checks
        security_service = SecurityService(db)
        identifier = str(user.id) if user else "anonymous"
        is_allowed, limit_info = security_service.check_rate_limit(identifier, "url_checks", "127.0.0.1")
        
        if not is_allowed:
            raise HTTPException(
                status_code=429,
                detail=f"URL check rate limit exceeded. Try again in {limit_info['retry_after']:.0f} seconds",
                headers={"Retry-After": str(int(limit_info['retry_after']))}
            )
        
        # Initialize services
        ai_service = AIService()
        url_analysis_service = URLAnalysisService(db, ai_service, security_service)
        
        # Perform URL analysis
        url_check = await url_analysis_service.analyze_url(
            url=request.url,
            user_id=user.id if user else None,
            scan_types=request.scan_types,
            priority=request.priority
        )
        
        # Log security event
        security_service.log_security_event(
            "url_check_requested",
            {
                "url": request.url,
                "scan_types": [st.value for st in request.scan_types],
                "threat_level": url_check.threat_level.value if url_check.threat_level else None
            },
            user_id=str(user.id) if user else None
        )
        
        # Send webhook if callback URL provided
        if request.callback_url and url_check.status == CheckStatus.COMPLETED:
            background_tasks.add_task(
                send_webhook_notification,
                str(request.callback_url),
                url_check
            )
        
        return URLCheckResponse.from_orm(url_check)
    
    except InvalidURLError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except URLAnalysisError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="URL analysis failed")


@router.post("/bulk-check", response_model=List[URLCheckResponse], summary="Analyze multiple URLs")
async def bulk_check_urls(
    request: BulkURLCheckRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze multiple URLs in a single request.
    
    **Limitations:**
    - Maximum 100 URLs per request
    - Requires authentication
    - Higher rate limits apply
    """
    try:
        # Check rate limits (stricter for bulk operations)
        security_service = SecurityService(db)
        is_allowed, limit_info = security_service.check_rate_limit(str(user.id), "url_checks", "127.0.0.1")
        
        # Check if user has enough quota for bulk operation
        remaining_quota = limit_info.get("remaining", 0)
        if remaining_quota < len(request.urls):
            raise HTTPException(
                status_code=429,
                detail=f"Insufficient quota. You have {remaining_quota} checks remaining, but requested {len(request.urls)}"
            )
        
        # Initialize services
        ai_service = AIService()
        url_analysis_service = URLAnalysisService(db, ai_service, security_service)
        
        # Process URLs
        results = []
        for url in request.urls:
            try:
                url_check = await url_analysis_service.analyze_url(
                    url=url,
                    user_id=user.id,
                    scan_types=request.scan_types,
                    priority=False  # Bulk operations are not prioritized
                )
                results.append(URLCheckResponse.from_orm(url_check))
            except Exception as e:
                # Create failed check record
                failed_check = URLCheck(
                    user_id=user.id,
                    original_url=url,
                    normalized_url=url,
                    domain="",
                    status=CheckStatus.FAILED,
                    error_message=str(e)
                )
                db.add(failed_check)
                db.flush()
                results.append(URLCheckResponse.from_orm(failed_check))
        
        db.commit()
        
        # Send webhook if callback URL provided
        if request.callback_url:
            background_tasks.add_task(
                send_bulk_webhook_notification,
                str(request.callback_url),
                results
            )
        
        return results
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Bulk URL analysis failed")


@router.get("/check/{check_id}", response_model=URLCheckResponse, summary="Get URL check results")
async def get_url_check(
    check_id: uuid.UUID = Path(..., description="URL check ID"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Retrieve results of a specific URL check.
    """
    url_check = db.query(URLCheck).filter(URLCheck.id == check_id).first()
    
    if not url_check:
        raise HTTPException(status_code=404, detail="URL check not found")
    
    # Check if user has access to this check
    if url_check.user_id and (not user or url_check.user_id != user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return URLCheckResponse.from_orm(url_check)


@router.get("/check/{check_id}/results", response_model=List[ScanResultResponse], summary="Get detailed scan results")
async def get_scan_results(
    check_id: uuid.UUID = Path(..., description="URL check ID"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed scan results for a URL check.
    """
    url_check = db.query(URLCheck).filter(URLCheck.id == check_id).first()
    
    if not url_check:
        raise HTTPException(status_code=404, detail="URL check not found")
    
    # Check access permissions
    if url_check.user_id and (not user or url_check.user_id != user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    scan_results = db.query(ScanResult).filter(ScanResult.url_check_id == check_id).all()
    
    return [ScanResultResponse.from_orm(result) for result in scan_results]


@router.get("/history", response_model=URLHistoryResponse, summary="Get URL check history")
async def get_url_history(
    url: Optional[str] = Query(None, description="Filter by specific URL"),
    domain: Optional[str] = Query(None, description="Filter by domain"),
    threat_level: Optional[ThreatLevel] = Query(None, description="Filter by threat level"),
    status: Optional[CheckStatus] = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get URL check history for the authenticated user.
    """
    query = db.query(URLCheck).filter(URLCheck.user_id == user.id)
    
    # Apply filters
    if url:
        query = query.filter(URLCheck.original_url.ilike(f"%{url}%"))
    
    if domain:
        query = query.filter(URLCheck.domain.ilike(f"%{domain}%"))
    
    if threat_level:
        query = query.filter(URLCheck.threat_level == threat_level)
    
    if status:
        query = query.filter(URLCheck.status == status)
    
    # Get total count
    total_count = query.count()
    
    # Apply pagination
    offset = (page - 1) * page_size
    checks = query.order_by(desc(URLCheck.created_at)).offset(offset).limit(page_size).all()
    
    return URLHistoryResponse(
        checks=[URLCheckResponse.from_orm(check) for check in checks],
        total_count=total_count,
        page=page,
        page_size=page_size
    )


@router.get("/reputation/{domain}", response_model=URLReputationResponse, summary="Get domain reputation")
async def get_domain_reputation(
    domain: str = Path(..., description="Domain to check"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Get reputation information for a specific domain.
    """
    try:
        # Check rate limits
        await check_rate_limits(user, db)
        
        # Initialize services
        ai_service = AIService()
        security_service = SecurityService(db)
        url_analysis_service = URLAnalysisService(db, ai_service, security_service)
        
        # Get domain reputation
        reputation = url_analysis_service.get_domain_reputation(domain.lower())
        
        if not reputation:
            raise HTTPException(status_code=404, detail="Domain reputation not found")
        
        return URLReputationResponse.from_orm(reputation)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to retrieve domain reputation")


@router.get("/stats", summary="Get URL check statistics")
async def get_url_check_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to include in stats"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get URL check statistics for the authenticated user.
    """
    from datetime import timedelta
    
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    # Get statistics
    total_checks = db.query(URLCheck).filter(
        and_(
            URLCheck.user_id == user.id,
            URLCheck.created_at >= start_date
        )
    ).count()
    
    threat_checks = db.query(URLCheck).filter(
        and_(
            URLCheck.user_id == user.id,
            URLCheck.created_at >= start_date,
            URLCheck.threat_level.in_([ThreatLevel.MEDIUM, ThreatLevel.HIGH])
        )
    ).count()
    
    safe_checks = db.query(URLCheck).filter(
        and_(
            URLCheck.user_id == user.id,
            URLCheck.created_at >= start_date,
            URLCheck.threat_level == ThreatLevel.SAFE
        )
    ).count()
    
    failed_checks = db.query(URLCheck).filter(
        and_(
            URLCheck.user_id == user.id,
            URLCheck.created_at >= start_date,
            URLCheck.status == CheckStatus.FAILED
        )
    ).count()
    
    return {
        "period_days": days,
        "total_checks": total_checks,
        "threat_checks": threat_checks,
        "safe_checks": safe_checks,
        "failed_checks": failed_checks,
        "threat_detection_rate": (threat_checks / total_checks * 100) if total_checks > 0 else 0,
        "success_rate": ((total_checks - failed_checks) / total_checks * 100) if total_checks > 0 else 0
    }


# Background task functions
async def send_webhook_notification(webhook_url: str, url_check: URLCheck):
    """
    Send webhook notification for completed URL check.
    """
    import aiohttp
    
    try:
        payload = {
            "event": "url_check_completed",
            "data": {
                "id": str(url_check.id),
                "url": url_check.original_url,
                "threat_level": url_check.threat_level.value if url_check.threat_level else None,
                "confidence_score": url_check.confidence_score,
                "status": url_check.status.value,
                "completed_at": url_check.scan_completed_at.isoformat() if url_check.scan_completed_at else None
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload, timeout=10) as response:
                if response.status != 200:
                    print(f"Webhook failed: {response.status}")
    
    except Exception as e:
        print(f"Webhook notification failed: {str(e)}")


async def send_bulk_webhook_notification(webhook_url: str, results: List[URLCheckResponse]):
    """
    Send webhook notification for bulk URL check completion.
    """
    import aiohttp
    
    try:
        payload = {
            "event": "bulk_url_check_completed",
            "data": {
                "total_urls": len(results),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "results": [
                    {
                        "id": str(result.id),
                        "url": result.original_url,
                        "threat_level": result.threat_level.value if result.threat_level else None,
                        "status": result.status.value
                    }
                    for result in results
                ]
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload, timeout=30) as response:
                if response.status != 200:
                    print(f"Bulk webhook failed: {response.status}")
    
    except Exception as e:
        print(f"Bulk webhook notification failed: {str(e)}")