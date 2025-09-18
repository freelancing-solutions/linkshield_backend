#!/usr/bin/env python3
"""
LinkShield Backend Report Management Routes

API routes for user reports, community feedback, and threat intelligence.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, HttpUrl, Field, validator
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func

from src.config.database import get_db
from src.config.settings import get_settings
from src.models.report import Report, ReportVote, ReportTemplate, ReportStatistics, ReportType, ReportStatus, ReportPriority, VoteType
from src.models.user import User, UserRole
from src.models.url_check import URLCheck, ThreatLevel
from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.controllers.report_controller import ReportController


# Initialize router
router = APIRouter(prefix="/api/v1/reports", tags=["Report Management"])
security = HTTPBearer()
settings = get_settings()


# Request/Response Models
class ReportCreateRequest(BaseModel):
    """
    Report creation request model.
    """
    url: str = Field(..., description="URL being reported", min_length=1, max_length=2048)
    report_type: ReportType = Field(..., description="Type of report")
    title: str = Field(..., min_length=1, max_length=200, description="Report title")
    description: str = Field(..., min_length=10, max_length=2000, description="Detailed description")
    evidence_urls: Optional[List[str]] = Field(None, max_items=10, description="Supporting evidence URLs")
    severity: Optional[int] = Field(None, ge=1, le=10, description="Severity rating (1-10)")
    tags: Optional[List[str]] = Field(None, max_items=20, description="Report tags")
    is_anonymous: bool = Field(default=False, description="Submit anonymously")
    
    @validator('url')
    def validate_url(cls, v):
        if not v or not v.strip():
            raise ValueError("URL cannot be empty")
        
        v = v.strip()
        if not (v.startswith('http://') or v.startswith('https://') or '.' in v):
            raise ValueError("Invalid URL format")
        
        return v
    
    @validator('tags')
    def validate_tags(cls, v):
        if v:
            # Clean and validate tags
            cleaned_tags = []
            for tag in v:
                tag = tag.strip().lower()
                if tag and len(tag) <= 50 and tag.isalnum():
                    cleaned_tags.append(tag)
            return cleaned_tags[:20]  # Limit to 20 tags
        return v


class ReportUpdateRequest(BaseModel):
    """
    Report update request model.
    """
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, min_length=10, max_length=2000)
    evidence_urls: Optional[List[str]] = Field(None, max_items=10)
    severity: Optional[int] = Field(None, ge=1, le=10)
    tags: Optional[List[str]] = Field(None, max_items=20)
    
    @validator('tags')
    def validate_tags(cls, v):
        if v:
            cleaned_tags = []
            for tag in v:
                tag = tag.strip().lower()
                if tag and len(tag) <= 50 and tag.isalnum():
                    cleaned_tags.append(tag)
            return cleaned_tags[:20]
        return v


class ReportResponse(BaseModel):
    """
    Report response model.
    """
    id: uuid.UUID
    url: str
    domain: str
    report_type: ReportType
    title: str
    description: str
    evidence_urls: List[str]
    severity: Optional[int]
    tags: List[str]
    status: ReportStatus
    priority: ReportPriority
    is_anonymous: bool
    reporter_id: Optional[uuid.UUID]
    reporter_name: Optional[str]
    assignee_id: Optional[uuid.UUID]
    assignee_name: Optional[str]
    upvotes: int
    downvotes: int
    user_vote: Optional[VoteType]
    resolution_notes: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """
    Report list response model.
    """
    reports: List[ReportResponse]
    total_count: int
    page: int
    page_size: int
    filters_applied: Dict[str, Any]


class ReportVoteRequest(BaseModel):
    """
    Report vote request model.
    """
    vote_type: VoteType = Field(..., description="Vote type (upvote/downvote)")
    comment: Optional[str] = Field(None, max_length=500, description="Optional comment")


class ReportVoteResponse(BaseModel):
    """
    Report vote response model.
    """
    id: uuid.UUID
    report_id: uuid.UUID
    user_id: uuid.UUID
    vote_type: VoteType
    comment: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class ReportStatsResponse(BaseModel):
    """
    Report statistics response model.
    """
    total_reports: int
    pending_reports: int
    resolved_reports: int
    reports_by_type: Dict[str, int]
    reports_by_priority: Dict[str, int]
    top_domains: List[Dict[str, Any]]
    recent_activity: List[Dict[str, Any]]
    user_contribution: Dict[str, int]


class ReportTemplateResponse(BaseModel):
    """
    Report template response model.
    """
    id: uuid.UUID
    name: str
    description: str
    report_type: ReportType
    template_fields: Dict[str, Any]
    is_active: bool
    usage_count: int
    created_at: datetime
    
    class Config:
        from_attributes = True


# Dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> User:
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
    
    except Exception as e:
        raise HTTPException(status_code=401, detail="Authentication failed")


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


async def check_admin_permissions(user: User) -> None:
    """
    Check if user has admin permissions.
    """
    if user.role not in [UserRole.ADMIN, UserRole.MODERATOR]:
        raise HTTPException(status_code=403, detail="Admin permissions required")


# Report Management Routes
@router.post("/", response_model=ReportResponse, summary="Create new report")
async def create_report(
    request: ReportCreateRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new security report for a URL.
    
    **Report Types:**
    - `PHISHING`: Phishing or social engineering attempts
    - `MALWARE`: Malware distribution or infected sites
    - `SPAM`: Spam or unwanted content
    - `SCAM`: Fraudulent or scam websites
    - `INAPPROPRIATE`: Inappropriate or offensive content
    - `COPYRIGHT`: Copyright infringement
    - `OTHER`: Other security or policy violations
    
    **Process:**
    1. Validates report data
    2. Checks for duplicate reports
    3. Creates report record
    4. Triggers automated analysis
    5. Notifies moderation team if high priority

    """
    controller = ReportController()
    return await controller.create_report(request, background_tasks, user, db)


@router.get("/", response_model=ReportListResponse, summary="List reports")
async def list_reports(
    report_type: Optional[ReportType] = Query(None, description="Filter by report type"),
    status: Optional[ReportStatus] = Query(None, description="Filter by status"),
    priority: Optional[ReportPriority] = Query(None, description="Filter by priority"),
    domain: Optional[str] = Query(None, description="Filter by domain"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    reporter_id: Optional[uuid.UUID] = Query(None, description="Filter by reporter"),
    assignee_id: Optional[uuid.UUID] = Query(None, description="Filter by assignee"),
    created_after: Optional[datetime] = Query(None, description="Filter by creation date"),
    created_before: Optional[datetime] = Query(None, description="Filter by creation date"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order (asc/desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    List reports with filtering and pagination.
    
    Delegates business logic to ReportController.
    """
    controller = ReportController()
    return await controller.list_reports(
        report_type, status, priority, domain, tag, reporter_id, assignee_id,
        created_after, created_before, sort_by, sort_order, page, page_size, user, db
    )


@router.get("/{report_id}", response_model=ReportResponse, summary="Get report details")
async def get_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific report.
    
    Delegates business logic to ReportController.
    """
    controller = ReportController()
    return await controller.get_report(report_id, user, db)


@router.put("/{report_id}", response_model=ReportResponse, summary="Update report")
async def update_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    request: ReportUpdateRequest = ...,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update a report. Only the reporter or admins can update reports.
    
    Delegates business logic to ReportController.
    """
    controller = ReportController()
    return await controller.update_report(report_id, request, user, db)


@router.post("/{report_id}/vote", response_model=ReportVoteResponse, summary="Vote on report")
async def vote_on_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    request: ReportVoteRequest = ...,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Vote on a report.
    
    Delegates business logic to ReportController.
    """
    controller = ReportController()
    return await controller.vote_on_report(report_id, request, user, db)


@router.delete("/{report_id}/vote", summary="Remove vote")
async def remove_vote(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Remove vote from a report.
    
    Delegates business logic to ReportController.
    """
    controller = ReportController()
    return await controller.remove_vote(report_id, user, db)


# Admin Routes
@router.put("/{report_id}/assign", summary="Assign report to user")
async def assign_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    assignee_id: uuid.UUID = ...,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Assign report to a user.
    
    Delegates business logic to ReportController.
    """
    controller = ReportController()
    return await controller.assign_report(report_id, assignee_id, user, db)


@router.put("/{report_id}/resolve", summary="Resolve report")
async def resolve_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    resolution_notes: str = Field(..., min_length=10, max_length=1000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Resolve a report.
    
    Delegates business logic to ReportController.
    """
    controller = ReportController()
    return await controller.resolve_report(report_id, resolution_notes, user, db)


@router.get("/stats/overview", response_model=ReportStatsResponse, summary="Get report statistics")
async def get_report_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Get report statistics.
    
    Delegates business logic to ReportController.
    """
    controller = ReportController()
    return await controller.get_report_stats(days, user, db)


@router.get("/templates/", response_model=List[ReportTemplateResponse], summary="Get report templates")
async def get_report_templates(
    report_type: Optional[ReportType] = Query(None, description="Filter by report type"),
    db: Session = Depends(get_db)
):
    """
    Get available report templates to help users create better reports.
    """
    controller = ReportController()
    return await controller.get_report_templates(report_type, db)


# Background task functions
async def analyze_reported_url(report_id: str, url: str):
    """
    Analyze reported URL for additional threat intelligence.
    """
    # This would integrate with the URL analysis service
    print(f"Analyzing reported URL: {url} for report {report_id}")


async def notify_moderation_team(report_id: str, report_type: str, url: str):
    """
    Notify moderation team of high-priority reports.
    """
    # This would send notifications to moderators
    print(f"High priority {report_type} report {report_id} for URL: {url}")