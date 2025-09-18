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
    try:
        # Check rate limits
        security_service = SecurityService(db)
        is_allowed, limit_info = security_service.check_rate_limit(str(user.id), "report_submissions", "127.0.0.1")
        
        if not is_allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Report submission rate limit exceeded. Try again in {limit_info['retry_after']:.0f} seconds"
            )
        
        # Extract domain from URL
        from urllib.parse import urlparse
        try:
            parsed_url = urlparse(request.url if request.url.startswith(('http://', 'https://')) else f'http://{request.url}')
            domain = parsed_url.netloc.lower()
        except:
            domain = request.url.split('/')[0].lower()
        
        # Check for duplicate reports (same URL and type within 24 hours)
        recent_duplicate = db.query(Report).filter(
            and_(
                Report.url == request.url,
                Report.report_type == request.report_type,
                Report.created_at >= datetime.now(timezone.utc) - timedelta(hours=24),
                Report.status != ReportStatus.RESOLVED
            )
        ).first()
        
        if recent_duplicate:
            raise HTTPException(
                status_code=409,
                detail="A similar report for this URL already exists. Please check existing reports or add a vote."
            )
        
        # Determine priority based on report type and severity
        priority = ReportPriority.MEDIUM
        if request.report_type in [ReportType.MALWARE, ReportType.PHISHING]:
            priority = ReportPriority.HIGH
        elif request.severity and request.severity >= 8:
            priority = ReportPriority.HIGH
        elif request.severity and request.severity <= 3:
            priority = ReportPriority.LOW
        
        # Create report
        report = Report(
            url=request.url,
            domain=domain,
            report_type=request.report_type,
            title=request.title,
            description=request.description,
            evidence_urls=request.evidence_urls or [],
            severity=request.severity,
            tags=request.tags or [],
            status=ReportStatus.PENDING,
            priority=priority,
            is_anonymous=request.is_anonymous,
            reporter_id=None if request.is_anonymous else user.id
        )
        
        db.add(report)
        db.flush()  # Get the ID
        
        # Update report statistics
        stats = db.query(ReportStatistics).filter(ReportStatistics.date == datetime.now(timezone.utc).date()).first()
        if not stats:
            stats = ReportStatistics(
                date=datetime.now(timezone.utc).date(),
                total_reports=0,
                pending_reports=0,
                resolved_reports=0,
                reports_by_type={},
                top_domains=[],
                user_contributions={}
            )
            db.add(stats)
        
        stats.total_reports += 1
        stats.pending_reports += 1
        
        # Update type statistics
        type_stats = stats.reports_by_type or {}
        type_key = request.report_type.value
        type_stats[type_key] = type_stats.get(type_key, 0) + 1
        stats.reports_by_type = type_stats
        
        # Update user contributions
        if not request.is_anonymous:
            user_contribs = stats.user_contributions or {}
            user_contribs[str(user.id)] = user_contribs.get(str(user.id), 0) + 1
            stats.user_contributions = user_contribs
        
        db.commit()
        
        # Log security event
        security_service.log_security_event(
            "report_created",
            {
                "report_id": str(report.id),
                "url": request.url,
                "report_type": request.report_type.value,
                "priority": priority.value,
                "is_anonymous": request.is_anonymous
            },
            user_id=str(user.id) if not request.is_anonymous else None
        )
        
        # Trigger background analysis
        background_tasks.add_task(
            analyze_reported_url,
            str(report.id),
            request.url
        )
        
        # Notify moderation team for high priority reports
        if priority == ReportPriority.HIGH:
            background_tasks.add_task(
                notify_moderation_team,
                str(report.id),
                request.report_type.value,
                request.url
            )
        
        # Prepare response
        response_data = ReportResponse.from_orm(report)
        response_data.upvotes = 0
        response_data.downvotes = 0
        response_data.user_vote = None
        response_data.reporter_name = user.full_name if not request.is_anonymous else None
        response_data.assignee_name = None
        
        return response_data
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Report creation failed")


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
    
    **Public Access:**
    - Anonymous users can view resolved reports only
    - Authenticated users can view all reports
    - Admins can view all reports including internal details
    """
    try:
        query = db.query(Report)
        
        # Apply access controls
        if not user:
            # Anonymous users can only see resolved reports
            query = query.filter(Report.status == ReportStatus.RESOLVED)
        elif user.role not in [UserRole.ADMIN, UserRole.MODERATOR]:
            # Regular users can see all reports but with limited details
            pass
        
        # Apply filters
        if report_type:
            query = query.filter(Report.report_type == report_type)
        
        if status:
            query = query.filter(Report.status == status)
        
        if priority:
            query = query.filter(Report.priority == priority)
        
        if domain:
            query = query.filter(Report.domain.ilike(f"%{domain}%"))
        
        if tag:
            query = query.filter(Report.tags.contains([tag]))
        
        if reporter_id:
            query = query.filter(Report.reporter_id == reporter_id)
        
        if assignee_id:
            query = query.filter(Report.assignee_id == assignee_id)
        
        if created_after:
            query = query.filter(Report.created_at >= created_after)
        
        if created_before:
            query = query.filter(Report.created_at <= created_before)
        
        # Get total count
        total_count = query.count()
        
        # Apply sorting
        if sort_by in ['created_at', 'updated_at', 'priority', 'status']:
            sort_column = getattr(Report, sort_by)
            if sort_order.lower() == 'asc':
                query = query.order_by(sort_column)
            else:
                query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(desc(Report.created_at))
        
        # Apply pagination
        offset = (page - 1) * page_size
        reports = query.offset(offset).limit(page_size).all()
        
        # Prepare response data
        report_responses = []
        for report in reports:
            # Get vote counts
            vote_counts = db.query(
                func.sum(func.case([(ReportVote.vote_type == VoteType.UPVOTE, 1)], else_=0)).label('upvotes'),
                func.sum(func.case([(ReportVote.vote_type == VoteType.DOWNVOTE, 1)], else_=0)).label('downvotes')
            ).filter(ReportVote.report_id == report.id).first()
            
            upvotes = int(vote_counts.upvotes or 0)
            downvotes = int(vote_counts.downvotes or 0)
            
            # Get user's vote if authenticated
            user_vote = None
            if user:
                user_vote_record = db.query(ReportVote).filter(
                    and_(
                        ReportVote.report_id == report.id,
                        ReportVote.user_id == user.id
                    )
                ).first()
                if user_vote_record:
                    user_vote = user_vote_record.vote_type
            
            # Get reporter and assignee names
            reporter_name = None
            if report.reporter_id and not report.is_anonymous:
                reporter = db.query(User).filter(User.id == report.reporter_id).first()
                if reporter:
                    reporter_name = reporter.full_name
            
            assignee_name = None
            if report.assignee_id:
                assignee = db.query(User).filter(User.id == report.assignee_id).first()
                if assignee:
                    assignee_name = assignee.full_name
            
            response_data = ReportResponse.from_orm(report)
            response_data.upvotes = upvotes
            response_data.downvotes = downvotes
            response_data.user_vote = user_vote
            response_data.reporter_name = reporter_name
            response_data.assignee_name = assignee_name
            
            report_responses.append(response_data)
        
        return ReportListResponse(
            reports=report_responses,
            total_count=total_count,
            page=page,
            page_size=page_size,
            filters_applied={
                "report_type": report_type.value if report_type else None,
                "status": status.value if status else None,
                "priority": priority.value if priority else None,
                "domain": domain,
                "tag": tag,
                "reporter_id": str(reporter_id) if reporter_id else None,
                "assignee_id": str(assignee_id) if assignee_id else None
            }
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to retrieve reports")


@router.get("/{report_id}", response_model=ReportResponse, summary="Get report details")
async def get_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific report.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Check access permissions
    if not user and report.status != ReportStatus.RESOLVED:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get vote counts
    vote_counts = db.query(
        func.sum(func.case([(ReportVote.vote_type == VoteType.UPVOTE, 1)], else_=0)).label('upvotes'),
        func.sum(func.case([(ReportVote.vote_type == VoteType.DOWNVOTE, 1)], else_=0)).label('downvotes')
    ).filter(ReportVote.report_id == report.id).first()
    
    upvotes = int(vote_counts.upvotes or 0)
    downvotes = int(vote_counts.downvotes or 0)
    
    # Get user's vote if authenticated
    user_vote = None
    if user:
        user_vote_record = db.query(ReportVote).filter(
            and_(
                ReportVote.report_id == report.id,
                ReportVote.user_id == user.id
            )
        ).first()
        if user_vote_record:
            user_vote = user_vote_record.vote_type
    
    # Get reporter and assignee names
    reporter_name = None
    if report.reporter_id and not report.is_anonymous:
        reporter = db.query(User).filter(User.id == report.reporter_id).first()
        if reporter:
            reporter_name = reporter.full_name
    
    assignee_name = None
    if report.assignee_id:
        assignee = db.query(User).filter(User.id == report.assignee_id).first()
        if assignee:
            assignee_name = assignee.full_name
    
    response_data = ReportResponse.from_orm(report)
    response_data.upvotes = upvotes
    response_data.downvotes = downvotes
    response_data.user_vote = user_vote
    response_data.reporter_name = reporter_name
    response_data.assignee_name = assignee_name
    
    return response_data


@router.put("/{report_id}", response_model=ReportResponse, summary="Update report")
async def update_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    request: ReportUpdateRequest = ...,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update a report. Only the reporter or admins can update reports.
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Check permissions
    if report.reporter_id != user.id and user.role not in [UserRole.ADMIN, UserRole.MODERATOR]:
        raise HTTPException(status_code=403, detail="Permission denied")
    
    # Can't update resolved reports unless admin
    if report.status == ReportStatus.RESOLVED and user.role not in [UserRole.ADMIN, UserRole.MODERATOR]:
        raise HTTPException(status_code=400, detail="Cannot update resolved reports")
    
    try:
        # Update fields
        if request.title is not None:
            report.title = request.title
        
        if request.description is not None:
            report.description = request.description
        
        if request.evidence_urls is not None:
            report.evidence_urls = request.evidence_urls
        
        if request.severity is not None:
            report.severity = request.severity
        
        if request.tags is not None:
            report.tags = request.tags
        
        report.updated_at = datetime.now(timezone.utc)
        db.commit()
        
        # Return updated report
        return await get_report(report_id, user, db)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Report update failed")


@router.post("/{report_id}/vote", response_model=ReportVoteResponse, summary="Vote on report")
async def vote_on_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    request: ReportVoteRequest = ...,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Vote on a report (upvote/downvote).
    """
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Can't vote on own reports
    if report.reporter_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot vote on your own report")
    
    try:
        # Check for existing vote
        existing_vote = db.query(ReportVote).filter(
            and_(
                ReportVote.report_id == report_id,
                ReportVote.user_id == user.id
            )
        ).first()
        
        if existing_vote:
            # Update existing vote
            existing_vote.vote_type = request.vote_type
            existing_vote.comment = request.comment
            existing_vote.updated_at = datetime.now(timezone.utc)
            vote = existing_vote
        else:
            # Create new vote
            vote = ReportVote(
                report_id=report_id,
                user_id=user.id,
                vote_type=request.vote_type,
                comment=request.comment
            )
            db.add(vote)
        
        db.commit()
        
        return ReportVoteResponse.from_orm(vote)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Vote submission failed")


@router.delete("/{report_id}/vote", summary="Remove vote")
async def remove_vote(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Remove user's vote from a report.
    """
    vote = db.query(ReportVote).filter(
        and_(
            ReportVote.report_id == report_id,
            ReportVote.user_id == user.id
        )
    ).first()
    
    if not vote:
        raise HTTPException(status_code=404, detail="Vote not found")
    
    db.delete(vote)
    db.commit()
    
    return {"message": "Vote removed successfully"}


# Admin Routes
@router.put("/{report_id}/assign", summary="Assign report to user")
async def assign_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    assignee_id: uuid.UUID = ...,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Assign a report to a user for investigation. Admin only.
    """
    await check_admin_permissions(user)
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Verify assignee exists
    assignee = db.query(User).filter(User.id == assignee_id).first()
    if not assignee:
        raise HTTPException(status_code=404, detail="Assignee not found")
    
    report.assignee_id = assignee_id
    report.status = ReportStatus.IN_PROGRESS
    report.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    return {"message": f"Report assigned to {assignee.full_name}"}


@router.put("/{report_id}/resolve", summary="Resolve report")
async def resolve_report(
    report_id: uuid.UUID = Path(..., description="Report ID"),
    resolution_notes: str = Field(..., min_length=10, max_length=1000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Resolve a report with resolution notes. Admin only.
    """
    await check_admin_permissions(user)
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report.status = ReportStatus.RESOLVED
    report.resolution_notes = resolution_notes
    report.resolved_at = datetime.now(timezone.utc)
    report.updated_at = datetime.now(timezone.utc)
    
    # Update statistics
    stats = db.query(ReportStatistics).filter(ReportStatistics.date == datetime.now(timezone.utc).date()).first()
    if stats:
        stats.pending_reports = max(0, stats.pending_reports - 1)
        stats.resolved_reports += 1
    
    db.commit()
    
    return {"message": "Report resolved successfully"}


@router.get("/stats/overview", response_model=ReportStatsResponse, summary="Get report statistics")
async def get_report_stats(
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Get report statistics and analytics.
    """
    try:
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Basic statistics
        total_reports = db.query(Report).filter(Report.created_at >= start_date).count()
        pending_reports = db.query(Report).filter(
            and_(
                Report.created_at >= start_date,
                Report.status == ReportStatus.PENDING
            )
        ).count()
        resolved_reports = db.query(Report).filter(
            and_(
                Report.created_at >= start_date,
                Report.status == ReportStatus.RESOLVED
            )
        ).count()
        
        # Reports by type
        type_stats = db.query(
            Report.report_type,
            func.count(Report.id).label('count')
        ).filter(Report.created_at >= start_date).group_by(Report.report_type).all()
        
        reports_by_type = {stat.report_type.value: stat.count for stat in type_stats}
        
        # Reports by priority
        priority_stats = db.query(
            Report.priority,
            func.count(Report.id).label('count')
        ).filter(Report.created_at >= start_date).group_by(Report.priority).all()
        
        reports_by_priority = {stat.priority.value: stat.count for stat in priority_stats}
        
        # Top domains
        domain_stats = db.query(
            Report.domain,
            func.count(Report.id).label('count')
        ).filter(Report.created_at >= start_date).group_by(Report.domain).order_by(desc(func.count(Report.id))).limit(10).all()
        
        top_domains = [{'domain': stat.domain, 'count': stat.count} for stat in domain_stats]
        
        # Recent activity (last 24 hours)
        recent_activity = db.query(Report).filter(
            Report.created_at >= datetime.now(timezone.utc) - timedelta(hours=24)
        ).order_by(desc(Report.created_at)).limit(10).all()
        
        recent_activity_data = [
            {
                'id': str(report.id),
                'url': report.url,
                'type': report.report_type.value,
                'status': report.status.value,
                'created_at': report.created_at
            }
            for report in recent_activity
        ]
        
        # User contribution (if authenticated)
        user_contribution = {}
        if user:
            user_reports = db.query(Report).filter(
                and_(
                    Report.reporter_id == user.id,
                    Report.created_at >= start_date
                )
            ).count()
            
            user_votes = db.query(ReportVote).filter(
                and_(
                    ReportVote.user_id == user.id,
                    ReportVote.created_at >= start_date
                )
            ).count()
            
            user_contribution = {
                'reports_submitted': user_reports,
                'votes_cast': user_votes
            }
        
        return ReportStatsResponse(
            total_reports=total_reports,
            pending_reports=pending_reports,
            resolved_reports=resolved_reports,
            reports_by_type=reports_by_type,
            reports_by_priority=reports_by_priority,
            top_domains=top_domains,
            recent_activity=recent_activity_data,
            user_contribution=user_contribution
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")


@router.get("/templates/", response_model=List[ReportTemplateResponse], summary="Get report templates")
async def get_report_templates(
    report_type: Optional[ReportType] = Query(None, description="Filter by report type"),
    db: Session = Depends(get_db)
):
    """
    Get available report templates to help users create better reports.
    """
    query = db.query(ReportTemplate).filter(ReportTemplate.is_active == True)
    
    if report_type:
        query = query.filter(ReportTemplate.report_type == report_type)
    
    templates = query.order_by(ReportTemplate.usage_count.desc()).all()
    
    return [ReportTemplateResponse.from_orm(template) for template in templates]


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