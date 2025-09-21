"""Report controller for handling report-related business logic.

This module contains the ReportController class that handles all business logic
for report management, including creation, updates, voting, assignment, resolution,
statistics, and template management.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
from pydantic import ValidationError

from src.controllers.base_controller import BaseController
from src.models.report import (
    Report, ReportVote, ReportTemplate, ReportStatistics,
    ReportType, ReportStatus, ReportPriority, VoteType
)
from src.models.user import User, UserRole
from src.models.url_check import URLCheck, ThreatLevel
from src.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority
from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.services.email_service import EmailService

from src.utils import utc_datetime

class ReportController(BaseController):
    """Controller for report management operations.
    
    Handles all business logic related to reports including:
    - Report creation and validation
    - Report updates and status management
    - Voting and community feedback
    - Report assignment and resolution
    - Statistics and analytics
    - Template management
    """
    
    def __init__(
        self, 
        security_service: SecurityService, 
        auth_service: AuthService,
        email_service: EmailService
    ):
        """Initialize report controller.
        
        Args:
            security_service: Security service for validation
            auth_service: Authentication service for user operations
            email_service: Email service for notifications
        """
        super().__init__(security_service, auth_service, email_service)
        self.max_reports_per_hour = 10  # Rate limit for report creation
        self.max_votes_per_hour = 50   # Rate limit for voting
    
    async def create_report(
        self,
        url: str,
        report_type: ReportType,
        title: str,
        description: str,
        user: User,
        background_tasks: BackgroundTasks,
        evidence_urls: Optional[List[str]] = None,
        severity: Optional[int] = None,
        tags: Optional[List[str]] = None,
        is_anonymous: bool = False,
        callback_url: Optional[str] = None
    ) -> Report:
        """Create a new report with validation and background processing.
        
        Args:
            url: URL being reported
            report_type: Type of report
            title: Report title
            description: Detailed description
            user: User creating the report
            background_tasks: FastAPI background tasks
            evidence_urls: Supporting evidence URLs
            severity: Severity rating (1-10)
            tags: Report tags
            is_anonymous: Whether to submit anonymously
            callback_url: Optional webhook URL for completion notification
            
        Returns:
            Report: Created report instance
            
        Raises:
            HTTPException: If validation fails or rate limit exceeded
        """
        # Check rate limiting
        if not await self.check_rate_limit(
            user.id, "create_report", self.max_reports_per_hour
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for report creation"
            )
        
        # Validate and normalize URL
        normalized_url = await self._validate_and_normalize_url(url)
        domain = self._extract_domain(normalized_url)
        
        # Validate evidence URLs if provided
        if evidence_urls:
            evidence_urls = await self._validate_evidence_urls(evidence_urls)
        
        # Check for duplicate reports
        await self._check_duplicate_report(normalized_url, user.id, report_type)
        
        # Determine priority based on report type and severity
        priority = self._calculate_priority(report_type, severity)
        
        try:
            # Create report using context manager
            async with self.get_db_session() as db:
                # Create report
                report = Report(
                    id=uuid.uuid4(),
                    url=normalized_url,
                    domain=domain,
                    report_type=report_type,
                    title=title.strip(),
                    description=description.strip(),
                    evidence_urls=evidence_urls or [],
                    severity=severity,
                    tags=tags or [],
                    status=ReportStatus.PENDING,
                    priority=priority,
                    is_anonymous=is_anonymous,
                    reporter_id=None if is_anonymous else user.id,
                    created_at=utc_datetime(),
                    updated_at=utc_datetime()
                )
                
                db.add(report)
                db.commit()
                db.refresh(report)
                
                # Log the operation
                self.log_operation(
                    "Report created",
                    user_id=user.id,
                    details={
                        "report_id": str(report.id),
                        "url": normalized_url,
                        "type": report_type.value,
                        "anonymous": is_anonymous
                    }
                )
                
                # Schedule background tasks
                if callback_url:
                    # Use webhook-enabled background task for async processing
                    task_id = await self.add_background_task_with_tracking(
                        background_tasks=background_tasks,
                        task_type=TaskType.REPORT_GENERATION,
                        task_func=self._analyze_reported_url_async,
                        task_data={
                            "report_id": str(report.id),
                            "url": normalized_url,
                            "report_type": report_type.value,
                            "priority": priority.value
                        },
                        user_id=user.id,
                        callback_url=callback_url,
                        priority=TaskPriority.HIGH if priority == ReportPriority.HIGH else TaskPriority.MEDIUM,
                        args=(
                        str(report.id),
                        normalized_url,
                        report_type.value,
                        priority.value,
                        callback_url)
                    )
                    
                    self.log_operation(
                        "Report analysis scheduled with webhook",
                        user_id=user.id,
                        details={
                            "report_id": str(report.id),
                            "task_id": task_id,
                            "callback_url": callback_url
                        }
                    )
                else:
                    # Use traditional background tasks
                    background_tasks.add_task(self._analyze_reported_url, str(report.id), normalized_url)
                
                if priority == ReportPriority.HIGH:
                    if callback_url:
                        # High priority moderation notification with webhook
                        await self.add_background_task_with_tracking(
                            background_tasks=background_tasks,
                            task_type=TaskType.NOTIFICATION,
                            task_func=self._notify_moderation_team_async,
                            task_data={
                                "report_id": str(report.id),
                                "report_type": report_type.value,
                                "url": normalized_url,
                                "priority": "HIGH"
                            },
                            user_id=user.id,
                            callback_url=callback_url,
                            priority=TaskPriority.HIGH,
                            args=(
                            str(report.id),
                            report_type.value,
                            normalized_url,
                            callback_url)
                        )
                    else:
                        # Traditional high priority notification
                        background_tasks.add_task(
                            self._notify_moderation_team,
                            str(report.id),
                            report_type.value,
                            normalized_url
                        )
                
                return report
            
        except Exception as e:
            raise self.handle_database_error(e, "report creation")
    
    async def list_reports(
        self,
        user: Optional[User] = None,
        report_type: Optional[ReportType] = None,
        status: Optional[ReportStatus] = None,
        priority: Optional[ReportPriority] = None,
        domain: Optional[str] = None,
        tag: Optional[str] = None,
        reporter_id: Optional[uuid.UUID] = None,
        assignee_id: Optional[uuid.UUID] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 20
    ) -> Tuple[List[Report], int, Dict[str, Any]]:
        """List reports with filtering and pagination.
        
        Args:
            user: Current user (for vote information)
            report_type: Filter by report type
            status: Filter by status
            priority: Filter by priority
            domain: Filter by domain
            tag: Filter by tag
            reporter_id: Filter by reporter
            assignee_id: Filter by assignee
            created_after: Filter by creation date
            created_before: Filter by creation date
            sort_by: Sort field
            sort_order: Sort order (asc/desc)
            page: Page number
            page_size: Items per page
            
        Returns:
            Tuple: (reports, total_count, filters_applied)
        """
        # Validate pagination
        skip, limit = self.validate_pagination(page - 1, page_size)
        
        async with self.get_db_session() as db:
            # Build query
            query = db.query(Report)
            filters_applied = {}
            
            # Apply filters
            if report_type:
                query = query.filter(Report.report_type == report_type)
                filters_applied["report_type"] = report_type.value
            
            if status:
                query = query.filter(Report.status == status)
                filters_applied["status"] = status.value
            
            if priority:
                query = query.filter(Report.priority == priority)
                filters_applied["priority"] = priority.value
            
            if domain:
                query = query.filter(Report.domain.ilike(f"%{domain}%"))
                filters_applied["domain"] = domain
            
            if tag:
                query = query.filter(Report.tags.contains([tag]))
                filters_applied["tag"] = tag
            
            if reporter_id:
                query = query.filter(Report.reporter_id == reporter_id)
                filters_applied["reporter_id"] = str(reporter_id)
            
            if assignee_id:
                query = query.filter(Report.assignee_id == assignee_id)
                filters_applied["assignee_id"] = str(assignee_id)
            
            if created_after:
                query = query.filter(Report.created_at >= created_after)
                filters_applied["created_after"] = created_after.isoformat()
            
            if created_before:
                query = query.filter(Report.created_at <= created_before)
                filters_applied["created_before"] = created_before.isoformat()
            
            # Apply sorting
            if hasattr(Report, sort_by):
                sort_column = getattr(Report, sort_by)
                if sort_order.lower() == "desc":
                    query = query.order_by(desc(sort_column))
                else:
                    query = query.order_by(sort_column)
            
            # Get total count
            total_count = query.count()
            
            # Apply pagination
            reports = query.offset(skip).limit(limit).all()
            
            # Add user votes if user is authenticated
            if user:
                await self._add_user_votes_to_reports(reports, user.id)
            
            self.log_operation(
                "Reports listed",
                user_id=user.id if user else None,
                details={
                    "filters": filters_applied,
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size
                }
            )
            
            return reports, total_count, filters_applied
    
    async def get_report_by_id(
        self,
        report_id: uuid.UUID,
        user: Optional[User] = None
    ) -> Report:
        """Get a specific report by ID.        
        Args:
            report_id: Report ID
            user: Current user (for vote information)            
        Returns:
            Report: Report instance            
        Raises:
            HTTPException: If report not found
        """
        async with self.get_db_session() as db:
            report = db.query(Report).filter(Report.id == report_id).first()
            
            if not report:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Report not found"
                )
            
            # Add user vote information if user is authenticated
            if user:
                await self._add_user_votes_to_reports([report], user.id)
            
            self.log_operation(
                "Report retrieved",
                user_id=user.id if user else None,
                details={"report_id": str(report_id)}
            )
            
            return report
    
    async def update_report(
        self,
        report_id: uuid.UUID,
        user: User,
        title: Optional[str] = None,
        description: Optional[str] = None,
        evidence_urls: Optional[List[str]] = None,
        severity: Optional[int] = None,
        tags: Optional[List[str]] = None
    ) -> Report:
        """Update an existing report.
        
        Args:
            report_id: Report ID
            user: User making the update
            title: New title
            description: New description
            evidence_urls: New evidence URLs
            severity: New severity rating
            tags: New tags
            
        Returns:
            Report: Updated report
            
        Raises:
            HTTPException: If report not found or access denied
        """
        report = await self.get_report_by_id(report_id)
        
        # Check permissions
        if report.reporter_id != user.id and user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only update your own reports"
            )
        
        # Validate evidence URLs if provided
        if evidence_urls is not None:
            evidence_urls = await self._validate_evidence_urls(evidence_urls)
        
        try:
            # Update fields using context manager
            async with self.get_db_session() as db:
                # Update fields
                if title is not None:
                    report.title = title.strip()
                if description is not None:
                    report.description = description.strip()
                if evidence_urls is not None:
                    report.evidence_urls = evidence_urls
                if severity is not None:
                    report.severity = severity
                    # Recalculate priority if severity changed
                    report.priority = self._calculate_priority(report.report_type, severity)
                if tags is not None:
                    report.tags = tags
                
                report.updated_at = utc_datetime()
                
                db.commit()
                db.refresh(report)
                
                self.log_operation(
                    "Report updated",
                    user_id=user.id,
                    details={"report_id": str(report_id)}
                )
                
                return report
            
        except Exception as e:
            raise self.handle_database_error(e, "report update")
    
    async def vote_on_report(
        self,
        report_id: uuid.UUID,
        user: User,
        vote_type: VoteType,
        comment: Optional[str] = None
    ) -> ReportVote:
        """Vote on a report.
        
        Args:
            report_id: Report ID
            user: User casting the vote
            vote_type: Type of vote (upvote/downvote)
            comment: Optional comment
            
        Returns:
            ReportVote: Created or updated vote
            
        Raises:
            HTTPException: If rate limit exceeded or report not found
        """
        # Check rate limiting
        if not await self.check_rate_limit(
            user.id, "vote_report", self.max_votes_per_hour
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for voting"
            )
        
        # Verify report exists
        report = await self.get_report_by_id(report_id)
        
        # Check if user is trying to vote on their own report
        if report.reporter_id == user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot vote on your own report"
            )
        
        try:
            # Vote on report using context manager
            async with self.get_db_session() as db:
                # Check for existing vote
                existing_vote = db.query(ReportVote).filter(
                    and_(ReportVote.report_id == report_id, ReportVote.user_id == user.id)
                ).first()
                
                if existing_vote:
                    # Update existing vote
                    existing_vote.vote_type = vote_type
                    existing_vote.comment = comment
                    existing_vote.updated_at = utc_datetime()
                    vote = existing_vote
                else:
                    # Create new vote
                    vote = ReportVote(
                        id=uuid.uuid4(),
                        report_id=report_id,
                        user_id=user.id,
                        vote_type=vote_type,
                        comment=comment,
                        created_at=utc_datetime(),
                        updated_at=utc_datetime()
                    )
                    db.add(vote)
                
                # Update report vote counts
                await self._update_report_vote_counts(report_id)
                
                db.commit()
                db.refresh(vote)
                
                self.log_operation(
                    "Vote cast on report",
                    user_id=user.id,
                    details={
                        "report_id": str(report_id),
                        "vote_type": vote_type.value
                    }
                )
                
                return vote
            
        except Exception as e:
            raise self.handle_database_error(e, "vote creation")
    
    async def remove_vote(
        self,
        report_id: uuid.UUID,
        user: User
    ) -> None:
        """Remove a user's vote from a report.
        
        Args:
            report_id: Report ID
            user: User removing the vote
            
        Raises:
            HTTPException: If vote not found
        """
        async with self.get_db_session() as db:
            vote = db.query(ReportVote).filter(
                and_(ReportVote.report_id == report_id, ReportVote.user_id == user.id)
            ).first()
            
            if not vote:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Vote not found"
                )
            
            try:
                db.delete(vote)
                await self._update_report_vote_counts(report_id)
                db.commit()
                
                self.log_operation(
                    "Vote removed from report",
                    user_id=user.id,
                    details={"report_id": str(report_id)}
                )
                
            except Exception as e:
                raise self.handle_database_error(e, "vote removal")
    
    async def assign_report(
        self,
        report_id: uuid.UUID,
        assignee_id: uuid.UUID,
        user: User
    ) -> Report:
        """Assign a report to a user.
        
        Args:
            report_id: Report ID
            assignee_id: ID of user to assign to
            user: User making the assignment (must be admin)
            
        Returns:
            Report: Updated report
            
        Raises:
            HTTPException: If not authorized or users not found
        """
        # Check admin permissions
        if user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can assign reports"
            )
        
        # Verify report exists
        report = await self.get_report_by_id(report_id)
        
        try:
            # Assign report using context manager
            async with self.get_db_session() as db:
                # Verify assignee exists
                assignee = db.query(User).filter(User.id == assignee_id).first()
                if not assignee:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Assignee not found"
                    )
                
                report.assignee_id = assignee_id
                report.status = ReportStatus.IN_PROGRESS
                report.updated_at = utc_datetime()
                
                db.commit()
                db.refresh(report)
                
                self.log_operation(
                    "Report assigned",
                    user_id=user.id,
                    details={
                        "report_id": str(report_id),
                        "assignee_id": str(assignee_id)
                    }
                )
                
                return report
            
        except Exception as e:
            raise self.handle_database_error(e, "report assignment")
    
    async def resolve_report(
        self,
        report_id: uuid.UUID,
        resolution_notes: str,
        user: User
    ) -> Report:
        """Resolve a report.
        
        Args:
            report_id: Report ID
            resolution_notes: Resolution notes
            user: User resolving the report (must be admin or assignee)
            
        Returns:
            Report: Resolved report
            
        Raises:
            HTTPException: If not authorized or report not found
        """
        report = await self.get_report_by_id(report_id)
        
        # Check permissions
        if user.role != UserRole.ADMIN and report.assignee_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators or assigned users can resolve reports"
            )
        
        try:
            # Resolve report using context manager
            async with self.get_db_session() as db:
                report.status = ReportStatus.RESOLVED
                report.resolution_notes = resolution_notes.strip()
                report.resolved_at = utc_datetime()
                report.updated_at = utc_datetime()
                
                db.commit()
                db.refresh(report)
                
                self.log_operation(
                    "Report resolved",
                    user_id=user.id,
                    details={"report_id": str(report_id)}
                )
                
                return report
            
        except Exception as e:
            raise self.handle_database_error(e, "report resolution")
    
    async def get_report_statistics(
        self,
        days: int = 30,
        user: Optional[User] = None
    ) -> Dict[str, Any]:
        """Get report statistics.
        
        Args:
            days: Number of days to include in statistics
            user: Current user (for user-specific stats)
            
        Returns:
            Dict: Report statistics
        """
        cutoff_date = utc_datetime() - timedelta(days=days)
        
        async with self.get_db_session() as db:
            # Base query for the time period
            base_query = db.query(Report).filter(Report.created_at >= cutoff_date)
            
            # Total counts
            total_reports = base_query.count()
            pending_reports = base_query.filter(Report.status == ReportStatus.PENDING).count()
            resolved_reports = base_query.filter(Report.status == ReportStatus.RESOLVED).count()
            
            # Reports by type
            reports_by_type = {}
            for report_type in ReportType:
                count = base_query.filter(Report.report_type == report_type).count()
                reports_by_type[report_type.value] = count
            
            # Reports by priority
            reports_by_priority = {}
            for priority in ReportPriority:
                count = base_query.filter(Report.priority == priority).count()
                reports_by_priority[priority.value] = count
            
            # Top domains
            top_domains = (
                base_query
                .with_entities(Report.domain, func.count(Report.id).label('count'))
                .group_by(Report.domain)
                .order_by(desc('count'))
                .limit(10)
                .all()
            )
            
            top_domains_list = [
                {"domain": domain, "count": count}
                for domain, count in top_domains
            ]
            
            # Recent activity (last 7 days)
            recent_cutoff = utc_datetime() - timedelta(days=7)
            recent_activity = (
                db.query(Report)
                .filter(Report.created_at >= recent_cutoff)
                .order_by(desc(Report.created_at))
                .limit(20)
                .all()
            )
            
            recent_activity_list = [
                {
                    "id": str(report.id),
                    "title": report.title,
                    "type": report.report_type.value,
                    "status": report.status.value,
                    "created_at": report.created_at.isoformat()
                }
                for report in recent_activity
            ]
            
            # User contribution (if user is provided)
            user_contribution = {}
            if user:
                user_reports = base_query.filter(Report.reporter_id == user.id).count()
                user_votes = (
                    db.query(ReportVote)
                    .filter(
                        and_(
                            ReportVote.user_id == user.id,
                            ReportVote.created_at >= cutoff_date
                        )
                    )
                    .count()
                )
                user_contribution = {
                    "reports_created": user_reports,
                    "votes_cast": user_votes
                }
            
            stats = {
                "total_reports": total_reports,
                "pending_reports": pending_reports,
                "resolved_reports": resolved_reports,
                "reports_by_type": reports_by_type,
                "reports_by_priority": reports_by_priority,
                "top_domains": top_domains_list,
                "recent_activity": recent_activity_list,
                "user_contribution": user_contribution
            }
            
            self.log_operation(
                "Report statistics retrieved",
                user_id=user.id if user else None,
                details={"days": days}
            )
            
            return stats
    
    async def get_report_templates(
        self,
        report_type: Optional[ReportType] = None
    ) -> List[ReportTemplate]:
        """Get available report templates.
        
        Args:
            report_type: Filter by report type
            
        Returns:
            List[ReportTemplate]: Available templates
        """
        async with self.get_db_session() as db:
            query = db.query(ReportTemplate).filter(ReportTemplate.is_active == True)
            
            if report_type:
                query = query.filter(ReportTemplate.report_type == report_type)
            
            templates = query.order_by(ReportTemplate.usage_count.desc()).all()
            
            self.log_operation(
                "Report templates retrieved",
                details={"report_type": report_type.value if report_type else None}
            )
            
            return templates
    
    # Private helper methods
    
    async def _validate_and_normalize_url(self, url: str) -> str:
        """Validate and normalize URL.
        
        Args:
            url: URL to validate
            
        Returns:
            str: Normalized URL
            
        Raises:
            HTTPException: If URL is invalid
        """
        url = url.strip()
        
        if not url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL cannot be empty"
            )
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            if '.' in url:
                url = f"https://{url}"
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid URL format"
                )
        
        # Validate URL format
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                raise ValueError("Invalid URL")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid URL format"
            )
        
        return url
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL.
        
        Args:
            url: URL to extract domain from
            
        Returns:
            str: Extracted domain
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return "unknown"
    
    async def _validate_evidence_urls(self, evidence_urls: List[str]) -> List[str]:
        """Validate evidence URLs.
        
        Args:
            evidence_urls: List of evidence URLs
            
        Returns:
            List[str]: Validated URLs
            
        Raises:
            HTTPException: If any URL is invalid
        """
        validated_urls = []
        
        for url in evidence_urls[:10]:  # Limit to 10 URLs
            try:
                validated_url = await self._validate_and_normalize_url(url)
                validated_urls.append(validated_url)
            except HTTPException:
                # Skip invalid URLs rather than failing the entire request
                continue
        
        return validated_urls
    
    async def _check_duplicate_report(
        self,
        url: str,
        user_id: uuid.UUID,
        report_type: ReportType
    ) -> None:
        """Check for duplicate reports.
        
        Args:
            url: URL being reported
            user_id: User ID
            report_type: Report type
            
        Raises:
            HTTPException: If duplicate report found
        """
        # Check for recent duplicate from same user
        recent_cutoff = utc_datetime() - timedelta(hours=24)
        
        async with self.get_db_session() as db:
            duplicate = (
                db.query(Report)
                .filter(
                    and_(
                        Report.url == url,
                        Report.reporter_id == user_id,
                        Report.report_type == report_type,
                        Report.created_at >= recent_cutoff
                    )
                )
                .first()
            )
            
            if duplicate:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="You have already reported this URL recently"
                )
    
    def _calculate_priority(
        self,
        report_type: ReportType,
        severity: Optional[int]
    ) -> ReportPriority:
        """Calculate report priority based on type and severity.
        
        Args:
            report_type: Type of report
            severity: Severity rating (1-10)
            
        Returns:
            ReportPriority: Calculated priority
        """
        # High priority types
        if report_type in [ReportType.MALWARE, ReportType.PHISHING]:
            return ReportPriority.HIGH
        
        # Priority based on severity
        if severity:
            if severity >= 8:
                return ReportPriority.HIGH
            elif severity >= 5:
                return ReportPriority.MEDIUM
            else:
                return ReportPriority.LOW
        
        # Default priority based on type
        if report_type in [ReportType.SPAM, ReportType.SCAM]:
            return ReportPriority.MEDIUM
        
        return ReportPriority.LOW
    
    async def _add_user_votes_to_reports(
        self,
        reports: List[Report],
        user_id: uuid.UUID
    ) -> None:
        """Add user vote information to reports.
        
        Args:
            reports: List of reports to add votes to
            user_id: User ID to get votes for
        """
        if not reports:
            return
        
        report_ids = [report.id for report in reports]
        
        async with self.get_db_session() as db:
            votes = (
                db.query(ReportVote)
                .filter(
                    and_(
                        ReportVote.report_id.in_(report_ids),
                        ReportVote.user_id == user_id
                    )
                )
                .all()
            )
            
            vote_map = {vote.report_id: vote.vote_type for vote in votes}
            
            for report in reports:
                report.user_vote = vote_map.get(report.id)
    
    async def _update_report_vote_counts(self, report_id: uuid.UUID) -> None:
        """Update vote counts for a report.
        
        Args:
            report_id: Report ID to update counts for
        """
        async with self.get_db_session() as db:
            upvotes = (
                db.query(ReportVote)
                .filter(
                    and_(
                        ReportVote.report_id == report_id,
                        ReportVote.vote_type == VoteType.UPVOTE
                    )
                )
                .count()
            )
            
            downvotes = (
                db.query(ReportVote)
                .filter(
                    and_(
                        ReportVote.report_id == report_id,
                        ReportVote.vote_type == VoteType.DOWNVOTE
                    )
                )
                .count()
            )
            
            report = db.query(Report).filter(Report.id == report_id).first()
            if report:
                report.upvotes = upvotes
                report.downvotes = downvotes
    
    async def _analyze_reported_url_async(
        self,
        task_id: str,
        report_id: str,
        url: str,
        report_type: str,
        priority: str,
        callback_url: Optional[str] = None
    ) -> None:
        """Asynchronously analyze reported URL with webhook notification.
        
        Args:
            task_id: Background task ID
            report_id: Report ID
            url: URL to analyze
            report_type: Type of report
            priority: Report priority level
            callback_url: Optional webhook URL for completion notification
        """
        task_tracking_service = get_task_tracking_service()
        webhook_service = get_webhook_service()
        
        try:
            # Get database session
            db = await self.get_db_session()
            
            # Update task status to running
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                progress=10
            )
            
            # Perform URL analysis (placeholder for actual analysis logic)
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                progress=50
            )
            
            # Simulate analysis processing
            analysis_result = {
                "report_id": report_id,
                "url": url,
                "report_type": report_type,
                "priority": priority,
                "analysis_completed": True,
                "threat_detected": False,  # This would be actual analysis result
                "confidence_score": 0.85,
                "analyzed_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Complete the task
            await task_tracking_service.complete_task(
                db=db,
                task_id=task_id,
                result=analysis_result
            )
            
            # Send webhook notification if callback URL provided
            if callback_url:
                webhook_payload = {
                    "event": "report_analysis_completed",
                    "task_id": task_id,
                    "report_id": report_id,
                    "analysis": analysis_result,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                await webhook_service.send_webhook(
                    url=callback_url,
                    payload=webhook_payload,
                    event_type="report_analysis_completed"
                )
            
            # Log successful completion
            self.log_operation(
                "Report URL analysis completed asynchronously",
                details={
                    "task_id": task_id,
                    "report_id": report_id,
                    "url": url,
                    "callback_url": callback_url
                }
            )
            
        except Exception as e:
            # Handle failure
            self.logger.error(f"Async report analysis failed for task {task_id}: {e}")
            
            try:
                # Mark task as failed
                await task_tracking_service.fail_task(
                    db=db,
                    task_id=task_id,
                    error=str(e)
                )
                
                # Send failure webhook if callback URL provided
                if callback_url:
                    webhook_payload = {
                        "event": "report_analysis_failed",
                        "task_id": task_id,
                        "report_id": report_id,
                        "error": str(e),
                        "url": url,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    
                    await webhook_service.send_webhook(
                        url=callback_url,
                        payload=webhook_payload,
                        event_type="report_analysis_failed"
                    )
                
            except Exception as cleanup_error:
                self.logger.error(f"Failed to handle async analysis failure for task {task_id}: {cleanup_error}")

    async def _notify_moderation_team_async(
        self,
        task_id: str,
        report_id: str,
        report_type: str,
        url: str,
        callback_url: Optional[str] = None
    ) -> None:
        """Asynchronously notify moderation team with webhook notification.
        
        Args:
            task_id: Background task ID
            report_id: Report ID
            report_type: Type of report
            url: Reported URL
            callback_url: Optional webhook URL for completion notification
        """
        task_tracking_service = get_task_tracking_service()
        webhook_service = get_webhook_service()
        
        try:
            # Get database session
            db = await self.get_db_session()
            
            # Update task status to running
            await task_tracking_service.update_task_status(
                db=db,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                progress=25
            )
            
            # Simulate moderation team notification
            notification_result = {
                "report_id": report_id,
                "report_type": report_type,
                "url": url,
                "notification_sent": True,
                "moderators_notified": 3,  # This would be actual count
                "notification_method": "email_and_slack",
                "notified_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Complete the task
            await task_tracking_service.complete_task(
                db=db,
                task_id=task_id,
                result=notification_result
            )
            
            # Send webhook notification if callback URL provided
            if callback_url:
                webhook_payload = {
                    "event": "moderation_notification_completed",
                    "task_id": task_id,
                    "report_id": report_id,
                    "notification": notification_result,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                await webhook_service.send_webhook(
                    url=callback_url,
                    payload=webhook_payload,
                    event_type="moderation_notification_completed"
                )
            
            # Log successful completion
            self.log_operation(
                "Moderation team notification completed asynchronously",
                details={
                    "task_id": task_id,
                    "report_id": report_id,
                    "report_type": report_type,
                    "url": url,
                    "callback_url": callback_url
                }
            )
            
        except Exception as e:
            # Handle failure
            self.logger.error(f"Async moderation notification failed for task {task_id}: {e}")
            
            try:
                # Mark task as failed
                await task_tracking_service.fail_task(
                    db=db,
                    task_id=task_id,
                    error=str(e)
                )
                
                # Send failure webhook if callback URL provided
                if callback_url:
                    webhook_payload = {
                        "event": "moderation_notification_failed",
                        "task_id": task_id,
                        "report_id": report_id,
                        "error": str(e),
                        "url": url,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    
                    await webhook_service.send_webhook(
                        url=callback_url,
                        payload=webhook_payload,
                        event_type="moderation_notification_failed"
                    )
                
            except Exception as cleanup_error:
                self.logger.error(f"Failed to handle async notification failure for task {task_id}: {cleanup_error}")

    async def _analyze_reported_url(self, report_id: str, url: str) -> None:
        """Background task to analyze reported URL.
        
        Args:
            report_id: Report ID
            url: URL to analyze
        """
        try:
            # This would integrate with the URL analysis service
            # For now, just log the analysis request
            self.log_operation(
                "URL analysis requested",
                details={"report_id": report_id, "url": url}
            )
        except Exception as e:
            self.logger.error(f"URL analysis failed for report {report_id}: {str(e)}")
    
    async def _notify_moderation_team(
        self,
        report_id: str,
        report_type: str,
        url: str
    ) -> None:
        """Background task to notify moderation team of high priority reports.
        
        Args:
            report_id: Report ID
            report_type: Type of report
            url: Reported URL
        """
        try:
            # This would send notifications to the moderation team
            # For now, just log the notification
            self.log_operation(
                "Moderation team notified",
                details={
                    "report_id": report_id,
                    "report_type": report_type,
                    "url": url
                },
                level="info"
            )
        except Exception as e:
            self.logger.error(f"Moderation notification failed for report {report_id}: {str(e)}")