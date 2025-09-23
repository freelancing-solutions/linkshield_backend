"""URL check controller for handling URL analysis business logic.

This module contains the URLCheckController class that handles all business logic
for URL analysis, security scanning, threat detection, reputation management,
and bulk processing operations.
"""

import uuid
import aiohttp
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from fastapi import HTTPException, status, BackgroundTasks

from sqlalchemy import and_,  desc, func, select
from src.controllers.base_controller import BaseController
from src.models.url_check import (
    URLCheck, ScanResult, URLReputation,
    CheckStatus, ThreatLevel, ScanType
)
from src.models.user import User, UserRole
from src.services.url_analysis_service import (
    URLAnalysisService, URLAnalysisError, InvalidURLError
)
from src.services.ai_service import AIService
from src.services.email_service import EmailService
from src.services.security_service import (
    SecurityService, AuthenticationError, RateLimitError
)
from src.authentication.auth_service import AuthService
from src.utils import utc_datetime


class URLCheckController(BaseController):
    """Controller for URL analysis and security checking operations.
    
    Handles all business logic related to URL checks including:
    - URL validation and normalization
    - Security scanning and threat detection
    - Reputation management
    - Bulk processing
    - History and statistics
    - Webhook notifications
    """
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        url_analysis_service: URLAnalysisService,
        ai_service: AIService = None
    ):
        """Initialize URL check controller.
        
        Args:
            security_service: Security service for validation
            auth_service: Authentication service
            email_service: Email service for notifications
            url_analysis_service: URL analysis service
            ai_service: AI service for advanced analysis
        """
        super().__init__(security_service, auth_service, email_service)
        self.url_analysis_service = url_analysis_service
        self.ai_service = ai_service or AIService()
        
        # Rate limits
        self.max_checks_per_hour_free = 100
        self.max_checks_per_hour_premium = 1000
        self.max_bulk_urls = 100
    
    async def check_url(
        self,
        url: str,
        user: Optional[User] = None,
        scan_types: Optional[List[ScanType]] = None,
        priority: bool = False,
        callback_url: Optional[str] = None,
        background_tasks: Optional[BackgroundTasks] = None
    ) -> URLCheck:
        """Perform URL security check and analysis.
        
        Args:
            url: URL to analyze
            user: User requesting the check (optional for anonymous)
            scan_types: Types of scans to perform
            priority: Whether to prioritize this scan
            callback_url: Webhook URL for async results
            background_tasks: FastAPI background tasks
            
        Returns:
            URLCheck: Created URL check instance
            
        Raises:
            HTTPException: If validation fails or rate limit exceeded
        """
        # Set default scan types
        if scan_types is None:
            scan_types = [ScanType.SECURITY, ScanType.REPUTATION, ScanType.CONTENT]
        
        # Check rate limits
        if user:
            rate_limit = (
                self.max_checks_per_hour_premium
                if user.subscription_plan == "premium"
                else self.max_checks_per_hour_free
            )
            
            if not await self.check_rate_limit(
                user.id, "url_check", rate_limit
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded for URL checks"
                )
        
        # Validate and normalize URL
        normalized_url = await self._validate_and_normalize_url(url)
        domain = self._extract_domain(normalized_url)
        
        # Check for recent duplicate analysis
        recent_check = await self._get_recent_check(normalized_url, user)
        if recent_check and not priority:
            self.log_operation(
                "Returning cached URL check result",
                user_id=user.id if user else None,
                details={"url": normalized_url, "cached_check_id": str(recent_check.id)}
            )
            return recent_check
        
        try:
            async with self.get_db_session() as session:
                # Create URL check record
                url_check = URLCheck(
                    id=uuid.uuid4(),
                    original_url=url,
                    normalized_url=normalized_url,
                    domain=domain,
                    status=CheckStatus.PENDING,
                    user_id=user.id if user else None,
                    scan_types=scan_types,
                    priority=priority,
                    callback_url=callback_url,
                    created_at=utc_datetime(),
                    scan_started_at=utc_datetime()
                )
                
                session.add(url_check)
                await session.refresh(url_check)
                
                # Log the operation
                self.log_operation(
                    "URL check initiated",
                    user_id=user.id if user else None,
                    details={
                        "check_id": str(url_check.id),
                        "url": normalized_url,
                        "scan_types": [st.value for st in scan_types],
                        "priority": priority
                    }
                )
                
                # Start analysis in background if background_tasks provided
                if background_tasks:
                    background_tasks.add_task(
                        self._perform_url_analysis,
                        url_check.id,
                        normalized_url,
                        scan_types,
                        callback_url
                    )
                else:
                    # Perform synchronous analysis for immediate results
                    await self._perform_url_analysis(
                        url_check.id,
                        normalized_url,
                        scan_types,
                        callback_url
                    )
                
                return url_check
            
        except Exception as e:
            raise self.handle_database_error(e, "URL check creation")
    
    async def bulk_check_urls(
        self,
        urls: List[str],
        user: User,
        scan_types: Optional[List[ScanType]] = None,
        callback_url: Optional[str] = None,
        background_tasks: Optional[BackgroundTasks] = None
    ) -> List[URLCheck]:
        """Perform bulk URL analysis.
        
        Args:
            urls: List of URLs to analyze
            user: User requesting the bulk check
            scan_types: Types of scans to perform
            callback_url: Webhook URL for async results
            background_tasks: FastAPI background tasks
            
        Returns:
            List[URLCheck]: Created URL check instances
            
        Raises:
            HTTPException: If validation fails or limits exceeded
        """
        # Validate bulk request
        if len(urls) > self.max_bulk_urls:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum {self.max_bulk_urls} URLs allowed per bulk request"
            )
        
        # Check rate limits (bulk requests count as multiple checks)
        rate_limit = (
            self.max_checks_per_hour_premium
            if user.subscription_plan == "premium"
            else self.max_checks_per_hour_free
        )
        
        if not await self.check_rate_limit(
            user.id, "url_check", rate_limit, window_seconds=3600
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for URL checks"
            )
        
        # Set default scan types
        if scan_types is None:
            scan_types = [ScanType.SECURITY, ScanType.REPUTATION]
        
        url_checks = []
        
        try:
            async with self.get_db_session() as session:
                for url in urls:
                    try:
                        # Validate and normalize each URL
                        normalized_url = await self._validate_and_normalize_url(url)
                        domain = self._extract_domain(normalized_url)
                        
                        # Create URL check record
                        url_check = URLCheck(
                            id=uuid.uuid4(),
                            original_url=url,
                            normalized_url=normalized_url,
                            domain=domain,
                            status=CheckStatus.PENDING,
                            user_id=user.id,
                            scan_types=scan_types,
                            priority=False,  # Bulk requests are not prioritized
                            callback_url=callback_url,
                            created_at=utc_datetime(),
                            scan_started_at=utc_datetime()
                        )
                        
                        session.add(url_check)
                        url_checks.append(url_check)
                        
                    except Exception as e:
                        # Log invalid URL but continue with others
                        self.logger.warning(
                            f"Invalid URL in bulk request: {url}",
                            extra={"error": str(e), "user_id": user.id}
                        )
                        continue
                
                if not url_checks:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="No valid URLs found in bulk request"
                    )
                
                # Refresh all URL checks
                for url_check in url_checks:
                    await session.refresh(url_check)
                
                # Log the operation
                self.log_operation(
                    "Bulk URL check initiated",
                    user_id=user.id,
                    details={
                        "total_urls": len(urls),
                        "valid_urls": len(url_checks),
                        "scan_types": [st.value for st in scan_types]
                    }
                )
                
                # Start bulk analysis in background
                if background_tasks:
                    background_tasks.add_task(
                        self._perform_bulk_analysis,
                        [uc.id for uc in url_checks],
                        scan_types,
                        callback_url
                    )
                
                return url_checks
            
        except Exception as e:
            raise self.handle_database_error(str(e), "bulk URL check creation")
    
    async def get_url_check(
        self,
        check_id: uuid.UUID,
        user: Optional[User] = None
    ) -> URLCheck:
        """Get URL check results by ID.
        
        Args:
            check_id: URL check ID
            user: Current user (for access control)
            
        Returns:
            URLCheck: URL check instance
            
        Raises:
            HTTPException: If check not found or access denied
        """
        async with self.get_db_session() as session:
            # Use async ORM API instead of sync session.query
            
            stmt = select(URLCheck).where(URLCheck.id == check_id)
            result = await session.execute(stmt)
            url_check = result.scalar_one_or_none()
            
            if not url_check:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="URL check not found"
                )
            
            # Check access permissions
            if user and url_check.user_id and url_check.user_id != user.id:
                if user.role != UserRole.ADMIN:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this URL check"
                    )
            
            self.log_operation(
                "URL check retrieved",
                user_id=user.id if user else None,
                details={"check_id": str(check_id)}
            )
            
            return url_check
    
    async def get_scan_results(
        self,
        check_id: uuid.UUID,
        user: Optional[User] = None
    ) -> List[ScanResult]:
        """Get detailed scan results for a URL check.
        
        Args:
            check_id: URL check ID
            user: Current user (for access control)
            
        Returns:
            List[ScanResult]: Detailed scan results
            
        Raises:
            HTTPException: If check not found or access denied
        """
        # Verify URL check exists and user has access
        url_check = await self.get_url_check(check_id, user)
        
        # Get scan results
        async with self.get_db_session() as session:
            # Use async ORM API instead of sync session.query
            from sqlalchemy import select
            stmt = (
                select(ScanResult)
                .where(ScanResult.url_check_id == check_id)
                .order_by(ScanResult.created_at.desc())
            )
            result = await session.execute(stmt)
            scan_results = result.scalars().all()
            
            self.log_operation(
                "Scan results retrieved",
                user_id=user.id if user else None,
                details={"check_id": str(check_id), "results_count": len(scan_results)}
            )
            
            return scan_results
    
    async def get_url_history(
        self,
        user: User,
        url: Optional[str] = None,
        domain: Optional[str] = None,
        threat_level: Optional[ThreatLevel] = None,
        status: Optional[CheckStatus] = None,
        page: int = 1,
        page_size: int = 20
    ) -> Tuple[List[URLCheck], int]:
        """Get URL check history for a user.
        
        Args:
            user: User to get history for
            url: Filter by specific URL
            domain: Filter by domain
            threat_level: Filter by threat level
            status: Filter by status
            page: Page number
            page_size: Items per page
            
        Returns:
            Tuple: (url_checks, total_count)
        """
        # Validate pagination
        skip, limit = self.validate_pagination(page - 1, page_size)
        
        async with self.get_db_session() as session:
            # Build query using async select
            stmt = (
                select(URLCheck)
                .where(URLCheck.user_id == user.id)
            )
            
            # Apply filters
            if url:
                normalized_url = await self._validate_and_normalize_url(url)
                stmt = stmt.where(URLCheck.normalized_url == normalized_url)
            
            if domain:
                stmt = stmt.where(URLCheck.domain.ilike(f"%{domain}%"))
            
            if threat_level:
                stmt = stmt.where(URLCheck.threat_level == threat_level)
            
            if status:
                stmt = stmt.where(URLCheck.status == status)
            
            # Get total count
            count_stmt = select(func.count()).select_from(stmt.subquery())
            total_count = (await session.execute(count_stmt)).scalar()
            
            # Apply pagination and ordering
            stmt = (
                stmt
                .order_by(desc(URLCheck.created_at))
                .offset(skip)
                .limit(limit)
            )
            
            result = await session.execute(stmt)
            url_checks = result.scalars().all()
            
            self.log_operation(
                "URL history retrieved",
                user_id=user.id,
                details={
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "filters": {
                        "url": url,
                        "domain": domain,
                        "threat_level": threat_level.value if threat_level else None,
                        "status": status.value if status else None
                    }
                }
            )
            
            return url_checks, total_count
    
    async def get_domain_reputation(
        self,
        domain: str,
        user: Optional[User] = None
    ) -> Optional[URLReputation]:
        """Get domain reputation information.
        
        Args:
            domain: Domain to check reputation for
            user: Current user (for logging)
            
        Returns:
            URLReputation: Domain reputation data or None if not found
        """
        # Normalize domain
        domain = domain.lower().strip()
        
        async with self.get_db_session() as session:
            # Get reputation data using async select
            stmt = select(URLReputation).where(URLReputation.domain == domain)
            result = await session.execute(stmt)
            reputation = result.scalar_one_or_none()
            
            if reputation:
                # Update last seen timestamp
                reputation.last_seen = utc_datetime()
            
            self.log_operation(
                "Domain reputation retrieved",
                user_id=user.id if user else None,
                details={
                    "domain": domain,
                    "reputation_found": reputation is not None
                }
            )
            
            return reputation
    
    async def get_url_check_statistics(
        self,
        user: User,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get URL check statistics for a user.
        
        Args:
            user: User to get statistics for
            days: Number of days to include in statistics
            
        Returns:
            Dict: URL check statistics
        """
        cutoff_date = utc_datetime() - timedelta(days=days)
        
        async with self.get_db_session() as session:
            # Base query for user's checks in the time period using async select
            base_stmt = (
                select(URLCheck)
                .where(
                    and_(
                        URLCheck.user_id == user.id,
                        URLCheck.created_at >= cutoff_date
                    )
                )
            )
            
            # Total counts
            total_count_stmt = select(func.count()).select_from(base_stmt.subquery())
            total_checks = (await session.execute(total_count_stmt)).scalar()
            
            completed_count_stmt = select(func.count()).select_from(
                base_stmt.where(URLCheck.status == CheckStatus.COMPLETED).subquery()
            )
            completed_checks = (await session.execute(completed_count_stmt)).scalar()
            
            failed_count_stmt = select(func.count()).select_from(
                base_stmt.where(URLCheck.status == CheckStatus.FAILED).subquery()
            )
            failed_checks = (await session.execute(failed_count_stmt)).scalar()
            
            # Threat level distribution
            threat_distribution = {}
            for threat_level in ThreatLevel:
                threat_count_stmt = select(func.count()).select_from(
                    base_stmt.where(URLCheck.threat_level == threat_level).subquery()
                )
                count = (await session.execute(threat_count_stmt)).scalar()
                threat_distribution[threat_level.value] = count
            
            # Top domains checked
            top_domains_stmt = (
                select(URLCheck.domain, func.count(URLCheck.id).label('count'))
                .where(
                    and_(
                        URLCheck.user_id == user.id,
                        URLCheck.created_at >= cutoff_date
                    )
                )
                .group_by(URLCheck.domain)
                .order_by(desc('count'))
                .limit(10)
            )
            
            top_domains_result = await session.execute(top_domains_stmt)
            top_domains = top_domains_result.all()
            
            top_domains_list = [
                {"domain": domain, "count": count}
                for domain, count in top_domains
            ]
            
            # Recent activity
            recent_checks_stmt = (
                base_stmt
                .order_by(desc(URLCheck.created_at))
                .limit(10)
            )
            
            recent_checks_result = await session.execute(recent_checks_stmt)
            recent_checks = recent_checks_result.scalars().all()
            
            recent_activity = [
                {
                    "id": str(check.id),
                    "url": check.normalized_url,
                    "threat_level": check.threat_level.value if check.threat_level else None,
                    "status": check.status.value,
                    "created_at": check.created_at.isoformat()
                }
                for check in recent_checks
            ]
            
            stats = {
                "total_checks": total_checks,
                "completed_checks": completed_checks,
                "failed_checks": failed_checks,
                "success_rate": round((completed_checks / total_checks * 100) if total_checks > 0 else 0, 2),
                "threat_distribution": threat_distribution,
                "top_domains": top_domains_list,
                "recent_activity": recent_activity
            }
            
            self.log_operation(
                "URL check statistics retrieved",
                user_id=user.id,
                details={"days": days, "total_checks": total_checks}
            )
            
            return stats
    
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
    
    async def _get_recent_check(self, normalized_url: str, user: Optional[User]) -> Optional[URLCheck]:
        """Get recent check for the same URL by the same user."""
        if not user:
            return None
            
        cutoff_time = utc_datetime() - timedelta(minutes=5)
        
        async with self.get_db_session() as session:
            return self._get_recent_check_from_db(session, normalized_url, user.id)

    def _get_recent_check_from_db(self, session, normalized_url: str, user_id: uuid.UUID) -> Optional[URLCheck]:
        """Get recent check for the same URL by the same user from database session.
        
        Args:
            session: Database session
            normalized_url: Normalized URL to check
            user_id: User ID
            
        Returns:
            Recent URLCheck record or None if not found
        """
        cutoff_time = utc_datetime() - timedelta(minutes=5)
        
        return (
            session.query(URLCheck)
            .filter(
                and_(
                    URLCheck.normalized_url == normalized_url,
                    URLCheck.created_at >= cutoff_time,
                    URLCheck.status == CheckStatus.COMPLETED,
                    URLCheck.user_id == user_id
                )
            )
            .order_by(desc(URLCheck.created_at))
            .first()
        )
    
    async def _perform_url_analysis(
        self,
        check_id: uuid.UUID,
        url: str,
        scan_types: List[ScanType],
        callback_url: Optional[str] = None
    ) -> None:
        """Perform URL analysis in background.
        
        Args:
            check_id: URL check ID
            url: URL to analyze
            scan_types: Types of scans to perform
            callback_url: Webhook URL for results
        """
        try:
            async with self.get_db_session() as db:
                # Get URL check record
                url_check = (
                    db.query(URLCheck)
                    .filter(URLCheck.id == check_id)
                    .first()
                )
                
                if not url_check:
                    self.logger.error(f"URL check {check_id} not found for analysis")
                    return
                
                # Update status to in progress
                url_check.status = CheckStatus.IN_PROGRESS
                db.commit()
                
                # Get domain reputation data for analysis
                domain = self._extract_domain(url)
                reputation_data = self._get_domain_reputation_data(db, domain)
                
                # Perform analysis using URL analysis service (now pure business logic)
                analysis_results = self.url_analysis_service.analyze_url(
                    url, scan_types, reputation_data
                )
                
                # Update URL check with results
                self._update_url_check_with_results(db, url_check, analysis_results)
                
                # Create scan result records
                self._create_scan_results(db, check_id, analysis_results)
                
                # Update domain reputation based on analysis
                self._update_domain_reputation_from_analysis(
                    db, domain, analysis_results.get('threat_level'), 
                    analysis_results.get('confidence_score')
                )
                
                db.commit()
            
            # Send webhook notification if callback URL provided
            if callback_url:
                await self._send_webhook_notification(callback_url, url_check)
            
            self.log_operation(
                "URL analysis completed",
                details={
                    "check_id": str(check_id),
                    "url": url,
                    "threat_level": url_check.threat_level.value if url_check.threat_level else None,
                    "confidence_score": url_check.confidence_score
                }
            )
            
        except Exception as e:
            # Update URL check with error status
            try:
                async with self.get_db_session() as db:
                    url_check = (
                        db.query(URLCheck)
                        .filter(URLCheck.id == check_id)
                        .first()
                    )
                    if url_check:
                        url_check.status = CheckStatus.FAILED
                        url_check.error_message = str(e)
                        url_check.scan_completed_at = utc_datetime()
                        db.commit()
            except Exception as commit_error:
                self.logger.error(f"Failed to update URL check status: {str(commit_error)}")
            
            self.logger.error(
                f"URL analysis failed for check {check_id}: {str(e)}",
                extra={"check_id": str(check_id), "url": url}
            )
    
    async def _perform_bulk_analysis(
        self,
        check_ids: List[uuid.UUID],
        scan_types: List[ScanType],
        callback_url: Optional[str] = None
    ) -> None:
        """Perform bulk URL analysis in background.
        
        Args:
            check_ids: List of URL check IDs
            scan_types: Types of scans to perform
            callback_url: Webhook URL for results
        """
        results = []
        
        async with self.get_db_session() as session:
            for check_id in check_ids:
                try:
                    url_check = (
                        session.query(URLCheck)
                        .filter(URLCheck.id == check_id)
                        .first()
                    )
                    
                    if url_check:
                        await self._perform_url_analysis(
                            check_id,
                            url_check.normalized_url,
                            scan_types
                        )
                        
                        # Refresh to get updated data
                        await session.refresh(url_check)
                        results.append(url_check)
                        
                except Exception as e:
                    self.logger.error(
                        f"Bulk analysis failed for check {check_id}: {str(e)}"
                    )
            
            # Send bulk webhook notification if callback URL provided
            if callback_url and results:
                await self._send_bulk_webhook_notification(callback_url, results)
            
            self.log_operation(
                "Bulk URL analysis completed",
                details={
                    "total_checks": len(check_ids),
                    "successful_checks": len(results)
                }
            )
    
    async def _update_domain_reputation(
        self,
        domain: str,
        threat_level: Optional[ThreatLevel]
    ) -> None:
        """Update domain reputation based on analysis results.
        
        Args:
            domain: Domain to update reputation for
            threat_level: Detected threat level
        """
        try:
            async with self.get_db_session() as session:
                self._update_domain_reputation_from_analysis(
                    session, domain, threat_level, None
                )
                session.commit()
        except Exception as e:
            self.logger.error(f"Failed to update domain reputation: {str(e)}")

    def _get_domain_reputation_data(self, session, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain reputation data for analysis.
        
        Args:
            session: Database session
            domain: Domain to get reputation for
            
        Returns:
            Dict containing reputation data or None if not found
        """
        reputation = (
            session.query(URLReputation)
            .filter(URLReputation.domain == domain)
            .first()
        )
        
        if not reputation:
            return None
            
        return {
            'domain': reputation.domain,
            'reputation_score': reputation.reputation_score,
            'total_checks': reputation.total_checks,
            'malicious_count': reputation.malicious_count,
            'first_seen': reputation.first_seen,
            'last_seen': reputation.last_seen,
            'last_threat_level': reputation.last_threat_level
        }

    def _update_url_check_with_results(self, session, url_check: URLCheck, analysis_results: Dict[str, Any]) -> None:
        """Update URL check record with analysis results.
        
        Args:
            session: Database session
            url_check: URLCheck record to update
            analysis_results: Analysis results from URLAnalysisService
        """
        url_check.status = CheckStatus.COMPLETED
        url_check.threat_level = analysis_results.get('threat_level')
        url_check.confidence_score = analysis_results.get('confidence_score')
        url_check.analysis_results = analysis_results
        url_check.scan_completed_at = utc_datetime()

    def _create_scan_results(self, session, url_check_id: uuid.UUID, analysis_results: Dict[str, Any]) -> None:
        """Create scan result records from analysis results.
        
        Args:
            session: Database session
            url_check_id: URL check ID
            analysis_results: Analysis results containing scan data
        """
        for scan_result_data in analysis_results.get('scan_results', []):
            scan_result = ScanResult(
                id=uuid.uuid4(),
                url_check_id=url_check_id,
                scan_type=ScanType(scan_result_data['scan_type']),
                provider=scan_result_data['provider'],
                threat_detected=scan_result_data['threat_detected'],
                threat_types=scan_result_data.get('threat_types', []),
                confidence_score=scan_result_data['confidence_score'],
                metadata=scan_result_data.get('metadata', {}),
                created_at=utc_datetime()
            )
            session.add(scan_result)

    def _update_domain_reputation_from_analysis(
        self, 
        session, 
        domain: str, 
        threat_level: Optional[ThreatLevel], 
        confidence_score: Optional[float]
    ) -> None:
        """Update domain reputation based on analysis results.
        
        Args:
            session: Database session
            domain: Domain to update reputation for
            threat_level: Detected threat level
            confidence_score: Analysis confidence score
        """
        reputation = (
            session.query(URLReputation)
            .filter(URLReputation.domain == domain)
            .first()
        )
        
        if not reputation:
            # Create new reputation record
            reputation = URLReputation(
                id=uuid.uuid4(),
                domain=domain,
                reputation_score=50,  # Neutral starting score
                total_checks=0,
                malicious_count=0,
                first_seen=utc_datetime(),
                last_seen=utc_datetime()
            )
            session.add(reputation)
        
        # Update reputation metrics
        reputation.total_checks += 1
        reputation.last_seen = utc_datetime()
        reputation.last_threat_level = threat_level
        
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            reputation.malicious_count += 1
        
        # Calculate new reputation score
        malicious_ratio = reputation.malicious_count / reputation.total_checks
        reputation.reputation_score = max(0, min(100, int(100 * (1 - malicious_ratio))))
    
    async def _send_webhook_notification(
        self,
        webhook_url: str,
        url_check: URLCheck
    ) -> None:
        """Send webhook notification for completed URL check.
        
        Args:
            webhook_url: Webhook URL to send notification to
            url_check: Completed URL check
        """
        try:
            # This would implement actual webhook sending
            # For now, just log the notification
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
                        self.log_operation(
                            "Webhook notification sent",
                            details={
                                "webhook_url": webhook_url,
                                "check_id": str(url_check.id),
                                "url": url_check.normalized_url,
                                "status": url_check.status.value
                            }
                        )
            
        except Exception as e:
            self.logger.error(f"Webhook notification failed: {str(e)}")
    
    async def _send_bulk_webhook_notification(
        self,
        webhook_url: str,
        url_checks: List[URLCheck]
    ) -> None:
        """Send bulk webhook notification for completed URL checks.
        
        Args:
            webhook_url: Webhook URL to send notification to
            url_checks: List of completed URL checks
        """
        try:
            payload = {
                "event": "bulk_url_check_completed",
                "data": {
                    "total_urls": len(url_checks),
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "results": [
                        {
                            "id": str(result.id),
                            "url": result.original_url,
                            "threat_level": result.threat_level.value if result.threat_level else None,
                            "status": result.status.value
                        }
                        for result in url_checks
                    ]
                }
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, timeout=30) as response:
                    if response.status != 200:
                        self.log_operation(
                            "Bulk webhook notification sent",
                            details={
                                "webhook_url": webhook_url,
                                "total_checks": len(url_checks),
                                "check_ids": [str(uc.id) for uc in url_checks]
                            }
                        )

        except Exception as e:
            self.logger.error(f"Bulk webhook notification failed: {str(e)}")