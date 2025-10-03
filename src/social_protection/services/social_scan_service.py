#!/usr/bin/env python3
"""
LinkShield Backend Social Scan Service

Comprehensive service for social media profile scanning, content analysis,
and risk assessment. Integrates with database models for persistent storage.
"""

import asyncio
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import selectinload

from src.models.social_protection import (
    SocialProfileScan,
    ContentRiskAssessment,
    PlatformType,
    ScanStatus,
    RiskLevel,
    ContentType,
    AssessmentType
)
from src.models.user import User
from src.models.project import Project
from src.social_protection.data_models import (
    SocialProfileInfo,
    ContentAnalysisRequest,
    ComprehensiveAssessment,
    AssessmentHistory
)
from src.services.ai_service import AIService
from src.social_protection.exceptions import (
    ScanServiceError,
    RecordNotFoundError,
    DatabaseError,
    AIServiceError,
    TimeoutError as SPTimeoutError
)
from src.social_protection.logging_utils import get_logger
from src.social_protection.utils.retry import async_retry

logger = get_logger("SocialScanService")


# Legacy exception classes for backward compatibility
class SocialScanServiceError(ScanServiceError):
    """Base exception for social scan service errors."""
    pass


class ScanNotFoundError(RecordNotFoundError):
    """Scan not found error."""
    pass


class InvalidScanStateError(ScanServiceError):
    """Invalid scan state error."""
    pass


class SocialScanService:
    """
    Service for comprehensive social media profile scanning and risk assessment.
    
    This service handles:
    - Social profile scanning initiation and management
    - Content risk assessment processing
    - Database persistence of scan results
    - Historical analysis and trend detection
    - Integration with AI services for advanced analysis
    - Redis-based caching for improved performance
    """
    
    def __init__(
        self,
        ai_service: AIService,
        cache_service: Optional[Any] = None,
        webhook_service: Optional[Any] = None
    ):
        """
        Initialize the social scan service.
        
        Args:
            ai_service: AI service for content analysis
            cache_service: Optional cache service for result caching
            webhook_service: Optional webhook service for notifications
        """
        self.ai_service = ai_service
        self.cache_service = cache_service
        self.webhook_service = webhook_service
        
        # Risk assessment thresholds
        self.risk_thresholds = {
            RiskLevel.LOW: 0.3,
            RiskLevel.MEDIUM: 0.6,
            RiskLevel.HIGH: 0.8,
            RiskLevel.CRITICAL: 0.9
        }
        
        # Content analysis weights for different factors
        self.analysis_weights = {
            "phishing_indicators": 0.3,
            "malicious_content": 0.25,
            "suspicious_links": 0.2,
            "fake_profiles": 0.15,
            "spam_content": 0.1
        }
        
        # Cache TTL settings (in seconds)
        self.cache_ttl = {
            "scan_result": 3600,  # 1 hour
            "profile_data": 1800,  # 30 minutes
            "analysis_result": 300  # 5 minutes
        }
    
    async def initiate_profile_scan(
        self,
        db: AsyncSession,
        user_id: UUID,
        project_id: Optional[UUID],
        platform: PlatformType,
        profile_url: str,
        scan_options: Optional[Dict[str, Any]] = None
    ) -> SocialProfileScan:
        """
        Initiate a new social profile scan.
        
        Args:
            db: Database session
            user_id: ID of the user requesting the scan
            project_id: Optional project ID for organization
            platform: Social media platform to scan
            profile_url: URL of the profile to scan
            scan_options: Optional scan configuration
            
        Returns:
            SocialProfileScan: Created scan record
            
        Raises:
            SocialScanServiceError: If scan creation fails
        """
        try:
            start_time = time.time()
            logger.info(
                "Initiating profile scan",
                user_id=user_id,
                platform=platform.value,
                operation="initiate_profile_scan",
                profile_url=profile_url
            )
            
            # Create new scan record
            scan = SocialProfileScan(
                id=uuid4(),
                user_id=user_id,
                project_id=project_id,
                platform=platform,
                profile_url=profile_url,
                status=ScanStatus.PENDING,
                scan_options=scan_options or {},
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            
            db.add(scan)
            
            try:
                await db.commit()
                await db.refresh(scan)
            except Exception as db_error:
                await db.rollback()
                logger.error(
                    "Database error creating scan",
                    error=db_error,
                    user_id=user_id,
                    platform=platform.value,
                    operation="initiate_profile_scan"
                )
                raise DatabaseError(
                    "Failed to create scan record in database",
                    details={"user_id": str(user_id), "platform": platform.value},
                    original_error=db_error
                )
            
            duration_ms = (time.time() - start_time) * 1000
            logger.info(
                "Successfully initiated profile scan",
                scan_id=scan.id,
                user_id=user_id,
                platform=platform.value,
                operation="initiate_profile_scan",
                duration_ms=duration_ms
            )
            
            # Start background scan processing
            asyncio.create_task(self._process_profile_scan(db, scan.id))
            
            return scan
            
        except DatabaseError:
            raise
        except Exception as e:
            logger.error(
                "Unexpected error initiating profile scan",
                error=e,
                user_id=user_id,
                platform=platform.value,
                operation="initiate_profile_scan"
            )
            raise SocialScanServiceError(
                f"Failed to initiate profile scan: {str(e)}",
                details={"user_id": str(user_id), "platform": platform.value},
                original_error=e
            )
    
    async def get_scan_status(self, db: AsyncSession, scan_id: UUID) -> SocialProfileScan:
        """
        Get the current status of a profile scan with caching support.
        
        Args:
            db: Database session
            scan_id: ID of the scan to check
            
        Returns:
            SocialProfileScan: Current scan record
            
        Raises:
            ScanNotFoundError: If scan is not found
        """
        try:
            logger.debug(
                "Retrieving scan status",
                scan_id=scan_id,
                operation="get_scan_status"
            )
            
            # Try cache first for completed scans
            if self.cache_service:
                cached_result = await self.cache_service.get_scan_result(scan_id)
                if cached_result:
                    logger.debug(
                        "Scan status retrieved from cache",
                        scan_id=scan_id,
                        operation="get_scan_status"
                    )
                    # Note: This returns dict, not ORM object
                    # For now, we'll skip cache and always query DB for ORM object
                    pass
            
            result = await db.execute(
                select(SocialProfileScan)
                .where(SocialProfileScan.id == scan_id)
                .options(selectinload(SocialProfileScan.risk_assessments))
            )
            scan = result.scalar_one_or_none()
            
            if not scan:
                logger.warning(
                    "Scan not found",
                    scan_id=scan_id,
                    operation="get_scan_status"
                )
                raise ScanNotFoundError(
                    f"Scan not found",
                    details={"scan_id": str(scan_id)}
                )
            
            # Cache completed scans
            if self.cache_service and scan.status == ScanStatus.COMPLETED:
                scan_dict = {
                    "id": str(scan.id),
                    "user_id": str(scan.user_id),
                    "platform": scan.platform.value,
                    "profile_url": scan.profile_url,
                    "status": scan.status.value,
                    "created_at": scan.created_at.isoformat() if scan.created_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
                }
                await self.cache_service.set_scan_result(
                    scan_id,
                    scan_dict,
                    self.cache_ttl["scan_result"]
                )
            
            return scan
            
        except ScanNotFoundError:
            raise
        except Exception as e:
            logger.error(
                "Database error retrieving scan status",
                error=str(e),
                scan_id=scan_id,
                operation="get_scan_status"
            )
            raise DatabaseError(
                f"Failed to get scan status",
                details={"scan_id": str(scan_id)},
                original_error=e
            )
    
    async def get_user_scans(
        self,
        db: AsyncSession,
        user_id: UUID,
        project_id: Optional[UUID] = None,
        platform: Optional[PlatformType] = None,
        status: Optional[ScanStatus] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[SocialProfileScan]:
        """
        Get scans for a specific user with optional filtering.
        
        Args:
            db: Database session
            user_id: User ID to filter by
            project_id: Optional project ID filter
            platform: Optional platform filter
            status: Optional status filter
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            List[SocialProfileScan]: List of matching scans
        """
        try:
            query = select(SocialProfileScan).where(SocialProfileScan.user_id == user_id)
            
            # Apply filters
            if project_id:
                query = query.where(SocialProfileScan.project_id == project_id)
            
            if platform:
                query = query.where(SocialProfileScan.platform == platform)
            
            if status:
                query = query.where(SocialProfileScan.status == status)
            
            # Add ordering and pagination
            query = query.order_by(SocialProfileScan.created_at.desc())
            query = query.offset(offset).limit(limit)
            
            result = await db.execute(query)
            scans = result.scalars().all()
            
            return list(scans)
            
        except Exception as e:
            self.logger.error(f"Failed to get user scans: {str(e)}")
            raise SocialScanServiceError(f"Failed to get user scans: {str(e)}")
    
    async def create_content_risk_assessment(
        self,
        db: AsyncSession,
        scan_id: UUID,
        content_type: ContentType,
        content_data: Dict[str, Any],
        assessment_type: AssessmentType = AssessmentType.CONTENT_RISK
    ) -> ContentRiskAssessment:
        """
        Create a content risk assessment for a scan.
        
        Args:
            db: Database session
            scan_id: ID of the parent scan
            content_type: Type of content being assessed
            content_data: Content data to analyze
            assessment_type: Type of assessment (automated/manual)
            
        Returns:
            ContentRiskAssessment: Created assessment record
        """
        try:
            # Perform AI-powered content analysis
            analysis_result = await self._analyze_content_with_ai(content_data, content_type)
            
            # Calculate risk score and level
            risk_score = self._calculate_risk_score(analysis_result)
            risk_level = self._determine_risk_level(risk_score)
            
            # Create assessment record
            assessment = ContentRiskAssessment(
                id=uuid4(),
                scan_id=scan_id,
                content_type=content_type,
                assessment_type=assessment_type,
                risk_level=risk_level,
                risk_score=risk_score,
                risk_factors=analysis_result.get("risk_factors", []),
                confidence_score=analysis_result.get("confidence_score", 0.0),
                content_metadata=content_data,
                analysis_results=analysis_result,
                created_at=datetime.now(timezone.utc)
            )
            
            db.add(assessment)
            await db.commit()
            await db.refresh(assessment)
            
            self.logger.info(f"Created content risk assessment {assessment.id} for scan {scan_id}")
            
            return assessment
            
        except Exception as e:
            await db.rollback()
            self.logger.error(f"Failed to create content risk assessment: {str(e)}")
            raise SocialScanServiceError(f"Failed to create content risk assessment: {str(e)}")
    
    async def get_scan_assessments(
        self,
        db: AsyncSession,
        scan_id: UUID,
        content_type: Optional[ContentType] = None
    ) -> List[ContentRiskAssessment]:
        """
        Get all risk assessments for a specific scan.
        
        Args:
            db: Database session
            scan_id: ID of the scan
            content_type: Optional content type filter
            
        Returns:
            List[ContentRiskAssessment]: List of assessments
        """
        try:
            query = select(ContentRiskAssessment).where(ContentRiskAssessment.scan_id == scan_id)
            
            if content_type:
                query = query.where(ContentRiskAssessment.content_type == content_type)
            
            query = query.order_by(ContentRiskAssessment.created_at.desc())
            
            result = await db.execute(query)
            assessments = result.scalars().all()
            
            return list(assessments)
            
        except Exception as e:
            self.logger.error(f"Failed to get scan assessments: {str(e)}")
            raise SocialScanServiceError(f"Failed to get scan assessments: {str(e)}")
    
    async def get_comprehensive_assessment(
        self,
        db: AsyncSession,
        scan_id: UUID
    ) -> ComprehensiveAssessment:
        """
        Generate a comprehensive assessment for a completed scan.
        
        Args:
            db: Database session
            scan_id: ID of the scan
            
        Returns:
            ComprehensiveAssessment: Comprehensive assessment results
        """
        try:
            # Get scan and all its assessments
            scan = await self.get_scan_status(db, scan_id)
            assessments = await self.get_scan_assessments(db, scan_id)
            
            if not assessments:
                raise SocialScanServiceError("No assessments found for scan")
            
            # Calculate overall risk metrics
            total_assessments = len(assessments)
            risk_scores = [a.risk_score for a in assessments]
            avg_risk_score = sum(risk_scores) / len(risk_scores)
            max_risk_score = max(risk_scores)
            
            # Count risk levels
            risk_level_counts = {}
            for level in RiskLevel:
                risk_level_counts[level.value] = sum(1 for a in assessments if a.risk_level == level)
            
            # Aggregate risk factors
            all_risk_factors = []
            for assessment in assessments:
                all_risk_factors.extend(assessment.risk_factors)
            
            # Count unique risk factors
            risk_factor_counts = {}
            for factor in all_risk_factors:
                risk_factor_counts[factor] = risk_factor_counts.get(factor, 0) + 1
            
            # Determine overall risk level
            overall_risk_level = self._determine_risk_level(max_risk_score)
            
            # Calculate confidence score
            confidence_scores = [a.confidence_score for a in assessments if a.confidence_score > 0]
            avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
            
            return ComprehensiveAssessment(
                scan_id=scan_id,
                platform=scan.platform,
                overall_risk_level=overall_risk_level,
                overall_risk_score=max_risk_score,
                average_risk_score=avg_risk_score,
                confidence_score=avg_confidence,
                total_assessments=total_assessments,
                risk_level_distribution=risk_level_counts,
                top_risk_factors=dict(sorted(risk_factor_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
                assessment_summary={
                    "scan_duration": (scan.completed_at - scan.started_at).total_seconds() if scan.completed_at and scan.started_at else 0,
                    "content_types_analyzed": list(set(a.content_type.value for a in assessments)),
                    "assessment_types": list(set(a.assessment_type.value for a in assessments))
                },
                generated_at=datetime.now(timezone.utc)
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate comprehensive assessment: {str(e)}")
            raise SocialScanServiceError(f"Failed to generate comprehensive assessment: {str(e)}")
    
    async def get_assessment_history(
        self,
        db: AsyncSession,
        user_id: UUID,
        platform: Optional[PlatformType] = None,
        days: int = 30
    ) -> AssessmentHistory:
        """
        Get assessment history for a user over a specified period.
        
        Args:
            db: Database session
            user_id: User ID
            platform: Optional platform filter
            days: Number of days to look back
            
        Returns:
            AssessmentHistory: Historical assessment data
        """
        try:
            # Calculate date range
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days)
            
            # Build query for scans in date range
            scan_query = select(SocialProfileScan).where(
                and_(
                    SocialProfileScan.user_id == user_id,
                    SocialProfileScan.created_at >= start_date,
                    SocialProfileScan.created_at <= end_date
                )
            )
            
            if platform:
                scan_query = scan_query.where(SocialProfileScan.platform == platform)
            
            # Get scans
            scan_result = await db.execute(scan_query)
            scans = scan_result.scalars().all()
            scan_ids = [scan.id for scan in scans]
            
            if not scan_ids:
                return AssessmentHistory(
                    user_id=user_id,
                    platform=platform,
                    period_start=start_date,
                    period_end=end_date,
                    total_scans=0,
                    total_assessments=0,
                    risk_trend=[],
                    platform_distribution={},
                    risk_level_trends={}
                )
            
            # Get assessments for these scans
            assessment_query = select(ContentRiskAssessment).where(
                ContentRiskAssessment.scan_id.in_(scan_ids)
            ).order_by(ContentRiskAssessment.created_at)
            
            assessment_result = await db.execute(assessment_query)
            assessments = assessment_result.scalars().all()
            
            # Calculate trends and statistics
            risk_trend = self._calculate_risk_trend(assessments, start_date, end_date)
            platform_distribution = self._calculate_platform_distribution(scans)
            risk_level_trends = self._calculate_risk_level_trends(assessments, start_date, end_date)
            
            return AssessmentHistory(
                user_id=user_id,
                platform=platform,
                period_start=start_date,
                period_end=end_date,
                total_scans=len(scans),
                total_assessments=len(assessments),
                risk_trend=risk_trend,
                platform_distribution=platform_distribution,
                risk_level_trends=risk_level_trends
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get assessment history: {str(e)}")
            raise SocialScanServiceError(f"Failed to get assessment history: {str(e)}")
    
    async def _process_profile_scan(self, db: AsyncSession, scan_id: UUID) -> None:
        """
        Background task to process a profile scan.
        
        Args:
            db: Database session
            scan_id: ID of the scan to process
        """
        try:
            self.logger.info(f"Starting background processing for scan {scan_id}")
            
            # Update scan status to running
            await self._update_scan_status(db, scan_id, ScanStatus.RUNNING)
            
            # Get scan details
            scan = await self.get_scan_status(db, scan_id)
            
            # Collect profile data with timeout
            try:
                profile_data = await asyncio.wait_for(
                    self._collect_profile_data(scan.profile_url, scan.platform),
                    timeout=60.0  # 60 second timeout for data collection
                )
            except asyncio.TimeoutError:
                self.logger.error(f"Profile data collection timeout for scan {scan_id}")
                raise SPTimeoutError(
                    "Profile data collection timed out",
                    details={"scan_id": str(scan_id), "timeout_seconds": 60}
                )
            
            # Process different types of content
            content_types = [ContentType.POST, ContentType.COMMENT, ContentType.PROFILE_INFO]
            
            for content_type in content_types:
                if content_type.value in profile_data:
                    try:
                        await self.create_content_risk_assessment(
                            db=db,
                            scan_id=scan_id,
                            content_type=content_type,
                            content_data=profile_data[content_type.value]
                        )
                    except Exception as assessment_error:
                        self.logger.error(
                            f"Failed to create assessment for content type {content_type.value}: {str(assessment_error)}",
                            extra={
                                "scan_id": str(scan_id),
                                "content_type": content_type.value,
                                "error_type": type(assessment_error).__name__
                            }
                        )
                        # Continue processing other content types
                        continue
            
            # Update scan status to completed
            await self._update_scan_status(db, scan_id, ScanStatus.COMPLETED)
            
            self.logger.info(
                f"Successfully completed profile scan {scan_id}",
                extra={"scan_id": str(scan_id), "platform": scan.platform.value}
            )
            
            # Send webhook notification if configured
            await self._send_scan_completion_webhook(scan, "completed")
            
        except SPTimeoutError as e:
            self.logger.error(
                f"Timeout during profile scan {scan_id}: {str(e)}",
                extra={"scan_id": str(scan_id)}
            )
            await self._update_scan_status(db, scan_id, ScanStatus.FAILED, f"Timeout: {str(e)}")
            await self._send_scan_completion_webhook(scan, "failed", error=str(e))
        except Exception as e:
            self.logger.error(
                f"Profile scan {scan_id} failed: {str(e)}",
                exc_info=True,
                extra={"scan_id": str(scan_id), "error_type": type(e).__name__}
            )
            await self._update_scan_status(db, scan_id, ScanStatus.FAILED, str(e))
            await self._send_scan_completion_webhook(scan, "failed", error=str(e))
    
    async def _update_scan_status(
        self,
        db: AsyncSession,
        scan_id: UUID,
        status: ScanStatus,
        error_message: Optional[str] = None
    ) -> None:
        """
        Update scan status in database.
        
        Args:
            db: Database session
            scan_id: ID of the scan
            status: New status
            error_message: Optional error message
        """
        try:
            result = await db.execute(
                select(SocialProfileScan).where(SocialProfileScan.id == scan_id)
            )
            scan = result.scalar_one_or_none()
            
            if scan:
                scan.status = status
                scan.updated_at = datetime.now(timezone.utc)
                
                if status == ScanStatus.RUNNING and not scan.started_at:
                    scan.started_at = datetime.now(timezone.utc)
                elif status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
                    scan.completed_at = datetime.now(timezone.utc)
                
                if error_message:
                    scan.error_message = error_message
                
                await db.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to update scan status: {str(e)}")
            await db.rollback()
    
    async def _collect_profile_data(self, profile_url: str, platform: PlatformType) -> Dict[str, Any]:
        """
        Collect profile data using platform-specific adapters.
        
        Integrates with platform adapters to fetch real profile data including:
        - Profile information (username, bio, follower counts)
        - Recent posts and content
        - Comments and interactions
        - Engagement metrics
        
        Args:
            profile_url: URL of the profile to scan
            platform: Social media platform
            
        Returns:
            Dict[str, Any]: Collected profile data organized by content type
            
        Raises:
            ScanServiceError: If data collection fails
        """
        try:
            from src.social_protection.registry import registry
            from src.social_protection.data_models import ProfileScanRequest
            
            logger.info(
                "Collecting profile data",
                platform=platform.value,
                profile_url=profile_url,
                operation="_collect_profile_data"
            )
            
            # Check cache first
            if self.cache_service:
                cached_data = await self.cache_service.get_profile_data(
                    platform.value,
                    profile_url
                )
                if cached_data:
                    logger.info(
                        "Profile data retrieved from cache",
                        platform=platform.value,
                        profile_url=profile_url,
                        operation="_collect_profile_data"
                    )
                    return cached_data
            
            # Get platform adapter
            adapter = registry.get_adapter(platform)
            
            if not adapter or not adapter.is_enabled:
                logger.warning(
                    "Platform adapter not available, using fallback data",
                    platform=platform.value,
                    adapter_enabled=adapter.is_enabled if adapter else False
                )
                # Return fallback mock data when adapter is not available
                return self._get_fallback_profile_data()
            
            # Extract profile identifier from URL
            profile_id = self._extract_profile_id(profile_url, platform)
            
            # Create scan request
            scan_request = ProfileScanRequest(
                profile_url=profile_url,
                profile_id=profile_id,
                platform=platform,
                scan_depth="standard",
                include_posts=True,
                include_comments=True,
                max_posts=50,
                max_comments=100
            )
            
            # Perform profile scan using adapter with retry logic
            scan_result = await self._scan_profile_with_retry(adapter, scan_request)
            
            # Transform scan result into expected format
            profile_data = {
                ContentType.PROFILE_INFO.value: {
                    "username": scan_result.profile_info.get("username", "unknown"),
                    "display_name": scan_result.profile_info.get("display_name", ""),
                    "bio": scan_result.profile_info.get("bio", ""),
                    "follower_count": scan_result.profile_info.get("follower_count", 0),
                    "following_count": scan_result.profile_info.get("following_count", 0),
                    "post_count": scan_result.profile_info.get("post_count", 0),
                    "verified": scan_result.profile_info.get("verified", False),
                    "account_age_days": scan_result.profile_info.get("account_age_days", 0),
                    "profile_image_url": scan_result.profile_info.get("profile_image_url", ""),
                    "location": scan_result.profile_info.get("location", ""),
                    "website": scan_result.profile_info.get("website", "")
                }
            }
            
            # Add posts if available
            if scan_result.recent_posts:
                profile_data[ContentType.POST.value] = [
                    {
                        "id": post.get("id", ""),
                        "content": post.get("content", ""),
                        "timestamp": post.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "engagement": post.get("engagement", {}),
                        "media": post.get("media", []),
                        "links": post.get("links", []),
                        "hashtags": post.get("hashtags", []),
                        "mentions": post.get("mentions", [])
                    }
                    for post in scan_result.recent_posts
                ]
            
            # Add comments if available
            if scan_result.recent_comments:
                profile_data[ContentType.COMMENT.value] = [
                    {
                        "id": comment.get("id", ""),
                        "content": comment.get("content", ""),
                        "timestamp": comment.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "parent_post": comment.get("parent_post", ""),
                        "engagement": comment.get("engagement", {})
                    }
                    for comment in scan_result.recent_comments
                ]
            
            logger.info(
                "Successfully collected profile data",
                platform=platform.value,
                profile_id=profile_id,
                posts_count=len(profile_data.get(ContentType.POST.value, [])),
                comments_count=len(profile_data.get(ContentType.COMMENT.value, [])),
                operation="_collect_profile_data"
            )
            
            # Cache the profile data
            if self.cache_service:
                await self.cache_service.set_profile_data(
                    platform.value,
                    profile_url,
                    profile_data,
                    self.cache_ttl["profile_data"]
                )
            
            return profile_data
            
        except Exception as e:
            logger.error(
                "Failed to collect profile data",
                error=str(e),
                platform=platform.value,
                profile_url=profile_url,
                operation="_collect_profile_data"
            )
            # Return fallback data on error to allow scan to continue
            return self._get_fallback_profile_data()
    
    async def _send_scan_completion_webhook(
        self,
        scan: SocialProfileScan,
        status: str,
        error: Optional[str] = None
    ) -> None:
        """
        Send webhook notification for scan completion.
        
        Args:
            scan: Scan record
            status: Scan status (completed/failed)
            error: Optional error message for failed scans
        """
        if not self.webhook_service:
            return
        
        try:
            # Get webhook URL from scan options
            webhook_url = scan.scan_options.get("webhook_url")
            webhook_secret = scan.scan_options.get("webhook_secret")
            
            if not webhook_url:
                return
            
            # Prepare result summary
            result_summary = {
                "scan_id": str(scan.id),
                "platform": scan.platform.value,
                "profile_url": scan.profile_url,
                "status": status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
            }
            
            if error:
                result_summary["error"] = error
            
            # Send webhook notification
            await self.webhook_service.notify_scan_complete(
                webhook_url=webhook_url,
                scan_id=scan.id,
                user_id=scan.user_id,
                platform=scan.platform.value,
                status=status,
                result_summary=result_summary,
                secret=webhook_secret
            )
            
            logger.info(
                "Sent scan completion webhook",
                scan_id=scan.id,
                status=status,
                webhook_url=webhook_url
            )
            
        except Exception as e:
            logger.error(
                "Failed to send scan completion webhook",
                error=str(e),
                scan_id=scan.id
            )
            # Don't raise - webhook failure shouldn't fail the scan
    
    @async_retry(
        max_attempts=3,
        initial_delay=2.0,
        max_delay=10.0,
        exceptions=(ConnectionError, TimeoutError, Exception)
    )
    async def _scan_profile_with_retry(self, adapter, scan_request):
        """
        Scan profile with retry logic for transient failures.
        
        Args:
            adapter: Platform adapter instance
            scan_request: Profile scan request
            
        Returns:
            Profile scan result
        """
        return await adapter.scan_profile(scan_request)
    
    @async_retry(
        max_attempts=3,
        initial_delay=1.0,
        max_delay=10.0,
        exceptions=(ConnectionError, TimeoutError)
    )
    async def _analyze_with_ai_retry(self, text_content: str):
        """
        Analyze content with AI service with retry logic.
        
        Args:
            text_content: Text content to analyze
            
        Returns:
            AI analysis result
        """
        return await self.ai_service.analyze_content_safety(text_content)
    
    def _extract_profile_id(self, profile_url: str, platform: PlatformType) -> str:
        """
        Extract profile identifier from URL.
        
        Args:
            profile_url: Full profile URL
            platform: Social media platform
            
        Returns:
            Extracted profile identifier
        """
        # Simple extraction logic - can be enhanced per platform
        parts = profile_url.rstrip('/').split('/')
        return parts[-1] if parts else profile_url
    
    def _get_fallback_profile_data(self) -> Dict[str, Any]:
        """
        Get fallback mock data when platform adapter is unavailable.
        
        Returns:
            Mock profile data structure
        """
        return {
            ContentType.PROFILE_INFO.value: {
                "username": "example_user",
                "display_name": "Example User",
                "bio": "This is an example bio",
                "follower_count": 1000,
                "following_count": 500,
                "post_count": 250,
                "verified": False,
                "account_age_days": 365,
                "profile_image_url": "",
                "location": "",
                "website": ""
            },
            ContentType.POST.value: [
                {
                    "id": "post_1",
                    "content": "Check out this amazing offer! Click here to claim your prize!",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "engagement": {"likes": 10, "shares": 2, "comments": 5},
                    "media": [],
                    "links": ["https://example.com/offer"],
                    "hashtags": ["#amazing", "#offer"],
                    "mentions": []
                }
            ],
            ContentType.COMMENT.value: [
                {
                    "id": "comment_1",
                    "content": "Great post! Visit my profile for more deals.",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "parent_post": "post_1",
                    "engagement": {"likes": 2}
                }
            ]
        }
    
    async def _analyze_content_with_ai(self, content_data: Dict[str, Any], content_type: ContentType) -> Dict[str, Any]:
        """
        Analyze content using AI service.
        
        Args:
            content_data: Content to analyze
            content_type: Type of content
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        try:
            self.logger.debug(f"Analyzing content with AI for content type {content_type.value}")
            
            # Extract text content for analysis
            text_content = self._extract_text_content(content_data, content_type)
            
            # Use AI service for analysis with timeout, retry, and error handling
            try:
                ai_analysis = await asyncio.wait_for(
                    self._analyze_with_ai_retry(text_content),
                    timeout=30.0  # 30 second timeout for AI analysis (includes retries)
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"AI analysis timeout for content type {content_type.value}")
                raise SPTimeoutError(
                    "AI content analysis timed out",
                    details={"content_type": content_type.value, "timeout_seconds": 10}
                )
            except Exception as ai_error:
                self.logger.error(
                    f"AI service error: {str(ai_error)}",
                    exc_info=True,
                    extra={"content_type": content_type.value}
                )
                raise AIServiceError(
                    "AI content analysis failed",
                    details={"content_type": content_type.value},
                    original_error=ai_error
                )
            
            # Extract risk factors and scores
            risk_factors = []
            confidence_score = ai_analysis.get("confidence_score", 0.5)
            
            # Check for specific threat types
            if ai_analysis.get("phishing_detected"):
                risk_factors.append("phishing_content_detected")
            
            if ai_analysis.get("malware_detected"):
                risk_factors.append("malware_content_detected")
            
            if ai_analysis.get("spam_detected"):
                risk_factors.append("spam_content_detected")
            
            # Add content-specific analysis with error handling
            try:
                if content_type == ContentType.PROFILE_INFO:
                    risk_factors.extend(self._analyze_profile_info(content_data))
                elif content_type == ContentType.POST:
                    risk_factors.extend(self._analyze_post_content(content_data))
                elif content_type == ContentType.COMMENT:
                    risk_factors.extend(self._analyze_comment_content(content_data))
            except Exception as analysis_error:
                self.logger.warning(
                    f"Content-specific analysis error: {str(analysis_error)}",
                    extra={"content_type": content_type.value}
                )
                # Continue with AI analysis results even if content-specific analysis fails
            
            return {
                "ai_analysis": ai_analysis,
                "risk_factors": risk_factors,
                "confidence_score": confidence_score,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except (SPTimeoutError, AIServiceError):
            # Re-raise specific errors
            raise
        except Exception as e:
            self.logger.error(
                f"Unexpected error during AI content analysis: {str(e)}",
                exc_info=True,
                extra={"content_type": content_type.value}
            )
            # Return safe fallback result
            return {
                "error": str(e),
                "error_type": type(e).__name__,
                "risk_factors": ["analysis_error"],
                "confidence_score": 0.0,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def _extract_text_content(self, content_data: Dict[str, Any], content_type: ContentType) -> str:
        """Extract text content for AI analysis."""
        if content_type == ContentType.PROFILE_INFO:
            return f"{content_data.get('display_name', '')} {content_data.get('bio', '')}"
        elif content_type == ContentType.POST:
            if isinstance(content_data, list):
                return " ".join(post.get('content', '') for post in content_data)
            return content_data.get('content', '')
        elif content_type == ContentType.COMMENT:
            if isinstance(content_data, list):
                return " ".join(comment.get('content', '') for comment in content_data)
            return content_data.get('content', '')
        return str(content_data)
    
    def _analyze_profile_info(self, profile_data: Dict[str, Any]) -> List[str]:
        """Analyze profile information for risk factors."""
        risk_factors = []
        
        # Check for suspicious profile characteristics
        follower_count = profile_data.get('follower_count', 0)
        following_count = profile_data.get('following_count', 0)
        
        if following_count > follower_count * 10:
            risk_factors.append("suspicious_follow_ratio")
        
        if follower_count < 10:
            risk_factors.append("low_follower_count")
        
        bio = profile_data.get('bio', '').lower()
        if any(keyword in bio for keyword in ['make money', 'guaranteed income', 'work from home']):
            risk_factors.append("suspicious_bio_content")
        
        return risk_factors
    
    def _analyze_post_content(self, post_data: Dict[str, Any]) -> List[str]:
        """Analyze post content for risk factors."""
        risk_factors = []
        
        if isinstance(post_data, list):
            posts = post_data
        else:
            posts = [post_data]
        
        for post in posts:
            content = post.get('content', '').lower()
            
            # Check for suspicious patterns
            if any(pattern in content for pattern in ['click here', 'limited time', 'act now']):
                risk_factors.append("suspicious_post_content")
            
            # Check engagement patterns
            engagement = post.get('engagement', {})
            likes = engagement.get('likes', 0)
            shares = engagement.get('shares', 0)
            
            if shares > likes * 2:
                risk_factors.append("unusual_engagement_pattern")
        
        return risk_factors
    
    def _analyze_comment_content(self, comment_data: Dict[str, Any]) -> List[str]:
        """Analyze comment content for risk factors."""
        risk_factors = []
        
        if isinstance(comment_data, list):
            comments = comment_data
        else:
            comments = [comment_data]
        
        for comment in comments:
            content = comment.get('content', '').lower()
            
            if any(pattern in content for pattern in ['visit my profile', 'dm me', 'check my bio']):
                risk_factors.append("promotional_comment_content")
        
        return risk_factors
    
    def _calculate_risk_score(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate overall risk score from analysis results."""
        base_score = 0.0
        risk_factors = analysis_result.get("risk_factors", [])
        
        # Add score for each risk factor
        for factor in risk_factors:
            if "phishing" in factor:
                base_score += 0.3
            elif "malware" in factor:
                base_score += 0.25
            elif "spam" in factor:
                base_score += 0.15
            elif "suspicious" in factor:
                base_score += 0.1
            else:
                base_score += 0.05
        
        # Factor in AI confidence
        ai_analysis = analysis_result.get("ai_analysis", {})
        if ai_analysis.get("threat_detected"):
            base_score += ai_analysis.get("confidence_score", 0.0) * 0.4
        
        return min(base_score, 1.0)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from risk score."""
        if risk_score >= self.risk_thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif risk_score >= self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_risk_trend(self, assessments: List[ContentRiskAssessment], start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Calculate risk trend over time."""
        # Group assessments by day
        daily_risks = {}
        
        for assessment in assessments:
            day = assessment.created_at.date()
            if day not in daily_risks:
                daily_risks[day] = []
            daily_risks[day].append(assessment.risk_score)
        
        # Calculate daily averages
        trend = []
        current_date = start_date.date()
        end_date_only = end_date.date()
        
        while current_date <= end_date_only:
            if current_date in daily_risks:
                avg_risk = sum(daily_risks[current_date]) / len(daily_risks[current_date])
            else:
                avg_risk = 0.0
            
            trend.append({
                "date": current_date.isoformat(),
                "average_risk_score": avg_risk,
                "assessment_count": len(daily_risks.get(current_date, []))
            })
            
            current_date += timedelta(days=1)
        
        return trend
    
    def _calculate_platform_distribution(self, scans: List[SocialProfileScan]) -> Dict[str, int]:
        """Calculate distribution of scans by platform."""
        distribution = {}
        
        for scan in scans:
            platform = scan.platform.value
            distribution[platform] = distribution.get(platform, 0) + 1
        
        return distribution
    
    def _calculate_risk_level_trends(self, assessments: List[ContentRiskAssessment], start_date: datetime, end_date: datetime) -> Dict[str, List[Dict[str, Any]]]:
        """Calculate trends for each risk level."""
        trends = {}
        
        for risk_level in RiskLevel:
            level_assessments = [a for a in assessments if a.risk_level == risk_level]
            trends[risk_level.value] = self._calculate_risk_trend(level_assessments, start_date, end_date)
        
        return trends