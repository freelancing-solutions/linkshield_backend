#!/usr/bin/env python3
"""
Social Protection Controller

Handles business logic for social media protection including:
- Extension data processing
- Social profile scanning
- Content risk assessment
- Real-time monitoring
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.authentication.auth_service import AuthService
from src.controllers.base_controller import BaseController
from src.models.user import User, UserRole
from src.models.project import Project
from src.social_protection.models import (
    SocialProfileScan, ContentRiskAssessment, 
    PlatformType, ScanStatus, RiskLevel, ContentType, AssessmentType
)
from src.social_protection.services import (
    ExtensionDataProcessor, SocialScanService,
    ExtensionDataProcessorError, SocialScanServiceError
)
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.utils import utc_datetime


class SocialProtectionController(BaseController):
    """Controller for social media protection operations.
    
    Handles all business logic related to social protection including:
    - Extension data processing and validation
    - Social profile scanning and monitoring
    - Content risk assessment
    - Real-time threat detection
    - User and project management
    """

    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        extension_data_processor: ExtensionDataProcessor,
        social_scan_service: SocialScanService
    ):
        """Initialize social protection controller.
        
        Args:
            security_service: Security service for validation
            auth_service: Authentication service
            email_service: Email service for notifications
            extension_data_processor: Service for processing extension data
            social_scan_service: Service for social media scanning
        """
        super().__init__(security_service, auth_service, email_service)
        self.extension_data_processor = extension_data_processor
        self.social_scan_service = social_scan_service
        
        # Rate limits
        self.max_scans_per_hour_free = 50
        self.max_scans_per_hour_premium = 500
        self.max_assessments_per_hour_free = 100
        self.max_assessments_per_hour_premium = 1000

    async def process_extension_data(
        self,
        data: Dict[str, Any],
        user: User,
        project_id: Optional[uuid.UUID] = None,
        background_tasks: Optional[BackgroundTasks] = None
    ) -> Dict[str, Any]:
        """Process data from browser extension.
        
        Args:
            data: Raw data from extension
            user: User submitting the data
            project_id: Optional project ID for organization
            background_tasks: FastAPI background tasks
            
        Returns:
            Dict containing processing results and any immediate alerts
            
        Raises:
            HTTPException: If validation fails or rate limit exceeded
        """
        # Check rate limits
        rate_limit = (
            self.max_assessments_per_hour_premium
            if user.subscription_plan == "premium"
            else self.max_assessments_per_hour_free
        )
        
        if not await self.check_rate_limit(
            user.id, "extension_data", rate_limit, window_seconds=3600
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for extension data processing"
            )

        try:
            # Validate project access if project_id provided
            if project_id:
                await self._validate_project_access(user, project_id)

            # Process the extension data
            processing_result = await self.extension_data_processor.process_data(
                data, user.id, project_id
            )
            
            # Log the operation
            self.log_operation(
                "Extension data processed",
                user_id=user.id,
                details={
                    "project_id": str(project_id) if project_id else None,
                    "data_type": processing_result.get("content_type"),
                    "risk_level": processing_result.get("risk_level")
                }
            )
            
            # Schedule background tasks if needed
            if background_tasks and processing_result.get("requires_deep_analysis"):
                background_tasks.add_task(
                    self._perform_deep_analysis,
                    processing_result.get("analysis_id"),
                    user.id
                )
            
            return processing_result
            
        except ExtensionDataProcessorError as e:
            self.log_operation(
                "Extension data processing failed",
                user_id=user.id,
                details={"error": str(e)},
                level="error"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Data processing failed: {str(e)}"
            )
        except Exception as e:
            self.log_operation(
                "Unexpected error in extension data processing",
                user_id=user.id,
                details={"error": str(e)},
                level="error"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during data processing"
            )

    async def initiate_social_scan(
        self,
        platform: PlatformType,
        profile_url: str,
        user: User,
        project_id: Optional[uuid.UUID] = None,
        scan_depth: str = "basic",
        background_tasks: Optional[BackgroundTasks] = None
    ) -> SocialProfileScan:
        """Initiate a social media profile scan.
        
        Args:
            platform: Social media platform type
            profile_url: URL of the profile to scan
            user: User requesting the scan
            project_id: Optional project ID for organization
            scan_depth: Depth of scan (basic, detailed, comprehensive)
            background_tasks: FastAPI background tasks
            
        Returns:
            SocialProfileScan: Created scan instance
            
        Raises:
            HTTPException: If validation fails or rate limit exceeded
        """
        # Check rate limits
        rate_limit = (
            self.max_scans_per_hour_premium
            if user.subscription_plan == "premium"
            else self.max_scans_per_hour_free
        )
        
        if not await self.check_rate_limit(
            user.id, "social_scan", rate_limit, window_seconds=3600
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for social scans"
            )

        try:
            # Validate project access if project_id provided
            if project_id:
                await self._validate_project_access(user, project_id)

            # Validate profile URL
            if not self._is_valid_profile_url(profile_url, platform):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid profile URL for the specified platform"
                )

            # Check for recent scan of the same profile
            recent_scan = await self._get_recent_social_scan(profile_url, user)
            if recent_scan and recent_scan.status in [ScanStatus.PENDING, ScanStatus.IN_PROGRESS]:
                return recent_scan

            async with self.get_db_session() as session:
                # Create scan record
                scan = SocialProfileScan(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    project_id=project_id,
                    platform=platform,
                    profile_url=profile_url,
                    status=ScanStatus.PENDING,
                    scan_depth=scan_depth,
                    created_at=utc_datetime(),
                    started_at=utc_datetime()
                )
                
                session.add(scan)
                await session.commit()
                await session.refresh(scan)
                
                # Log the operation
                self.log_operation(
                    "Social scan initiated",
                    user_id=user.id,
                    details={
                        "scan_id": str(scan.id),
                        "platform": platform.value,
                        "profile_url": profile_url,
                        "project_id": str(project_id) if project_id else None
                    }
                )
                
                # Schedule background scan
                if background_tasks:
                    background_tasks.add_task(
                        self._perform_social_scan,
                        scan.id,
                        user.id
                    )
                
                return scan
                
        except SocialScanServiceError as e:
            self.log_operation(
                "Social scan initiation failed",
                user_id=user.id,
                details={"error": str(e)},
                level="error"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan initiation failed: {str(e)}"
            )
        except Exception as e:
            self.log_operation(
                "Unexpected error in social scan initiation",
                user_id=user.id,
                details={"error": str(e)},
                level="error"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during scan initiation"
            )

    async def get_scan_status(
        self,
        scan_id: uuid.UUID,
        user: User
    ) -> SocialProfileScan:
        """Get the status of a social media scan.
        
        Args:
            scan_id: ID of the scan to check
            user: User requesting the status
            
        Returns:
            SocialProfileScan: Scan instance with current status
            
        Raises:
            HTTPException: If scan not found or access denied
        """
        async with self.get_db_session() as session:
            # Get scan with access control
            stmt = select(SocialProfileScan).where(
                and_(
                    SocialProfileScan.id == scan_id,
                    SocialProfileScan.user_id == user.id
                )
            )
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()
            
            if not scan:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Scan not found or access denied"
                )
            
            return scan

    async def create_content_assessment(
        self,
        content_type: ContentType,
        content_data: Dict[str, Any],
        user: User,
        project_id: Optional[uuid.UUID] = None,
        assessment_type: AssessmentType = AssessmentType.AUTOMATED
    ) -> ContentRiskAssessment:
        """Create a content risk assessment.
        
        Args:
            content_type: Type of content being assessed
            content_data: Content data and metadata
            user: User requesting the assessment
            project_id: Optional project ID for organization
            assessment_type: Type of assessment (automated/manual)
            
        Returns:
            ContentRiskAssessment: Created assessment instance
            
        Raises:
            HTTPException: If validation fails or rate limit exceeded
        """
        # Check rate limits
        rate_limit = (
            self.max_assessments_per_hour_premium
            if user.subscription_plan == "premium"
            else self.max_assessments_per_hour_free
        )
        
        if not await self.check_rate_limit(
            user.id, "content_assessment", rate_limit, window_seconds=3600
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for content assessments"
            )

        try:
            # Validate project access if project_id provided
            if project_id:
                await self._validate_project_access(user, project_id)

            # Create assessment using service
            assessment_result = await self.social_scan_service.create_content_assessment(
                content_type=content_type,
                content_data=content_data,
                user_id=user.id,
                project_id=project_id,
                assessment_type=assessment_type
            )
            
            # Log the operation
            self.log_operation(
                "Content assessment created",
                user_id=user.id,
                details={
                    "assessment_id": str(assessment_result.id),
                    "content_type": content_type.value,
                    "risk_level": assessment_result.risk_level.value if assessment_result.risk_level else None,
                    "project_id": str(project_id) if project_id else None
                }
            )
            
            return assessment_result
            
        except SocialScanServiceError as e:
            self.log_operation(
                "Content assessment creation failed",
                user_id=user.id,
                details={"error": str(e)},
                level="error"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Assessment creation failed: {str(e)}"
            )
        except Exception as e:
            self.log_operation(
                "Unexpected error in content assessment creation",
                user_id=user.id,
                details={"error": str(e)},
                level="error"
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during assessment creation"
            )

    async def get_user_scans(
        self,
        user: User,
        project_id: Optional[uuid.UUID] = None,
        platform: Optional[PlatformType] = None,
        status: Optional[ScanStatus] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[SocialProfileScan]:
        """Get user's social media scans with filtering.
        
        Args:
            user: User requesting the scans
            project_id: Optional project filter
            platform: Optional platform filter
            status: Optional status filter
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            List[SocialProfileScan]: List of user's scans
        """
        async with self.get_db_session() as session:
            # Build query with filters
            stmt = select(SocialProfileScan).where(
                SocialProfileScan.user_id == user.id
            )
            
            if project_id:
                stmt = stmt.where(SocialProfileScan.project_id == project_id)
            if platform:
                stmt = stmt.where(SocialProfileScan.platform == platform)
            if status:
                stmt = stmt.where(SocialProfileScan.status == status)
            
            stmt = stmt.order_by(desc(SocialProfileScan.created_at))
            stmt = stmt.limit(limit).offset(offset)
            
            result = await session.execute(stmt)
            return result.scalars().all()

    async def get_user_assessments(
        self,
        user: User,
        project_id: Optional[uuid.UUID] = None,
        content_type: Optional[ContentType] = None,
        risk_level: Optional[RiskLevel] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[ContentRiskAssessment]:
        """Get user's content risk assessments with filtering.
        
        Args:
            user: User requesting the assessments
            project_id: Optional project filter
            content_type: Optional content type filter
            risk_level: Optional risk level filter
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            List[ContentRiskAssessment]: List of user's assessments
        """
        async with self.get_db_session() as session:
            # Build query with filters
            stmt = select(ContentRiskAssessment).where(
                ContentRiskAssessment.user_id == user.id
            )
            
            if project_id:
                stmt = stmt.where(ContentRiskAssessment.project_id == project_id)
            if content_type:
                stmt = stmt.where(ContentRiskAssessment.content_type == content_type)
            if risk_level:
                stmt = stmt.where(ContentRiskAssessment.risk_level == risk_level)
            
            stmt = stmt.order_by(desc(ContentRiskAssessment.created_at))
            stmt = stmt.limit(limit).offset(offset)
            
            result = await session.execute(stmt)
            return result.scalars().all()

    # Private helper methods
    
    async def _validate_project_access(self, user: User, project_id: uuid.UUID) -> None:
        """Validate that user has access to the specified project."""
        async with self.get_db_session() as session:
            stmt = select(Project).where(
                and_(
                    Project.id == project_id,
                    Project.owner_id == user.id  # Simplified - could check membership too
                )
            )
            result = await session.execute(stmt)
            project = result.scalar_one_or_none()
            
            if not project:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to project"
                )

    def _is_valid_profile_url(self, url: str, platform: PlatformType) -> bool:
        """Validate that the URL is appropriate for the specified platform."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            platform_domains = {
                PlatformType.TWITTER: ["twitter.com", "x.com"],
                PlatformType.FACEBOOK: ["facebook.com", "fb.com"],
                PlatformType.INSTAGRAM: ["instagram.com"],
                PlatformType.LINKEDIN: ["linkedin.com"],
                PlatformType.TIKTOK: ["tiktok.com"],
                PlatformType.YOUTUBE: ["youtube.com", "youtu.be"],
                PlatformType.REDDIT: ["reddit.com"],
                PlatformType.DISCORD: ["discord.com", "discord.gg"],
                PlatformType.TELEGRAM: ["t.me", "telegram.me"],
                PlatformType.OTHER: []  # Allow any domain for OTHER
            }
            
            if platform == PlatformType.OTHER:
                return True
                
            valid_domains = platform_domains.get(platform, [])
            return any(domain.endswith(d) for d in valid_domains)
            
        except Exception:
            return False

    async def _get_recent_social_scan(
        self, 
        profile_url: str, 
        user: User
    ) -> Optional[SocialProfileScan]:
        """Get recent scan for the same profile by the same user."""
        cutoff_time = utc_datetime() - timedelta(minutes=30)  # 30 minute cooldown
        
        async with self.get_db_session() as session:
            stmt = select(SocialProfileScan).where(
                and_(
                    SocialProfileScan.profile_url == profile_url,
                    SocialProfileScan.user_id == user.id,
                    SocialProfileScan.created_at > cutoff_time
                )
            ).order_by(desc(SocialProfileScan.created_at))
            
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def _perform_social_scan(self, scan_id: uuid.UUID, user_id: uuid.UUID) -> None:
        """Background task to perform the actual social media scan."""
        try:
            await self.social_scan_service.perform_scan(scan_id)
        except Exception as e:
            self.log_operation(
                "Background social scan failed",
                user_id=user_id,
                details={"scan_id": str(scan_id), "error": str(e)},
                level="error"
            )

    async def _perform_deep_analysis(self, analysis_id: str, user_id: uuid.UUID) -> None:
        """Background task to perform deep content analysis."""
        try:
            await self.extension_data_processor.perform_deep_analysis(analysis_id)
        except Exception as e:
            self.log_operation(
                "Background deep analysis failed",
                user_id=user_id,
                details={"analysis_id": analysis_id, "error": str(e)},
                level="error"
            )