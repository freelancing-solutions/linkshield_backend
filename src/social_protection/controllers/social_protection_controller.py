#!/usr/bin/env python3
"""
Social Protection Controller (DEPRECATED)

⚠️ DEPRECATION WARNING ⚠️
This controller is deprecated and will be removed in a future version.

Please use the following controllers instead:
- UserController: For user-facing dashboard operations
- BotController: For bot integration and automated analysis
- ExtensionController: For browser extension integration

Migration Guide:
- Extension data processing → ExtensionController.process_extension_data()
- Social profile scanning → UserController.initiate_user_platform_scan()
- Content risk assessment → UserController.analyze_user_content()
- Bot operations → BotController methods

Handles business logic for social media protection including:
- Extension data processing
- Social profile scanning
- Content risk assessment
- Real-time monitoring
"""

import uuid
import warnings
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
from src.social_protection.data_models import (
    ContentRiskAssessment, ContentType
)
from src.social_protection.types import (
    PlatformType, ScanStatus, RiskLevel
)
from src.models.social_protection import SocialProfileScan, AssessmentType
from src.social_protection.services import (
    ExtensionDataProcessor, SocialScanService,
    ExtensionDataProcessorError, SocialScanServiceError
)
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.utils import utc_datetime
from src.social_protection.logging_utils import get_logger

logger = get_logger("SocialProtectionController")

# DEPRECATED - THIS CONTROLLER SHOULD NOT BE USED EITHER USE BOT_CONTROLLER OR 
# EXTENSION_CONTROLLER OR USER_CONTROLLER DEPENDING ON WHAT YOU ARE DOING 
#  BOT_CONTROLLER IS FACING BOTS - EXTENSIONS IS BROWSER EXTENSIONS AND USER IS FACING THE USER DASHBOARD
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
        
        ⚠️ DEPRECATED: Use ExtensionController.process_extension_data() instead.
        This method will be removed in version 2.0.
        
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
        # Log deprecation warning
        logger.warning(
            "DEPRECATED: SocialProtectionController.process_extension_data() is deprecated. "
            "Use ExtensionController.process_extension_data() instead.",
            extra={"user_id": str(user.id), "method": "process_extension_data"}
        )
        
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
        
        ⚠️ DEPRECATED: Use UserController.initiate_user_platform_scan() instead.
        This method will be removed in version 2.0.
        
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
        assessment_type: AssessmentType = AssessmentType.CONTENT_RISK
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

    async def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status of social protection services.
        
        Checks the operational status of all major components:
        - Core services (extension processor, scan service)
        - Content analyzers
        - Algorithm health analyzers
        - Platform adapters
        - Crisis detection system
        
        Returns:
            Dict containing overall status and detailed component health
            
        Raises:
            HTTPException: 503 if critical services are unavailable
        """
        import time
        from src.social_protection.types import PlatformType
        
        overall_status = "healthy"
        checks = {}
        start_time = time.time()
        
        # Check core services
        try:
            checks["extension_data_processor"] = {
                "status": "healthy" if self.extension_data_processor else "unavailable",
                "message": "Extension data processor operational" if self.extension_data_processor else "Service not initialized"
            }
            if not self.extension_data_processor:
                overall_status = "degraded"
        except Exception as e:
            checks["extension_data_processor"] = {
                "status": "unhealthy",
                "message": f"Error checking extension processor: {str(e)}"
            }
            overall_status = "degraded"
        
        try:
            checks["social_scan_service"] = {
                "status": "healthy" if self.social_scan_service else "unavailable",
                "message": "Social scan service operational" if self.social_scan_service else "Service not initialized"
            }
            if not self.social_scan_service:
                overall_status = "degraded"
        except Exception as e:
            checks["social_scan_service"] = {
                "status": "unhealthy",
                "message": f"Error checking scan service: {str(e)}"
            }
            overall_status = "degraded"
        
        # Check analyzers availability
        analyzers_status = []
        analyzer_components = [
            "content_risk_analyzer",
            "link_penalty_detector", 
            "spam_pattern_detector",
            "community_notes_analyzer",
            "visibility_scorer",
            "engagement_analyzer",
            "penalty_detector",
            "shadow_ban_detector"
        ]
        
        for analyzer in analyzer_components:
            try:
                has_analyzer = hasattr(self, analyzer) and getattr(self, analyzer) is not None
                analyzers_status.append({
                    "name": analyzer,
                    "status": "available" if has_analyzer else "not_configured"
                })
            except Exception:
                analyzers_status.append({
                    "name": analyzer,
                    "status": "error"
                })
        
        available_count = sum(1 for a in analyzers_status if a["status"] == "available")
        checks["analyzers"] = {
            "status": "healthy" if available_count > 0 else "degraded",
            "message": f"{available_count}/{len(analyzer_components)} analyzers available",
            "details": analyzers_status
        }
        
        # Check platform adapters (if available)
        platform_adapters_status = []
        platforms = [
            PlatformType.TWITTER,
            PlatformType.FACEBOOK,
            PlatformType.INSTAGRAM,
            PlatformType.TIKTOK,
            PlatformType.LINKEDIN,
            PlatformType.TELEGRAM,
            PlatformType.DISCORD
        ]
        
        for platform in platforms:
            try:
                # Check if adapter registry exists and has the platform
                adapter_available = False
                if hasattr(self, 'adapter_registry'):
                    adapter_available = platform in self.adapter_registry
                
                platform_adapters_status.append({
                    "platform": platform.value,
                    "status": "available" if adapter_available else "not_configured"
                })
            except Exception:
                platform_adapters_status.append({
                    "platform": platform.value,
                    "status": "error"
                })
        
        configured_count = sum(1 for p in platform_adapters_status if p["status"] == "available")
        checks["platform_adapters"] = {
            "status": "healthy" if configured_count > 0 else "degraded",
            "message": f"{configured_count}/{len(platforms)} platform adapters configured",
            "details": platform_adapters_status
        }
        
        # Check crisis detection (if available)
        try:
            has_crisis_detector = hasattr(self, 'crisis_detector') and self.crisis_detector is not None
            checks["crisis_detection"] = {
                "status": "available" if has_crisis_detector else "not_configured",
                "message": "Crisis detection system operational" if has_crisis_detector else "Crisis detection not configured"
            }
        except Exception as e:
            checks["crisis_detection"] = {
                "status": "error",
                "message": f"Error checking crisis detector: {str(e)}"
            }
        
        # Check database connectivity
        try:
            async with self.get_db_session() as session:
                # Simple query to verify database connection
                await session.execute(select(1))
                checks["database"] = {
                    "status": "healthy",
                    "message": "Database connection successful"
                }
        except Exception as e:
            checks["database"] = {
                "status": "unhealthy",
                "message": f"Database connection failed: {str(e)}"
            }
            overall_status = "unhealthy"
        
        response_time = time.time() - start_time
        
        response = {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "response_time_seconds": round(response_time, 3),
            "checks": checks,
            "summary": {
                "total_checks": len(checks),
                "healthy": sum(1 for c in checks.values() if c.get("status") in ["healthy", "available"]),
                "degraded": sum(1 for c in checks.values() if c.get("status") in ["degraded", "not_configured"]),
                "unhealthy": sum(1 for c in checks.values() if c.get("status") in ["unhealthy", "error", "unavailable"])
            }
        }
        
        # Return 503 if system is unhealthy
        if overall_status == "unhealthy":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=response
            )
        
        return response
