#!/usr/bin/env python3
"""
LinkShield Backend Social Scan Service

Comprehensive service for social media profile scanning, content analysis,
and risk assessment. Integrates with database models for persistent storage.
"""

import asyncio
import logging
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
    SocialProfileData,
    ContentAnalysisRequest,
    RiskAssessmentResult,
    ComprehensiveAssessment,
    AssessmentHistory
)
from src.services.ai_service import AIService

logger = logging.getLogger(__name__)


class SocialScanServiceError(Exception):
    """Base exception for social scan service errors."""
    pass


class ScanNotFoundError(SocialScanServiceError):
    """Scan not found error."""
    pass


class InvalidScanStateError(SocialScanServiceError):
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
    """
    
    def __init__(self, ai_service: AIService):
        """
        Initialize the social scan service.
        
        Args:
            ai_service: AI service for content analysis
        """
        self.ai_service = ai_service
        self.logger = logging.getLogger(__name__)
        
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
            await db.commit()
            await db.refresh(scan)
            
            self.logger.info(f"Initiated profile scan {scan.id} for platform {platform.value}")
            
            # Start background scan processing
            asyncio.create_task(self._process_profile_scan(db, scan.id))
            
            return scan
            
        except Exception as e:
            await db.rollback()
            self.logger.error(f"Failed to initiate profile scan: {str(e)}")
            raise SocialScanServiceError(f"Failed to initiate profile scan: {str(e)}")
    
    async def get_scan_status(self, db: AsyncSession, scan_id: UUID) -> SocialProfileScan:
        """
        Get the current status of a profile scan.
        
        Args:
            db: Database session
            scan_id: ID of the scan to check
            
        Returns:
            SocialProfileScan: Current scan record
            
        Raises:
            ScanNotFoundError: If scan is not found
        """
        try:
            result = await db.execute(
                select(SocialProfileScan)
                .where(SocialProfileScan.id == scan_id)
                .options(selectinload(SocialProfileScan.risk_assessments))
            )
            scan = result.scalar_one_or_none()
            
            if not scan:
                raise ScanNotFoundError(f"Scan {scan_id} not found")
            
            return scan
            
        except ScanNotFoundError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get scan status: {str(e)}")
            raise SocialScanServiceError(f"Failed to get scan status: {str(e)}")
    
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
        assessment_type: AssessmentType = AssessmentType.AUTOMATED
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
            # Update scan status to running
            await self._update_scan_status(db, scan_id, ScanStatus.RUNNING)
            
            # Get scan details
            scan = await self.get_scan_status(db, scan_id)
            
            # Simulate profile data collection (in real implementation, this would
            # involve API calls to social media platforms or web scraping)
            profile_data = await self._collect_profile_data(scan.profile_url, scan.platform)
            
            # Process different types of content
            content_types = [ContentType.POST, ContentType.COMMENT, ContentType.PROFILE_INFO]
            
            for content_type in content_types:
                if content_type.value in profile_data:
                    await self.create_content_risk_assessment(
                        db=db,
                        scan_id=scan_id,
                        content_type=content_type,
                        content_data=profile_data[content_type.value]
                    )
            
            # Update scan status to completed
            await self._update_scan_status(db, scan_id, ScanStatus.COMPLETED)
            
            self.logger.info(f"Successfully completed profile scan {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Profile scan {scan_id} failed: {str(e)}")
            await self._update_scan_status(db, scan_id, ScanStatus.FAILED, str(e))
    
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
        Simulate profile data collection.
        
        In a real implementation, this would involve:
        - API calls to social media platforms
        - Web scraping (where legally permitted)
        - Data parsing and normalization
        
        Args:
            profile_url: URL of the profile to scan
            platform: Social media platform
            
        Returns:
            Dict[str, Any]: Collected profile data
        """
        # Simulate data collection delay
        await asyncio.sleep(2)
        
        # Return mock data structure
        return {
            ContentType.PROFILE_INFO.value: {
                "username": "example_user",
                "display_name": "Example User",
                "bio": "This is an example bio",
                "follower_count": 1000,
                "following_count": 500,
                "post_count": 250
            },
            ContentType.POST.value: [
                {
                    "id": "post_1",
                    "content": "Check out this amazing offer! Click here to claim your prize!",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "engagement": {"likes": 10, "shares": 2, "comments": 5}
                }
            ],
            ContentType.COMMENT.value: [
                {
                    "id": "comment_1",
                    "content": "Great post! Visit my profile for more deals.",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "parent_post": "post_1"
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
            # Extract text content for analysis
            text_content = self._extract_text_content(content_data, content_type)
            
            # Use AI service for analysis
            ai_analysis = await self.ai_service.analyze_content_safety(text_content)
            
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
            
            # Add content-specific analysis
            if content_type == ContentType.PROFILE_INFO:
                risk_factors.extend(self._analyze_profile_info(content_data))
            elif content_type == ContentType.POST:
                risk_factors.extend(self._analyze_post_content(content_data))
            elif content_type == ContentType.COMMENT:
                risk_factors.extend(self._analyze_comment_content(content_data))
            
            return {
                "ai_analysis": ai_analysis,
                "risk_factors": risk_factors,
                "confidence_score": confidence_score,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"AI content analysis failed: {str(e)}")
            return {
                "error": str(e),
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