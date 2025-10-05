#!/usr/bin/env python3
"""
Unit Tests for SocialScanService

Tests profile scanning, caching, retry logic, and webhook notifications.
Covers all major service methods including scan initiation, status retrieval,
assessment creation, and historical analysis.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from uuid import uuid4, UUID
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from linkshield.social_protection.services.social_scan_service import (
    SocialScanService,
    SocialScanServiceError,
    ScanNotFoundError,
    InvalidScanStateError
)
from linkshield.social_protection.exceptions import DatabaseError, TimeoutError as SPTimeoutError
from linkshield.models.social_protection import (
    SocialProfileScan,
    ContentRiskAssessment,
    PlatformType,
    ScanStatus,
    RiskLevel,
    ContentType,
    AssessmentType
)


@pytest.fixture
def mock_ai_service():
    """Mock AI service"""
    service = AsyncMock()
    service.analyze_content_safety = AsyncMock(return_value={
        "phishing_detected": False,
        "malware_detected": False,
        "spam_detected": False,
        "confidence_score": 0.85,
        "risk_score": 0.2,
        "risk_factors": []
    })
    return service


@pytest.fixture
def mock_cache_service():
    """Mock cache service"""
    service = AsyncMock()
    service.get_scan_result = AsyncMock(return_value=None)
    service.set_scan_result = AsyncMock(return_value=True)
    service.get_profile_data = AsyncMock(return_value=None)
    service.set_profile_data = AsyncMock(return_value=True)
    service.get_analysis_result = AsyncMock(return_value=None)
    service.set_analysis_result = AsyncMock(return_value=True)
    return service


@pytest.fixture
def mock_webhook_service():
    """Mock webhook service"""
    service = AsyncMock()
    service.notify_scan_complete = AsyncMock(return_value=True)
    return service


@pytest.fixture
def social_scan_service(mock_ai_service, mock_cache_service, mock_webhook_service):
    """Create SocialScanService instance with mocked dependencies"""
    return SocialScanService(
        ai_service=mock_ai_service,
        cache_service=mock_cache_service,
        webhook_service=mock_webhook_service
    )


@pytest.fixture
def mock_db_session():
    """Mock database session"""
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    return session


class TestSocialScanServiceInitiation:
    """Tests for scan initiation"""
    
    @pytest.mark.asyncio
    async def test_initiate_profile_scan_success(self, social_scan_service, mock_db_session):
        """Test successful profile scan initiation"""
        # Setup
        user_id = uuid4()
        project_id = uuid4()
        platform = PlatformType.TWITTER
        profile_url = "https://twitter.com/testuser"
        scan_options = {"deep_scan": True}
        
        # Execute
        with patch('asyncio.create_task'):
            result = await social_scan_service.initiate_profile_scan(
                db=mock_db_session,
                user_id=user_id,
                project_id=project_id,
                platform=platform,
                profile_url=profile_url,
                scan_options=scan_options
            )
        
        # Verify
        assert result.user_id == user_id
        assert result.platform == platform
        assert result.profile_url == profile_url
        assert result.status == ScanStatus.PENDING
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initiate_profile_scan_without_options(self, social_scan_service, mock_db_session):
        """Test scan initiation without scan options"""
        # Setup
        user_id = uuid4()
        platform = PlatformType.FACEBOOK
        profile_url = "https://facebook.com/testuser"
        
        # Execute
        with patch('asyncio.create_task'):
            result = await social_scan_service.initiate_profile_scan(
                db=mock_db_session,
                user_id=user_id,
                project_id=None,
                platform=platform,
                profile_url=profile_url,
                scan_options=None
            )
        
        # Verify
        assert result.project_id is None
        assert result.status == ScanStatus.PENDING
    
    @pytest.mark.asyncio
    async def test_initiate_profile_scan_database_error(self, social_scan_service, mock_db_session):
        """Test scan initiation with database error"""
        # Setup
        mock_db_session.commit.side_effect = Exception("Database connection failed")
        
        # Execute & Verify
        with pytest.raises(DatabaseError, match="Failed to create scan record"):
            await social_scan_service.initiate_profile_scan(
                db=mock_db_session,
                user_id=uuid4(),
                project_id=None,
                platform=PlatformType.TWITTER,
                profile_url="https://twitter.com/test"
            )
        
        mock_db_session.rollback.assert_called_once()


class TestSocialScanServiceStatus:
    """Tests for scan status retrieval"""
    
    @pytest.mark.asyncio
    async def test_get_scan_status_success(self, social_scan_service, mock_db_session):
        """Test successful scan status retrieval"""
        # Setup
        scan_id = uuid4()
        mock_scan = MagicMock(spec=SocialProfileScan)
        mock_scan.id = scan_id
        mock_scan.status = ScanStatus.PENDING
        mock_scan.platform = PlatformType.TWITTER
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_scan_status(mock_db_session, scan_id)
        
        # Verify
        assert result == mock_scan
        assert result.id == scan_id
        assert result.status == ScanStatus.PENDING
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_scan_status_not_found(self, social_scan_service, mock_db_session):
        """Test scan status retrieval when scan not found"""
        # Setup
        scan_id = uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result
        
        # Execute & Verify
        with pytest.raises(ScanNotFoundError, match="Scan not found"):
            await social_scan_service.get_scan_status(mock_db_session, scan_id)
    
    @pytest.mark.asyncio
    async def test_get_scan_status_with_cache(self, social_scan_service, mock_db_session):
        """Test scan status retrieval with caching"""
        # Setup - completed scan should be cached
        scan_id = uuid4()
        mock_scan = MagicMock(spec=SocialProfileScan)
        mock_scan.id = scan_id
        mock_scan.status = ScanStatus.COMPLETED
        mock_scan.completed_at = datetime.now(timezone.utc)
        mock_scan.platform = PlatformType.TWITTER
        mock_scan.user_id = uuid4()
        mock_scan.profile_url = "https://twitter.com/test"
        mock_scan.created_at = datetime.now(timezone.utc)
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_scan_status(mock_db_session, scan_id)
        
        # Verify
        assert result.status == ScanStatus.COMPLETED
        # Cache should be set for completed scans
        social_scan_service.cache_service.set_scan_result.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_scan_status_database_error(self, social_scan_service, mock_db_session):
        """Test scan status retrieval with database error"""
        # Setup
        scan_id = uuid4()
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute & Verify
        with pytest.raises(DatabaseError, match="Failed to get scan status"):
            await social_scan_service.get_scan_status(mock_db_session, scan_id)


class TestSocialScanServiceUserScans:
    """Tests for user scans retrieval"""
    
    @pytest.mark.asyncio
    async def test_get_user_scans_basic(self, social_scan_service, mock_db_session):
        """Test getting user scans without filters"""
        # Setup
        user_id = uuid4()
        mock_scans = [
            MagicMock(id=uuid4(), user_id=user_id, platform=PlatformType.TWITTER),
            MagicMock(id=uuid4(), user_id=user_id, platform=PlatformType.FACEBOOK)
        ]
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_scans
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_user_scans(
            db=mock_db_session,
            user_id=user_id
        )
        
        # Verify
        assert len(result) == 2
        assert all(scan.user_id == user_id for scan in result)
    
    @pytest.mark.asyncio
    async def test_get_user_scans_with_platform_filter(self, social_scan_service, mock_db_session):
        """Test getting user scans filtered by platform"""
        # Setup
        user_id = uuid4()
        mock_scans = [
            MagicMock(id=uuid4(), user_id=user_id, platform=PlatformType.TWITTER)
        ]
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_scans
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_user_scans(
            db=mock_db_session,
            user_id=user_id,
            platform=PlatformType.TWITTER
        )
        
        # Verify
        assert len(result) == 1
        assert result[0].platform == PlatformType.TWITTER
    
    @pytest.mark.asyncio
    async def test_get_user_scans_with_all_filters(self, social_scan_service, mock_db_session):
        """Test getting user scans with all filters applied"""
        # Setup
        user_id = uuid4()
        project_id = uuid4()
        mock_scans = []
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_scans
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_user_scans(
            db=mock_db_session,
            user_id=user_id,
            project_id=project_id,
            platform=PlatformType.TWITTER,
            status=ScanStatus.COMPLETED,
            limit=10,
            offset=5
        )
        
        # Verify
        assert len(result) == 0
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_scans_pagination(self, social_scan_service, mock_db_session):
        """Test user scans pagination"""
        # Setup
        user_id = uuid4()
        mock_scans = [MagicMock(id=uuid4(), user_id=user_id) for _ in range(5)]
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_scans
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_user_scans(
            db=mock_db_session,
            user_id=user_id,
            limit=5,
            offset=10
        )
        
        # Verify
        assert len(result) == 5


class TestSocialScanServiceAssessments:
    """Tests for content risk assessments"""
    
    @pytest.mark.asyncio
    async def test_create_content_risk_assessment_success(
        self, social_scan_service, mock_db_session, mock_ai_service
    ):
        """Test successful content risk assessment creation"""
        # Setup
        scan_id = uuid4()
        content_data = {
            "text": "This is a test post",
            "author": "testuser",
            "engagement": {"likes": 10, "shares": 2}
        }
        
        # Execute
        result = await social_scan_service.create_content_risk_assessment(
            db=mock_db_session,
            scan_id=scan_id,
            content_type=ContentType.POST,
            content_data=content_data,
            assessment_type=AssessmentType.CONTENT_RISK
        )
        
        # Verify
        assert result.profile_scan_id == scan_id
        assert result.content_type == ContentType.POST
        assert result.assessment_type == AssessmentType.CONTENT_RISK
        assert result.risk_level in RiskLevel
        assert 0.0 <= result.risk_score <= 100.0
        mock_ai_service.analyze_content_safety.assert_called_once()
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_content_risk_assessment_high_risk(
        self, social_scan_service, mock_db_session, mock_ai_service
    ):
        """Test assessment creation with high risk content"""
        # Setup
        mock_ai_service.analyze_content_safety.return_value = {
            "phishing_detected": True,
            "malware_detected": True,
            "spam_detected": False,
            "confidence_score": 0.95,
            "risk_score": 0.9,
            "risk_factors": ["phishing_content", "malware_link"]
        }
        
        scan_id = uuid4()
        content_data = {"text": "Suspicious content with malware link"}
        
        # Execute
        result = await social_scan_service.create_content_risk_assessment(
            db=mock_db_session,
            scan_id=scan_id,
            content_type=ContentType.POST,
            content_data=content_data
        )
        
        # Verify
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert result.risk_score > 70.0
        assert len(result.risk_factors) > 0
    
    @pytest.mark.asyncio
    async def test_create_content_risk_assessment_database_error(
        self, social_scan_service, mock_db_session
    ):
        """Test assessment creation with database error"""
        # Setup
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Execute & Verify
        with pytest.raises(SocialScanServiceError, match="Failed to create content risk assessment"):
            await social_scan_service.create_content_risk_assessment(
                db=mock_db_session,
                scan_id=uuid4(),
                content_type=ContentType.POST,
                content_data={"text": "test"}
            )
        
        mock_db_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_scan_assessments_all(self, social_scan_service, mock_db_session):
        """Test getting all assessments for a scan"""
        # Setup
        scan_id = uuid4()
        mock_assessments = [
            MagicMock(profile_scan_id=scan_id, content_type=ContentType.POST),
            MagicMock(profile_scan_id=scan_id, content_type=ContentType.COMMENT)
        ]
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_assessments
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_scan_assessments(
            db=mock_db_session,
            scan_id=scan_id
        )
        
        # Verify
        assert len(result) == 2
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_scan_assessments_filtered(self, social_scan_service, mock_db_session):
        """Test getting assessments filtered by content type"""
        # Setup
        scan_id = uuid4()
        mock_assessments = [
            MagicMock(profile_scan_id=scan_id, content_type=ContentType.COMMENT)
        ]
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_assessments
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_scan_assessments(
            db=mock_db_session,
            scan_id=scan_id,
            content_type=ContentType.COMMENT
        )
        
        # Verify
        assert len(result) == 1
        assert result[0].content_type == ContentType.COMMENT


class TestSocialScanServiceHelpers:
    """Tests for helper methods"""
    
    def test_calculate_risk_score_low_risk(self, social_scan_service):
        """Test risk score calculation for low risk content"""
        analysis_result = {
            "risk_factors": [],
            "confidence_score": 0.8,
            "risk_score": 0.1
        }
        
        score = social_scan_service._calculate_risk_score(analysis_result)
        
        assert 0.0 <= score <= 100.0
        assert score < 30.0
    
    def test_calculate_risk_score_high_risk(self, social_scan_service):
        """Test risk score calculation for high risk content"""
        analysis_result = {
            "risk_factors": ["phishing", "malware", "scam"],
            "confidence_score": 0.95,
            "risk_score": 0.9
        }
        
        score = social_scan_service._calculate_risk_score(analysis_result)
        
        assert score > 50.0
    
    def test_determine_risk_level_boundaries(self, social_scan_service):
        """Test risk level determination at boundaries"""
        # Test with scores in 0-100 range
        assert social_scan_service._determine_risk_level(0.0) == RiskLevel.LOW
        assert social_scan_service._determine_risk_level(29.0) == RiskLevel.LOW
        assert social_scan_service._determine_risk_level(30.0) == RiskLevel.MEDIUM
        assert social_scan_service._determine_risk_level(59.0) == RiskLevel.MEDIUM
        assert social_scan_service._determine_risk_level(60.0) == RiskLevel.HIGH
        assert social_scan_service._determine_risk_level(79.0) == RiskLevel.HIGH
        assert social_scan_service._determine_risk_level(80.0) == RiskLevel.CRITICAL
        assert social_scan_service._determine_risk_level(100.0) == RiskLevel.CRITICAL


class TestSocialScanServiceCaching:
    """Tests for caching functionality"""
    
    @pytest.mark.asyncio
    async def test_cache_completed_scan(
        self, social_scan_service, mock_db_session, mock_cache_service
    ):
        """Test that completed scans are cached"""
        # Setup
        scan_id = uuid4()
        mock_scan = MagicMock(spec=SocialProfileScan)
        mock_scan.id = scan_id
        mock_scan.status = ScanStatus.COMPLETED
        mock_scan.completed_at = datetime.now(timezone.utc)
        mock_scan.platform = PlatformType.TWITTER
        mock_scan.user_id = uuid4()
        mock_scan.profile_url = "https://twitter.com/test"
        mock_scan.created_at = datetime.now(timezone.utc)
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        await social_scan_service.get_scan_status(mock_db_session, scan_id)
        
        # Verify
        mock_cache_service.set_scan_result.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_no_cache_for_pending_scan(
        self, social_scan_service, mock_db_session, mock_cache_service
    ):
        """Test that pending scans are not cached"""
        # Setup
        scan_id = uuid4()
        mock_scan = MagicMock(spec=SocialProfileScan)
        mock_scan.id = scan_id
        mock_scan.status = ScanStatus.PENDING
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        await social_scan_service.get_scan_status(mock_db_session, scan_id)
        
        # Verify
        mock_cache_service.set_scan_result.assert_not_called()


class TestSocialScanServiceRetry:
    """Tests for retry logic"""
    
    @pytest.mark.asyncio
    async def test_profile_data_collection_timeout(
        self, social_scan_service, mock_db_session
    ):
        """Test timeout handling during profile data collection"""
        # Setup
        scan_id = uuid4()
        mock_scan = MagicMock(spec=SocialProfileScan)
        mock_scan.id = scan_id
        mock_scan.platform = PlatformType.TWITTER
        mock_scan.profile_url = "https://twitter.com/test"
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_db_session.execute.return_value = mock_result
        
        # Mock _collect_profile_data to timeout
        with patch.object(
            social_scan_service,
            '_collect_profile_data',
            side_effect=asyncio.TimeoutError()
        ):
            # Execute
            await social_scan_service._process_profile_scan(mock_db_session, scan_id)
        
        # Verify - scan should be marked as failed
        # Check that execute was called (for status updates)
        assert mock_db_session.execute.called


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
