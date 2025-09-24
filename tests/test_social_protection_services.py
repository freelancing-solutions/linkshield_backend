#!/usr/bin/env python3
"""
Unit tests for Social Protection Services

Tests for SocialScanService and ExtensionDataProcessor services,
covering all major functionality including profile scanning, content analysis,
risk assessment, and extension data processing.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4, UUID
from typing import Dict, Any, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.social_protection.services.social_scan_service import (
    SocialScanService,
    SocialScanServiceError,
    ScanNotFoundError,
    InvalidScanStateError
)
from src.social_protection.services.extension_data_processor import (
    ExtensionDataProcessor,
    ExtensionDataProcessorError,
    ValidationError,
    ProcessingError
)
from src.models.social_protection import (
    SocialProfileScan,
    ContentRiskAssessment,
    PlatformType,
    ScanStatus,
    RiskLevel,
    ContentType,
    AssessmentType
)
from src.social_protection.data_models import (
    ExtensionRequest,
    ExtensionResponse,
    RealTimeAssessment,
    LinkSafetyCheck,
    BatchExtensionRequest,
    BatchExtensionResponse,
    ComprehensiveAssessment,
    AssessmentHistory
)
from src.services.ai_service import AIService


class TestSocialScanService:
    """Test cases for SocialScanService."""
    
    @pytest.fixture
    def mock_ai_service(self):
        """Mock AI service for testing."""
        ai_service = MagicMock(spec=AIService)
        ai_service.analyze_content_safety = AsyncMock(return_value={
            "confidence_score": 0.8,
            "phishing_detected": False,
            "malware_detected": False,
            "spam_detected": False,
            "risk_score": 0.2
        })
        return ai_service
    
    @pytest.fixture
    def social_scan_service(self, mock_ai_service):
        """Create SocialScanService instance for testing."""
        return SocialScanService(ai_service=mock_ai_service)
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session."""
        session = AsyncMock(spec=AsyncSession)
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.fixture
    def sample_scan_data(self):
        """Sample scan data for testing."""
        return {
            "user_id": uuid4(),
            "project_id": uuid4(),
            "platform": PlatformType.TWITTER,
            "profile_url": "https://twitter.com/testuser",
            "scan_options": {"deep_scan": True}
        }
    
    @pytest.mark.asyncio
    async def test_initiate_profile_scan_success(self, social_scan_service, mock_db_session, sample_scan_data):
        """Test successful profile scan initiation."""
        # Setup
        mock_scan = SocialProfileScan(
            id=uuid4(),
            user_id=sample_scan_data["user_id"],
            project_id=sample_scan_data["project_id"],
            platform=sample_scan_data["platform"],
            profile_url=sample_scan_data["profile_url"],
            status=ScanStatus.PENDING,
            scan_options=sample_scan_data["scan_options"],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        mock_db_session.refresh.side_effect = lambda obj: setattr(obj, 'id', mock_scan.id)
        
        # Execute
        with patch('asyncio.create_task'):
            result = await social_scan_service.initiate_profile_scan(
                db=mock_db_session,
                user_id=sample_scan_data["user_id"],
                project_id=sample_scan_data["project_id"],
                platform=sample_scan_data["platform"],
                profile_url=sample_scan_data["profile_url"],
                scan_options=sample_scan_data["scan_options"]
            )
        
        # Verify
        assert result.user_id == sample_scan_data["user_id"]
        assert result.platform == sample_scan_data["platform"]
        assert result.profile_url == sample_scan_data["profile_url"]
        assert result.status == ScanStatus.PENDING
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initiate_profile_scan_database_error(self, social_scan_service, mock_db_session, sample_scan_data):
        """Test profile scan initiation with database error."""
        # Setup
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Execute & Verify
        with pytest.raises(SocialScanServiceError, match="Failed to initiate profile scan"):
            await social_scan_service.initiate_profile_scan(
                db=mock_db_session,
                user_id=sample_scan_data["user_id"],
                project_id=sample_scan_data["project_id"],
                platform=sample_scan_data["platform"],
                profile_url=sample_scan_data["profile_url"]
            )
        
        mock_db_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_scan_status_success(self, social_scan_service, mock_db_session):
        """Test successful scan status retrieval."""
        # Setup
        scan_id = uuid4()
        mock_scan = SocialProfileScan(
            id=scan_id,
            user_id=uuid4(),
            platform=PlatformType.FACEBOOK,
            profile_url="https://facebook.com/testuser",
            status=ScanStatus.COMPLETED
        )
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await social_scan_service.get_scan_status(mock_db_session, scan_id)
        
        # Verify
        assert result == mock_scan
        assert result.id == scan_id
        assert result.status == ScanStatus.COMPLETED
    
    @pytest.mark.asyncio
    async def test_get_scan_status_not_found(self, social_scan_service, mock_db_session):
        """Test scan status retrieval when scan not found."""
        # Setup
        scan_id = uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result
        
        # Execute & Verify
        with pytest.raises(ScanNotFoundError, match=f"Scan {scan_id} not found"):
            await social_scan_service.get_scan_status(mock_db_session, scan_id)
    
    @pytest.mark.asyncio
    async def test_create_content_risk_assessment_success(self, social_scan_service, mock_db_session, mock_ai_service):
        """Test successful content risk assessment creation."""
        # Setup
        scan_id = uuid4()
        content_data = {
            "text": "This is a test post with some content",
            "author": "testuser",
            "engagement": {"likes": 10, "shares": 2}
        }
        
        mock_assessment = ContentRiskAssessment(
            id=uuid4(),
            scan_id=scan_id,
            content_type=ContentType.POST,
            risk_level=RiskLevel.LOW,
            risk_score=0.2,
            analysis_result={"risk_factors": [], "confidence_score": 0.8}
        )
        mock_db_session.refresh.side_effect = lambda obj: setattr(obj, 'id', mock_assessment.id)
        
        # Execute
        result = await social_scan_service.create_content_risk_assessment(
            db=mock_db_session,
            scan_id=scan_id,
            content_type=ContentType.POST,
            content_data=content_data
        )
        
        # Verify
        assert result.scan_id == scan_id
        assert result.content_type == ContentType.POST
        mock_ai_service.analyze_content_safety.assert_called_once()
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_scans_with_filters(self, social_scan_service, mock_db_session):
        """Test getting user scans with various filters."""
        # Setup
        user_id = uuid4()
        project_id = uuid4()
        mock_scans = [
            SocialProfileScan(id=uuid4(), user_id=user_id, platform=PlatformType.TWITTER),
            SocialProfileScan(id=uuid4(), user_id=user_id, platform=PlatformType.FACEBOOK)
        ]
        
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
            offset=0
        )
        
        # Verify
        assert len(result) == 2
        assert all(scan.user_id == user_id for scan in result)
        mock_db_session.execute.assert_called_once()
    
    def test_calculate_risk_score(self, social_scan_service):
        """Test risk score calculation."""
        # Test low risk
        analysis_result = {
            "risk_factors": ["low_follower_count"],
            "confidence_score": 0.8,
            "ai_analysis": {"risk_score": 0.2}
        }
        score = social_scan_service._calculate_risk_score(analysis_result)
        assert 0.0 <= score <= 1.0
        assert score < 0.5  # Should be low risk
        
        # Test high risk
        analysis_result = {
            "risk_factors": ["phishing_content_detected", "malware_content_detected", "suspicious_bio_content"],
            "confidence_score": 0.9,
            "ai_analysis": {"risk_score": 0.8}
        }
        score = social_scan_service._calculate_risk_score(analysis_result)
        assert score > 0.7  # Should be high risk
    
    def test_determine_risk_level(self, social_scan_service):
        """Test risk level determination."""
        assert social_scan_service._determine_risk_level(0.1) == RiskLevel.LOW
        assert social_scan_service._determine_risk_level(0.4) == RiskLevel.MEDIUM
        assert social_scan_service._determine_risk_level(0.7) == RiskLevel.HIGH
        assert social_scan_service._determine_risk_level(0.95) == RiskLevel.CRITICAL
    
    def test_analyze_profile_info(self, social_scan_service):
        """Test profile information analysis."""
        # Test suspicious profile
        profile_data = {
            "follower_count": 5,
            "following_count": 1000,
            "bio": "Make money fast with this guaranteed income opportunity!"
        }
        risk_factors = social_scan_service._analyze_profile_info(profile_data)
        
        assert "suspicious_follow_ratio" in risk_factors
        assert "low_follower_count" in risk_factors
        assert "suspicious_bio_content" in risk_factors
        
        # Test normal profile
        normal_profile = {
            "follower_count": 500,
            "following_count": 300,
            "bio": "Software developer interested in technology"
        }
        risk_factors = social_scan_service._analyze_profile_info(normal_profile)
        assert len(risk_factors) == 0
    
    def test_analyze_post_content(self, social_scan_service):
        """Test post content analysis."""
        # Test suspicious post
        post_data = {
            "content": "Click here now! Limited time offer - act now!",
            "engagement": {"likes": 1, "shares": 10}
        }
        risk_factors = social_scan_service._analyze_post_content(post_data)
        
        assert "suspicious_post_content" in risk_factors
        assert "unusual_engagement_pattern" in risk_factors
        
        # Test normal post
        normal_post = {
            "content": "Just had a great day at the park with friends!",
            "engagement": {"likes": 15, "shares": 2}
        }
        risk_factors = social_scan_service._analyze_post_content(normal_post)
        assert len(risk_factors) == 0


class TestExtensionDataProcessor:
    """Test cases for ExtensionDataProcessor."""
    
    @pytest.fixture
    def extension_processor(self):
        """Create ExtensionDataProcessor instance for testing."""
        return ExtensionDataProcessor()
    
    @pytest.fixture
    def sample_extension_request(self):
        """Sample extension request data."""
        return {
            "request_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": "twitter",
            "content_type": "post",
            "content_data": {
                "text": "Check out this amazing opportunity!",
                "url": "https://twitter.com/user/status/123",
                "author": "testuser"
            },
            "page_context": {
                "url": "https://twitter.com/home",
                "domain": "twitter.com"
            }
        }
    
    @pytest.mark.asyncio
    async def test_process_extension_request_success(self, extension_processor, sample_extension_request):
        """Test successful extension request processing."""
        # Execute
        result = await extension_processor.process_extension_request(sample_extension_request)
        
        # Verify
        assert isinstance(result, ExtensionResponse)
        assert result.success is True
        assert result.error_message is None
        assert result.assessment is not None
        assert isinstance(result.assessment, RealTimeAssessment)
        assert result.processing_time_ms > 0
    
    @pytest.mark.asyncio
    async def test_process_extension_request_invalid_data(self, extension_processor):
        """Test extension request processing with invalid data."""
        # Setup invalid request
        invalid_request = {
            "request_id": "invalid-uuid",
            "platform": "unknown_platform",
            "content_data": None
        }
        
        # Execute & Verify
        with pytest.raises(ValidationError):
            await extension_processor.process_extension_request(invalid_request)
    
    @pytest.mark.asyncio
    async def test_process_batch_request_success(self, extension_processor, sample_extension_request):
        """Test successful batch request processing."""
        # Setup batch request
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": [sample_extension_request, sample_extension_request.copy()],
            "processing_options": {"parallel": True}
        }
        
        # Execute
        result = await extension_processor.process_batch_request(batch_data)
        
        # Verify
        assert isinstance(result, BatchExtensionResponse)
        assert result.success is True
        assert len(result.responses) == 2
        assert all(response.success for response in result.responses)
    
    @pytest.mark.asyncio
    async def test_check_link_safety_safe_url(self, extension_processor):
        """Test link safety check for safe URL."""
        # Execute
        result = await extension_processor.check_link_safety(
            url="https://github.com/user/repo",
            platform=PlatformType.TWITTER
        )
        
        # Verify
        assert isinstance(result, LinkSafetyCheck)
        assert result.is_safe is True
        assert result.risk_level == RiskLevel.LOW
        assert len(result.risk_factors) == 0
    
    @pytest.mark.asyncio
    async def test_check_link_safety_suspicious_url(self, extension_processor):
        """Test link safety check for suspicious URL."""
        # Execute
        result = await extension_processor.check_link_safety(
            url="https://fb-security.com/verify-account",
            platform=PlatformType.FACEBOOK
        )
        
        # Verify
        assert isinstance(result, LinkSafetyCheck)
        assert result.is_safe is False
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert len(result.risk_factors) > 0
        assert "suspicious_domain" in result.risk_factors
    
    def test_validate_extension_request_valid(self, extension_processor, sample_extension_request):
        """Test extension request validation with valid data."""
        # Execute
        result = extension_processor._validate_extension_request(sample_extension_request)
        
        # Verify
        assert isinstance(result, ExtensionRequest)
        assert result.request_id == sample_extension_request["request_id"]
        assert result.platform.value == sample_extension_request["platform"]
    
    def test_validate_extension_request_invalid(self, extension_processor):
        """Test extension request validation with invalid data."""
        # Test missing required fields
        invalid_request = {"request_id": str(uuid4())}
        
        with pytest.raises(ValidationError, match="Missing required field"):
            extension_processor._validate_extension_request(invalid_request)
        
        # Test invalid UUID
        invalid_request = {
            "request_id": "not-a-uuid",
            "platform": "twitter",
            "content_type": "post",
            "content_data": {}
        }
        
        with pytest.raises(ValidationError, match="Invalid request_id format"):
            extension_processor._validate_extension_request(invalid_request)
    
    @pytest.mark.asyncio
    async def test_perform_real_time_assessment_phishing_content(self, extension_processor):
        """Test real-time assessment with phishing content."""
        # Setup request with phishing indicators
        request_data = {
            "request_id": str(uuid4()),
            "platform": "facebook",
            "content_type": "post",
            "content_data": {
                "text": "URGENT: Verify your account immediately or it will be suspended! Click here to confirm.",
                "url": "https://fb-security.com/verify"
            }
        }
        
        request = extension_processor._validate_extension_request(request_data)
        
        # Execute
        result = await extension_processor._perform_real_time_assessment(request)
        
        # Verify
        assert isinstance(result, RealTimeAssessment)
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert len(result.risk_factors) > 0
        assert any("phishing" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_perform_real_time_assessment_safe_content(self, extension_processor):
        """Test real-time assessment with safe content."""
        # Setup request with safe content
        request_data = {
            "request_id": str(uuid4()),
            "platform": "twitter",
            "content_type": "post",
            "content_data": {
                "text": "Just finished reading a great book about software development!",
                "url": "https://twitter.com/user/status/123"
            }
        }
        
        request = extension_processor._validate_extension_request(request_data)
        
        # Execute
        result = await extension_processor._perform_real_time_assessment(request)
        
        # Verify
        assert isinstance(result, RealTimeAssessment)
        assert result.risk_level == RiskLevel.LOW
        assert len(result.risk_factors) == 0 or all("safe" in factor for factor in result.risk_factors)
    
    def test_risk_pattern_detection(self, extension_processor):
        """Test risk pattern detection in content."""
        # Test phishing patterns
        phishing_text = "Verify your account immediately! Urgent action required!"
        patterns_found = []
        
        for category, patterns in extension_processor.risk_patterns.items():
            for pattern in patterns:
                if re.search(pattern, phishing_text, re.IGNORECASE):
                    patterns_found.append(category)
                    break
        
        assert "phishing" in patterns_found
        
        # Test scam patterns
        scam_text = "Make money fast with this guaranteed income opportunity!"
        patterns_found = []
        
        for category, patterns in extension_processor.risk_patterns.items():
            for pattern in patterns:
                if re.search(pattern, scam_text, re.IGNORECASE):
                    patterns_found.append(category)
                    break
        
        assert "scam" in patterns_found
    
    def test_platform_specific_indicators(self, extension_processor):
        """Test platform-specific risk indicators."""
        # Test Facebook suspicious domain
        facebook_indicators = extension_processor.platform_indicators[PlatformType.FACEBOOK]
        assert "fb-security" in facebook_indicators["suspicious_domains"]
        assert "account verification" in facebook_indicators["risk_keywords"]
        
        # Test Twitter suspicious domain
        twitter_indicators = extension_processor.platform_indicators[PlatformType.TWITTER]
        assert "twitter-support" in twitter_indicators["suspicious_domains"]
        assert "account suspended" in twitter_indicators["risk_keywords"]


if __name__ == "__main__":
    pytest.main([__file__])