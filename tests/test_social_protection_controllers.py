"""
Unit tests for social protection controller methods.

This module tests the social protection functionality in the dashboard controller,
including overview generation, protection health calculation, and scoring algorithms.
"""

import pytest
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException, status

from linkshield.controllers.dashboard_controller import DashboardController
from linkshield.controllers.dashboard_models import (
    SocialProtectionOverviewResponse,
    ProtectionHealthResponse,
)
from linkshield.models.user import User
from linkshield.models.social_protection import (
    SocialProfileScan,
    ContentRiskAssessment,
    RiskLevel,
)
from linkshield.services.security_service import SecurityService
from linkshield.authentication.auth_service import AuthService
from linkshield.services.email_service import EmailService


class TestSocialProtectionController:
    """Test suite for social protection controller methods."""

    @pytest.fixture
    def mock_security_service(self):
        """Mock security service."""
        return MagicMock(spec=SecurityService)

    @pytest.fixture
    def mock_auth_service(self):
        """Mock authentication service."""
        return MagicMock(spec=AuthService)

    @pytest.fixture
    def mock_email_service(self):
        """Mock email service."""
        return MagicMock(spec=EmailService)

    @pytest.fixture
    def controller(self, mock_security_service, mock_auth_service, mock_email_service):
        """Create dashboard controller instance."""
        return DashboardController(
            security_service=mock_security_service,
            auth_service=mock_auth_service,
            email_service=mock_email_service,
        )

    @pytest.fixture
    def mock_user(self):
        """Create mock user."""
        user = MagicMock(spec=User)
        user.id = uuid.uuid4()
        user.email = "test@example.com"
        return user

    @pytest.fixture
    def mock_project_id(self):
        """Create mock project ID."""
        return uuid.uuid4()

    @pytest.fixture
    def sample_scans(self):
        """Create sample social profile scans."""
        base_time = datetime.utcnow()
        return [
            MagicMock(
                id=uuid.uuid4(),
                platform="twitter",
                status="COMPLETED",
                created_at=base_time - timedelta(days=1),
                completed_at=base_time - timedelta(hours=23),
                project_id=uuid.uuid4(),
            ),
            MagicMock(
                id=uuid.uuid4(),
                platform="facebook",
                status="FAILED",
                created_at=base_time - timedelta(days=2),
                completed_at=None,
                project_id=uuid.uuid4(),
            ),
            MagicMock(
                id=uuid.uuid4(),
                platform="instagram",
                status="COMPLETED",
                created_at=base_time - timedelta(days=3),
                completed_at=base_time - timedelta(days=2, hours=22),
                project_id=uuid.uuid4(),
            ),
        ]

    @pytest.fixture
    def sample_assessments(self):
        """Create sample content risk assessments."""
        base_time = datetime.utcnow()
        return [
            MagicMock(
                id=uuid.uuid4(),
                risk_level=RiskLevel.HIGH,
                content_type="post",
                created_at=base_time - timedelta(days=1),
                project_id=uuid.uuid4(),
            ),
            MagicMock(
                id=uuid.uuid4(),
                risk_level=RiskLevel.MEDIUM,
                content_type="comment",
                created_at=base_time - timedelta(days=5),
                project_id=uuid.uuid4(),
            ),
            MagicMock(
                id=uuid.uuid4(),
                risk_level=RiskLevel.CRITICAL,
                content_type="message",
                created_at=base_time - timedelta(days=10),
                project_id=uuid.uuid4(),
            ),
        ]

    @pytest.fixture
    def sample_url_checks(self):
        """Create sample URL checks."""
        base_time = datetime.utcnow()
        return [
            MagicMock(
                id=uuid.uuid4(),
                is_threat=False,
                created_at=base_time - timedelta(hours=1),
            ),
            MagicMock(
                id=uuid.uuid4(),
                is_threat=True,
                created_at=base_time - timedelta(hours=2),
            ),
            MagicMock(
                id=uuid.uuid4(),
                is_threat=False,
                created_at=base_time - timedelta(hours=3),
            ),
        ]

    @pytest.mark.asyncio
    async def test_get_social_protection_overview_success(
        self, controller, mock_user, mock_project_id, sample_scans, sample_assessments
    ):
        """Test successful social protection overview retrieval."""
        with patch.object(controller, 'get_db_session') as mock_session:
            # Mock database session and queries
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # Mock scan query results
            mock_scan_result = MagicMock()
            mock_scan_result.scalars.return_value.all.return_value = sample_scans
            
            # Mock assessment query results
            mock_assessment_result = MagicMock()
            mock_assessment_result.scalars.return_value.all.return_value = sample_assessments
            
            mock_db_session.execute.side_effect = [mock_scan_result, mock_assessment_result]

            # Execute method
            result = await controller.get_social_protection_overview(
                user=mock_user, project_id=mock_project_id
            )

            # Assertions
            assert isinstance(result, SocialProtectionOverviewResponse)
            assert result.total_scans == 3
            assert result.active_scans == 2  # COMPLETED scans
            assert result.failed_scans == 1
            assert result.total_assessments == 3
            assert result.high_risk_items == 2  # HIGH and CRITICAL
            assert len(result.recent_activity) <= 10
            assert len(result.platform_breakdown) > 0

    @pytest.mark.asyncio
    async def test_get_social_protection_overview_no_project_filter(
        self, controller, mock_user, sample_scans, sample_assessments
    ):
        """Test social protection overview without project filter."""
        with patch.object(controller, 'get_db_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            mock_scan_result = MagicMock()
            mock_scan_result.scalars.return_value.all.return_value = sample_scans
            
            mock_assessment_result = MagicMock()
            mock_assessment_result.scalars.return_value.all.return_value = sample_assessments
            
            mock_db_session.execute.side_effect = [mock_scan_result, mock_assessment_result]

            result = await controller.get_social_protection_overview(
                user=mock_user, project_id=None
            )

            assert isinstance(result, SocialProtectionOverviewResponse)
            assert result.total_scans == 3
            assert result.total_assessments == 3

    @pytest.mark.asyncio
    async def test_get_social_protection_overview_empty_data(
        self, controller, mock_user, mock_project_id
    ):
        """Test social protection overview with no data."""
        with patch.object(controller, 'get_db_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # Mock empty results
            mock_empty_result = MagicMock()
            mock_empty_result.scalars.return_value.all.return_value = []
            
            mock_db_session.execute.side_effect = [mock_empty_result, mock_empty_result]

            result = await controller.get_social_protection_overview(
                user=mock_user, project_id=mock_project_id
            )

            assert isinstance(result, SocialProtectionOverviewResponse)
            assert result.total_scans == 0
            assert result.active_scans == 0
            assert result.failed_scans == 0
            assert result.total_assessments == 0
            assert result.high_risk_items == 0
            assert len(result.recent_activity) == 0
            assert len(result.platform_breakdown) == 0

    @pytest.mark.asyncio
    async def test_get_social_protection_overview_database_error(
        self, controller, mock_user, mock_project_id
    ):
        """Test social protection overview with database error."""
        with patch.object(controller, 'get_db_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # Mock database error
            mock_db_session.execute.side_effect = Exception("Database connection failed")

            with pytest.raises(HTTPException) as exc_info:
                await controller.get_social_protection_overview(
                    user=mock_user, project_id=mock_project_id
                )

            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Failed to retrieve social protection overview" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_get_protection_health_success(
        self, controller, mock_user, mock_project_id, sample_scans, 
        sample_assessments, sample_url_checks
    ):
        """Test successful protection health retrieval."""
        with patch.object(controller, 'get_db_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # Mock query results
            mock_url_result = MagicMock()
            mock_url_result.scalars.return_value.all.return_value = sample_url_checks
            
            mock_scan_result = MagicMock()
            mock_scan_result.scalars.return_value.all.return_value = sample_scans
            
            mock_assessment_result = MagicMock()
            mock_assessment_result.scalars.return_value.all.return_value = sample_assessments
            
            mock_db_session.execute.side_effect = [
                mock_url_result, mock_scan_result, mock_assessment_result
            ]

            # Mock helper methods
            with patch.object(controller, '_calculate_trending', return_value="improving"):
                result = await controller.get_protection_health(
                    user=mock_user, project_id=mock_project_id
                )

            # Assertions
            assert isinstance(result, ProtectionHealthResponse)
            assert 0 <= result.overall_score <= 100
            assert 0 <= result.url_safety_score <= 100
            assert 0 <= result.social_protection_score <= 100
            assert "url_threats" in result.risk_breakdown
            assert "social_risks" in result.risk_breakdown
            assert "reputation_health" in result.risk_breakdown
            assert "monitoring_coverage" in result.risk_breakdown
            assert result.trending == "improving"
            assert isinstance(result.recommendations, list)
            assert len(result.recommendations) <= 5

    @pytest.mark.asyncio
    async def test_get_protection_health_no_data(
        self, controller, mock_user, mock_project_id
    ):
        """Test protection health with no data."""
        with patch.object(controller, 'get_db_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # Mock empty results
            mock_empty_result = MagicMock()
            mock_empty_result.scalars.return_value.all.return_value = []
            
            mock_db_session.execute.side_effect = [
                mock_empty_result, mock_empty_result, mock_empty_result
            ]

            with patch.object(controller, '_calculate_trending', return_value="stable"):
                result = await controller.get_protection_health(
                    user=mock_user, project_id=mock_project_id
                )

            assert isinstance(result, ProtectionHealthResponse)
            assert result.overall_score == 100.0  # No data means perfect score
            assert result.url_safety_score == 100.0
            assert result.social_protection_score == 100.0

    def test_calculate_protection_health_score_no_data(self, controller):
        """Test protection health score calculation with no data."""
        score = controller._calculate_protection_health_score([], [])
        assert score == 100.0

    def test_calculate_protection_health_score_with_risks(self, controller, sample_assessments):
        """Test protection health score calculation with risk assessments."""
        # Create assessments with different risk levels
        high_risk_assessment = MagicMock()
        high_risk_assessment.risk_level = "HIGH"
        
        critical_risk_assessment = MagicMock()
        critical_risk_assessment.risk_level = "CRITICAL"
        
        assessments = [high_risk_assessment, critical_risk_assessment]
        
        score = controller._calculate_protection_health_score([], assessments)
        assert score < 100.0  # Should be reduced due to high-risk items

    def test_calculate_protection_health_score_with_failed_scans(self, controller):
        """Test protection health score calculation with failed scans."""
        failed_scan = MagicMock()
        failed_scan.status = "FAILED"
        
        scans = [failed_scan]
        
        score = controller._calculate_protection_health_score(scans, [])
        assert score < 100.0  # Should be reduced due to failed scans

    def test_calculate_protection_health_score_with_recent_success(self, controller):
        """Test protection health score calculation with recent successful scans."""
        successful_scan = MagicMock()
        successful_scan.status = "COMPLETED"
        successful_scan.completed_at = datetime.utcnow() - timedelta(days=3)
        
        scans = [successful_scan]
        
        score = controller._calculate_protection_health_score(scans, [])
        assert score >= 100.0  # Should get bonus for recent success

    def test_calculate_url_safety_score_no_data(self, controller):
        """Test URL safety score calculation with no data."""
        score = controller._calculate_url_safety_score([])
        assert score == 100.0

    def test_calculate_url_safety_score_with_threats(self, controller, sample_url_checks):
        """Test URL safety score calculation with threats."""
        score = controller._calculate_url_safety_score(sample_url_checks)
        # Should be less than 100 due to one threat in sample data
        assert 0 <= score < 100

    def test_calculate_url_threat_score_no_data(self, controller):
        """Test URL threat score calculation with no data."""
        score = controller._calculate_url_threat_score([])
        assert score == 100.0

    def test_calculate_social_risk_score_no_data(self, controller):
        """Test social risk score calculation with no data."""
        score = controller._calculate_social_risk_score([])
        assert score == 100.0

    def test_calculate_social_risk_score_with_risks(self, controller):
        """Test social risk score calculation with various risk levels."""
        critical_assessment = MagicMock()
        critical_assessment.risk_level.value = "CRITICAL"
        
        high_assessment = MagicMock()
        high_assessment.risk_level.value = "HIGH"
        
        low_assessment = MagicMock()
        low_assessment.risk_level.value = "LOW"
        
        assessments = [critical_assessment, high_assessment, low_assessment]
        
        score = controller._calculate_social_risk_score(assessments)
        assert 0 <= score < 100  # Should be reduced due to high-risk items

    def test_calculate_reputation_score_no_data(self, controller):
        """Test reputation score calculation with no data."""
        score = controller._calculate_reputation_score([], [])
        assert score == 100.0

    def test_calculate_reputation_score_with_recent_risks(self, controller):
        """Test reputation score calculation with recent high-risk assessments."""
        recent_high_risk = MagicMock()
        recent_high_risk.risk_level = "HIGH"
        recent_high_risk.created_at = datetime.utcnow() - timedelta(days=15)
        
        assessments = [recent_high_risk]
        
        score = controller._calculate_reputation_score([], assessments)
        assert score < 100.0  # Should be reduced due to recent high-risk

    def test_calculate_coverage_score_no_activity(self, controller):
        """Test coverage score calculation with no activity."""
        score = controller._calculate_coverage_score([], [])
        assert score == 0.0

    def test_calculate_coverage_score_with_activity(self, controller):
        """Test coverage score calculation with recent activity."""
        recent_scan = MagicMock()
        recent_scan.created_at = datetime.utcnow() - timedelta(days=15)
        
        recent_url_check = MagicMock()
        recent_url_check.created_at = datetime.utcnow() - timedelta(days=10)
        
        score = controller._calculate_coverage_score([recent_scan], [recent_url_check])
        assert 0 < score <= 100

    def test_calculate_trending_returns_stable(self, controller, mock_user):
        """Test trending calculation returns stable."""
        # Mock session parameter
        mock_session = MagicMock()
        
        trending = controller._calculate_trending(mock_user, mock_session)
        assert trending == "stable"

    def test_generate_protection_recommendations_low_score(self, controller):
        """Test recommendation generation for low protection score."""
        recommendations = controller._generate_protection_recommendations(
            [], [], [], 50.0  # Low overall score
        )
        
        assert len(recommendations) > 0
        assert any("below optimal" in rec for rec in recommendations)

    def test_generate_protection_recommendations_no_scans(self, controller):
        """Test recommendation generation when no scans exist."""
        recommendations = controller._generate_protection_recommendations(
            [], [], [], 80.0
        )
        
        assert any("social media monitoring" in rec for rec in recommendations)

    def test_generate_protection_recommendations_high_risk_assessments(self, controller):
        """Test recommendation generation with high-risk assessments."""
        high_risk_assessment = MagicMock()
        high_risk_assessment.risk_level = "HIGH"
        
        assessments = [high_risk_assessment]
        
        recommendations = controller._generate_protection_recommendations(
            [], [], assessments, 80.0
        )
        
        assert any("high-risk content" in rec for rec in recommendations)

    def test_generate_protection_recommendations_failed_scans(self, controller):
        """Test recommendation generation with failed scans."""
        failed_scan = MagicMock()
        failed_scan.status = "FAILED"
        
        scans = [failed_scan]
        
        recommendations = controller._generate_protection_recommendations(
            [], scans, [], 80.0
        )
        
        assert any("failed social media scans" in rec for rec in recommendations)

    def test_generate_protection_recommendations_good_setup(self, controller):
        """Test recommendation generation for good protection setup."""
        recommendations = controller._generate_protection_recommendations(
            [MagicMock()], [MagicMock()], [], 90.0  # Good score with some data
        )
        
        # Should get positive feedback when setup is good
        assert any("looks good" in rec for rec in recommendations)

    def test_generate_protection_recommendations_limit(self, controller):
        """Test that recommendations are limited to 5 items."""
        # Create conditions that would generate many recommendations
        failed_scan = MagicMock()
        failed_scan.status = "FAILED"
        
        high_risk_assessment = MagicMock()
        high_risk_assessment.risk_level = "HIGH"
        
        recommendations = controller._generate_protection_recommendations(
            [], [failed_scan] * 10, [high_risk_assessment] * 10, 30.0  # Very low score
        )
        
        assert len(recommendations) <= 5

    @pytest.mark.asyncio
    async def test_get_protection_health_database_error(
        self, controller, mock_user, mock_project_id
    ):
        """Test protection health with database error."""
        with patch.object(controller, 'get_db_session') as mock_session:
            mock_db_session = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db_session
            
            # Mock database error
            mock_db_session.execute.side_effect = Exception("Database error")

            with pytest.raises(HTTPException) as exc_info:
                await controller.get_protection_health(
                    user=mock_user, project_id=mock_project_id
                )

            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Failed to retrieve protection health" in str(exc_info.value.detail)