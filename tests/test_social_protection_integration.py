"""
Integration tests for social protection API endpoints.

This module tests the complete API integration for social protection functionality,
including extension data processing, social scanning, content assessment, and
dashboard integration endpoints.
"""

import pytest
import uuid
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status

from linkshield.main import create_app
from linkshield.models.user import User
from linkshield.models.social_protection import (
    SocialProfileScan,
    ContentRiskAssessment,
    RiskLevel,
    PlatformType,
    ScanStatus,
    ContentType,
    AssessmentType,
)


class TestSocialProtectionIntegration:
    """Integration test suite for social protection API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(create_app())

    @pytest.fixture
    def mock_user_token(self):
        """Mock JWT token for authenticated requests."""
        return "Bearer mock_jwt_token_12345"

    @pytest.fixture
    def mock_user_id(self):
        """Mock user ID."""
        return uuid.uuid4()

    @pytest.fixture
    def mock_project_id(self):
        """Mock project ID."""
        return uuid.uuid4()

    @pytest.fixture
    def sample_extension_data(self, mock_project_id):
        """Sample extension data request."""
        return {
            "data": {
                "url": "https://twitter.com/example_user",
                "content_type": "social_profile",
                "platform": "twitter",
                "content": "User profile content with potential risks...",
                "metadata": {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            },
            "project_id": str(mock_project_id)
        }

    @pytest.fixture
    def sample_scan_request(self, mock_project_id):
        """Sample social scan request."""
        return {
            "platform": "twitter",
            "profile_url": "https://twitter.com/example_user",
            "project_id": str(mock_project_id),
            "scan_depth": "detailed"
        }

    @pytest.fixture
    def sample_assessment_request(self, mock_project_id):
        """Sample content assessment request."""
        return {
            "content_type": "text",
            "content_data": {
                "text": "This is some content to be assessed for risks",
                "source_url": "https://example.com/post/123",
                "metadata": {
                    "author": "user123",
                    "timestamp": "2024-01-01T00:00:00Z"
                }
            },
            "project_id": str(mock_project_id),
            "assessment_type": "automated"
        }

    def test_social_protection_health_endpoint(self, client):
        """Test social protection health check endpoint."""
        response = client.get("/api/v1/social-protection/health")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "services" in data

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_process_extension_data_success(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, sample_extension_data
    ):
        """Test successful extension data processing."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        mock_response.processing_id = "proc_123456789"
        mock_response.risk_level = RiskLevel.MEDIUM
        mock_response.confidence_score = 0.75
        mock_response.alerts = [
            {
                "type": "suspicious_content",
                "message": "Potentially harmful content detected",
                "severity": "medium"
            }
        ]
        mock_response.requires_deep_analysis = True
        mock_response.processed_at = datetime.utcnow()
        
        mock_controller.process_extension_data.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.post(
            "/api/v1/social-protection/extension/process",
            json=sample_extension_data,
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["processing_id"] == "proc_123456789"
        assert data["risk_level"] == "medium"
        assert data["confidence_score"] == 0.75
        assert len(data["alerts"]) == 1
        assert data["requires_deep_analysis"] is True

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_process_extension_data_validation_error(
        self, mock_get_controller, mock_get_user, client, mock_user_token, mock_user_id
    ):
        """Test extension data processing with validation error."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Invalid request data (missing required fields)
        invalid_data = {
            "data": {}  # Missing required fields
        }

        # Make request
        response = client.post(
            "/api/v1/social-protection/extension/process",
            json=invalid_data,
            headers={"Authorization": mock_user_token}
        )

        # Should return validation error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_initiate_social_scan_success(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, sample_scan_request
    ):
        """Test successful social media scan initiation."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response
        mock_controller = AsyncMock()
        scan_id = uuid.uuid4()
        mock_response = MagicMock()
        mock_response.id = scan_id
        mock_response.platform = PlatformType.TWITTER
        mock_response.profile_url = "https://twitter.com/example_user"
        mock_response.status = ScanStatus.PENDING
        mock_response.scan_depth = "detailed"
        mock_response.risk_level = None
        mock_response.confidence_score = None
        mock_response.findings = None
        mock_response.created_at = datetime.utcnow()
        mock_response.started_at = None
        mock_response.completed_at = None
        
        mock_controller.initiate_social_scan.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.post(
            "/api/v1/social-protection/scans",
            json=sample_scan_request,
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["id"] == str(scan_id)
        assert data["platform"] == "twitter"
        assert data["profile_url"] == "https://twitter.com/example_user"
        assert data["status"] == "pending"
        assert data["scan_depth"] == "detailed"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_get_scan_status_success(
        self, mock_get_controller, mock_get_user, client, mock_user_token, mock_user_id
    ):
        """Test successful scan status retrieval."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response
        mock_controller = AsyncMock()
        scan_id = uuid.uuid4()
        mock_response = MagicMock()
        mock_response.id = scan_id
        mock_response.platform = PlatformType.TWITTER
        mock_response.profile_url = "https://twitter.com/example_user"
        mock_response.status = ScanStatus.COMPLETED
        mock_response.scan_depth = "detailed"
        mock_response.risk_level = RiskLevel.LOW
        mock_response.confidence_score = 0.85
        mock_response.findings = {"threats_detected": 0, "warnings": 2}
        mock_response.created_at = datetime.utcnow() - timedelta(hours=2)
        mock_response.started_at = datetime.utcnow() - timedelta(hours=1, minutes=30)
        mock_response.completed_at = datetime.utcnow() - timedelta(minutes=15)
        
        mock_controller.get_scan_status.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.get(
            f"/api/v1/social-protection/scans/{scan_id}",
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == str(scan_id)
        assert data["status"] == "completed"
        assert data["risk_level"] == "low"
        assert data["confidence_score"] == 0.85
        assert data["findings"]["threats_detected"] == 0

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_list_user_scans_success(
        self, mock_get_controller, mock_get_user, client, mock_user_token, mock_user_id
    ):
        """Test successful user scans listing."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response
        mock_controller = AsyncMock()
        scan1 = MagicMock()
        scan1.id = uuid.uuid4()
        scan1.platform = PlatformType.TWITTER
        scan1.profile_url = "https://twitter.com/user1"
        scan1.status = ScanStatus.COMPLETED
        scan1.scan_depth = "basic"
        scan1.risk_level = RiskLevel.LOW
        scan1.confidence_score = 0.9
        scan1.findings = None
        scan1.created_at = datetime.utcnow() - timedelta(days=1)
        scan1.started_at = datetime.utcnow() - timedelta(days=1)
        scan1.completed_at = datetime.utcnow() - timedelta(hours=23)

        scan2 = MagicMock()
        scan2.id = uuid.uuid4()
        scan2.platform = PlatformType.FACEBOOK
        scan2.profile_url = "https://facebook.com/user2"
        scan2.status = ScanStatus.PENDING
        scan2.scan_depth = "detailed"
        scan2.risk_level = None
        scan2.confidence_score = None
        scan2.findings = None
        scan2.created_at = datetime.utcnow() - timedelta(hours=2)
        scan2.started_at = None
        scan2.completed_at = None
        
        mock_controller.get_user_scans.return_value = [scan1, scan2]
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.get(
            "/api/v1/social-protection/scans?limit=10&offset=0",
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 2
        assert data[0]["platform"] == "twitter"
        assert data[0]["status"] == "completed"
        assert data[1]["platform"] == "facebook"
        assert data[1]["status"] == "pending"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_create_content_assessment_success(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, sample_assessment_request
    ):
        """Test successful content assessment creation."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response
        mock_controller = AsyncMock()
        assessment_id = uuid.uuid4()
        mock_response = MagicMock()
        mock_response.id = assessment_id
        mock_response.content_type = ContentType.TEXT
        mock_response.assessment_type = AssessmentType.AUTOMATED
        mock_response.risk_level = RiskLevel.MEDIUM
        mock_response.confidence_score = 0.72
        mock_response.risk_factors = ["suspicious_language", "potential_misinformation"]
        mock_response.recommendations = ["Review content manually", "Consider fact-checking"]
        mock_response.created_at = datetime.utcnow()
        
        mock_controller.create_content_assessment.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.post(
            "/api/v1/social-protection/assessments",
            json=sample_assessment_request,
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["id"] == str(assessment_id)
        assert data["content_type"] == "text"
        assert data["assessment_type"] == "automated"
        assert data["risk_level"] == "medium"
        assert data["confidence_score"] == 0.72
        assert len(data["risk_factors"]) == 2
        assert len(data["recommendations"]) == 2

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_list_user_assessments_success(
        self, mock_get_controller, mock_get_user, client, mock_user_token, mock_user_id
    ):
        """Test successful user assessments listing."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response
        mock_controller = AsyncMock()
        assessment1 = MagicMock()
        assessment1.id = uuid.uuid4()
        assessment1.content_type = ContentType.TEXT
        assessment1.assessment_type = AssessmentType.AUTOMATED
        assessment1.risk_level = RiskLevel.HIGH
        assessment1.confidence_score = 0.88
        assessment1.risk_factors = ["hate_speech", "harassment"]
        assessment1.recommendations = ["Remove content", "Report to platform"]
        assessment1.created_at = datetime.utcnow() - timedelta(hours=3)

        assessment2 = MagicMock()
        assessment2.id = uuid.uuid4()
        assessment2.content_type = ContentType.IMAGE
        assessment2.assessment_type = AssessmentType.MANUAL
        assessment2.risk_level = RiskLevel.LOW
        assessment2.confidence_score = 0.95
        assessment2.risk_factors = []
        assessment2.recommendations = ["Content appears safe"]
        assessment2.created_at = datetime.utcnow() - timedelta(hours=1)
        
        mock_controller.get_user_assessments.return_value = [assessment1, assessment2]
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.get(
            "/api/v1/social-protection/assessments?limit=10&offset=0",
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 2
        assert data[0]["content_type"] == "text"
        assert data[0]["risk_level"] == "high"
        assert data[1]["content_type"] == "image"
        assert data[1]["risk_level"] == "low"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_dashboard_social_protection_overview_success(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test successful dashboard social protection overview."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        mock_response.total_scans = 15
        mock_response.active_scans = 12
        mock_response.failed_scans = 3
        mock_response.total_assessments = 45
        mock_response.high_risk_items = 8
        mock_response.recent_activity = [
            {
                "type": "scan_completed",
                "platform": "twitter",
                "timestamp": datetime.utcnow() - timedelta(hours=2),
                "details": "Profile scan completed successfully"
            }
        ]
        mock_response.platform_breakdown = {
            "twitter": {"scans": 8, "assessments": 20},
            "facebook": {"scans": 4, "assessments": 15},
            "instagram": {"scans": 3, "assessments": 10}
        }
        mock_response.risk_distribution = {
            "critical": 2,
            "high": 6,
            "medium": 15,
            "low": 22
        }
        mock_response.last_updated = datetime.utcnow()
        
        mock_controller.get_social_protection_overview.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.get(
            f"/dashboard/social-protection/overview?project_id={mock_project_id}",
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total_scans"] == 15
        assert data["active_scans"] == 12
        assert data["failed_scans"] == 3
        assert data["total_assessments"] == 45
        assert data["high_risk_items"] == 8
        assert len(data["recent_activity"]) == 1
        assert "twitter" in data["platform_breakdown"]
        assert data["risk_distribution"]["critical"] == 2

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_dashboard_protection_health_success(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test successful dashboard protection health retrieval."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        mock_response.overall_score = 78.5
        mock_response.url_safety_score = 85.2
        mock_response.social_protection_score = 72.8
        mock_response.risk_breakdown = {
            "url_threats": 88.5,
            "social_risks": 75.2,
            "reputation_health": 82.1,
            "monitoring_coverage": 69.8
        }
        mock_response.trending = "improving"
        mock_response.last_updated = datetime.utcnow()
        mock_response.recommendations = [
            "Increase social media monitoring frequency",
            "Review high-risk content assessments",
            "Enable additional platform scanning"
        ]
        
        mock_controller.get_protection_health.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.get(
            f"/dashboard/protection-health?project_id={mock_project_id}",
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["overall_score"] == 78.5
        assert data["url_safety_score"] == 85.2
        assert data["social_protection_score"] == 72.8
        assert "url_threats" in data["risk_breakdown"]
        assert data["trending"] == "improving"
        assert len(data["recommendations"]) == 3

    def test_unauthorized_access(self, client, sample_extension_data):
        """Test unauthorized access to protected endpoints."""
        # Test without authorization header
        response = client.post(
            "/api/v1/social-protection/extension/process",
            json=sample_extension_data
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Test dashboard endpoints without authorization
        response = client.get("/dashboard/social-protection/overview")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        response = client.get("/dashboard/protection-health")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_invalid_scan_id_format(
        self, mock_get_controller, mock_get_user, client, mock_user_token, mock_user_id
    ):
        """Test invalid scan ID format handling."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Make request with invalid UUID
        response = client.get(
            "/api/v1/social-protection/scans/invalid-uuid",
            headers={"Authorization": mock_user_token}
        )

        # Should return validation error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_scan_not_found(
        self, mock_get_controller, mock_get_user, client, mock_user_token, mock_user_id
    ):
        """Test scan not found handling."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller to raise not found exception
        mock_controller = AsyncMock()
        from fastapi import HTTPException
        mock_controller.get_scan_status.side_effect = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
        mock_get_controller.return_value = mock_controller

        # Make request with valid but non-existent UUID
        non_existent_id = uuid.uuid4()
        response = client.get(
            f"/api/v1/social-protection/scans/{non_existent_id}",
            headers={"Authorization": mock_user_token}
        )

        # Should return not found
        assert response.status_code == status.HTTP_404_NOT_FOUND

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_dashboard_internal_server_error(
        self, mock_get_controller, mock_get_user, client, mock_user_token, mock_user_id
    ):
        """Test dashboard endpoint internal server error handling."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller to raise internal server error
        mock_controller = AsyncMock()
        from fastapi import HTTPException
        mock_controller.get_social_protection_overview.side_effect = HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.get(
            "/dashboard/social-protection/overview",
            headers={"Authorization": mock_user_token}
        )

        # Should return internal server error
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_query_parameter_validation(self, client, mock_user_token):
        """Test query parameter validation for list endpoints."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test invalid limit parameter
            response = client.get(
                "/api/v1/social-protection/scans?limit=0",
                headers={"Authorization": mock_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test invalid offset parameter
            response = client.get(
                "/api/v1/social-protection/scans?offset=-1",
                headers={"Authorization": mock_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test limit exceeding maximum
            response = client.get(
                "/api/v1/social-protection/scans?limit=101",
                headers={"Authorization": mock_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY