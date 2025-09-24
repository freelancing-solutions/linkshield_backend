"""
Dashboard integration tests for social protection functionality.

This module tests the dashboard integration aspects of social protection,
including data aggregation, metrics calculation, visualization data preparation,
and cross-module integration with other dashboard components.
"""

import pytest
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status

from src.app import app
from src.models.user import User
from src.models.social_protection import (
    SocialProfileScan,
    ContentRiskAssessment,
    RiskLevel,
    PlatformType,
    ScanStatus,
    ContentType,
    AssessmentType,
)


class TestSocialProtectionDashboard:
    """Dashboard integration test suite for social protection."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

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
    def sample_scans_data(self, mock_user_id, mock_project_id):
        """Sample social protection scans data."""
        base_time = datetime.utcnow()
        
        return [
            # Completed scan - Twitter
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                platform=PlatformType.TWITTER,
                profile_url="https://twitter.com/user1",
                status=ScanStatus.COMPLETED,
                scan_depth="detailed",
                risk_level=RiskLevel.LOW,
                confidence_score=0.92,
                findings={"threats_detected": 0, "warnings": 1, "info": 3},
                created_at=base_time - timedelta(hours=24),
                started_at=base_time - timedelta(hours=23, minutes=45),
                completed_at=base_time - timedelta(hours=23, minutes=30)
            ),
            # Completed scan - Facebook
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                platform=PlatformType.FACEBOOK,
                profile_url="https://facebook.com/user2",
                status=ScanStatus.COMPLETED,
                scan_depth="basic",
                risk_level=RiskLevel.MEDIUM,
                confidence_score=0.78,
                findings={"threats_detected": 2, "warnings": 3, "info": 1},
                created_at=base_time - timedelta(hours=12),
                started_at=base_time - timedelta(hours=11, minutes=45),
                completed_at=base_time - timedelta(hours=11, minutes=30)
            ),
            # Failed scan - Instagram
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                platform=PlatformType.INSTAGRAM,
                profile_url="https://instagram.com/user3",
                status=ScanStatus.FAILED,
                scan_depth="detailed",
                risk_level=None,
                confidence_score=None,
                findings=None,
                created_at=base_time - timedelta(hours=6),
                started_at=base_time - timedelta(hours=5, minutes=45),
                completed_at=None,
                error_message="Profile not accessible"
            ),
            # Active scan - LinkedIn
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                platform=PlatformType.LINKEDIN,
                profile_url="https://linkedin.com/in/user4",
                status=ScanStatus.IN_PROGRESS,
                scan_depth="basic",
                risk_level=None,
                confidence_score=None,
                findings=None,
                created_at=base_time - timedelta(hours=2),
                started_at=base_time - timedelta(hours=1, minutes=45),
                completed_at=None
            ),
            # High risk scan - Twitter
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                platform=PlatformType.TWITTER,
                profile_url="https://twitter.com/suspicious_user",
                status=ScanStatus.COMPLETED,
                scan_depth="detailed",
                risk_level=RiskLevel.HIGH,
                confidence_score=0.95,
                findings={"threats_detected": 5, "warnings": 8, "info": 2},
                created_at=base_time - timedelta(hours=8),
                started_at=base_time - timedelta(hours=7, minutes=45),
                completed_at=base_time - timedelta(hours=7, minutes=30)
            )
        ]

    @pytest.fixture
    def sample_assessments_data(self, mock_user_id, mock_project_id):
        """Sample content risk assessments data."""
        base_time = datetime.utcnow()
        
        return [
            # High risk text assessment
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                content_type=ContentType.TEXT,
                assessment_type=AssessmentType.AUTOMATED,
                risk_level=RiskLevel.HIGH,
                confidence_score=0.89,
                risk_factors=["hate_speech", "harassment", "misinformation"],
                recommendations=["Remove content", "Report to platform", "Block user"],
                created_at=base_time - timedelta(hours=18)
            ),
            # Medium risk image assessment
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                content_type=ContentType.IMAGE,
                assessment_type=AssessmentType.MANUAL,
                risk_level=RiskLevel.MEDIUM,
                confidence_score=0.72,
                risk_factors=["inappropriate_content", "potential_spam"],
                recommendations=["Review manually", "Consider flagging"],
                created_at=base_time - timedelta(hours=10)
            ),
            # Low risk video assessment
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                content_type=ContentType.VIDEO,
                assessment_type=AssessmentType.AUTOMATED,
                risk_level=RiskLevel.LOW,
                confidence_score=0.94,
                risk_factors=[],
                recommendations=["Content appears safe"],
                created_at=base_time - timedelta(hours=4)
            ),
            # Critical risk link assessment
            MagicMock(
                id=uuid.uuid4(),
                user_id=mock_user_id,
                project_id=mock_project_id,
                content_type=ContentType.LINK,
                assessment_type=AssessmentType.AUTOMATED,
                risk_level=RiskLevel.CRITICAL,
                confidence_score=0.98,
                risk_factors=["malware", "phishing", "suspicious_domain"],
                recommendations=["Block immediately", "Alert users", "Report to security team"],
                created_at=base_time - timedelta(hours=2)
            )
        ]

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_social_protection_overview_data_aggregation(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id, sample_scans_data, sample_assessments_data
    ):
        """Test social protection overview data aggregation."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response with aggregated data
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        
        # Calculate expected aggregations from sample data
        completed_scans = [s for s in sample_scans_data if s.status == ScanStatus.COMPLETED]
        active_scans = [s for s in sample_scans_data if s.status == ScanStatus.IN_PROGRESS]
        failed_scans = [s for s in sample_scans_data if s.status == ScanStatus.FAILED]
        high_risk_assessments = [a for a in sample_assessments_data if a.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        
        mock_response.total_scans = len(sample_scans_data)
        mock_response.active_scans = len(active_scans)
        mock_response.failed_scans = len(failed_scans)
        mock_response.total_assessments = len(sample_assessments_data)
        mock_response.high_risk_items = len(high_risk_assessments)
        
        # Platform breakdown
        platform_counts = {}
        for scan in sample_scans_data:
            platform = scan.platform.value
            if platform not in platform_counts:
                platform_counts[platform] = {"scans": 0, "assessments": 0}
            platform_counts[platform]["scans"] += 1
        
        for assessment in sample_assessments_data:
            # Assume assessments are distributed across platforms
            pass
        
        mock_response.platform_breakdown = {
            "twitter": {"scans": 2, "assessments": 1},
            "facebook": {"scans": 1, "assessments": 1},
            "instagram": {"scans": 1, "assessments": 1},
            "linkedin": {"scans": 1, "assessments": 1}
        }
        
        # Risk distribution
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for scan in completed_scans:
            if scan.risk_level:
                risk_counts[scan.risk_level.value] += 1
        for assessment in sample_assessments_data:
            risk_counts[assessment.risk_level.value] += 1
        
        mock_response.risk_distribution = risk_counts
        
        # Recent activity
        mock_response.recent_activity = [
            {
                "type": "scan_completed",
                "platform": "twitter",
                "timestamp": datetime.utcnow() - timedelta(hours=2),
                "details": "High-risk profile detected",
                "risk_level": "high"
            },
            {
                "type": "assessment_created",
                "content_type": "link",
                "timestamp": datetime.utcnow() - timedelta(hours=2),
                "details": "Critical risk content blocked",
                "risk_level": "critical"
            }
        ]
        
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
        
        # Verify aggregated metrics
        assert data["total_scans"] == 5
        assert data["active_scans"] == 1
        assert data["failed_scans"] == 1
        assert data["total_assessments"] == 4
        assert data["high_risk_items"] == 2
        
        # Verify platform breakdown
        assert "twitter" in data["platform_breakdown"]
        assert "facebook" in data["platform_breakdown"]
        assert data["platform_breakdown"]["twitter"]["scans"] == 2
        
        # Verify risk distribution
        assert "critical" in data["risk_distribution"]
        assert "high" in data["risk_distribution"]
        assert "medium" in data["risk_distribution"]
        assert "low" in data["risk_distribution"]
        
        # Verify recent activity
        assert len(data["recent_activity"]) == 2
        assert data["recent_activity"][0]["type"] == "scan_completed"
        assert data["recent_activity"][1]["type"] == "assessment_created"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_protection_health_score_calculation(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test protection health score calculation and trending."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response with calculated health scores
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        
        # Health scores based on risk levels and coverage
        mock_response.overall_score = 76.8
        mock_response.url_safety_score = 82.5
        mock_response.social_protection_score = 71.2
        
        # Detailed risk breakdown
        mock_response.risk_breakdown = {
            "url_threats": 85.3,  # High score = low threats
            "social_risks": 68.7,  # Lower score = more social risks detected
            "reputation_health": 79.4,
            "monitoring_coverage": 74.6
        }
        
        # Trending analysis
        mock_response.trending = "improving"  # Based on historical comparison
        mock_response.trend_percentage = 5.2  # 5.2% improvement
        
        # Time-based metrics
        mock_response.last_updated = datetime.utcnow()
        mock_response.calculation_period = "7_days"
        
        # Recommendations based on scores
        mock_response.recommendations = [
            "Increase social media monitoring frequency for better coverage",
            "Review and address medium-risk content assessments",
            "Consider enabling additional platform scanning for LinkedIn",
            "Implement automated response for high-risk detections"
        ]
        
        # Historical data points for trending
        mock_response.historical_scores = [
            {"date": "2024-01-01", "score": 71.6},
            {"date": "2024-01-02", "score": 73.2},
            {"date": "2024-01-03", "score": 74.8},
            {"date": "2024-01-04", "score": 76.8}
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
        
        # Verify calculated scores
        assert data["overall_score"] == 76.8
        assert data["url_safety_score"] == 82.5
        assert data["social_protection_score"] == 71.2
        
        # Verify risk breakdown
        assert data["risk_breakdown"]["url_threats"] == 85.3
        assert data["risk_breakdown"]["social_risks"] == 68.7
        assert data["risk_breakdown"]["reputation_health"] == 79.4
        assert data["risk_breakdown"]["monitoring_coverage"] == 74.6
        
        # Verify trending analysis
        assert data["trending"] == "improving"
        assert data["trend_percentage"] == 5.2
        
        # Verify recommendations
        assert len(data["recommendations"]) == 4
        assert "monitoring frequency" in data["recommendations"][0]
        
        # Verify historical data
        assert len(data["historical_scores"]) == 4
        assert data["historical_scores"][-1]["score"] == 76.8

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_cross_module_integration_metrics(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test integration with other dashboard modules (URL scanning, reputation, etc.)."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response with cross-module data
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        
        # Combined protection metrics
        mock_response.overall_score = 78.5
        mock_response.url_safety_score = 85.2  # From URL scanning module
        mock_response.social_protection_score = 72.8  # From social protection
        mock_response.reputation_score = 81.3  # From reputation module
        
        # Cross-module correlations
        mock_response.correlation_insights = {
            "social_url_overlap": {
                "shared_threats": 12,
                "social_only_threats": 8,
                "url_only_threats": 15,
                "correlation_strength": 0.73
            },
            "reputation_impact": {
                "social_reputation_events": 5,
                "reputation_score_impact": -2.4,
                "recovery_trend": "stable"
            }
        }
        
        # Integrated threat landscape
        mock_response.threat_landscape = {
            "total_threats": 35,
            "social_threats": 20,
            "url_threats": 27,
            "reputation_threats": 8,
            "cross_platform_threats": 12
        }
        
        # Unified recommendations
        mock_response.recommendations = [
            "Social media threats correlate with URL risks - implement unified monitoring",
            "Recent social activity has impacted reputation score - consider proactive engagement",
            "Cross-platform threat patterns detected - enable comprehensive scanning"
        ]
        
        mock_controller.get_protection_health.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request
        response = client.get(
            f"/dashboard/protection-health?project_id={mock_project_id}&include_correlations=true",
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Verify cross-module scores
        assert data["url_safety_score"] == 85.2
        assert data["social_protection_score"] == 72.8
        assert data["reputation_score"] == 81.3
        
        # Verify correlation insights
        correlations = data["correlation_insights"]
        assert correlations["social_url_overlap"]["shared_threats"] == 12
        assert correlations["social_url_overlap"]["correlation_strength"] == 0.73
        assert correlations["reputation_impact"]["social_reputation_events"] == 5
        
        # Verify integrated threat landscape
        threats = data["threat_landscape"]
        assert threats["total_threats"] == 35
        assert threats["social_threats"] == 20
        assert threats["cross_platform_threats"] == 12
        
        # Verify unified recommendations
        assert len(data["recommendations"]) == 3
        assert "unified monitoring" in data["recommendations"][0]

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_time_series_data_aggregation(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test time series data aggregation for dashboard charts."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response with time series data
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        
        # Time series for scans
        base_date = datetime.utcnow().date()
        mock_response.scan_timeline = [
            {
                "date": str(base_date - timedelta(days=6)),
                "total_scans": 8,
                "completed_scans": 7,
                "failed_scans": 1,
                "high_risk_detections": 2
            },
            {
                "date": str(base_date - timedelta(days=5)),
                "total_scans": 12,
                "completed_scans": 10,
                "failed_scans": 2,
                "high_risk_detections": 3
            },
            {
                "date": str(base_date - timedelta(days=4)),
                "total_scans": 15,
                "completed_scans": 14,
                "failed_scans": 1,
                "high_risk_detections": 1
            },
            {
                "date": str(base_date - timedelta(days=3)),
                "total_scans": 18,
                "completed_scans": 16,
                "failed_scans": 2,
                "high_risk_detections": 4
            },
            {
                "date": str(base_date - timedelta(days=2)),
                "total_scans": 22,
                "completed_scans": 20,
                "failed_scans": 2,
                "high_risk_detections": 2
            },
            {
                "date": str(base_date - timedelta(days=1)),
                "total_scans": 25,
                "completed_scans": 23,
                "failed_scans": 2,
                "high_risk_detections": 3
            },
            {
                "date": str(base_date),
                "total_scans": 28,
                "completed_scans": 26,
                "failed_scans": 2,
                "high_risk_detections": 1
            }
        ]
        
        # Time series for assessments
        mock_response.assessment_timeline = [
            {
                "date": str(base_date - timedelta(days=6)),
                "total_assessments": 45,
                "high_risk_assessments": 8,
                "medium_risk_assessments": 15,
                "low_risk_assessments": 22
            },
            {
                "date": str(base_date - timedelta(days=5)),
                "total_assessments": 52,
                "high_risk_assessments": 10,
                "medium_risk_assessments": 18,
                "low_risk_assessments": 24
            },
            {
                "date": str(base_date - timedelta(days=4)),
                "total_assessments": 58,
                "high_risk_assessments": 9,
                "medium_risk_assessments": 20,
                "low_risk_assessments": 29
            },
            {
                "date": str(base_date - timedelta(days=3)),
                "total_assessments": 65,
                "high_risk_assessments": 12,
                "medium_risk_assessments": 22,
                "low_risk_assessments": 31
            },
            {
                "date": str(base_date - timedelta(days=2)),
                "total_assessments": 71,
                "high_risk_assessments": 11,
                "medium_risk_assessments": 25,
                "low_risk_assessments": 35
            },
            {
                "date": str(base_date - timedelta(days=1)),
                "total_assessments": 78,
                "high_risk_assessments": 13,
                "medium_risk_assessments": 27,
                "low_risk_assessments": 38
            },
            {
                "date": str(base_date),
                "total_assessments": 84,
                "high_risk_assessments": 12,
                "medium_risk_assessments": 29,
                "low_risk_assessments": 43
            }
        ]
        
        # Platform activity over time
        mock_response.platform_activity = {
            "twitter": [5, 7, 8, 9, 11, 12, 14],
            "facebook": [2, 3, 4, 5, 6, 7, 8],
            "instagram": [1, 2, 2, 3, 3, 4, 4],
            "linkedin": [0, 0, 1, 1, 2, 2, 2]
        }
        
        mock_controller.get_social_protection_overview.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request with time series parameter
        response = client.get(
            f"/dashboard/social-protection/overview?project_id={mock_project_id}&include_timeline=true&days=7",
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Verify scan timeline
        scan_timeline = data["scan_timeline"]
        assert len(scan_timeline) == 7
        assert scan_timeline[0]["total_scans"] == 8
        assert scan_timeline[-1]["total_scans"] == 28
        assert scan_timeline[-1]["high_risk_detections"] == 1
        
        # Verify assessment timeline
        assessment_timeline = data["assessment_timeline"]
        assert len(assessment_timeline) == 7
        assert assessment_timeline[0]["total_assessments"] == 45
        assert assessment_timeline[-1]["total_assessments"] == 84
        
        # Verify platform activity trends
        platform_activity = data["platform_activity"]
        assert len(platform_activity["twitter"]) == 7
        assert platform_activity["twitter"][-1] == 14  # Most recent day
        assert platform_activity["linkedin"][-1] == 2  # Least active platform

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_dashboard_filtering_and_grouping(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test dashboard data filtering and grouping capabilities."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response with filtered data
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        
        # Filtered by platform (Twitter only)
        mock_response.total_scans = 8  # Only Twitter scans
        mock_response.active_scans = 2
        mock_response.failed_scans = 1
        mock_response.total_assessments = 15  # Twitter-related assessments
        mock_response.high_risk_items = 3
        
        # Platform-specific breakdown
        mock_response.platform_breakdown = {
            "twitter": {
                "scans": 8,
                "assessments": 15,
                "avg_risk_score": 0.65,
                "success_rate": 0.875
            }
        }
        
        # Risk level grouping for Twitter
        mock_response.risk_distribution = {
            "critical": 1,
            "high": 2,
            "medium": 4,
            "low": 8
        }
        
        # Time-based grouping (last 24 hours)
        mock_response.recent_activity = [
            {
                "type": "scan_completed",
                "platform": "twitter",
                "timestamp": datetime.utcnow() - timedelta(hours=2),
                "details": "Profile scan completed",
                "risk_level": "medium"
            },
            {
                "type": "assessment_created",
                "platform": "twitter",
                "timestamp": datetime.utcnow() - timedelta(hours=4),
                "details": "Tweet content assessed",
                "risk_level": "low"
            }
        ]
        
        mock_controller.get_social_protection_overview.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request with filters
        response = client.get(
            f"/dashboard/social-protection/overview?project_id={mock_project_id}&platform=twitter&time_range=24h",
            headers={"Authorization": mock_user_token}
        )

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Verify filtered results
        assert data["total_scans"] == 8  # Only Twitter scans
        assert data["total_assessments"] == 15
        
        # Verify platform-specific data
        assert "twitter" in data["platform_breakdown"]
        assert len(data["platform_breakdown"]) == 1  # Only Twitter
        assert data["platform_breakdown"]["twitter"]["success_rate"] == 0.875
        
        # Verify time-filtered activity
        assert len(data["recent_activity"]) == 2
        for activity in data["recent_activity"]:
            assert activity["platform"] == "twitter"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_dashboard_error_handling_and_fallbacks(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test dashboard error handling and fallback mechanisms."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Test partial data availability
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        
        # Simulate partial service availability
        mock_response.total_scans = 10
        mock_response.active_scans = 2
        mock_response.failed_scans = 1
        mock_response.total_assessments = None  # Assessment service unavailable
        mock_response.high_risk_items = 3
        
        # Partial platform data
        mock_response.platform_breakdown = {
            "twitter": {"scans": 6, "assessments": None},
            "facebook": {"scans": 4, "assessments": None}
        }
        
        # Fallback risk distribution
        mock_response.risk_distribution = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "unknown": 0  # For failed assessments
        }
        
        # Limited recent activity
        mock_response.recent_activity = []  # Activity service unavailable
        
        # Service status indicators
        mock_response.service_status = {
            "scan_service": "operational",
            "assessment_service": "degraded",
            "activity_service": "unavailable"
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
        
        # Verify available data is returned
        assert data["total_scans"] == 10
        assert data["active_scans"] == 2
        
        # Verify graceful handling of unavailable data
        assert data["total_assessments"] is None
        assert data["recent_activity"] == []
        
        # Verify service status is communicated
        assert "service_status" in data
        assert data["service_status"]["scan_service"] == "operational"
        assert data["service_status"]["assessment_service"] == "degraded"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_dashboard_performance_with_large_datasets(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test dashboard performance with large datasets."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller response with large dataset indicators
        mock_controller = AsyncMock()
        mock_response = MagicMock()
        
        # Large dataset metrics
        mock_response.total_scans = 50000
        mock_response.active_scans = 1200
        mock_response.failed_scans = 850
        mock_response.total_assessments = 125000
        mock_response.high_risk_items = 2500
        
        # Aggregated platform data (not individual records)
        mock_response.platform_breakdown = {
            "twitter": {"scans": 25000, "assessments": 62500},
            "facebook": {"scans": 15000, "assessments": 37500},
            "instagram": {"scans": 8000, "assessments": 20000},
            "linkedin": {"scans": 2000, "assessments": 5000}
        }
        
        # Sampled recent activity (not all records)
        mock_response.recent_activity = [
            {
                "type": "scan_completed",
                "platform": "twitter",
                "timestamp": datetime.utcnow() - timedelta(minutes=5),
                "details": "Batch scan completed (500 profiles)",
                "batch_size": 500
            }
        ]
        
        # Performance metadata
        mock_response.query_performance = {
            "execution_time_ms": 245,
            "records_processed": 175000,
            "cache_hit_rate": 0.87,
            "data_freshness": "2_minutes"
        }
        
        mock_controller.get_social_protection_overview.return_value = mock_response
        mock_get_controller.return_value = mock_controller

        # Make request
        start_time = datetime.utcnow()
        response = client.get(
            f"/dashboard/social-protection/overview?project_id={mock_project_id}",
            headers={"Authorization": mock_user_token}
        )
        end_time = datetime.utcnow()
        
        # Assertions
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Verify large dataset handling
        assert data["total_scans"] == 50000
        assert data["total_assessments"] == 125000
        
        # Verify performance is acceptable (should be fast due to aggregation)
        response_time = (end_time - start_time).total_seconds()
        assert response_time < 5.0  # Should respond within 5 seconds
        
        # Verify performance metadata if available
        if "query_performance" in data:
            assert data["query_performance"]["execution_time_ms"] < 1000
            assert data["query_performance"]["cache_hit_rate"] > 0.5

    def test_dashboard_unauthorized_access(self, client, mock_project_id):
        """Test unauthorized access to dashboard endpoints."""
        # Test without authentication
        response = client.get(f"/dashboard/social-protection/overview?project_id={mock_project_id}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        response = client.get(f"/dashboard/protection-health?project_id={mock_project_id}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @patch('src.authentication.dependencies.get_current_user')
    def test_dashboard_invalid_project_access(self, mock_get_user, client, mock_user_token, mock_user_id):
        """Test access to invalid or unauthorized projects."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Test with invalid project ID format
        response = client.get(
            "/dashboard/social-protection/overview?project_id=invalid-uuid",
            headers={"Authorization": mock_user_token}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Test with non-existent project ID
        non_existent_project = uuid.uuid4()
        with patch('src.controllers.depends.get_dashboard_controller') as mock_controller:
            mock_ctrl = AsyncMock()
            from fastapi import HTTPException
            mock_ctrl.get_social_protection_overview.side_effect = HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
            mock_controller.return_value = mock_ctrl

            response = client.get(
                f"/dashboard/social-protection/overview?project_id={non_existent_project}",
                headers={"Authorization": mock_user_token}
            )
            assert response.status_code == status.HTTP_404_NOT_FOUND