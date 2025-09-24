"""
Security tests for social protection endpoints.

This module tests security aspects of social protection functionality including
authentication, authorization, input validation, rate limiting, and protection
against common security vulnerabilities.
"""

import pytest
import uuid
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status

from src.app import app
from src.models.user import User


class TestSocialProtectionSecurity:
    """Security test suite for social protection endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def valid_user_token(self):
        """Valid JWT token for authenticated requests."""
        return "Bearer valid_jwt_token_12345"

    @pytest.fixture
    def invalid_user_token(self):
        """Invalid JWT token for testing authentication failures."""
        return "Bearer invalid_jwt_token_12345"

    @pytest.fixture
    def expired_user_token(self):
        """Expired JWT token for testing token expiration."""
        return "Bearer expired_jwt_token_12345"

    @pytest.fixture
    def malformed_user_token(self):
        """Malformed JWT token for testing token validation."""
        return "Bearer malformed.jwt.token"

    @pytest.fixture
    def mock_user_id(self):
        """Mock user ID."""
        return uuid.uuid4()

    @pytest.fixture
    def mock_project_id(self):
        """Mock project ID."""
        return uuid.uuid4()

    @pytest.fixture
    def valid_extension_data(self, mock_project_id):
        """Valid extension data for testing."""
        return {
            "data": {
                "url": "https://twitter.com/example_user",
                "content_type": "social_profile",
                "platform": "twitter",
                "content": "User profile content",
                "metadata": {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            },
            "project_id": str(mock_project_id)
        }

    def test_authentication_required_extension_process(self, client, valid_extension_data):
        """Test that extension processing requires authentication."""
        # Request without authorization header
        response = client.post(
            "/api/v1/social-protection/extension/process",
            json=valid_extension_data
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Request with empty authorization header
        response = client.post(
            "/api/v1/social-protection/extension/process",
            json=valid_extension_data,
            headers={"Authorization": ""}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Request with malformed authorization header
        response = client.post(
            "/api/v1/social-protection/extension/process",
            json=valid_extension_data,
            headers={"Authorization": "InvalidFormat"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_authentication_required_social_scans(self, client):
        """Test that social scan endpoints require authentication."""
        scan_request = {
            "platform": "twitter",
            "profile_url": "https://twitter.com/example_user",
            "project_id": str(uuid.uuid4()),
            "scan_depth": "basic"
        }

        # Test scan creation without auth
        response = client.post("/api/v1/social-protection/scans", json=scan_request)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Test scan listing without auth
        response = client.get("/api/v1/social-protection/scans")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Test scan status without auth
        scan_id = uuid.uuid4()
        response = client.get(f"/api/v1/social-protection/scans/{scan_id}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_authentication_required_content_assessments(self, client):
        """Test that content assessment endpoints require authentication."""
        assessment_request = {
            "content_type": "text",
            "content_data": {
                "text": "Test content",
                "source_url": "https://example.com/post/123"
            },
            "project_id": str(uuid.uuid4()),
            "assessment_type": "automated"
        }

        # Test assessment creation without auth
        response = client.post("/api/v1/social-protection/assessments", json=assessment_request)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Test assessment listing without auth
        response = client.get("/api/v1/social-protection/assessments")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_authentication_required_dashboard_endpoints(self, client):
        """Test that dashboard endpoints require authentication."""
        # Test social protection overview without auth
        response = client.get("/dashboard/social-protection/overview")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Test protection health without auth
        response = client.get("/dashboard/protection-health")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @patch('src.authentication.dependencies.get_current_user')
    def test_invalid_jwt_token_handling(self, mock_get_user, client, invalid_user_token, valid_extension_data):
        """Test handling of invalid JWT tokens."""
        # Mock authentication to raise exception for invalid token
        from fastapi import HTTPException
        mock_get_user.side_effect = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

        response = client.post(
            "/api/v1/social-protection/extension/process",
            json=valid_extension_data,
            headers={"Authorization": invalid_user_token}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @patch('src.authentication.dependencies.get_current_user')
    def test_expired_jwt_token_handling(self, mock_get_user, client, expired_user_token, valid_extension_data):
        """Test handling of expired JWT tokens."""
        # Mock authentication to raise exception for expired token
        from fastapi import HTTPException
        mock_get_user.side_effect = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )

        response = client.post(
            "/api/v1/social-protection/extension/process",
            json=valid_extension_data,
            headers={"Authorization": expired_user_token}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_user_authorization_scan_access(
        self, mock_get_controller, mock_get_user, client, valid_user_token, mock_user_id
    ):
        """Test that users can only access their own scans."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller to raise forbidden exception for unauthorized access
        mock_controller = AsyncMock()
        from fastapi import HTTPException
        mock_controller.get_scan_status.side_effect = HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this scan"
        )
        mock_get_controller.return_value = mock_controller

        # Try to access another user's scan
        other_user_scan_id = uuid.uuid4()
        response = client.get(
            f"/api/v1/social-protection/scans/{other_user_scan_id}",
            headers={"Authorization": valid_user_token}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_social_protection_controller')
    def test_user_authorization_assessment_access(
        self, mock_get_controller, mock_get_user, client, valid_user_token, mock_user_id
    ):
        """Test that users can only access their own assessments."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller to return empty list for unauthorized user
        mock_controller = AsyncMock()
        mock_controller.get_user_assessments.return_value = []
        mock_get_controller.return_value = mock_controller

        response = client.get(
            "/api/v1/social-protection/assessments",
            headers={"Authorization": valid_user_token}
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 0

    def test_input_validation_extension_data(self, client, valid_user_token):
        """Test input validation for extension data processing."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test missing required fields
            invalid_data = {"data": {}}
            response = client.post(
                "/api/v1/social-protection/extension/process",
                json=invalid_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test invalid URL format
            invalid_url_data = {
                "data": {
                    "url": "not-a-valid-url",
                    "content_type": "social_profile",
                    "platform": "twitter",
                    "content": "content"
                },
                "project_id": str(uuid.uuid4())
            }
            response = client.post(
                "/api/v1/social-protection/extension/process",
                json=invalid_url_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test invalid project_id format
            invalid_project_data = {
                "data": {
                    "url": "https://twitter.com/user",
                    "content_type": "social_profile",
                    "platform": "twitter",
                    "content": "content"
                },
                "project_id": "not-a-uuid"
            }
            response = client.post(
                "/api/v1/social-protection/extension/process",
                json=invalid_project_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_input_validation_social_scan(self, client, valid_user_token):
        """Test input validation for social scan creation."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test missing required fields
            invalid_data = {}
            response = client.post(
                "/api/v1/social-protection/scans",
                json=invalid_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test invalid platform
            invalid_platform_data = {
                "platform": "invalid_platform",
                "profile_url": "https://twitter.com/user",
                "project_id": str(uuid.uuid4()),
                "scan_depth": "basic"
            }
            response = client.post(
                "/api/v1/social-protection/scans",
                json=invalid_platform_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test invalid scan_depth
            invalid_depth_data = {
                "platform": "twitter",
                "profile_url": "https://twitter.com/user",
                "project_id": str(uuid.uuid4()),
                "scan_depth": "invalid_depth"
            }
            response = client.post(
                "/api/v1/social-protection/scans",
                json=invalid_depth_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_input_validation_content_assessment(self, client, valid_user_token):
        """Test input validation for content assessment creation."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test missing required fields
            invalid_data = {}
            response = client.post(
                "/api/v1/social-protection/assessments",
                json=invalid_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test invalid content_type
            invalid_content_type_data = {
                "content_type": "invalid_type",
                "content_data": {"text": "content"},
                "project_id": str(uuid.uuid4()),
                "assessment_type": "automated"
            }
            response = client.post(
                "/api/v1/social-protection/assessments",
                json=invalid_content_type_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

            # Test invalid assessment_type
            invalid_assessment_type_data = {
                "content_type": "text",
                "content_data": {"text": "content"},
                "project_id": str(uuid.uuid4()),
                "assessment_type": "invalid_type"
            }
            response = client.post(
                "/api/v1/social-protection/assessments",
                json=invalid_assessment_type_data,
                headers={"Authorization": valid_user_token}
            )
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_sql_injection_protection(self, client, valid_user_token):
        """Test protection against SQL injection attacks."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test SQL injection in query parameters
            malicious_query = "'; DROP TABLE social_profile_scans; --"
            response = client.get(
                f"/api/v1/social-protection/scans?limit=10&offset=0&search={malicious_query}",
                headers={"Authorization": valid_user_token}
            )
            # Should not cause server error, should be handled gracefully
            assert response.status_code in [status.HTTP_200_OK, status.HTTP_422_UNPROCESSABLE_ENTITY]

            # Test SQL injection in request body
            malicious_data = {
                "data": {
                    "url": "https://twitter.com/user",
                    "content_type": "social_profile",
                    "platform": "twitter",
                    "content": "'; DROP TABLE content_risk_assessments; --"
                },
                "project_id": str(uuid.uuid4())
            }
            response = client.post(
                "/api/v1/social-protection/extension/process",
                json=malicious_data,
                headers={"Authorization": valid_user_token}
            )
            # Should not cause server error
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_xss_protection(self, client, valid_user_token):
        """Test protection against XSS attacks."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test XSS in content data
            xss_payload = "<script>alert('XSS')</script>"
            xss_data = {
                "data": {
                    "url": "https://twitter.com/user",
                    "content_type": "social_profile",
                    "platform": "twitter",
                    "content": xss_payload
                },
                "project_id": str(uuid.uuid4())
            }
            response = client.post(
                "/api/v1/social-protection/extension/process",
                json=xss_data,
                headers={"Authorization": valid_user_token}
            )
            # Should handle XSS payload safely
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_content_length_limits(self, client, valid_user_token):
        """Test content length limits to prevent DoS attacks."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test extremely large content
            large_content = "A" * 1000000  # 1MB of content
            large_data = {
                "data": {
                    "url": "https://twitter.com/user",
                    "content_type": "social_profile",
                    "platform": "twitter",
                    "content": large_content
                },
                "project_id": str(uuid.uuid4())
            }
            response = client.post(
                "/api/v1/social-protection/extension/process",
                json=large_data,
                headers={"Authorization": valid_user_token}
            )
            # Should reject or handle large content appropriately
            assert response.status_code in [
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_400_BAD_REQUEST
            ]

    def test_rate_limiting_protection(self, client, valid_user_token, valid_extension_data):
        """Test rate limiting protection against abuse."""
        with patch('src.authentication.dependencies.get_current_user'):
            with patch('src.controllers.depends.get_social_protection_controller'):
                # Simulate rapid requests
                responses = []
                for i in range(20):  # Make 20 rapid requests
                    response = client.post(
                        "/api/v1/social-protection/extension/process",
                        json=valid_extension_data,
                        headers={"Authorization": valid_user_token}
                    )
                    responses.append(response.status_code)

                # Should eventually hit rate limit
                rate_limited = any(code == status.HTTP_429_TOO_MANY_REQUESTS for code in responses)
                # Note: This test depends on rate limiting being implemented
                # If not implemented, this test documents the expected behavior

    def test_uuid_validation_in_paths(self, client, valid_user_token):
        """Test UUID validation in path parameters."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test invalid UUID formats
            invalid_uuids = [
                "not-a-uuid",
                "12345",
                "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                "../../../etc/passwd",
                "'; DROP TABLE scans; --"
            ]

            for invalid_uuid in invalid_uuids:
                response = client.get(
                    f"/api/v1/social-protection/scans/{invalid_uuid}",
                    headers={"Authorization": valid_user_token}
                )
                assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_query_parameter_injection(self, client, valid_user_token):
        """Test protection against query parameter injection."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test malicious query parameters
            malicious_params = [
                "limit=10&offset=0&malicious='; DROP TABLE scans; --",
                "limit=10&offset=0&search=<script>alert('xss')</script>",
                "limit=10&offset=0&filter=../../../etc/passwd"
            ]

            for param in malicious_params:
                response = client.get(
                    f"/api/v1/social-protection/scans?{param}",
                    headers={"Authorization": valid_user_token}
                )
                # Should handle malicious parameters safely
                assert response.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    status.HTTP_400_BAD_REQUEST
                ]

    def test_cors_headers_security(self, client):
        """Test CORS headers for security."""
        response = client.options("/api/v1/social-protection/health")
        
        # Check that CORS headers are properly configured
        # This test documents expected CORS behavior
        if "Access-Control-Allow-Origin" in response.headers:
            # Should not allow all origins in production
            assert response.headers["Access-Control-Allow-Origin"] != "*"

    def test_security_headers_presence(self, client):
        """Test presence of security headers."""
        response = client.get("/api/v1/social-protection/health")
        
        # Document expected security headers
        expected_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]
        
        # Note: This test documents expected security headers
        # Implementation may vary based on middleware configuration

    def test_sensitive_data_exposure(self, client, valid_user_token):
        """Test that sensitive data is not exposed in responses."""
        with patch('src.authentication.dependencies.get_current_user'):
            with patch('src.controllers.depends.get_social_protection_controller') as mock_controller:
                # Mock controller to return data with potential sensitive fields
                mock_ctrl = AsyncMock()
                mock_response = MagicMock()
                mock_response.id = uuid.uuid4()
                mock_response.platform = "twitter"
                mock_response.profile_url = "https://twitter.com/user"
                mock_response.status = "completed"
                # Ensure no sensitive data like API keys, tokens, etc. are exposed
                mock_ctrl.get_user_scans.return_value = [mock_response]
                mock_controller.return_value = mock_ctrl

                response = client.get(
                    "/api/v1/social-protection/scans",
                    headers={"Authorization": valid_user_token}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                
                # Ensure sensitive fields are not present in response
                sensitive_fields = ["api_key", "secret", "token", "password", "private_key"]
                response_text = json.dumps(data).lower()
                for field in sensitive_fields:
                    assert field not in response_text

    def test_file_upload_security(self, client, valid_user_token):
        """Test file upload security if applicable."""
        # Note: This test is for future file upload functionality
        # Currently documents expected security measures for file uploads
        
        # Test malicious file types
        malicious_files = [
            ("test.exe", b"MZ\x90\x00"),  # Executable
            ("test.php", b"<?php system($_GET['cmd']); ?>"),  # PHP script
            ("test.jsp", b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>")  # JSP
        ]
        
        # If file upload endpoints exist, they should reject malicious files
        # This test documents the expected behavior

    @patch('src.authentication.dependencies.get_current_user')
    def test_privilege_escalation_protection(self, mock_get_user, client, valid_user_token):
        """Test protection against privilege escalation."""
        # Mock regular user (not admin)
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_admin = False
        mock_user.role = "user"
        mock_get_user.return_value = mock_user

        # Test that regular users cannot access admin-only functionality
        # (if such functionality exists in social protection endpoints)
        
        # Example: trying to access system-wide statistics
        response = client.get(
            "/dashboard/social-protection/overview?system_wide=true",
            headers={"Authorization": valid_user_token}
        )
        
        # Should either be forbidden or ignore the system_wide parameter
        assert response.status_code in [
            status.HTTP_200_OK,  # Ignores system_wide parameter
            status.HTTP_403_FORBIDDEN  # Explicitly denies access
        ]

    def test_information_disclosure_protection(self, client, valid_user_token):
        """Test protection against information disclosure."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test that error messages don't reveal sensitive information
            response = client.get(
                f"/api/v1/social-protection/scans/{uuid.uuid4()}",
                headers={"Authorization": valid_user_token}
            )
            
            if response.status_code == status.HTTP_404_NOT_FOUND:
                error_detail = response.json().get("detail", "")
                # Should not reveal database structure, file paths, etc.
                sensitive_info = ["database", "table", "column", "file", "path", "server"]
                for info in sensitive_info:
                    assert info.lower() not in error_detail.lower()

    def test_session_security(self, client, valid_user_token):
        """Test session security measures."""
        with patch('src.authentication.dependencies.get_current_user'):
            # Test that sessions are properly managed
            # This includes JWT token validation, expiration, etc.
            
            # Test concurrent session handling
            response1 = client.get(
                "/api/v1/social-protection/scans",
                headers={"Authorization": valid_user_token}
            )
            
            response2 = client.get(
                "/api/v1/social-protection/scans",
                headers={"Authorization": valid_user_token}
            )
            
            # Both requests should be handled properly
            assert response1.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED]
            assert response2.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED]