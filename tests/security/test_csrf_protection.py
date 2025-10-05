#!/usr/bin/env python3
"""
Comprehensive tests for CSRF Protection System

Tests CSRF token generation, validation, double-submit cookie pattern,
middleware integration, and security validation.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import secrets
import hmac
import hashlib
from fastapi import Request, Response, HTTPException
from fastapi.testclient import TestClient

from src.security.csrf_protection import (
    CSRFProtectionService,
    CSRFToken,
    CSRFConfig,
    CSRFValidationResult,
    CSRFError,
    CSRFErrorType
)
from src.middleware.csrf_middleware import CSRFMiddleware


class TestCSRFProtectionService:
    """Test suite for CSRF Protection Service"""

    @pytest.fixture
    def csrf_config(self):
        """CSRF configuration for testing"""
        return CSRFConfig(
            secret_key="test-secret-key-32-characters-long",
            token_lifetime=3600,  # 1 hour
            cookie_name="csrf_token",
            header_name="X-CSRF-Token",
            cookie_secure=True,
            cookie_samesite="strict",
            exempt_paths=["/api/auth/login", "/api/health"]
        )

    @pytest.fixture
    def csrf_service(self, csrf_config):
        """Create CSRF protection service"""
        return CSRFProtectionService(csrf_config)

    @pytest.fixture
    def mock_request(self):
        """Mock FastAPI request"""
        request = Mock(spec=Request)
        request.cookies = {}
        request.headers = {}
        request.method = "POST"
        request.url.path = "/api/test"
        request.client.host = "127.0.0.1"
        return request

    @pytest.fixture
    def mock_response(self):
        """Mock FastAPI response"""
        response = Mock(spec=Response)
        response.set_cookie = Mock()
        return response

    # Token Generation Tests
    def test_generate_csrf_token(self, csrf_service):
        """Test CSRF token generation"""
        session_id = "test-session-123"
        
        token = csrf_service.generate_token(session_id)
        
        assert isinstance(token, CSRFToken)
        assert token.session_id == session_id
        assert len(token.token_value) > 0
        assert token.expires_at > datetime.now(timezone.utc)
        assert token.is_valid() is True

    def test_generate_token_with_custom_lifetime(self, csrf_service):
        """Test token generation with custom lifetime"""
        session_id = "test-session-123"
        custom_lifetime = 7200  # 2 hours
        
        token = csrf_service.generate_token(session_id, lifetime_seconds=custom_lifetime)
        
        expected_expiry = datetime.now(timezone.utc) + timedelta(seconds=custom_lifetime)
        assert abs((token.expires_at - expected_expiry).total_seconds()) < 5

    def test_token_uniqueness(self, csrf_service):
        """Test that generated tokens are unique"""
        session_id = "test-session-123"
        
        token1 = csrf_service.generate_token(session_id)
        token2 = csrf_service.generate_token(session_id)
        
        assert token1.token_value != token2.token_value
        assert token1.token_hash != token2.token_hash

    # Token Validation Tests
    def test_validate_token_success(self, csrf_service):
        """Test successful token validation"""
        session_id = "test-session-123"
        token = csrf_service.generate_token(session_id)
        
        result = csrf_service.validate_token(token.token_value, session_id)
        
        assert result.is_valid is True
        assert result.error is None

    def test_validate_token_invalid_session(self, csrf_service):
        """Test token validation with wrong session ID"""
        session_id = "test-session-123"
        wrong_session_id = "wrong-session-456"
        token = csrf_service.generate_token(session_id)
        
        result = csrf_service.validate_token(token.token_value, wrong_session_id)
        
        assert result.is_valid is False
        assert result.error == CSRFErrorType.INVALID_TOKEN

    def test_validate_expired_token(self, csrf_service):
        """Test validation of expired token"""
        session_id = "test-session-123"
        
        # Generate token with very short lifetime
        token = csrf_service.generate_token(session_id, lifetime_seconds=1)
        
        # Wait for token to expire
        import time
        time.sleep(2)
        
        result = csrf_service.validate_token(token.token_value, session_id)
        
        assert result.is_valid is False
        assert result.error == CSRFErrorType.TOKEN_EXPIRED

    def test_validate_malformed_token(self, csrf_service):
        """Test validation of malformed token"""
        session_id = "test-session-123"
        malformed_token = "invalid-token-format"
        
        result = csrf_service.validate_token(malformed_token, session_id)
        
        assert result.is_valid is False
        assert result.error == CSRFErrorType.MALFORMED_TOKEN

    def test_validate_empty_token(self, csrf_service):
        """Test validation of empty token"""
        session_id = "test-session-123"
        
        result = csrf_service.validate_token("", session_id)
        
        assert result.is_valid is False
        assert result.error == CSRFErrorType.MISSING_TOKEN

    # Double-Submit Cookie Pattern Tests
    def test_set_csrf_cookie(self, csrf_service, mock_response):
        """Test setting CSRF cookie"""
        session_id = "test-session-123"
        token = csrf_service.generate_token(session_id)
        
        csrf_service.set_csrf_cookie(mock_response, token)
        
        mock_response.set_cookie.assert_called_once()
        call_args = mock_response.set_cookie.call_args
        assert call_args[1]['key'] == csrf_service.config.cookie_name
        assert call_args[1]['secure'] == csrf_service.config.cookie_secure
        assert call_args[1]['samesite'] == csrf_service.config.cookie_samesite

    def test_extract_token_from_header(self, csrf_service, mock_request):
        """Test extracting CSRF token from header"""
        token_value = "test-token-value"
        mock_request.headers = {csrf_service.config.header_name: token_value}
        
        extracted_token = csrf_service.extract_token_from_request(mock_request)
        
        assert extracted_token == token_value

    def test_extract_token_from_cookie(self, csrf_service, mock_request):
        """Test extracting CSRF token from cookie"""
        token_value = "test-token-value"
        mock_request.cookies = {csrf_service.config.cookie_name: token_value}
        mock_request.headers = {}  # No header token
        
        extracted_token = csrf_service.extract_token_from_request(mock_request)
        
        assert extracted_token == token_value

    def test_extract_token_priority(self, csrf_service, mock_request):
        """Test token extraction priority (header over cookie)"""
        header_token = "header-token"
        cookie_token = "cookie-token"
        
        mock_request.headers = {csrf_service.config.header_name: header_token}
        mock_request.cookies = {csrf_service.config.cookie_name: cookie_token}
        
        extracted_token = csrf_service.extract_token_from_request(mock_request)
        
        assert extracted_token == header_token

    # Path Exemption Tests
    def test_is_exempt_path_true(self, csrf_service, mock_request):
        """Test exempt path detection"""
        mock_request.url.path = "/api/auth/login"
        
        is_exempt = csrf_service.is_exempt_path(mock_request)
        
        assert is_exempt is True

    def test_is_exempt_path_false(self, csrf_service, mock_request):
        """Test non-exempt path detection"""
        mock_request.url.path = "/api/protected/resource"
        
        is_exempt = csrf_service.is_exempt_path(mock_request)
        
        assert is_exempt is False

    def test_is_exempt_path_wildcard(self, csrf_config, mock_request):
        """Test wildcard exempt paths"""
        csrf_config.exempt_paths = ["/api/public/*", "/health"]
        csrf_service = CSRFProtectionService(csrf_config)
        
        mock_request.url.path = "/api/public/status"
        assert csrf_service.is_exempt_path(mock_request) is True
        
        mock_request.url.path = "/api/public/info/details"
        assert csrf_service.is_exempt_path(mock_request) is True
        
        mock_request.url.path = "/api/private/data"
        assert csrf_service.is_exempt_path(mock_request) is False

    # Security Tests
    def test_token_tampering_detection(self, csrf_service):
        """Test detection of tampered tokens"""
        session_id = "test-session-123"
        token = csrf_service.generate_token(session_id)
        
        # Tamper with token
        tampered_token = token.token_value[:-5] + "XXXXX"
        
        result = csrf_service.validate_token(tampered_token, session_id)
        
        assert result.is_valid is False
        assert result.error == CSRFErrorType.INVALID_TOKEN

    def test_timing_attack_resistance(self, csrf_service):
        """Test timing attack resistance"""
        session_id = "test-session-123"
        valid_token = csrf_service.generate_token(session_id).token_value
        invalid_token = "invalid-token-same-length-as-valid-one"
        
        import time
        
        # Measure validation time for valid token
        start_time = time.perf_counter()
        csrf_service.validate_token(valid_token, session_id)
        valid_time = time.perf_counter() - start_time
        
        # Measure validation time for invalid token
        start_time = time.perf_counter()
        csrf_service.validate_token(invalid_token, session_id)
        invalid_time = time.perf_counter() - start_time
        
        # Times should be similar (within reasonable variance)
        time_difference = abs(valid_time - invalid_time)
        assert time_difference < 0.001  # 1ms tolerance

    def test_session_isolation(self, csrf_service):
        """Test that tokens are isolated by session"""
        session1 = "session-1"
        session2 = "session-2"
        
        token1 = csrf_service.generate_token(session1)
        token2 = csrf_service.generate_token(session2)
        
        # Token1 should not validate for session2
        result = csrf_service.validate_token(token1.token_value, session2)
        assert result.is_valid is False
        
        # Token2 should not validate for session1
        result = csrf_service.validate_token(token2.token_value, session1)
        assert result.is_valid is False


class TestCSRFMiddleware:
    """Test suite for CSRF Middleware"""

    @pytest.fixture
    def csrf_middleware(self, csrf_config):
        """Create CSRF middleware"""
        csrf_service = CSRFProtectionService(csrf_config)
        return CSRFMiddleware(csrf_service)

    @pytest.fixture
    def mock_call_next(self):
        """Mock next middleware call"""
        async def call_next(request):
            response = Mock(spec=Response)
            response.status_code = 200
            return response
        return call_next

    @pytest.mark.asyncio
    async def test_middleware_exempt_path(self, csrf_middleware, mock_request, mock_call_next):
        """Test middleware with exempt path"""
        mock_request.url.path = "/api/auth/login"
        mock_request.method = "POST"
        
        response = await csrf_middleware.dispatch(mock_request, mock_call_next)
        
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_middleware_get_request(self, csrf_middleware, mock_request, mock_call_next):
        """Test middleware with GET request (should be exempt)"""
        mock_request.method = "GET"
        mock_request.url.path = "/api/data"
        
        response = await csrf_middleware.dispatch(mock_request, mock_call_next)
        
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_middleware_missing_token(self, csrf_middleware, mock_request, mock_call_next):
        """Test middleware with missing CSRF token"""
        mock_request.method = "POST"
        mock_request.url.path = "/api/protected"
        mock_request.headers = {}
        mock_request.cookies = {}
        
        with pytest.raises(HTTPException) as exc_info:
            await csrf_middleware.dispatch(mock_request, mock_call_next)
        
        assert exc_info.value.status_code == 403
        assert "CSRF token missing" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_middleware_invalid_token(self, csrf_middleware, mock_request, mock_call_next):
        """Test middleware with invalid CSRF token"""
        mock_request.method = "POST"
        mock_request.url.path = "/api/protected"
        mock_request.headers = {"X-CSRF-Token": "invalid-token"}
        mock_request.cookies = {}
        
        # Mock session extraction
        with patch.object(csrf_middleware, '_extract_session_id', return_value="test-session"):
            with pytest.raises(HTTPException) as exc_info:
                await csrf_middleware.dispatch(mock_request, mock_call_next)
        
        assert exc_info.value.status_code == 403
        assert "CSRF token invalid" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_middleware_valid_token(self, csrf_middleware, mock_request, mock_call_next):
        """Test middleware with valid CSRF token"""
        session_id = "test-session-123"
        token = csrf_middleware.csrf_service.generate_token(session_id)
        
        mock_request.method = "POST"
        mock_request.url.path = "/api/protected"
        mock_request.headers = {"X-CSRF-Token": token.token_value}
        mock_request.cookies = {}
        
        # Mock session extraction
        with patch.object(csrf_middleware, '_extract_session_id', return_value=session_id):
            response = await csrf_middleware.dispatch(mock_request, mock_call_next)
        
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_middleware_double_submit_validation(self, csrf_middleware, mock_request, mock_call_next):
        """Test double-submit cookie validation"""
        session_id = "test-session-123"
        token = csrf_middleware.csrf_service.generate_token(session_id)
        
        mock_request.method = "POST"
        mock_request.url.path = "/api/protected"
        mock_request.headers = {"X-CSRF-Token": token.token_value}
        mock_request.cookies = {"csrf_token": token.token_value}
        
        # Mock session extraction
        with patch.object(csrf_middleware, '_extract_session_id', return_value=session_id):
            response = await csrf_middleware.dispatch(mock_request, mock_call_next)
        
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_middleware_token_mismatch(self, csrf_middleware, mock_request, mock_call_next):
        """Test token mismatch between header and cookie"""
        session_id = "test-session-123"
        token1 = csrf_middleware.csrf_service.generate_token(session_id)
        token2 = csrf_middleware.csrf_service.generate_token(session_id)
        
        mock_request.method = "POST"
        mock_request.url.path = "/api/protected"
        mock_request.headers = {"X-CSRF-Token": token1.token_value}
        mock_request.cookies = {"csrf_token": token2.token_value}
        
        # Mock session extraction
        with patch.object(csrf_middleware, '_extract_session_id', return_value=session_id):
            with pytest.raises(HTTPException) as exc_info:
                await csrf_middleware.dispatch(mock_request, mock_call_next)
        
        assert exc_info.value.status_code == 403


class TestCSRFToken:
    """Test suite for CSRF Token model"""

    def test_csrf_token_creation(self):
        """Test CSRF token creation"""
        session_id = "test-session"
        token_value = "test-token-value"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        token = CSRFToken(
            session_id=session_id,
            token_value=token_value,
            expires_at=expires_at
        )
        
        assert token.session_id == session_id
        assert token.token_value == token_value
        assert token.expires_at == expires_at
        assert token.is_valid() is True

    def test_csrf_token_expiry(self):
        """Test CSRF token expiry check"""
        token = CSRFToken(
            session_id="test-session",
            token_value="test-token",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)  # Expired
        )
        
        assert token.is_valid() is False

    def test_csrf_token_hash_generation(self):
        """Test CSRF token hash generation"""
        token = CSRFToken(
            session_id="test-session",
            token_value="test-token-value",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        assert len(token.token_hash) > 0
        assert token.token_hash != token.token_value

    def test_csrf_token_serialization(self):
        """Test CSRF token serialization"""
        token = CSRFToken(
            session_id="test-session",
            token_value="test-token-value",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        serialized = token.to_dict()
        assert "session_id" in serialized
        assert "token_value" in serialized
        assert "expires_at" in serialized
        assert "token_hash" in serialized


class TestCSRFIntegration:
    """Integration tests for CSRF protection system"""

    @pytest.mark.asyncio
    async def test_full_csrf_flow(self, csrf_service, mock_request, mock_response):
        """Test complete CSRF protection flow"""
        session_id = "test-session-123"
        
        # 1. Generate CSRF token
        token = csrf_service.generate_token(session_id)
        assert token.is_valid() is True
        
        # 2. Set CSRF cookie
        csrf_service.set_csrf_cookie(mock_response, token)
        mock_response.set_cookie.assert_called_once()
        
        # 3. Simulate request with token
        mock_request.headers = {"X-CSRF-Token": token.token_value}
        mock_request.cookies = {"csrf_token": token.token_value}
        
        # 4. Extract and validate token
        extracted_token = csrf_service.extract_token_from_request(mock_request)
        assert extracted_token == token.token_value
        
        validation_result = csrf_service.validate_token(extracted_token, session_id)
        assert validation_result.is_valid is True

    @pytest.mark.asyncio
    async def test_csrf_attack_prevention(self, csrf_service):
        """Test CSRF attack prevention scenarios"""
        legitimate_session = "legitimate-session"
        attacker_session = "attacker-session"
        
        # Legitimate user gets token
        legitimate_token = csrf_service.generate_token(legitimate_session)
        
        # Attacker tries to use legitimate token with their session
        attack_result = csrf_service.validate_token(
            legitimate_token.token_value, 
            attacker_session
        )
        
        assert attack_result.is_valid is False
        assert attack_result.error == CSRFErrorType.INVALID_TOKEN

    @pytest.mark.asyncio
    async def test_token_rotation(self, csrf_service):
        """Test token rotation for enhanced security"""
        session_id = "test-session"
        
        # Generate initial token
        token1 = csrf_service.generate_token(session_id)
        
        # Generate new token (rotation)
        token2 = csrf_service.generate_token(session_id)
        
        # Both tokens should be valid for the same session
        result1 = csrf_service.validate_token(token1.token_value, session_id)
        result2 = csrf_service.validate_token(token2.token_value, session_id)
        
        assert result1.is_valid is True
        assert result2.is_valid is True
        assert token1.token_value != token2.token_value

    @pytest.mark.asyncio
    async def test_concurrent_token_validation(self, csrf_service):
        """Test concurrent token validation"""
        session_id = "test-session"
        token = csrf_service.generate_token(session_id)
        
        # Create multiple concurrent validation tasks
        tasks = [
            csrf_service.validate_token(token.token_value, session_id)
            for _ in range(10)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # All validations should succeed
        assert all(result.is_valid for result in results)

    def test_configuration_validation(self):
        """Test CSRF configuration validation"""
        # Valid configuration
        valid_config = CSRFConfig(
            secret_key="valid-secret-key-32-characters-long",
            token_lifetime=3600,
            cookie_name="csrf_token",
            header_name="X-CSRF-Token"
        )
        
        service = CSRFProtectionService(valid_config)
        assert service.config.secret_key == valid_config.secret_key
        
        # Invalid configuration (short secret key)
        with pytest.raises(ValueError, match="Secret key must be at least 32 characters"):
            invalid_config = CSRFConfig(
                secret_key="short-key",
                token_lifetime=3600,
                cookie_name="csrf_token",
                header_name="X-CSRF-Token"
            )
            CSRFProtectionService(invalid_config)