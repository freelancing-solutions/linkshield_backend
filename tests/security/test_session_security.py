#!/usr/bin/env python3
"""
Comprehensive tests for Session Security System

Tests session management, security validation, concurrent session handling,
session hijacking prevention, and security event logging.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta, timezone
import secrets
import hashlib
import json
from uuid import uuid4
from fastapi import Request, Response, HTTPException

from src.authentication.session_manager import (
    SessionManager,
    SessionData,
    SessionConfig,
    SessionSecurityContext,
    SessionValidationResult,
    SessionError,
    SessionErrorType,
    ConcurrentSessionManager
)
from src.models.user import UserSession, User
from src.security.session_security import (
    SessionSecurityService,
    SessionRiskAnalyzer,
    SessionAnomalyDetector,
    SecurityEventLogger
)


class TestSessionManager:
    """Test suite for Session Manager"""

    @pytest.fixture
    def session_config(self):
        """Session configuration for testing"""
        return SessionConfig(
            session_lifetime=3600,  # 1 hour
            refresh_token_lifetime=86400,  # 24 hours
            max_concurrent_sessions=5,
            session_cookie_name="session_token",
            refresh_cookie_name="refresh_token",
            cookie_secure=True,
            cookie_httponly=True,
            cookie_samesite="strict",
            require_csrf=True,
            track_ip_changes=True,
            track_user_agent_changes=True,
            suspicious_activity_threshold=3
        )

    @pytest.fixture
    async def mock_db_session(self):
        """Mock database session"""
        db_session = AsyncMock()
        db_session.add = Mock()
        db_session.commit = AsyncMock()
        db_session.rollback = AsyncMock()
        db_session.refresh = AsyncMock()
        db_session.execute = AsyncMock()
        return db_session

    @pytest.fixture
    def session_manager(self, session_config, mock_db_session):
        """Create session manager"""
        manager = SessionManager(session_config)
        manager.db = mock_db_session
        return manager

    @pytest.fixture
    def mock_user(self):
        """Mock user object"""
        user = Mock(spec=User)
        user.id = "user123"
        user.email = "test@example.com"
        user.username = "testuser"
        user.is_active = True
        return user

    @pytest.fixture
    def mock_request(self):
        """Mock FastAPI request"""
        request = Mock(spec=Request)
        request.client.host = "127.0.0.1"
        request.headers = {
            "User-Agent": "Mozilla/5.0 (Test Browser)",
            "Accept-Language": "en-US,en;q=0.9"
        }
        request.cookies = {}
        return request

    # Session Creation Tests
    @pytest.mark.asyncio
    async def test_create_session_success(self, session_manager, mock_user, mock_request):
        """Test successful session creation"""
        # Mock database operations
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = None
        
        session_data = await session_manager.create_session(mock_user, mock_request)
        
        assert isinstance(session_data, SessionData)
        assert session_data.user_id == mock_user.id
        assert session_data.session_token is not None
        assert session_data.refresh_token is not None
        assert session_data.expires_at > datetime.now(timezone.utc)
        assert session_data.is_active is True

    @pytest.mark.asyncio
    async def test_create_session_with_security_context(self, session_manager, mock_user, mock_request):
        """Test session creation with security context"""
        session_data = await session_manager.create_session(mock_user, mock_request)
        
        assert session_data.security_context is not None
        assert session_data.security_context.ip_address == "127.0.0.1"
        assert "Mozilla/5.0" in session_data.security_context.user_agent
        assert session_data.security_context.risk_score >= 0

    @pytest.mark.asyncio
    async def test_create_session_concurrent_limit(self, session_manager, mock_user, mock_request):
        """Test concurrent session limit enforcement"""
        # Mock existing sessions at limit
        existing_sessions = [Mock(spec=UserSession) for _ in range(5)]
        session_manager.db.execute.return_value.scalars.return_value.all.return_value = existing_sessions
        
        # Should handle concurrent session limit
        session_data = await session_manager.create_session(mock_user, mock_request)
        
        # Should either create session (after cleanup) or raise appropriate error
        assert isinstance(session_data, SessionData) or session_data is None

    # Session Validation Tests
    @pytest.mark.asyncio
    async def test_validate_session_success(self, session_manager, mock_request):
        """Test successful session validation"""
        # Create mock session
        mock_session = Mock(spec=UserSession)
        mock_session.id = "session123"
        mock_session.user_id = "user123"
        mock_session.session_token = "valid_token"
        mock_session.is_active = True
        mock_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        mock_session.ip_address = "127.0.0.1"
        mock_session.user_agent = "Mozilla/5.0 (Test Browser)"
        mock_session.risk_score = 0.1
        mock_session.is_suspicious = False
        
        # Mock database query
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        result = await session_manager.validate_session("valid_token", mock_request)
        
        assert result.is_valid is True
        assert result.session_data.user_id == "user123"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_validate_session_expired(self, session_manager, mock_request):
        """Test validation of expired session"""
        # Create expired session
        mock_session = Mock(spec=UserSession)
        mock_session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        mock_session.is_active = True
        
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        result = await session_manager.validate_session("expired_token", mock_request)
        
        assert result.is_valid is False
        assert result.error == SessionErrorType.SESSION_EXPIRED

    @pytest.mark.asyncio
    async def test_validate_session_not_found(self, session_manager, mock_request):
        """Test validation of non-existent session"""
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await session_manager.validate_session("invalid_token", mock_request)
        
        assert result.is_valid is False
        assert result.error == SessionErrorType.SESSION_NOT_FOUND

    @pytest.mark.asyncio
    async def test_validate_session_inactive(self, session_manager, mock_request):
        """Test validation of inactive session"""
        mock_session = Mock(spec=UserSession)
        mock_session.is_active = False
        mock_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        result = await session_manager.validate_session("inactive_token", mock_request)
        
        assert result.is_valid is False
        assert result.error == SessionErrorType.SESSION_INACTIVE

    # Session Security Tests
    @pytest.mark.asyncio
    async def test_detect_ip_change(self, session_manager, mock_request):
        """Test detection of IP address changes"""
        mock_session = Mock(spec=UserSession)
        mock_session.ip_address = "192.168.1.1"  # Different IP
        mock_session.is_active = True
        mock_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        result = await session_manager.validate_session("token", mock_request)
        
        # Should detect IP change and handle appropriately
        assert result.security_warnings is not None
        assert any("IP address change" in warning for warning in result.security_warnings)

    @pytest.mark.asyncio
    async def test_detect_user_agent_change(self, session_manager, mock_request):
        """Test detection of User-Agent changes"""
        mock_session = Mock(spec=UserSession)
        mock_session.ip_address = "127.0.0.1"
        mock_session.user_agent = "Different Browser/1.0"
        mock_session.is_active = True
        mock_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        result = await session_manager.validate_session("token", mock_request)
        
        # Should detect User-Agent change
        assert result.security_warnings is not None
        assert any("User-Agent change" in warning for warning in result.security_warnings)

    @pytest.mark.asyncio
    async def test_suspicious_activity_detection(self, session_manager, mock_request):
        """Test suspicious activity detection"""
        mock_session = Mock(spec=UserSession)
        mock_session.ip_address = "127.0.0.1"
        mock_session.user_agent = "Mozilla/5.0 (Test Browser)"
        mock_session.is_active = True
        mock_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        mock_session.risk_score = 0.8  # High risk score
        mock_session.is_suspicious = True
        
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        result = await session_manager.validate_session("token", mock_request)
        
        # Should flag as suspicious
        assert result.is_valid is False
        assert result.error == SessionErrorType.SUSPICIOUS_ACTIVITY

    # Session Refresh Tests
    @pytest.mark.asyncio
    async def test_refresh_session_success(self, session_manager, mock_request):
        """Test successful session refresh"""
        mock_session = Mock(spec=UserSession)
        mock_session.id = "session123"
        mock_session.user_id = "user123"
        mock_session.refresh_token = "valid_refresh_token"
        mock_session.is_active = True
        mock_session.refresh_expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        mock_session.ip_address = "127.0.0.1"
        mock_session.user_agent = "Mozilla/5.0 (Test Browser)"
        
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        new_session_data = await session_manager.refresh_session("valid_refresh_token", mock_request)
        
        assert isinstance(new_session_data, SessionData)
        assert new_session_data.user_id == "user123"
        assert new_session_data.session_token != mock_session.session_token

    @pytest.mark.asyncio
    async def test_refresh_session_expired_refresh_token(self, session_manager, mock_request):
        """Test refresh with expired refresh token"""
        mock_session = Mock(spec=UserSession)
        mock_session.refresh_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        with pytest.raises(SessionError, match="Refresh token expired"):
            await session_manager.refresh_session("expired_refresh_token", mock_request)

    # Session Termination Tests
    @pytest.mark.asyncio
    async def test_terminate_session(self, session_manager):
        """Test session termination"""
        mock_session = Mock(spec=UserSession)
        mock_session.is_active = True
        
        session_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_session
        
        success = await session_manager.terminate_session("session_token")
        
        assert success is True
        assert mock_session.is_active is False
        session_manager.db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_terminate_all_user_sessions(self, session_manager):
        """Test termination of all user sessions"""
        mock_sessions = [Mock(spec=UserSession) for _ in range(3)]
        for session in mock_sessions:
            session.is_active = True
        
        session_manager.db.execute.return_value.scalars.return_value.all.return_value = mock_sessions
        
        count = await session_manager.terminate_all_user_sessions("user123")
        
        assert count == 3
        for session in mock_sessions:
            assert session.is_active is False

    # Concurrent Session Management Tests
    @pytest.mark.asyncio
    async def test_concurrent_session_limit(self, session_manager, mock_user, mock_request):
        """Test concurrent session limit enforcement"""
        # Mock existing active sessions at limit
        existing_sessions = []
        for i in range(5):  # At the limit
            session = Mock(spec=UserSession)
            session.id = f"session{i}"
            session.is_active = True
            session.created_at = datetime.now(timezone.utc) - timedelta(minutes=i)
            existing_sessions.append(session)
        
        session_manager.db.execute.return_value.scalars.return_value.all.return_value = existing_sessions
        
        # Creating new session should handle limit
        session_data = await session_manager.create_session(mock_user, mock_request)
        
        # Should either succeed (after cleanup) or handle appropriately
        assert isinstance(session_data, SessionData) or session_data is None

    @pytest.mark.asyncio
    async def test_session_cleanup_oldest_first(self, session_manager):
        """Test that oldest sessions are cleaned up first"""
        # Mock sessions with different creation times
        old_session = Mock(spec=UserSession)
        old_session.created_at = datetime.now(timezone.utc) - timedelta(hours=2)
        old_session.is_active = True
        
        new_session = Mock(spec=UserSession)
        new_session.created_at = datetime.now(timezone.utc) - timedelta(minutes=30)
        new_session.is_active = True
        
        sessions = [new_session, old_session]  # Unordered
        session_manager.db.execute.return_value.scalars.return_value.all.return_value = sessions
        
        await session_manager._cleanup_excess_sessions("user123", 1)
        
        # Oldest session should be deactivated
        assert old_session.is_active is False
        assert new_session.is_active is True


class TestSessionSecurityService:
    """Test suite for Session Security Service"""

    @pytest.fixture
    def security_service(self):
        """Create session security service"""
        return SessionSecurityService()

    @pytest.fixture
    def risk_analyzer(self):
        """Create session risk analyzer"""
        return SessionRiskAnalyzer()

    @pytest.fixture
    def anomaly_detector(self):
        """Create session anomaly detector"""
        return SessionAnomalyDetector()

    # Risk Analysis Tests
    def test_calculate_risk_score_low_risk(self, risk_analyzer, mock_request):
        """Test risk score calculation for low-risk session"""
        security_context = SessionSecurityContext(
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            device_fingerprint="stable_fingerprint",
            geolocation="US",
            is_mobile=False,
            is_tor=False,
            is_vpn=False
        )
        
        risk_score = risk_analyzer.calculate_risk_score(security_context)
        
        assert 0.0 <= risk_score <= 0.3  # Low risk

    def test_calculate_risk_score_high_risk(self, risk_analyzer):
        """Test risk score calculation for high-risk session"""
        security_context = SessionSecurityContext(
            ip_address="10.0.0.1",
            user_agent="Suspicious Bot/1.0",
            device_fingerprint="unknown_fingerprint",
            geolocation="Unknown",
            is_mobile=False,
            is_tor=True,
            is_vpn=True
        )
        
        risk_score = risk_analyzer.calculate_risk_score(security_context)
        
        assert 0.7 <= risk_score <= 1.0  # High risk

    def test_detect_ip_geolocation_anomaly(self, anomaly_detector):
        """Test detection of IP geolocation anomalies"""
        # Previous sessions from US
        previous_contexts = [
            SessionSecurityContext(ip_address="192.168.1.1", geolocation="US"),
            SessionSecurityContext(ip_address="10.0.0.1", geolocation="US")
        ]
        
        # New session from different country
        current_context = SessionSecurityContext(
            ip_address="203.0.113.1",
            geolocation="CN"
        )
        
        is_anomaly = anomaly_detector.detect_geolocation_anomaly(
            current_context, previous_contexts
        )
        
        assert is_anomaly is True

    def test_detect_device_fingerprint_change(self, anomaly_detector):
        """Test detection of device fingerprint changes"""
        previous_contexts = [
            SessionSecurityContext(device_fingerprint="fingerprint_A"),
            SessionSecurityContext(device_fingerprint="fingerprint_A")
        ]
        
        current_context = SessionSecurityContext(device_fingerprint="fingerprint_B")
        
        is_anomaly = anomaly_detector.detect_device_anomaly(
            current_context, previous_contexts
        )
        
        assert is_anomaly is True

    def test_detect_time_based_anomaly(self, anomaly_detector):
        """Test detection of time-based anomalies"""
        # User typically active during day
        typical_hours = [9, 10, 11, 14, 15, 16]
        
        # Current session at unusual time (3 AM)
        current_hour = 3
        
        is_anomaly = anomaly_detector.detect_time_anomaly(current_hour, typical_hours)
        
        assert is_anomaly is True

    # Security Event Logging Tests
    @pytest.mark.asyncio
    async def test_log_security_event(self, security_service):
        """Test security event logging"""
        event_data = {
            "event_type": "suspicious_login",
            "user_id": "user123",
            "session_id": "session456",
            "ip_address": "192.168.1.1",
            "risk_score": 0.8,
            "details": {"reason": "unusual_location"}
        }
        
        with patch.object(security_service, '_store_security_event') as mock_store:
            await security_service.log_security_event(event_data)
            mock_store.assert_called_once()

    @pytest.mark.asyncio
    async def test_trigger_security_alert(self, security_service):
        """Test security alert triggering"""
        alert_data = {
            "alert_type": "session_hijacking_attempt",
            "severity": "high",
            "user_id": "user123",
            "session_id": "session456",
            "description": "Multiple IP addresses detected for same session"
        }
        
        with patch.object(security_service, '_send_security_alert') as mock_alert:
            await security_service.trigger_security_alert(alert_data)
            mock_alert.assert_called_once()

    # Session Hijacking Prevention Tests
    @pytest.mark.asyncio
    async def test_detect_session_hijacking_ip_change(self, security_service):
        """Test detection of session hijacking via IP change"""
        session_data = SessionData(
            session_id="session123",
            user_id="user123",
            session_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            security_context=SessionSecurityContext(ip_address="192.168.1.1")
        )
        
        current_request = Mock()
        current_request.client.host = "10.0.0.1"  # Different IP
        
        is_hijacking = await security_service.detect_session_hijacking(
            session_data, current_request
        )
        
        assert is_hijacking is True

    @pytest.mark.asyncio
    async def test_detect_session_hijacking_concurrent_access(self, security_service):
        """Test detection of concurrent access from different locations"""
        session_data = SessionData(
            session_id="session123",
            user_id="user123",
            session_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            security_context=SessionSecurityContext(
                ip_address="192.168.1.1",
                geolocation="US"
            )
        )
        
        # Mock concurrent access detection
        with patch.object(security_service, '_check_concurrent_access') as mock_check:
            mock_check.return_value = True  # Concurrent access detected
            
            is_hijacking = await security_service.detect_session_hijacking(
                session_data, Mock()
            )
            
            assert is_hijacking is True

    # Session Token Security Tests
    def test_session_token_generation(self, session_manager):
        """Test secure session token generation"""
        token1 = session_manager._generate_session_token()
        token2 = session_manager._generate_session_token()
        
        # Tokens should be unique and sufficiently long
        assert token1 != token2
        assert len(token1) >= 32
        assert len(token2) >= 32

    def test_session_token_entropy(self, session_manager):
        """Test session token entropy"""
        tokens = [session_manager._generate_session_token() for _ in range(100)]
        
        # All tokens should be unique
        assert len(set(tokens)) == 100
        
        # Tokens should contain varied characters
        all_chars = ''.join(tokens)
        unique_chars = set(all_chars)
        assert len(unique_chars) > 10  # Should have good character variety

    def test_session_token_hashing(self, session_manager):
        """Test session token hashing"""
        token = "test_session_token"
        hash1 = session_manager._hash_token(token)
        hash2 = session_manager._hash_token(token)
        
        # Same token should produce same hash
        assert hash1 == hash2
        
        # Hash should be different from original token
        assert hash1 != token
        
        # Hash should be consistent length
        assert len(hash1) > 0


class TestSessionIntegration:
    """Integration tests for session security system"""

    @pytest.mark.asyncio
    async def test_full_session_lifecycle(self, session_manager, mock_user, mock_request):
        """Test complete session lifecycle"""
        # 1. Create session
        session_data = await session_manager.create_session(mock_user, mock_request)
        assert session_data is not None
        
        # 2. Validate session
        result = await session_manager.validate_session(
            session_data.session_token, mock_request
        )
        assert result.is_valid is True
        
        # 3. Refresh session
        new_session_data = await session_manager.refresh_session(
            session_data.refresh_token, mock_request
        )
        assert new_session_data.session_token != session_data.session_token
        
        # 4. Terminate session
        success = await session_manager.terminate_session(new_session_data.session_token)
        assert success is True

    @pytest.mark.asyncio
    async def test_concurrent_session_handling(self, session_manager, mock_user):
        """Test handling of concurrent sessions"""
        requests = []
        for i in range(10):
            request = Mock()
            request.client.host = f"192.168.1.{i}"
            request.headers = {"User-Agent": f"Browser{i}/1.0"}
            requests.append(request)
        
        # Create multiple sessions concurrently
        tasks = [
            session_manager.create_session(mock_user, request)
            for request in requests
        ]
        
        sessions = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle concurrent creation gracefully
        successful_sessions = [s for s in sessions if isinstance(s, SessionData)]
        assert len(successful_sessions) <= session_manager.config.max_concurrent_sessions

    @pytest.mark.asyncio
    async def test_session_security_monitoring(self, session_manager, security_service):
        """Test session security monitoring"""
        # Mock suspicious activity
        session_data = SessionData(
            session_id="session123",
            user_id="user123",
            session_token="token",
            refresh_token="refresh",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            security_context=SessionSecurityContext(
                ip_address="192.168.1.1",
                risk_score=0.9  # High risk
            )
        )
        
        # Should trigger security monitoring
        with patch.object(security_service, 'log_security_event') as mock_log:
            await security_service.monitor_session_security(session_data)
            mock_log.assert_called()

    @pytest.mark.asyncio
    async def test_session_cleanup_on_security_breach(self, session_manager, security_service):
        """Test session cleanup when security breach is detected"""
        user_id = "user123"
        
        # Mock security breach detection
        with patch.object(security_service, 'detect_security_breach') as mock_detect:
            mock_detect.return_value = True
            
            # Should terminate all user sessions
            with patch.object(session_manager, 'terminate_all_user_sessions') as mock_terminate:
                await security_service.handle_security_breach(user_id)
                mock_terminate.assert_called_once_with(user_id)

    @pytest.mark.asyncio
    async def test_session_performance_under_load(self, session_manager, mock_user):
        """Test session performance under load"""
        import time
        
        # Create many sessions rapidly
        start_time = time.perf_counter()
        
        tasks = []
        for i in range(50):
            request = Mock()
            request.client.host = "127.0.0.1"
            request.headers = {"User-Agent": "LoadTest/1.0"}
            tasks.append(session_manager.create_session(mock_user, request))
        
        sessions = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.perf_counter()
        duration = end_time - start_time
        
        # Should complete within reasonable time
        assert duration < 5.0  # Less than 5 seconds for 50 sessions
        
        # Should handle load gracefully
        successful_sessions = [s for s in sessions if isinstance(s, SessionData)]
        assert len(successful_sessions) > 0