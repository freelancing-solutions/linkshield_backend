#!/usr/bin/env python3
"""
Comprehensive tests for API Key Security System

Tests API key rotation, versioning, validation, security monitoring,
and emergency revocation functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta, timezone
import secrets
import hashlib
import json
from uuid import uuid4
from fastapi import Request, HTTPException

from linkshield.authentication.api_key_manager import (
    APIKeyManager,
    APIKeyData,
    APIKeyConfig,
    APIKeyValidationResult,
    APIKeyError,
    APIKeyErrorType,
    APIKeyRotationService,
    APIKeyVersionManager
)
from linkshield.models.user import APIKey, User
from linkshield.security.api_key_security import (
    APIKeySecurityService,
    APIKeyValidator,
    APIKeyMonitor,
    EmergencyRevocationService
)


class TestAPIKeyManager:
    """Test suite for API Key Manager"""

    @pytest.fixture
    def api_key_config(self):
        """API key configuration for testing"""
        return APIKeyConfig(
            key_length=32,
            prefix_length=8,
            rotation_interval=86400,  # 24 hours
            max_keys_per_user=10,
            require_rotation=True,
            enable_versioning=True,
            security_level="high",
            allowed_scopes=["read", "write", "admin"],
            rate_limit_per_key=1000,
            enable_ip_restrictions=True,
            log_all_usage=True
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
    def api_key_manager(self, api_key_config, mock_db_session):
        """Create API key manager"""
        manager = APIKeyManager(api_key_config)
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
            "User-Agent": "API Client/1.0",
            "Authorization": "Bearer test_api_key"
        }
        return request

    # API Key Creation Tests
    @pytest.mark.asyncio
    async def test_create_api_key_success(self, api_key_manager, mock_user):
        """Test successful API key creation"""
        # Mock database operations
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = None
        
        api_key_data = await api_key_manager.create_api_key(
            user=mock_user,
            name="Test API Key",
            scopes=["read", "write"],
            expires_in_days=30
        )
        
        assert isinstance(api_key_data, APIKeyData)
        assert api_key_data.user_id == mock_user.id
        assert api_key_data.name == "Test API Key"
        assert api_key_data.key_hash is not None
        assert api_key_data.key_prefix is not None
        assert api_key_data.scopes == ["read", "write"]
        assert api_key_data.is_active is True
        assert api_key_data.expires_at > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_create_api_key_with_ip_restrictions(self, api_key_manager, mock_user):
        """Test API key creation with IP restrictions"""
        allowed_ips = ["192.168.1.0/24", "10.0.0.1"]
        
        api_key_data = await api_key_manager.create_api_key(
            user=mock_user,
            name="Restricted API Key",
            scopes=["read"],
            allowed_ips=allowed_ips
        )
        
        assert api_key_data.allowed_ips == allowed_ips

    @pytest.mark.asyncio
    async def test_create_api_key_limit_exceeded(self, api_key_manager, mock_user):
        """Test API key creation when limit is exceeded"""
        # Mock existing keys at limit
        existing_keys = [Mock(spec=APIKey) for _ in range(10)]
        api_key_manager.db.execute.return_value.scalars.return_value.all.return_value = existing_keys
        
        with pytest.raises(APIKeyError, match="Maximum number of API keys reached"):
            await api_key_manager.create_api_key(
                user=mock_user,
                name="Excess Key",
                scopes=["read"]
            )

    @pytest.mark.asyncio
    async def test_create_api_key_invalid_scopes(self, api_key_manager, mock_user):
        """Test API key creation with invalid scopes"""
        with pytest.raises(APIKeyError, match="Invalid scope"):
            await api_key_manager.create_api_key(
                user=mock_user,
                name="Invalid Scope Key",
                scopes=["invalid_scope"]
            )

    # API Key Validation Tests
    @pytest.mark.asyncio
    async def test_validate_api_key_success(self, api_key_manager, mock_request):
        """Test successful API key validation"""
        # Create mock API key
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.id = "key123"
        mock_api_key.user_id = "user123"
        mock_api_key.key_hash = "hashed_key"
        mock_api_key.key_prefix = "lsk_test"
        mock_api_key.is_active = True
        mock_api_key.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        mock_api_key.scopes = ["read", "write"]
        mock_api_key.allowed_ips = None
        mock_api_key.security_level = "high"
        mock_api_key.last_used_at = None
        
        # Mock database query
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        
        # Mock key hash verification
        with patch.object(api_key_manager, '_verify_key_hash', return_value=True):
            result = await api_key_manager.validate_api_key("lsk_test_actual_key", mock_request)
        
        assert result.is_valid is True
        assert result.api_key_data.user_id == "user123"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_validate_api_key_expired(self, api_key_manager, mock_request):
        """Test validation of expired API key"""
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        mock_api_key.is_active = True
        
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        
        with patch.object(api_key_manager, '_verify_key_hash', return_value=True):
            result = await api_key_manager.validate_api_key("expired_key", mock_request)
        
        assert result.is_valid is False
        assert result.error == APIKeyErrorType.KEY_EXPIRED

    @pytest.mark.asyncio
    async def test_validate_api_key_not_found(self, api_key_manager, mock_request):
        """Test validation of non-existent API key"""
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await api_key_manager.validate_api_key("invalid_key", mock_request)
        
        assert result.is_valid is False
        assert result.error == APIKeyErrorType.KEY_NOT_FOUND

    @pytest.mark.asyncio
    async def test_validate_api_key_inactive(self, api_key_manager, mock_request):
        """Test validation of inactive API key"""
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.is_active = False
        mock_api_key.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        
        with patch.object(api_key_manager, '_verify_key_hash', return_value=True):
            result = await api_key_manager.validate_api_key("inactive_key", mock_request)
        
        assert result.is_valid is False
        assert result.error == APIKeyErrorType.KEY_INACTIVE

    @pytest.mark.asyncio
    async def test_validate_api_key_ip_restriction(self, api_key_manager, mock_request):
        """Test API key validation with IP restrictions"""
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.is_active = True
        mock_api_key.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        mock_api_key.allowed_ips = ["192.168.1.0/24"]  # Different from request IP
        
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        
        with patch.object(api_key_manager, '_verify_key_hash', return_value=True):
            result = await api_key_manager.validate_api_key("restricted_key", mock_request)
        
        assert result.is_valid is False
        assert result.error == APIKeyErrorType.IP_NOT_ALLOWED

    # API Key Rotation Tests
    @pytest.mark.asyncio
    async def test_rotate_api_key_success(self, api_key_manager):
        """Test successful API key rotation"""
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.id = "key123"
        mock_api_key.user_id = "user123"
        mock_api_key.name = "Test Key"
        mock_api_key.scopes = ["read", "write"]
        mock_api_key.is_active = True
        mock_api_key.rotation_count = 0
        
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        
        new_key_data = await api_key_manager.rotate_api_key("key123")
        
        assert isinstance(new_key_data, APIKeyData)
        assert new_key_data.user_id == "user123"
        assert new_key_data.name == "Test Key"
        assert new_key_data.scopes == ["read", "write"]
        assert mock_api_key.rotation_count == 1

    @pytest.mark.asyncio
    async def test_rotate_api_key_not_found(self, api_key_manager):
        """Test rotation of non-existent API key"""
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = None
        
        with pytest.raises(APIKeyError, match="API key not found"):
            await api_key_manager.rotate_api_key("nonexistent_key")

    @pytest.mark.asyncio
    async def test_automatic_rotation_due(self, api_key_manager):
        """Test automatic rotation when due"""
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.next_rotation_at = datetime.now(timezone.utc) - timedelta(hours=1)
        mock_api_key.is_active = True
        
        api_key_manager.db.execute.return_value.scalars.return_value.all.return_value = [mock_api_key]
        
        with patch.object(api_key_manager, 'rotate_api_key') as mock_rotate:
            await api_key_manager.check_and_rotate_keys()
            mock_rotate.assert_called_once()

    # API Key Versioning Tests
    @pytest.mark.asyncio
    async def test_create_api_key_version(self, api_key_manager):
        """Test API key version creation"""
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.id = "key123"
        mock_api_key.version_id = None
        
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        
        version_data = await api_key_manager.create_key_version(
            api_key_id="key123",
            version_type="rotation",
            compatibility_level="backward_compatible"
        )
        
        assert version_data is not None
        assert version_data["version_type"] == "rotation"
        assert version_data["compatibility_level"] == "backward_compatible"

    @pytest.mark.asyncio
    async def test_get_api_key_versions(self, api_key_manager):
        """Test retrieving API key versions"""
        mock_versions = [
            Mock(version_number=1, created_at=datetime.now(timezone.utc) - timedelta(days=2)),
            Mock(version_number=2, created_at=datetime.now(timezone.utc) - timedelta(days=1)),
            Mock(version_number=3, created_at=datetime.now(timezone.utc))
        ]
        
        api_key_manager.db.execute.return_value.scalars.return_value.all.return_value = mock_versions
        
        versions = await api_key_manager.get_key_versions("key123")
        
        assert len(versions) == 3
        assert versions[0]["version_number"] == 3  # Most recent first

    # Emergency Revocation Tests
    @pytest.mark.asyncio
    async def test_emergency_revoke_api_key(self, api_key_manager):
        """Test emergency API key revocation"""
        mock_api_key = Mock(spec=APIKey)
        mock_api_key.id = "key123"
        mock_api_key.is_active = True
        
        api_key_manager.db.execute.return_value.scalar_one_or_none.return_value = mock_api_key
        
        success = await api_key_manager.emergency_revoke_key(
            api_key_id="key123",
            reason="security_breach",
            revoked_by="admin123"
        )
        
        assert success is True
        assert mock_api_key.is_active is False

    @pytest.mark.asyncio
    async def test_emergency_revoke_all_user_keys(self, api_key_manager):
        """Test emergency revocation of all user keys"""
        mock_keys = [Mock(spec=APIKey) for _ in range(3)]
        for key in mock_keys:
            key.is_active = True
        
        api_key_manager.db.execute.return_value.scalars.return_value.all.return_value = mock_keys
        
        count = await api_key_manager.emergency_revoke_all_user_keys(
            user_id="user123",
            reason="account_compromise",
            revoked_by="security_team"
        )
        
        assert count == 3
        for key in mock_keys:
            assert key.is_active is False

    # API Key Security Tests
    def test_api_key_generation_entropy(self, api_key_manager):
        """Test API key generation entropy"""
        keys = [api_key_manager._generate_api_key() for _ in range(100)]
        
        # All keys should be unique
        assert len(set(keys)) == 100
        
        # Keys should have proper length
        for key in keys:
            assert len(key) == api_key_manager.config.key_length + api_key_manager.config.prefix_length + 1  # +1 for separator

    def test_api_key_prefix_consistency(self, api_key_manager):
        """Test API key prefix consistency"""
        keys = [api_key_manager._generate_api_key() for _ in range(10)]
        
        # All keys should have same prefix
        prefixes = [key.split('_')[0] for key in keys]
        assert len(set(prefixes)) == 1

    def test_api_key_hashing(self, api_key_manager):
        """Test API key hashing"""
        key = "lsk_test_1234567890abcdef"
        hash1 = api_key_manager._hash_api_key(key)
        hash2 = api_key_manager._hash_api_key(key)
        
        # Same key should produce same hash
        assert hash1 == hash2
        
        # Hash should be different from original key
        assert hash1 != key
        
        # Hash should be consistent length
        assert len(hash1) > 0

    def test_api_key_verification(self, api_key_manager):
        """Test API key verification"""
        key = "lsk_test_1234567890abcdef"
        key_hash = api_key_manager._hash_api_key(key)
        
        # Correct key should verify
        assert api_key_manager._verify_key_hash(key, key_hash) is True
        
        # Incorrect key should not verify
        assert api_key_manager._verify_key_hash("wrong_key", key_hash) is False


class TestAPIKeySecurityService:
    """Test suite for API Key Security Service"""

    @pytest.fixture
    def security_service(self):
        """Create API key security service"""
        return APIKeySecurityService()

    @pytest.fixture
    def validator(self):
        """Create API key validator"""
        return APIKeyValidator()

    @pytest.fixture
    def monitor(self):
        """Create API key monitor"""
        return APIKeyMonitor()

    # Security Validation Tests
    def test_validate_key_strength(self, validator):
        """Test API key strength validation"""
        # Strong key
        strong_key = "lsk_prod_" + secrets.token_urlsafe(32)
        assert validator.validate_key_strength(strong_key) is True
        
        # Weak key
        weak_key = "lsk_test_123"
        assert validator.validate_key_strength(weak_key) is False

    def test_validate_key_format(self, validator):
        """Test API key format validation"""
        # Valid format
        valid_key = "lsk_prod_1234567890abcdef1234567890abcdef"
        assert validator.validate_key_format(valid_key) is True
        
        # Invalid format
        invalid_key = "invalid_key_format"
        assert validator.validate_key_format(invalid_key) is False

    def test_detect_key_pattern_anomalies(self, validator):
        """Test detection of key pattern anomalies"""
        # Normal keys
        normal_keys = [
            "lsk_prod_" + secrets.token_urlsafe(32) for _ in range(10)
        ]
        
        # Suspicious key (predictable pattern)
        suspicious_key = "lsk_prod_1111111111111111111111111111111111111111"
        
        is_anomaly = validator.detect_pattern_anomaly(suspicious_key, normal_keys)
        assert is_anomaly is True

    # Usage Monitoring Tests
    @pytest.mark.asyncio
    async def test_monitor_api_key_usage(self, monitor):
        """Test API key usage monitoring"""
        usage_data = {
            "api_key_id": "key123",
            "user_id": "user123",
            "endpoint": "/api/v1/data",
            "method": "GET",
            "ip_address": "192.168.1.1",
            "user_agent": "API Client/1.0",
            "timestamp": datetime.now(timezone.utc),
            "response_status": 200,
            "response_time": 0.15
        }
        
        with patch.object(monitor, '_store_usage_data') as mock_store:
            await monitor.log_api_key_usage(usage_data)
            mock_store.assert_called_once()

    @pytest.mark.asyncio
    async def test_detect_suspicious_usage_patterns(self, monitor):
        """Test detection of suspicious usage patterns"""
        # High frequency usage
        usage_events = [
            {
                "api_key_id": "key123",
                "timestamp": datetime.now(timezone.utc) - timedelta(seconds=i),
                "ip_address": "192.168.1.1"
            }
            for i in range(100)  # 100 requests in short time
        ]
        
        is_suspicious = await monitor.detect_suspicious_patterns(usage_events)
        assert is_suspicious is True

    @pytest.mark.asyncio
    async def test_detect_geographic_anomalies(self, monitor):
        """Test detection of geographic anomalies"""
        # Previous usage from US
        previous_usage = [
            {"ip_address": "192.168.1.1", "geolocation": "US"},
            {"ip_address": "10.0.0.1", "geolocation": "US"}
        ]
        
        # Current usage from different country
        current_usage = {"ip_address": "203.0.113.1", "geolocation": "CN"}
        
        is_anomaly = await monitor.detect_geographic_anomaly(
            current_usage, previous_usage
        )
        assert is_anomaly is True

    # Rate Limiting Tests
    @pytest.mark.asyncio
    async def test_api_key_rate_limiting(self, security_service):
        """Test API key rate limiting"""
        api_key_id = "key123"
        
        # Mock rate limit check
        with patch.object(security_service, '_check_rate_limit') as mock_check:
            mock_check.return_value = False  # Rate limit exceeded
            
            is_allowed = await security_service.check_rate_limit(api_key_id)
            assert is_allowed is False

    @pytest.mark.asyncio
    async def test_api_key_rate_limit_reset(self, security_service):
        """Test API key rate limit reset"""
        api_key_id = "key123"
        
        with patch.object(security_service, '_reset_rate_limit') as mock_reset:
            await security_service.reset_rate_limit(api_key_id)
            mock_reset.assert_called_once_with(api_key_id)

    # Security Event Logging Tests
    @pytest.mark.asyncio
    async def test_log_security_event(self, security_service):
        """Test security event logging"""
        event_data = {
            "event_type": "suspicious_api_usage",
            "api_key_id": "key123",
            "user_id": "user123",
            "ip_address": "192.168.1.1",
            "details": {"reason": "high_frequency_requests"}
        }
        
        with patch.object(security_service, '_store_security_event') as mock_store:
            await security_service.log_security_event(event_data)
            mock_store.assert_called_once()

    @pytest.mark.asyncio
    async def test_trigger_security_alert(self, security_service):
        """Test security alert triggering"""
        alert_data = {
            "alert_type": "api_key_compromise",
            "severity": "high",
            "api_key_id": "key123",
            "user_id": "user123",
            "description": "API key used from suspicious location"
        }
        
        with patch.object(security_service, '_send_security_alert') as mock_alert:
            await security_service.trigger_security_alert(alert_data)
            mock_alert.assert_called_once()


class TestAPIKeyIntegration:
    """Integration tests for API key security system"""

    @pytest.mark.asyncio
    async def test_full_api_key_lifecycle(self, api_key_manager, mock_user, mock_request):
        """Test complete API key lifecycle"""
        # 1. Create API key
        api_key_data = await api_key_manager.create_api_key(
            user=mock_user,
            name="Test Key",
            scopes=["read", "write"]
        )
        assert api_key_data is not None
        
        # 2. Validate API key
        with patch.object(api_key_manager, '_verify_key_hash', return_value=True):
            result = await api_key_manager.validate_api_key(
                api_key_data.raw_key, mock_request
            )
            assert result.is_valid is True
        
        # 3. Rotate API key
        new_key_data = await api_key_manager.rotate_api_key(api_key_data.id)
        assert new_key_data.raw_key != api_key_data.raw_key
        
        # 4. Revoke API key
        success = await api_key_manager.revoke_api_key(new_key_data.id)
        assert success is True

    @pytest.mark.asyncio
    async def test_concurrent_api_key_operations(self, api_key_manager, mock_user):
        """Test concurrent API key operations"""
        # Create multiple keys concurrently
        tasks = [
            api_key_manager.create_api_key(
                user=mock_user,
                name=f"Concurrent Key {i}",
                scopes=["read"]
            )
            for i in range(5)
        ]
        
        keys = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle concurrent creation gracefully
        successful_keys = [k for k in keys if isinstance(k, APIKeyData)]
        assert len(successful_keys) == 5

    @pytest.mark.asyncio
    async def test_api_key_security_monitoring(self, api_key_manager, security_service):
        """Test API key security monitoring"""
        api_key_data = APIKeyData(
            id="key123",
            user_id="user123",
            name="Test Key",
            key_hash="hashed_key",
            key_prefix="lsk_test",
            scopes=["read"],
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        # Should trigger security monitoring
        with patch.object(security_service, 'monitor_key_usage') as mock_monitor:
            await security_service.monitor_key_usage(api_key_data)
            mock_monitor.assert_called()

    @pytest.mark.asyncio
    async def test_emergency_response_system(self, api_key_manager, security_service):
        """Test emergency response system"""
        user_id = "user123"
        
        # Mock security breach detection
        with patch.object(security_service, 'detect_security_breach') as mock_detect:
            mock_detect.return_value = True
            
            # Should trigger emergency revocation
            with patch.object(api_key_manager, 'emergency_revoke_all_user_keys') as mock_revoke:
                await security_service.handle_security_breach(user_id)
                mock_revoke.assert_called_once_with(
                    user_id=user_id,
                    reason="security_breach",
                    revoked_by="security_system"
                )

    @pytest.mark.asyncio
    async def test_api_key_performance_under_load(self, api_key_manager, mock_user):
        """Test API key performance under load"""
        import time
        
        # Create many keys rapidly
        start_time = time.perf_counter()
        
        tasks = []
        for i in range(20):
            tasks.append(api_key_manager.create_api_key(
                user=mock_user,
                name=f"Load Test Key {i}",
                scopes=["read"]
            ))
        
        keys = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.perf_counter()
        duration = end_time - start_time
        
        # Should complete within reasonable time
        assert duration < 3.0  # Less than 3 seconds for 20 keys
        
        # Should handle load gracefully
        successful_keys = [k for k in keys if isinstance(k, APIKeyData)]
        assert len(successful_keys) > 0

    @pytest.mark.asyncio
    async def test_api_key_rotation_automation(self, api_key_manager):
        """Test automated API key rotation"""
        # Mock keys due for rotation
        mock_keys = []
        for i in range(3):
            key = Mock(spec=APIKey)
            key.id = f"key{i}"
            key.next_rotation_at = datetime.now(timezone.utc) - timedelta(hours=1)
            key.is_active = True
            mock_keys.append(key)
        
        api_key_manager.db.execute.return_value.scalars.return_value.all.return_value = mock_keys
        
        with patch.object(api_key_manager, 'rotate_api_key') as mock_rotate:
            await api_key_manager.check_and_rotate_keys()
            assert mock_rotate.call_count == 3

    @pytest.mark.asyncio
    async def test_api_key_compliance_monitoring(self, api_key_manager, security_service):
        """Test API key compliance monitoring"""
        # Mock compliance check
        compliance_data = {
            "api_key_id": "key123",
            "user_id": "user123",
            "compliance_level": "high",
            "policy_violations": [],
            "last_check": datetime.now(timezone.utc)
        }
        
        with patch.object(security_service, 'check_compliance') as mock_check:
            mock_check.return_value = compliance_data
            
            result = await security_service.check_key_compliance("key123")
            assert result["compliance_level"] == "high"
            assert len(result["policy_violations"]) == 0