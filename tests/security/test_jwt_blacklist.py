#!/usr/bin/env python3
"""
Comprehensive tests for JWT Blacklist System

Tests JWT token revocation, blacklist management, Redis integration,
and security validation for the JWT blacklist system.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import json
import redis.asyncio as redis

from linkshield.security.jwt_blacklist import (
    JWTBlacklistService,
    BlacklistEntry,
    BlacklistReason,
    TokenRevocationRequest,
    BulkRevocationRequest,
    BlacklistStats
)


class TestJWTBlacklistService:
    """Test suite for JWT Blacklist Service"""

    @pytest.fixture
    async def mock_redis(self):
        """Mock Redis client for testing"""
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock()
        mock_redis.set = AsyncMock()
        mock_redis.delete = AsyncMock()
        mock_redis.exists = AsyncMock()
        mock_redis.keys = AsyncMock()
        mock_redis.pipeline = AsyncMock()
        mock_redis.expire = AsyncMock()
        return mock_redis

    @pytest.fixture
    async def blacklist_service(self, mock_redis):
        """Create JWT blacklist service with mocked Redis"""
        with patch('src.security.jwt_blacklist.redis.from_url', return_value=mock_redis):
            service = JWTBlacklistService()
            await service.initialize()
            return service

    @pytest.fixture
    def sample_token(self):
        """Sample JWT token for testing"""
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    @pytest.fixture
    def sample_jti(self):
        """Sample JWT ID for testing"""
        return str(uuid4())

    # Token Revocation Tests
    @pytest.mark.asyncio
    async def test_revoke_token_success(self, blacklist_service, mock_redis, sample_token, sample_jti):
        """Test successful token revocation"""
        mock_redis.set.return_value = True
        mock_redis.expire.return_value = True
        
        request = TokenRevocationRequest(
            token=sample_token,
            jti=sample_jti,
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        result = await blacklist_service.revoke_token(request)
        
        assert result is True
        mock_redis.set.assert_called_once()
        mock_redis.expire.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_token_already_blacklisted(self, blacklist_service, mock_redis, sample_token, sample_jti):
        """Test revoking already blacklisted token"""
        mock_redis.exists.return_value = True
        
        request = TokenRevocationRequest(
            token=sample_token,
            jti=sample_jti,
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        result = await blacklist_service.revoke_token(request)
        
        assert result is False
        mock_redis.set.assert_not_called()

    @pytest.mark.asyncio
    async def test_revoke_token_redis_error(self, blacklist_service, mock_redis, sample_token, sample_jti):
        """Test token revocation with Redis error"""
        mock_redis.set.side_effect = redis.RedisError("Connection failed")
        
        request = TokenRevocationRequest(
            token=sample_token,
            jti=sample_jti,
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        with pytest.raises(Exception):
            await blacklist_service.revoke_token(request)

    # Token Validation Tests
    @pytest.mark.asyncio
    async def test_is_token_blacklisted_true(self, blacklist_service, mock_redis, sample_jti):
        """Test checking blacklisted token"""
        mock_redis.exists.return_value = True
        
        result = await blacklist_service.is_token_blacklisted(sample_jti)
        
        assert result is True
        mock_redis.exists.assert_called_once_with(f"blacklist:{sample_jti}")

    @pytest.mark.asyncio
    async def test_is_token_blacklisted_false(self, blacklist_service, mock_redis, sample_jti):
        """Test checking non-blacklisted token"""
        mock_redis.exists.return_value = False
        
        result = await blacklist_service.is_token_blacklisted(sample_jti)
        
        assert result is False
        mock_redis.exists.assert_called_once_with(f"blacklist:{sample_jti}")

    @pytest.mark.asyncio
    async def test_get_blacklist_entry(self, blacklist_service, mock_redis, sample_jti):
        """Test retrieving blacklist entry details"""
        entry_data = {
            "jti": sample_jti,
            "user_id": "user123",
            "reason": "USER_LOGOUT",
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        mock_redis.get.return_value = json.dumps(entry_data)
        
        result = await blacklist_service.get_blacklist_entry(sample_jti)
        
        assert result is not None
        assert result.jti == sample_jti
        assert result.user_id == "user123"
        assert result.reason == BlacklistReason.USER_LOGOUT

    # Bulk Operations Tests
    @pytest.mark.asyncio
    async def test_bulk_revoke_tokens(self, blacklist_service, mock_redis):
        """Test bulk token revocation"""
        mock_pipeline = AsyncMock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.set = Mock()
        mock_pipeline.expire = Mock()
        mock_pipeline.execute = AsyncMock(return_value=[True, True, True, True])
        
        request = BulkRevocationRequest(
            user_id="user123",
            reason=BlacklistReason.SECURITY_BREACH,
            token_jtis=["jti1", "jti2"]
        )
        
        result = await blacklist_service.bulk_revoke_tokens(request)
        
        assert result == 2
        mock_redis.pipeline.assert_called_once()
        assert mock_pipeline.set.call_count == 2
        assert mock_pipeline.expire.call_count == 2

    @pytest.mark.asyncio
    async def test_revoke_user_tokens(self, blacklist_service, mock_redis):
        """Test revoking all tokens for a user"""
        mock_redis.keys.return_value = [b"user_tokens:user123:jti1", b"user_tokens:user123:jti2"]
        mock_pipeline = AsyncMock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.set = Mock()
        mock_pipeline.expire = Mock()
        mock_pipeline.delete = Mock()
        mock_pipeline.execute = AsyncMock(return_value=[True] * 6)
        
        result = await blacklist_service.revoke_user_tokens(
            user_id="user123",
            reason=BlacklistReason.ACCOUNT_SUSPENDED
        )
        
        assert result == 2
        mock_redis.keys.assert_called_once()

    # Cleanup Tests
    @pytest.mark.asyncio
    async def test_cleanup_expired_entries(self, blacklist_service, mock_redis):
        """Test cleanup of expired blacklist entries"""
        expired_keys = [b"blacklist:expired1", b"blacklist:expired2"]
        mock_redis.keys.return_value = expired_keys
        mock_redis.delete.return_value = 2
        
        result = await blacklist_service.cleanup_expired_entries()
        
        assert result == 2
        mock_redis.delete.assert_called_once_with(*expired_keys)

    # Statistics Tests
    @pytest.mark.asyncio
    async def test_get_blacklist_stats(self, blacklist_service, mock_redis):
        """Test retrieving blacklist statistics"""
        mock_redis.keys.side_effect = [
            [b"blacklist:1", b"blacklist:2", b"blacklist:3"],  # total entries
            [b"blacklist:expired1"],  # expired entries
        ]
        
        stats = await blacklist_service.get_blacklist_stats()
        
        assert isinstance(stats, BlacklistStats)
        assert stats.total_entries == 3
        assert stats.expired_entries == 1
        assert stats.active_entries == 2

    # Edge Cases and Error Handling
    @pytest.mark.asyncio
    async def test_revoke_token_invalid_expiry(self, blacklist_service, sample_token, sample_jti):
        """Test token revocation with past expiry date"""
        request = TokenRevocationRequest(
            token=sample_token,
            jti=sample_jti,
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)  # Past date
        )
        
        with pytest.raises(ValueError, match="Token expiry cannot be in the past"):
            await blacklist_service.revoke_token(request)

    @pytest.mark.asyncio
    async def test_revoke_token_missing_jti(self, blacklist_service, sample_token):
        """Test token revocation without JTI"""
        request = TokenRevocationRequest(
            token=sample_token,
            jti="",
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        with pytest.raises(ValueError, match="JTI is required"):
            await blacklist_service.revoke_token(request)

    @pytest.mark.asyncio
    async def test_connection_recovery(self, blacklist_service, mock_redis, sample_jti):
        """Test Redis connection recovery"""
        # First call fails, second succeeds
        mock_redis.exists.side_effect = [
            redis.ConnectionError("Connection lost"),
            True
        ]
        
        # Should retry and succeed
        result = await blacklist_service.is_token_blacklisted(sample_jti)
        assert result is True
        assert mock_redis.exists.call_count == 2

    # Performance Tests
    @pytest.mark.asyncio
    async def test_bulk_operations_performance(self, blacklist_service, mock_redis):
        """Test performance of bulk operations"""
        # Simulate large number of tokens
        token_jtis = [f"jti_{i}" for i in range(1000)]
        
        mock_pipeline = AsyncMock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.set = Mock()
        mock_pipeline.expire = Mock()
        mock_pipeline.execute = AsyncMock(return_value=[True] * 2000)
        
        request = BulkRevocationRequest(
            user_id="user123",
            reason=BlacklistReason.SECURITY_BREACH,
            token_jtis=token_jtis
        )
        
        start_time = datetime.now()
        result = await blacklist_service.bulk_revoke_tokens(request)
        end_time = datetime.now()
        
        assert result == 1000
        # Should complete within reasonable time (adjust as needed)
        assert (end_time - start_time).total_seconds() < 1.0

    # Security Tests
    @pytest.mark.asyncio
    async def test_token_isolation(self, blacklist_service, mock_redis):
        """Test that tokens are properly isolated by user"""
        # Mock different user tokens
        mock_redis.keys.side_effect = [
            [b"user_tokens:user1:jti1", b"user_tokens:user1:jti2"],
            [b"user_tokens:user2:jti3"]
        ]
        
        # Revoke tokens for user1
        mock_pipeline = AsyncMock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.execute = AsyncMock(return_value=[True] * 4)
        
        result = await blacklist_service.revoke_user_tokens("user1", BlacklistReason.ACCOUNT_SUSPENDED)
        
        # Should only affect user1's tokens
        assert result == 2
        mock_redis.keys.assert_called_with("user_tokens:user1:*")

    @pytest.mark.asyncio
    async def test_reason_validation(self, blacklist_service, sample_token, sample_jti):
        """Test blacklist reason validation"""
        request = TokenRevocationRequest(
            token=sample_token,
            jti=sample_jti,
            user_id="user123",
            reason="INVALID_REASON",  # Invalid reason
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        with pytest.raises(ValueError, match="Invalid blacklist reason"):
            await blacklist_service.revoke_token(request)


class TestBlacklistEntry:
    """Test suite for BlacklistEntry model"""

    def test_blacklist_entry_creation(self):
        """Test creating a blacklist entry"""
        entry = BlacklistEntry(
            jti="test-jti",
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            revoked_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        assert entry.jti == "test-jti"
        assert entry.user_id == "user123"
        assert entry.reason == BlacklistReason.USER_LOGOUT
        assert entry.is_expired() is False

    def test_blacklist_entry_expiry(self):
        """Test blacklist entry expiry check"""
        entry = BlacklistEntry(
            jti="test-jti",
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            revoked_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)  # Expired
        )
        
        assert entry.is_expired() is True

    def test_blacklist_entry_serialization(self):
        """Test blacklist entry JSON serialization"""
        entry = BlacklistEntry(
            jti="test-jti",
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            revoked_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        json_data = entry.to_json()
        assert "jti" in json_data
        assert "user_id" in json_data
        assert "reason" in json_data
        
        # Test deserialization
        restored_entry = BlacklistEntry.from_json(json_data)
        assert restored_entry.jti == entry.jti
        assert restored_entry.user_id == entry.user_id
        assert restored_entry.reason == entry.reason


class TestBlacklistIntegration:
    """Integration tests for JWT blacklist system"""

    @pytest.mark.asyncio
    async def test_full_token_lifecycle(self, blacklist_service, mock_redis, sample_token, sample_jti):
        """Test complete token lifecycle from creation to cleanup"""
        # Setup mocks for full lifecycle
        mock_redis.exists.side_effect = [False, True, True, False]  # Not exists, then exists, then cleaned up
        mock_redis.set.return_value = True
        mock_redis.expire.return_value = True
        mock_redis.get.return_value = json.dumps({
            "jti": sample_jti,
            "user_id": "user123",
            "reason": "USER_LOGOUT",
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        })
        mock_redis.delete.return_value = 1
        
        # 1. Token is not blacklisted initially
        is_blacklisted = await blacklist_service.is_token_blacklisted(sample_jti)
        assert is_blacklisted is False
        
        # 2. Revoke the token
        request = TokenRevocationRequest(
            token=sample_token,
            jti=sample_jti,
            user_id="user123",
            reason=BlacklistReason.USER_LOGOUT,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        revoked = await blacklist_service.revoke_token(request)
        assert revoked is True
        
        # 3. Token is now blacklisted
        is_blacklisted = await blacklist_service.is_token_blacklisted(sample_jti)
        assert is_blacklisted is True
        
        # 4. Get blacklist entry details
        entry = await blacklist_service.get_blacklist_entry(sample_jti)
        assert entry is not None
        assert entry.jti == sample_jti
        
        # 5. Cleanup expired entries
        mock_redis.keys.return_value = [f"blacklist:{sample_jti}".encode()]
        cleaned = await blacklist_service.cleanup_expired_entries()
        assert cleaned >= 0

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, blacklist_service, mock_redis):
        """Test concurrent blacklist operations"""
        mock_redis.set.return_value = True
        mock_redis.expire.return_value = True
        mock_redis.exists.return_value = False
        
        # Create multiple concurrent revocation requests
        tasks = []
        for i in range(10):
            request = TokenRevocationRequest(
                token=f"token_{i}",
                jti=f"jti_{i}",
                user_id=f"user_{i}",
                reason=BlacklistReason.USER_LOGOUT,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            )
            tasks.append(blacklist_service.revoke_token(request))
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should succeed
        assert all(result is True for result in results if not isinstance(result, Exception))
        assert len([r for r in results if isinstance(r, Exception)]) == 0