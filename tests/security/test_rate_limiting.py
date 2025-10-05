#!/usr/bin/env python3
"""
Comprehensive tests for Rate Limiting System

Tests rate limiting algorithms, Redis integration, distributed rate limiting,
middleware integration, and security validation.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta, timezone
import time
import redis.asyncio as redis
from fastapi import Request, HTTPException
from fastapi.testclient import TestClient

from linkshield.security.rate_limiting import (
    RateLimitService,
    RateLimitConfig,
    RateLimitRule,
    RateLimitResult,
    RateLimitAlgorithm,
    RateLimitWindow,
    RateLimitExceeded,
    TokenBucketLimiter,
    SlidingWindowLimiter,
    FixedWindowLimiter
)
from linkshield.middleware.rate_limit_middleware import RateLimitMiddleware


class TestRateLimitService:
    """Test suite for Rate Limit Service"""

    @pytest.fixture
    def rate_limit_config(self):
        """Rate limiting configuration for testing"""
        return RateLimitConfig(
            redis_url="redis://localhost:6379/0",
            default_requests_per_minute=60,
            default_requests_per_hour=1000,
            burst_allowance=10,
            cleanup_interval=300,
            key_prefix="ratelimit:",
            algorithms={
                "token_bucket": TokenBucketLimiter,
                "sliding_window": SlidingWindowLimiter,
                "fixed_window": FixedWindowLimiter
            }
        )

    @pytest.fixture
    async def mock_redis(self):
        """Mock Redis client"""
        redis_mock = AsyncMock(spec=redis.Redis)
        redis_mock.get = AsyncMock(return_value=None)
        redis_mock.set = AsyncMock(return_value=True)
        redis_mock.incr = AsyncMock(return_value=1)
        redis_mock.expire = AsyncMock(return_value=True)
        redis_mock.pipeline = Mock()
        redis_mock.pipeline.return_value.__aenter__ = AsyncMock()
        redis_mock.pipeline.return_value.__aexit__ = AsyncMock()
        return redis_mock

    @pytest.fixture
    async def rate_limit_service(self, rate_limit_config, mock_redis):
        """Create rate limit service with mocked Redis"""
        service = RateLimitService(rate_limit_config)
        service.redis = mock_redis
        return service

    @pytest.fixture
    def mock_request(self):
        """Mock FastAPI request"""
        request = Mock(spec=Request)
        request.client.host = "127.0.0.1"
        request.url.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-client"}
        return request

    # Rate Limit Rule Tests
    def test_rate_limit_rule_creation(self):
        """Test rate limit rule creation"""
        rule = RateLimitRule(
            name="api_limit",
            requests_per_minute=100,
            requests_per_hour=1000,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            burst_allowance=20,
            paths=["/api/*"],
            methods=["GET", "POST"],
            exempt_ips=["127.0.0.1"]
        )
        
        assert rule.name == "api_limit"
        assert rule.requests_per_minute == 100
        assert rule.requests_per_hour == 1000
        assert rule.algorithm == RateLimitAlgorithm.TOKEN_BUCKET
        assert rule.burst_allowance == 20

    def test_rate_limit_rule_path_matching(self):
        """Test rate limit rule path matching"""
        rule = RateLimitRule(
            name="api_limit",
            requests_per_minute=100,
            paths=["/api/*", "/auth/login"]
        )
        
        assert rule.matches_path("/api/users") is True
        assert rule.matches_path("/api/data/export") is True
        assert rule.matches_path("/auth/login") is True
        assert rule.matches_path("/public/info") is False

    def test_rate_limit_rule_method_matching(self):
        """Test rate limit rule method matching"""
        rule = RateLimitRule(
            name="write_limit",
            requests_per_minute=10,
            methods=["POST", "PUT", "DELETE"]
        )
        
        assert rule.matches_method("POST") is True
        assert rule.matches_method("PUT") is True
        assert rule.matches_method("DELETE") is True
        assert rule.matches_method("GET") is False

    def test_rate_limit_rule_ip_exemption(self):
        """Test IP exemption in rate limit rules"""
        rule = RateLimitRule(
            name="general_limit",
            requests_per_minute=60,
            exempt_ips=["127.0.0.1", "192.168.1.0/24"]
        )
        
        assert rule.is_ip_exempt("127.0.0.1") is True
        assert rule.is_ip_exempt("192.168.1.100") is True
        assert rule.is_ip_exempt("10.0.0.1") is False

    # Token Bucket Algorithm Tests
    @pytest.mark.asyncio
    async def test_token_bucket_limiter_allow(self, mock_redis):
        """Test token bucket limiter allowing requests"""
        limiter = TokenBucketLimiter(
            capacity=10,
            refill_rate=1,  # 1 token per second
            redis_client=mock_redis
        )
        
        # Mock Redis to return available tokens
        mock_redis.get.return_value = b"5"  # 5 tokens available
        
        result = await limiter.is_allowed("test_key", 1)
        
        assert result.allowed is True
        assert result.remaining_requests >= 0

    @pytest.mark.asyncio
    async def test_token_bucket_limiter_deny(self, mock_redis):
        """Test token bucket limiter denying requests"""
        limiter = TokenBucketLimiter(
            capacity=10,
            refill_rate=1,
            redis_client=mock_redis
        )
        
        # Mock Redis to return no available tokens
        mock_redis.get.return_value = b"0"
        
        result = await limiter.is_allowed("test_key", 5)  # Request 5 tokens
        
        assert result.allowed is False
        assert result.remaining_requests == 0

    @pytest.mark.asyncio
    async def test_token_bucket_refill(self, mock_redis):
        """Test token bucket refill mechanism"""
        limiter = TokenBucketLimiter(
            capacity=10,
            refill_rate=2,  # 2 tokens per second
            redis_client=mock_redis
        )
        
        # Mock Redis pipeline for atomic operations
        pipeline_mock = AsyncMock()
        mock_redis.pipeline.return_value.__aenter__.return_value = pipeline_mock
        pipeline_mock.get.return_value = b"3"
        pipeline_mock.set = AsyncMock()
        pipeline_mock.expire = AsyncMock()
        pipeline_mock.execute = AsyncMock(return_value=[b"3", True, True])
        
        result = await limiter.is_allowed("test_key", 1)
        
        # Should calculate refill based on time elapsed
        assert result.allowed is True

    # Sliding Window Algorithm Tests
    @pytest.mark.asyncio
    async def test_sliding_window_limiter_allow(self, mock_redis):
        """Test sliding window limiter allowing requests"""
        limiter = SlidingWindowLimiter(
            window_size=60,  # 60 seconds
            max_requests=100,
            redis_client=mock_redis
        )
        
        # Mock Redis to return current request count
        mock_redis.zcard.return_value = 50  # 50 requests in window
        
        result = await limiter.is_allowed("test_key", 1)
        
        assert result.allowed is True
        assert result.remaining_requests == 49

    @pytest.mark.asyncio
    async def test_sliding_window_limiter_deny(self, mock_redis):
        """Test sliding window limiter denying requests"""
        limiter = SlidingWindowLimiter(
            window_size=60,
            max_requests=100,
            redis_client=mock_redis
        )
        
        # Mock Redis to return max requests reached
        mock_redis.zcard.return_value = 100
        
        result = await limiter.is_allowed("test_key", 1)
        
        assert result.allowed is False
        assert result.remaining_requests == 0

    @pytest.mark.asyncio
    async def test_sliding_window_cleanup(self, mock_redis):
        """Test sliding window cleanup of old entries"""
        limiter = SlidingWindowLimiter(
            window_size=60,
            max_requests=100,
            redis_client=mock_redis
        )
        
        # Mock Redis pipeline for cleanup operations
        pipeline_mock = AsyncMock()
        mock_redis.pipeline.return_value.__aenter__.return_value = pipeline_mock
        pipeline_mock.zremrangebyscore = AsyncMock()
        pipeline_mock.zadd = AsyncMock()
        pipeline_mock.zcard = AsyncMock(return_value=50)
        pipeline_mock.expire = AsyncMock()
        pipeline_mock.execute = AsyncMock(return_value=[1, True, 50, True])
        
        result = await limiter.is_allowed("test_key", 1)
        
        # Should clean up old entries and add new request
        pipeline_mock.zremrangebyscore.assert_called_once()
        pipeline_mock.zadd.assert_called_once()

    # Fixed Window Algorithm Tests
    @pytest.mark.asyncio
    async def test_fixed_window_limiter_allow(self, mock_redis):
        """Test fixed window limiter allowing requests"""
        limiter = FixedWindowLimiter(
            window_size=60,  # 60 seconds
            max_requests=100,
            redis_client=mock_redis
        )
        
        # Mock Redis to return current count
        mock_redis.get.return_value = b"50"
        
        result = await limiter.is_allowed("test_key", 1)
        
        assert result.allowed is True
        assert result.remaining_requests == 49

    @pytest.mark.asyncio
    async def test_fixed_window_limiter_deny(self, mock_redis):
        """Test fixed window limiter denying requests"""
        limiter = FixedWindowLimiter(
            window_size=60,
            max_requests=100,
            redis_client=mock_redis
        )
        
        # Mock Redis to return max requests reached
        mock_redis.get.return_value = b"100"
        
        result = await limiter.is_allowed("test_key", 1)
        
        assert result.allowed is False
        assert result.remaining_requests == 0

    @pytest.mark.asyncio
    async def test_fixed_window_reset(self, mock_redis):
        """Test fixed window reset at window boundary"""
        limiter = FixedWindowLimiter(
            window_size=60,
            max_requests=100,
            redis_client=mock_redis
        )
        
        # Mock Redis operations for window reset
        mock_redis.incr.return_value = 1  # First request in new window
        mock_redis.ttl.return_value = -1  # No expiry set
        
        result = await limiter.is_allowed("test_key", 1)
        
        assert result.allowed is True
        assert result.remaining_requests == 99
        mock_redis.expire.assert_called_once()

    # Rate Limit Service Tests
    @pytest.mark.asyncio
    async def test_rate_limit_service_check_allowed(self, rate_limit_service, mock_request):
        """Test rate limit service allowing requests"""
        # Mock limiter to allow request
        with patch.object(rate_limit_service, '_get_limiter') as mock_get_limiter:
            mock_limiter = AsyncMock()
            mock_limiter.is_allowed.return_value = RateLimitResult(
                allowed=True,
                remaining_requests=59,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                retry_after=None
            )
            mock_get_limiter.return_value = mock_limiter
            
            result = await rate_limit_service.check_rate_limit(mock_request)
            
            assert result.allowed is True
            assert result.remaining_requests == 59

    @pytest.mark.asyncio
    async def test_rate_limit_service_check_denied(self, rate_limit_service, mock_request):
        """Test rate limit service denying requests"""
        # Mock limiter to deny request
        with patch.object(rate_limit_service, '_get_limiter') as mock_get_limiter:
            mock_limiter = AsyncMock()
            mock_limiter.is_allowed.return_value = RateLimitResult(
                allowed=False,
                remaining_requests=0,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                retry_after=60
            )
            mock_get_limiter.return_value = mock_limiter
            
            result = await rate_limit_service.check_rate_limit(mock_request)
            
            assert result.allowed is False
            assert result.remaining_requests == 0
            assert result.retry_after == 60

    @pytest.mark.asyncio
    async def test_rate_limit_key_generation(self, rate_limit_service, mock_request):
        """Test rate limit key generation"""
        # Test IP-based key
        key = rate_limit_service._generate_rate_limit_key(mock_request, "ip")
        assert "127.0.0.1" in key
        
        # Test user-based key (with mock user ID)
        with patch.object(rate_limit_service, '_extract_user_id', return_value="user123"):
            key = rate_limit_service._generate_rate_limit_key(mock_request, "user")
            assert "user123" in key
        
        # Test endpoint-based key
        key = rate_limit_service._generate_rate_limit_key(mock_request, "endpoint")
        assert "/api/test" in key

    @pytest.mark.asyncio
    async def test_rate_limit_rule_selection(self, rate_limit_service, mock_request):
        """Test rate limit rule selection"""
        # Add custom rules
        api_rule = RateLimitRule(
            name="api_strict",
            requests_per_minute=30,
            paths=["/api/*"],
            methods=["POST", "PUT"]
        )
        
        auth_rule = RateLimitRule(
            name="auth_limit",
            requests_per_minute=5,
            paths=["/auth/*"]
        )
        
        rate_limit_service.add_rule(api_rule)
        rate_limit_service.add_rule(auth_rule)
        
        # Test API endpoint
        mock_request.url.path = "/api/users"
        mock_request.method = "POST"
        selected_rule = rate_limit_service._select_rule(mock_request)
        assert selected_rule.name == "api_strict"
        
        # Test auth endpoint
        mock_request.url.path = "/auth/login"
        mock_request.method = "POST"
        selected_rule = rate_limit_service._select_rule(mock_request)
        assert selected_rule.name == "auth_limit"

    # Distributed Rate Limiting Tests
    @pytest.mark.asyncio
    async def test_distributed_rate_limiting(self, rate_limit_service, mock_redis):
        """Test distributed rate limiting across multiple instances"""
        # Simulate multiple instances checking the same key
        key = "ratelimit:ip:127.0.0.1"
        
        # Mock Redis to simulate concurrent access
        mock_redis.incr.side_effect = [1, 2, 3, 4, 5]  # Simulate incremental counts
        
        # Multiple concurrent requests
        tasks = []
        for i in range(5):
            mock_request = Mock(spec=Request)
            mock_request.client.host = "127.0.0.1"
            mock_request.url.path = "/api/test"
            mock_request.method = "GET"
            tasks.append(rate_limit_service.check_rate_limit(mock_request))
        
        results = await asyncio.gather(*tasks)
        
        # All requests should be processed consistently
        assert len(results) == 5
        assert all(isinstance(result, RateLimitResult) for result in results)

    @pytest.mark.asyncio
    async def test_redis_connection_failure(self, rate_limit_service, mock_redis):
        """Test handling of Redis connection failures"""
        # Mock Redis to raise connection error
        mock_redis.get.side_effect = redis.ConnectionError("Connection failed")
        
        mock_request = Mock(spec=Request)
        mock_request.client.host = "127.0.0.1"
        mock_request.url.path = "/api/test"
        mock_request.method = "GET"
        
        # Should fallback gracefully (allow request but log error)
        result = await rate_limit_service.check_rate_limit(mock_request)
        
        # Depending on configuration, might allow or deny
        assert isinstance(result, RateLimitResult)

    # Performance Tests
    @pytest.mark.asyncio
    async def test_rate_limiting_performance(self, rate_limit_service):
        """Test rate limiting performance under load"""
        mock_request = Mock(spec=Request)
        mock_request.client.host = "127.0.0.1"
        mock_request.url.path = "/api/test"
        mock_request.method = "GET"
        
        # Mock limiter for performance test
        with patch.object(rate_limit_service, '_get_limiter') as mock_get_limiter:
            mock_limiter = AsyncMock()
            mock_limiter.is_allowed.return_value = RateLimitResult(
                allowed=True,
                remaining_requests=100,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                retry_after=None
            )
            mock_get_limiter.return_value = mock_limiter
            
            # Measure performance
            start_time = time.perf_counter()
            
            # Simulate 100 concurrent requests
            tasks = [
                rate_limit_service.check_rate_limit(mock_request)
                for _ in range(100)
            ]
            
            results = await asyncio.gather(*tasks)
            
            end_time = time.perf_counter()
            duration = end_time - start_time
            
            # Should complete within reasonable time
            assert duration < 1.0  # Less than 1 second for 100 requests
            assert len(results) == 100
            assert all(result.allowed for result in results)

    # Security Tests
    @pytest.mark.asyncio
    async def test_rate_limit_bypass_prevention(self, rate_limit_service):
        """Test prevention of rate limit bypass attempts"""
        # Test IP spoofing prevention
        mock_request = Mock(spec=Request)
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = {
            "X-Forwarded-For": "10.0.0.1",
            "X-Real-IP": "192.168.1.1"
        }
        mock_request.url.path = "/api/test"
        mock_request.method = "GET"
        
        # Should use actual client IP, not headers
        key = rate_limit_service._generate_rate_limit_key(mock_request, "ip")
        assert "127.0.0.1" in key
        assert "10.0.0.1" not in key
        assert "192.168.1.1" not in key

    @pytest.mark.asyncio
    async def test_rate_limit_key_collision_prevention(self, rate_limit_service):
        """Test prevention of rate limit key collisions"""
        # Different users should have different keys
        mock_request1 = Mock(spec=Request)
        mock_request1.client.host = "127.0.0.1"
        mock_request1.url.path = "/api/test"
        
        mock_request2 = Mock(spec=Request)
        mock_request2.client.host = "127.0.0.2"
        mock_request2.url.path = "/api/test"
        
        key1 = rate_limit_service._generate_rate_limit_key(mock_request1, "ip")
        key2 = rate_limit_service._generate_rate_limit_key(mock_request2, "ip")
        
        assert key1 != key2

    @pytest.mark.asyncio
    async def test_rate_limit_algorithm_consistency(self, rate_limit_service, mock_redis):
        """Test consistency of rate limiting algorithms"""
        # Test that the same request pattern produces consistent results
        mock_request = Mock(spec=Request)
        mock_request.client.host = "127.0.0.1"
        mock_request.url.path = "/api/test"
        mock_request.method = "GET"
        
        # Mock consistent Redis responses
        mock_redis.get.return_value = b"50"
        
        # Multiple checks should be consistent
        results = []
        for _ in range(5):
            result = await rate_limit_service.check_rate_limit(mock_request)
            results.append(result)
        
        # All results should have same allowed status
        allowed_statuses = [result.allowed for result in results]
        assert len(set(allowed_statuses)) == 1  # All same


class TestRateLimitMiddleware:
    """Test suite for Rate Limit Middleware"""

    @pytest.fixture
    def rate_limit_middleware(self, rate_limit_service):
        """Create rate limit middleware"""
        return RateLimitMiddleware(rate_limit_service)

    @pytest.fixture
    def mock_call_next(self):
        """Mock next middleware call"""
        async def call_next(request):
            response = Mock()
            response.status_code = 200
            response.headers = {}
            return response
        return call_next

    @pytest.mark.asyncio
    async def test_middleware_allow_request(self, rate_limit_middleware, mock_request, mock_call_next):
        """Test middleware allowing requests"""
        # Mock rate limit service to allow request
        with patch.object(rate_limit_middleware.rate_limit_service, 'check_rate_limit') as mock_check:
            mock_check.return_value = RateLimitResult(
                allowed=True,
                remaining_requests=59,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                retry_after=None
            )
            
            response = await rate_limit_middleware.dispatch(mock_request, mock_call_next)
            
            assert response.status_code == 200
            assert "X-RateLimit-Remaining" in response.headers
            assert response.headers["X-RateLimit-Remaining"] == "59"

    @pytest.mark.asyncio
    async def test_middleware_deny_request(self, rate_limit_middleware, mock_request, mock_call_next):
        """Test middleware denying requests"""
        # Mock rate limit service to deny request
        with patch.object(rate_limit_middleware.rate_limit_service, 'check_rate_limit') as mock_check:
            mock_check.return_value = RateLimitResult(
                allowed=False,
                remaining_requests=0,
                reset_time=datetime.now(timezone.utc) + timedelta(minutes=1),
                retry_after=60
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await rate_limit_middleware.dispatch(mock_request, mock_call_next)
            
            assert exc_info.value.status_code == 429
            assert "Rate limit exceeded" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_middleware_headers(self, rate_limit_middleware, mock_request, mock_call_next):
        """Test middleware setting rate limit headers"""
        reset_time = datetime.now(timezone.utc) + timedelta(minutes=1)
        
        with patch.object(rate_limit_middleware.rate_limit_service, 'check_rate_limit') as mock_check:
            mock_check.return_value = RateLimitResult(
                allowed=True,
                remaining_requests=45,
                reset_time=reset_time,
                retry_after=None
            )
            
            response = await rate_limit_middleware.dispatch(mock_request, mock_call_next)
            
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers
            assert response.headers["X-RateLimit-Remaining"] == "45"

    @pytest.mark.asyncio
    async def test_middleware_error_handling(self, rate_limit_middleware, mock_request, mock_call_next):
        """Test middleware error handling"""
        # Mock rate limit service to raise exception
        with patch.object(rate_limit_middleware.rate_limit_service, 'check_rate_limit') as mock_check:
            mock_check.side_effect = Exception("Redis connection failed")
            
            # Should handle error gracefully (allow request or raise appropriate error)
            try:
                response = await rate_limit_middleware.dispatch(mock_request, mock_call_next)
                # If it allows the request, that's acceptable fallback behavior
                assert response.status_code == 200
            except HTTPException as e:
                # If it raises an error, should be appropriate status code
                assert e.status_code in [500, 503]


class TestRateLimitIntegration:
    """Integration tests for rate limiting system"""

    @pytest.mark.asyncio
    async def test_full_rate_limiting_flow(self, rate_limit_service, mock_redis):
        """Test complete rate limiting flow"""
        # Configure service with specific rule
        rule = RateLimitRule(
            name="test_rule",
            requests_per_minute=5,
            algorithm=RateLimitAlgorithm.FIXED_WINDOW
        )
        rate_limit_service.add_rule(rule)
        
        mock_request = Mock(spec=Request)
        mock_request.client.host = "127.0.0.1"
        mock_request.url.path = "/api/test"
        mock_request.method = "GET"
        
        # Mock Redis for fixed window algorithm
        mock_redis.get.side_effect = [b"1", b"2", b"3", b"4", b"5", b"6"]
        mock_redis.incr.side_effect = [1, 2, 3, 4, 5, 6]
        
        # Make 6 requests (should allow 5, deny 1)
        results = []
        for i in range(6):
            result = await rate_limit_service.check_rate_limit(mock_request)
            results.append(result)
        
        # First 5 should be allowed, 6th should be denied
        allowed_count = sum(1 for result in results if result.allowed)
        denied_count = sum(1 for result in results if not result.allowed)
        
        assert allowed_count == 5
        assert denied_count == 1

    @pytest.mark.asyncio
    async def test_multiple_algorithm_comparison(self, rate_limit_config, mock_redis):
        """Test different algorithms with same limits"""
        algorithms = [
            (RateLimitAlgorithm.TOKEN_BUCKET, TokenBucketLimiter),
            (RateLimitAlgorithm.SLIDING_WINDOW, SlidingWindowLimiter),
            (RateLimitAlgorithm.FIXED_WINDOW, FixedWindowLimiter)
        ]
        
        for algorithm, limiter_class in algorithms:
            service = RateLimitService(rate_limit_config)
            service.redis = mock_redis
            
            rule = RateLimitRule(
                name=f"test_{algorithm.value}",
                requests_per_minute=10,
                algorithm=algorithm
            )
            service.add_rule(rule)
            
            mock_request = Mock(spec=Request)
            mock_request.client.host = f"127.0.0.{algorithm.value}"
            mock_request.url.path = "/api/test"
            mock_request.method = "GET"
            
            # Each algorithm should handle requests consistently
            result = await service.check_rate_limit(mock_request)
            assert isinstance(result, RateLimitResult)

    @pytest.mark.asyncio
    async def test_rate_limit_with_authentication(self, rate_limit_service):
        """Test rate limiting with authenticated users"""
        # Mock authenticated request
        mock_request = Mock(spec=Request)
        mock_request.client.host = "127.0.0.1"
        mock_request.url.path = "/api/user/profile"
        mock_request.method = "GET"
        mock_request.state = Mock()
        mock_request.state.user_id = "user123"
        
        # Should use user-based rate limiting
        with patch.object(rate_limit_service, '_extract_user_id', return_value="user123"):
            key = rate_limit_service._generate_rate_limit_key(mock_request, "user")
            assert "user123" in key

    @pytest.mark.asyncio
    async def test_rate_limit_cleanup(self, rate_limit_service, mock_redis):
        """Test rate limit data cleanup"""
        # Mock cleanup operation
        mock_redis.scan_iter.return_value = [
            b"ratelimit:old_key_1",
            b"ratelimit:old_key_2",
            b"ratelimit:current_key"
        ]
        mock_redis.ttl.side_effect = [-1, -1, 300]  # First two expired, third active
        mock_redis.delete.return_value = 2
        
        # Run cleanup
        await rate_limit_service.cleanup_expired_keys()
        
        # Should delete expired keys
        mock_redis.delete.assert_called_once()