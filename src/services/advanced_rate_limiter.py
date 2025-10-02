#!/usr/bin/env python3
"""
Advanced Rate Limiting System for LinkShield Backend
"""

import time
import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Any, Union, Callable
from functools import wraps

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

from fastapi import Request, HTTPException

# Configure logging
logger = logging.getLogger(__name__)

# =============================================================================
# Configuration and Constants
# =============================================================================

class RateLimitStrategy(str, Enum):
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    TOKEN_BUCKET = "token_bucket"

class RateLimitScope(str, Enum):
    API_AUTHENTICATED = "api_authenticated"
    API_ANONYMOUS = "api_anonymous"
    PROJECT_CREATION = "project_creation"
    PROJECT_MODIFICATION = "project_modification"
    TEAM_INVITATION = "team_invitation"
    ALERT_CREATION = "alert_creation"
    ALERT_MODIFICATION = "alert_modification"
    # Extension-specific scopes
    EXTENSION_URL_CHECK = "extension_url_check"
    EXTENSION_BULK_URL_CHECK = "extension_bulk_url_check"
    EXTENSION_CONTENT_ANALYZE = "extension_content_analyze"

@dataclass
class RateLimitConfig:
    limit: int
    window: int  # seconds
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    burst: Optional[int] = None  # For token bucket strategy

@dataclass
class RateLimitResult:
    allowed: bool
    current: int
    limit: int
    remaining: int
    reset_time: float
    retry_after: Optional[int] = None

# Default rate limits for different scopes
DEFAULT_RATE_LIMITS = {
    RateLimitScope.API_AUTHENTICATED: RateLimitConfig(limit=1000, window=3600),
    RateLimitScope.API_ANONYMOUS: RateLimitConfig(limit=100, window=3600),
    RateLimitScope.PROJECT_CREATION: RateLimitConfig(limit=10, window=3600),
    RateLimitScope.PROJECT_MODIFICATION: RateLimitConfig(limit=50, window=3600),
    RateLimitScope.TEAM_INVITATION: RateLimitConfig(limit=20, window=3600),
    RateLimitScope.ALERT_CREATION: RateLimitConfig(limit=100, window=3600),
    RateLimitScope.ALERT_MODIFICATION: RateLimitConfig(limit=200, window=3600),
    # Extension quotas (per 60s window). Multiplied by subscription tier via SUBSCRIPTION_MULTIPLIERS
    RateLimitScope.EXTENSION_URL_CHECK: RateLimitConfig(limit=12, window=60, strategy=RateLimitStrategy.SLIDING_WINDOW),
    RateLimitScope.EXTENSION_BULK_URL_CHECK: RateLimitConfig(limit=6, window=60, strategy=RateLimitStrategy.SLIDING_WINDOW),
    RateLimitScope.EXTENSION_CONTENT_ANALYZE: RateLimitConfig(limit=12, window=60, strategy=RateLimitStrategy.SLIDING_WINDOW),
}

# Subscription tier multipliers
SUBSCRIPTION_MULTIPLIERS = {
    "free": 1.0,
    "basic": 1.5,
    "premium": 5.0,
    "enterprise": 10.0,
}

# =============================================================================
# Storage Backends
# =============================================================================

class RateLimitStorage(ABC):
    """Abstract base class for rate limit storage backends."""
    
    @abstractmethod
    async def increment_counter(self, key: str, window: int) -> int:
        """Increment counter and return new value."""
        pass
    
    @abstractmethod
    async def get_counter(self, key: str) -> int:
        """Get current counter value."""
        pass
    
    @abstractmethod
    async def reset_counter(self, key: str) -> None:
        """Reset counter to zero."""
        pass
    
    @abstractmethod
    async def add_to_window(self, key: str, timestamp: float, window: int) -> int:
        """Add timestamp to sliding window and return count."""
        pass
    
    @abstractmethod
    async def get_window_count(self, key: str, cutoff_time: float) -> int:
        """Get count of entries in window after cutoff time."""
        pass

class InMemoryStorage(RateLimitStorage):
    """In-memory storage backend for development and testing."""
    
    def __init__(self):
        self.counters: Dict[str, int] = {}
        self.windows: Dict[str, list] = {}
        self._lock = asyncio.Lock()
    
    async def increment_counter(self, key: str, window: int) -> int:
        """Increment counter and return new value."""
        async with self._lock:
            current = self.counters.get(key, 0)
            current += 1
            self.counters[key] = current
            return current
    
    async def get_counter(self, key: str) -> int:
        """Get current counter value."""
        return self.counters.get(key, 0)
    
    async def reset_counter(self, key: str) -> None:
        """Reset counter to zero."""
        async with self._lock:
            self.counters[key] = 0
    
    async def add_to_window(self, key: str, timestamp: float, window: int) -> int:
        """Add timestamp to sliding window and return count."""
        async with self._lock:
            if key not in self.windows:
                self.windows[key] = []
            
            # Add timestamp and clean old entries
            self.windows[key].append(timestamp)
            cutoff_time = timestamp - window
            self.windows[key] = [ts for ts in self.windows[key] if ts > cutoff_time]
            
            return len(self.windows[key])
    
    async def get_window_count(self, key: str, cutoff_time: float) -> int:
        """Get count of entries in window after cutoff time."""
        if key not in self.windows:
            return 0
        
        return len([ts for ts in self.windows[key] if ts > cutoff_time])

class RedisStorage(RateLimitStorage):
    """Redis storage backend for production environments."""
    
    def __init__(self, redis_client: Optional[Any] = None, redis_url: str = "redis://localhost:6379/1"):
        if not REDIS_AVAILABLE:
            raise ImportError("Redis is not available. Install redis package: pip install redis")
        
        self.redis_client = redis_client or redis.from_url(redis_url)
        self.redis_url = redis_url
    
    async def increment_counter(self, key: str, window: int) -> int:
        """Increment counter and return new value."""
        try:
            pipe = self.redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window)
            results = await pipe.execute()
            return results[0]
        except Exception as e:
            logger.error(f"Redis increment_counter error: {e}")
            raise
    
    async def get_counter(self, key: str) -> int:
        """Get current counter value."""
        try:
            value = await self.redis_client.get(key)
            return int(value) if value else 0
        except Exception as e:
            logger.error(f"Redis get_counter error: {e}")
            raise
    
    async def reset_counter(self, key: str) -> None:
        """Reset counter to zero."""
        try:
            await self.redis_client.delete(key)
        except Exception as e:
            logger.error(f"Redis reset_counter error: {e}")
            raise
    
    async def add_to_window(self, key: str, timestamp: float, window: int) -> int:
        """Add timestamp to sliding window and return count."""
        try:
            pipe = self.redis_client.pipeline()
            
            # Add timestamp to sorted set
            pipe.zadd(key, {str(timestamp): timestamp})
            
            # Remove old entries
            cutoff_time = timestamp - window
            pipe.zremrangebyscore(key, 0, cutoff_time)
            
            # Set expiration
            pipe.expire(key, window)
            
            # Get count
            pipe.zcard(key)
            
            results = await pipe.execute()
            return results[3]  # zcard result
        except Exception as e:
            logger.error(f"Redis add_to_window error: {e}")
            raise
    
    async def get_window_count(self, key: str, cutoff_time: float) -> int:
        """Get count of entries in window after cutoff time."""
        try:
            return await self.redis_client.zcard(key) - await self.redis_client.zcount(key, 0, cutoff_time)
        except Exception as e:
            logger.error(f"Redis get_window_count error: {e}")
            raise

# =============================================================================
# Rate Limiting Strategies
# =============================================================================

class RateLimitingStrategy(ABC):
    """Abstract base class for rate limiting strategies."""
    
    def __init__(self, storage: RateLimitStorage):
        self.storage = storage
    
    @abstractmethod
    async def is_allowed(self, key: str, limit: int, window: int, **kwargs) -> RateLimitResult:
        """Check if request is allowed under rate limit."""
        pass

class SlidingWindowStrategy(RateLimitingStrategy):
    """Sliding window rate limiting strategy."""
    
    async def is_allowed(self, key: str, limit: int, window: int, **kwargs) -> RateLimitResult:
        """Check if request is allowed using sliding window."""
        current_time = time.time()
        
        # Add current request to window
        current_count = await self.storage.add_to_window(key, current_time, window)
        
        # Calculate reset time (end of current window)
        reset_time = current_time + window
        
        # Check if allowed
        allowed = current_count <= limit
        remaining = max(0, limit - current_count)
        
        # Calculate retry after if denied
        retry_after = None
        if not allowed:
            retry_after = window
        
        return RateLimitResult(
            allowed=allowed,
            current=current_count,
            limit=limit,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=retry_after
        )

class FixedWindowStrategy(RateLimitingStrategy):
    """Fixed window rate limiting strategy."""
    
    async def is_allowed(self, key: str, limit: int, window: int, **kwargs) -> RateLimitResult:
        """Check if request is allowed using fixed window."""
        # Increment counter
        current_count = await self.storage.increment_counter(key, window)
        
        # Calculate reset time (end of current window)
        current_time = time.time()
        reset_time = current_time + window
        
        # Check if allowed
        allowed = current_count <= limit
        remaining = max(0, limit - current_count)
        
        # Calculate retry after if denied
        retry_after = window if not allowed else None
        
        return RateLimitResult(
            allowed=allowed,
            current=current_count,
            limit=limit,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=retry_after
        )

class TokenBucketStrategy(RateLimitingStrategy):
    """Token bucket rate limiting strategy."""
    
    async def is_allowed(self, key: str, limit: int, window: int, burst: Optional[int] = None, **kwargs) -> RateLimitResult:
        """Check if request is allowed using token bucket."""
        burst_capacity = burst or limit
        refill_rate = limit / window  # tokens per second
        
        # Get current bucket state
        bucket_key = f"{key}:bucket"
        current_tokens = await self.storage.get_counter(bucket_key)
        
        # Calculate tokens to add based on time elapsed
        last_refill_key = f"{key}:last_refill"
        current_time = time.time()
        
        try:
            last_refill = float(await self.storage.get_counter(last_refill_key) or current_time)
        except (ValueError, TypeError):
            last_refill = current_time
        
        time_elapsed = current_time - last_refill
        tokens_to_add = time_elapsed * refill_rate
        
        # Update bucket state
        new_tokens = min(burst_capacity, current_tokens + tokens_to_add)
        
        # Check if request can be processed
        if new_tokens >= 1:
            # Consume one token
            new_tokens -= 1
            allowed = True
            
            # Update storage
            await self.storage.increment_counter(bucket_key, window * 2)
            await self.storage.increment_counter(last_refill_key, window * 2)
            
            current_count = int(new_tokens)
            remaining = int(new_tokens)
        else:
            allowed = False
            current_count = int(new_tokens)
            remaining = int(new_tokens)
        
        # Calculate reset time and retry after
        reset_time = current_time + window
        retry_after = None
        if not allowed:
            retry_after = int((1 - new_tokens) / refill_rate) + 1
        
        return RateLimitResult(
            allowed=allowed,
            current=current_count,
            limit=burst_capacity,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=retry_after
        )

# =============================================================================
# Advanced Rate Limiter
# =============================================================================

class AdvancedRateLimiter:
    """Advanced rate limiter with multiple strategies and storage backends."""
    
    def __init__(self, storage: Optional[RateLimitStorage] = None, config: Optional[Dict[RateLimitScope, RateLimitConfig]] = None):
        self.storage = storage or InMemoryStorage()
        self.config = config or DEFAULT_RATE_LIMITS
        self.strategies = {
            RateLimitStrategy.SLIDING_WINDOW: SlidingWindowStrategy(self.storage),
            RateLimitStrategy.FIXED_WINDOW: FixedWindowStrategy(self.storage),
            RateLimitStrategy.TOKEN_BUCKET: TokenBucketStrategy(self.storage),
        }
    
    async def check_rate_limit(
        self,
        identifier: str,
        scope: Union[RateLimitScope, str],
        user_id: Optional[str] = None,
        subscription_plan: Optional[str] = None
    ) -> RateLimitResult:
        """
        Check if request is allowed under rate limit.
        
        Args:
            identifier: Unique identifier for the client (IP, user ID, etc.)
            scope: Rate limiting scope
            user_id: Optional user ID for user-specific limits
            subscription_plan: Optional subscription tier for tier-based limits
            
        Returns:
            RateLimitResult with allowance status and metadata
        """
        try:
            # Convert string scope to enum if needed
            if isinstance(scope, str):
                try:
                    scope = RateLimitScope(scope)
                except ValueError:
                    logger.warning(f"Unknown rate limit scope: {scope}")
                    # Allow request if scope not found (fail open)
                    return RateLimitResult(
                        allowed=True,
                        current=0,
                        limit=0,
                        remaining=0,
                        reset_time=time.time() + 3600,
                        retry_after=None
                    )
            
            # Get configuration for scope
            config = self.config.get(scope)
            if not config:
                logger.warning(f"No rate limit configuration for scope: {scope}")
                # Allow request if no configuration (fail open)
                return RateLimitResult(
                    allowed=True,
                    current=0,
                    limit=0,
                    remaining=0,
                    reset_time=time.time() + 3600,
                    retry_after=None
                )
            
            # Calculate effective limit based on subscription tier
            effective_limit = config.limit
            if subscription_plan and subscription_plan in SUBSCRIPTION_MULTIPLIERS:
                multiplier = SUBSCRIPTION_MULTIPLIERS[subscription_plan]
                effective_limit = int(config.limit * multiplier)
            
            # Generate rate limit key
            rate_limit_key = self._generate_key(identifier, scope, user_id)
            
            # Get strategy for this scope
            strategy = self.strategies.get(config.strategy, self.strategies[RateLimitStrategy.SLIDING_WINDOW])
            
            # Check rate limit
            result = await strategy.is_allowed(
                rate_limit_key,
                effective_limit,
                config.window,
                burst=config.burst
            )
            
            logger.debug(f"Rate limit check: {identifier} -> {scope} -> allowed={result.allowed}, remaining={result.remaining}")
            return result
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}", exc_info=True)
            # Fail open - allow request if rate limiting fails
            return RateLimitResult(
                allowed=True,
                current=0,
                limit=0,
                remaining=0,
                reset_time=time.time() + 3600,
                retry_after=None
            )
    
    def _generate_key(self, identifier: str, scope: RateLimitScope, user_id: Optional[str] = None) -> str:
        """Generate rate limit key."""
        if user_id:
            return f"rate_limit:{scope.value}:user:{user_id}"
        return f"rate_limit:{scope.value}:client:{identifier}"
    
    def get_rate_limit_headers(self, result: RateLimitResult) -> Dict[str, str]:
        """Generate rate limit headers for HTTP response."""
        headers = {
            "X-RateLimit-Limit": str(result.limit),
            "X-RateLimit-Remaining": str(result.remaining),
            "X-RateLimit-Reset": str(int(result.reset_time)),
        }
        
        if result.retry_after is not None:
            headers["Retry-After"] = str(result.retry_after)
        
        return headers

# =============================================================================
# FastAPI Integration
# =============================================================================

# Global rate limiter instance
_rate_limiter_instance: Optional[AdvancedRateLimiter] = None

def get_rate_limiter() -> AdvancedRateLimiter:
    """Get global rate limiter instance (singleton)."""
    global _rate_limiter_instance
    if _rate_limiter_instance is None:
        # Auto-configure based on environment
        storage = None
        try:
            if REDIS_AVAILABLE:
                storage = RedisStorage()
            else:
                storage = InMemoryStorage()
        except Exception:
            storage = InMemoryStorage()
        
        _rate_limiter_instance = AdvancedRateLimiter(storage=storage)
    
    return _rate_limiter_instance

def rate_limit(scope: str):
    """
    FastAPI decorator for rate limiting endpoints.
    
    Args:
        scope: Rate limiting scope (e.g., "api_authenticated", "project_creation")
        
    Returns:
        Decorator function for rate limiting
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from kwargs
            request: Optional[Request] = None
            for key, value in kwargs.items():
                if isinstance(value, Request):
                    request = value
                    break
            
            if not request:
                # Try to find request in args
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
            
            if not request:
                logger.warning(f"No request object found for rate limiting in {func.__name__}")
                return await func(*args, **kwargs)
            
            # Get client identifier (IP address)
            client_ip = request.client.host if request.client else "unknown"
            
            # Get user information if available
            user_id = None
            subscription_plan = None
            
            # Try to get current user from request state or kwargs
            if hasattr(request.state, 'user') and request.state.user:
                user = request.state.user
                user_id = getattr(user, 'id', None)
                subscription_plan = getattr(user, 'subscription_plan', None)
            else:
                # Check kwargs for user objects
                for key, value in kwargs.items():
                    if hasattr(value, 'id') and hasattr(value, 'subscription_plan'):
                        user_id = value.id
                        subscription_plan = value.subscription_plan
                        break
            
            # Check rate limit
            rate_limiter = get_rate_limiter()
            result = await rate_limiter.check_rate_limit(
                identifier=client_ip,
                scope=scope,
                user_id=user_id,
                subscription_plan=subscription_plan
            )
            
            # Add rate limit headers to response
            if hasattr(request, 'state'):
                request.state.rate_limit_result = result
            
            # Handle rate limit exceeded
            if not result.allowed:
                headers = rate_limiter.get_rate_limit_headers(result)
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Try again in {result.retry_after} seconds.",
                    headers=headers
                )
            
            # Call original function
            response = await func(*args, **kwargs)
            
            # Add rate limit headers to response
            if hasattr(response, 'headers') and result.limit > 0:
                headers = rate_limiter.get_rate_limit_headers(result)
                for key, value in headers.items():
                    response.headers[key] = value
            
            return response
        
        return wrapper
    return decorator

# =============================================================================
# Health Check Integration
# =============================================================================

async def check_rate_limiter_health() -> Dict[str, Any]:
    """Check health of rate limiting system."""
    try:
        rate_limiter = get_rate_limiter()
        
        # Test storage backend
        test_key = "health_check:test"
        test_result = await rate_limiter.storage.increment_counter(test_key, 60)
        await rate_limiter.storage.reset_counter(test_key)
        
        return {
            "status": "healthy",
            "storage": "redis" if isinstance(rate_limiter.storage, RedisStorage) else "memory",
            "strategy": list(rate_limiter.strategies.keys())[0].value,
            "enabled": True
        }
    except Exception as e:
        logger.error(f"Rate limiter health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "enabled": False
        }

# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Main classes
    'AdvancedRateLimiter',
    'RateLimitStorage',
    'RedisStorage',
    'InMemoryStorage',
    'SlidingWindowStrategy',
    'FixedWindowStrategy',
    'TokenBucketStrategy',
    
    # Configuration
    'RateLimitStrategy',
    'RateLimitScope',
    'RateLimitConfig',
    'RateLimitResult',
    'DEFAULT_RATE_LIMITS',
    'SUBSCRIPTION_MULTIPLIERS',
    
    # Utilities
    'get_rate_limiter',
    'rate_limit',
    'check_rate_limiter_health',
]