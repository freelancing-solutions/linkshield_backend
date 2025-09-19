# Rate Limiting System

## Overview

LinkShield implements a comprehensive rate limiting system to protect against abuse, ensure fair resource usage, and maintain service quality. The system uses multiple layers of rate limiting including global limits, subscription-based limits, and endpoint-specific restrictions.

## Architecture

### Core Components

1. **SlowAPI Integration** - Primary rate limiting framework
2. **Custom Rate Limiting Service** - Business logic and subscription integration
3. **Rate Limiting Middleware** - Request-level enforcement
4. **Redis Backend** - Distributed rate limit storage (production)
5. **In-Memory Fallback** - Development and fallback storage

### Rate Limiting Layers

```
Request → SlowAPI Decorator → Custom Rate Limiter → Subscription Limits → Endpoint Logic
```

## Configuration

### Environment Variables

```bash
# Rate Limiting Configuration
LINKSHIELD_RATE_LIMIT_ENABLED=true
LINKSHIELD_RATE_LIMIT_DEFAULT="100/hour"
LINKSHIELD_RATE_LIMIT_AUTH="1000/hour"
LINKSHIELD_RATE_LIMIT_CHECK="50/hour"
LINKSHIELD_RATE_LIMIT_REQUESTS_PER_MINUTE=60
LINKSHIELD_RATE_LIMIT_BURST_SIZE=10
```

### Default Rate Limits

| Limit Type | Default Value | Description |
|------------|---------------|-------------|
| `RATE_LIMIT_DEFAULT` | 100/hour | General API endpoints |
| `RATE_LIMIT_AUTH` | 1000/hour | Authentication endpoints |
| `RATE_LIMIT_CHECK` | 50/hour | URL checking endpoints |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | 60 | Per-minute request limit |
| `RATE_LIMIT_BURST_SIZE` | 10 | Burst allowance |

## SlowAPI Implementation

### Global Limiter Setup

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize global limiter
limiter = Limiter(key_func=get_remote_address)
```

### Rate Limit Configurations

```python
RATE_LIMITS = {
    "ai_analysis": "10/minute",
    "url_check": "30/minute", 
    "user_auth": "5/minute",
    "report_generation": "20/minute",
    "general_api": "100/minute"
}
```

### Custom Key Functions

```python
def create_rate_limit_key_func(prefix: str = "") -> Callable[[Request], str]:
    """Create custom key function with optional prefix."""
    def key_func(request: Request) -> str:
        client_id = get_remote_address(request)
        return f"{prefix}:{client_id}" if prefix else client_id
    return key_func

# Specialized key functions
ai_analysis_key_func = create_rate_limit_key_func("ai_analysis")
url_check_key_func = create_rate_limit_key_func("url_check")
user_auth_key_func = create_rate_limit_key_func("user_auth")
```

## Subscription-Based Rate Limits

### Plan-Based Limits

Each subscription plan defines specific rate limits:

```python
class SubscriptionPlan:
    daily_check_limit: int = 0          # Daily URL checks
    monthly_check_limit: int = 0        # Monthly URL checks  
    api_rate_limit: int = 60           # Requests per minute
```

### Plan Types and Limits

| Plan Type | Daily Checks | Monthly Checks | API Rate (req/min) |
|-----------|--------------|----------------|-------------------|
| Free | 10 | 100 | 30 |
| Basic | 100 | 1,000 | 60 |
| Pro | 500 | 10,000 | 120 |
| Enterprise | Unlimited | Unlimited | 300 |

### Usage Tracking

```python
class UserSubscription:
    def can_make_check(self) -> bool:
        """Check if user can perform URL check within limits."""
        
    def increment_usage(self, check_type: str = "url_check") -> bool:
        """Increment usage counter and check limits."""
        
    def get_usage_limits(self) -> Dict[str, Any]:
        """Get current usage and limits."""
```

## Rate Limiting Middleware

### Security Middleware

```python
class SecurityMiddleware:
    async def dispatch(self, request: Request, call_next):
        # Rate limiting enforcement
        # Security header injection
        # Request logging
```

### Rate Limit Middleware

```python
class RateLimitMiddleware:
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.clients = {}  # In-memory storage
        
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        current_time = time.time()
        
        # Sliding window rate limiting
        if not self._is_allowed(client_ip, current_time):
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"},
                headers={
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(current_time + 60))
                }
            )
```

## Endpoint-Specific Rate Limits

### Decorator Usage

```python
from slowapi import limiter

@router.post("/check-url")
@limiter.limit("30/minute", key_func=url_check_key_func)
async def check_url(request: Request, ...):
    """URL checking endpoint with specific rate limit."""
```

### Common Endpoint Limits

| Endpoint Category | Rate Limit | Key Function |
|------------------|------------|--------------|
| URL Checking | 30/minute | `url_check_key_func` |
| AI Analysis | 10/minute | `ai_analysis_key_func` |
| User Authentication | 5/minute | `user_auth_key_func` |
| Report Generation | 20/minute | `report_key_func` |
| General API | 100/minute | `get_remote_address` |

## Rate Limit Headers

### Standard Headers

All rate-limited responses include these headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
X-RateLimit-Window: 3600
```

### Header Descriptions

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |
| `X-RateLimit-Window` | Window duration in seconds |

## Error Responses

### Rate Limit Exceeded (429)

```json
{
  "error": "Rate limit exceeded",
  "error_code": "RATE_LIMIT_EXCEEDED",
  "message": "Too many requests. Please try again later.",
  "details": {
    "limit": 100,
    "window_seconds": 3600,
    "retry_after": 1800
  }
}
```

### Subscription Limit Exceeded (402)

```json
{
  "error": "Subscription limit exceeded",
  "error_code": "SUBSCRIPTION_LIMIT_EXCEEDED", 
  "message": "Daily check limit reached. Upgrade your plan for more checks.",
  "details": {
    "daily_limit": 10,
    "daily_used": 10,
    "monthly_limit": 100,
    "monthly_used": 45,
    "plan_type": "free"
  }
}
```

## Rate Limiting Service

### Core Methods

```python
class SecurityService:
    def check_rate_limit(
        self, 
        identifier: str, 
        limit_type: str, 
        ip_address: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is within rate limits."""
        
    def get_user_rate_limits(self, user_id: int) -> Dict[str, int]:
        """Get rate limits for specific user based on subscription."""
        
    def increment_usage(self, user_id: int, operation: str) -> bool:
        """Increment usage counter for user operation."""
```

### Rate Limit Types

| Type | Description | Default Limit |
|------|-------------|---------------|
| `api_requests` | General API calls | 60/minute |
| `url_checks` | URL checking operations | 100/hour |
| `failed_logins` | Failed authentication attempts | 5/15min |
| `ai_analysis` | AI-powered analysis | 10/minute |
| `report_generation` | Report creation | 20/minute |

## Storage Backends

### Redis Backend (Production)

```python
import redis

class RedisRateLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        
    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """Check rate limit using Redis sliding window."""
        current_time = time.time()
        pipeline = self.redis.pipeline()
        
        # Remove expired entries
        pipeline.zremrangebyscore(key, 0, current_time - window)
        
        # Count current requests
        pipeline.zcard(key)
        
        # Add current request
        pipeline.zadd(key, {str(current_time): current_time})
        
        # Set expiration
        pipeline.expire(key, window)
        
        results = pipeline.execute()
        current_count = results[1]
        
        return current_count < limit
```

### In-Memory Backend (Development)

```python
class InMemoryRateLimiter:
    def __init__(self):
        self._cache = {}
        
    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """Simple sliding window implementation."""
        current_time = time.time()
        
        if key not in self._cache:
            self._cache[key] = []
            
        # Clean expired entries
        self._cache[key] = [
            timestamp for timestamp in self._cache[key]
            if current_time - timestamp < window
        ]
        
        # Check limit
        if len(self._cache[key]) >= limit:
            return False
            
        # Add current request
        self._cache[key].append(current_time)
        return True
```

## Monitoring and Analytics

### Rate Limit Metrics

Track these metrics for monitoring:

- **Request Rate**: Requests per second/minute/hour
- **Rate Limit Hits**: Number of requests blocked
- **Top Rate Limited IPs**: Most frequently limited clients
- **Endpoint Rate Limits**: Per-endpoint rate limiting statistics
- **Subscription Usage**: Plan-based usage patterns

### Logging

```python
def log_rate_limit_event(
    client_ip: str,
    user_id: Optional[int],
    endpoint: str,
    limit_type: str,
    exceeded: bool
):
    """Log rate limiting events for analysis."""
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "client_ip": client_ip,
        "user_id": user_id,
        "endpoint": endpoint,
        "limit_type": limit_type,
        "exceeded": exceeded,
        "event_type": "rate_limit"
    }
    logger.info("Rate limit event", extra=event)
```

## Best Practices

### Implementation Guidelines

1. **Fail Open**: If rate limiting service fails, allow requests
2. **Graceful Degradation**: Provide meaningful error messages
3. **Header Consistency**: Always include rate limit headers
4. **Monitoring**: Track rate limiting effectiveness
5. **Documentation**: Keep rate limits documented and visible

### Performance Considerations

1. **Redis Clustering**: Use Redis cluster for high availability
2. **Connection Pooling**: Reuse Redis connections
3. **Async Operations**: Use async Redis operations
4. **Caching**: Cache rate limit configurations
5. **Batch Operations**: Batch Redis operations when possible

### Security Considerations

1. **IP Spoofing**: Validate client IP addresses
2. **Distributed Attacks**: Monitor for distributed rate limit evasion
3. **Legitimate Traffic**: Whitelist known good clients
4. **Rate Limit Bypass**: Monitor for bypass attempts
5. **Resource Protection**: Protect expensive operations with stricter limits

## Troubleshooting

### Common Issues

1. **Rate Limits Too Strict**: Monitor false positives
2. **Redis Connection Issues**: Implement fallback mechanisms
3. **Clock Synchronization**: Ensure server time synchronization
4. **Memory Usage**: Monitor in-memory rate limiter memory usage
5. **Performance Impact**: Profile rate limiting overhead

### Debugging

```python
# Enable rate limiting debug logging
logging.getLogger("slowapi").setLevel(logging.DEBUG)
logging.getLogger("linkshield.rate_limiting").setLevel(logging.DEBUG)

# Check rate limit status
def debug_rate_limit_status(user_id: int):
    """Debug rate limit status for user."""
    security_service = SecurityService(db)
    limits = security_service.get_user_rate_limits(user_id)
    usage = security_service.get_user_usage(user_id)
    
    print(f"User {user_id} rate limits: {limits}")
    print(f"User {user_id} current usage: {usage}")
```

## Migration and Scaling

### Redis Migration

When migrating from in-memory to Redis:

1. **Gradual Rollout**: Implement feature flags
2. **Data Migration**: No data migration needed (fresh start)
3. **Monitoring**: Monitor Redis performance
4. **Fallback**: Keep in-memory fallback available

### Horizontal Scaling

For multiple application instances:

1. **Shared Redis**: Use shared Redis instance
2. **Consistent Hashing**: Distribute load evenly
3. **Health Checks**: Monitor Redis connectivity
4. **Circuit Breakers**: Implement circuit breaker pattern

## API Reference

### Rate Limiting Decorators

```python
@limiter.limit("100/hour")
@limiter.limit("10/minute", key_func=custom_key_func)
@limiter.limit("5/minute", per_method=True)
```

### Rate Limiting Functions

```python
# Check rate limit programmatically
is_allowed, info = security_service.check_rate_limit(
    identifier="user:123",
    limit_type="api_requests", 
    ip_address="192.168.1.1"
)

# Get user subscription limits
limits = subscription.get_usage_limits()

# Increment usage counter
success = subscription.increment_usage("url_check")
```

### Configuration Classes

```python
class RateLimitConfig:
    enabled: bool = True
    default_limit: str = "100/hour"
    auth_limit: str = "1000/hour"
    check_limit: str = "50/hour"
    requests_per_minute: int = 60
    burst_size: int = 10
```