# Advanced Rate Limiting System

## Overview

LinkShield implements a comprehensive, multi-layered rate limiting system to protect against abuse, ensure fair resource usage, and maintain service quality. The system integrates advanced algorithms, subscription-based limits, and endpoint-specific restrictions using a unified service architecture.

## Architecture

### Core Components

1. **AdvancedRateLimiter Service** - Unified service handling all rate limiting logic
2. **RateLimitMiddleware** - Request-level enforcement with FastAPI integration
3. **@rate_limit Decorator** - Endpoint-specific rate limiting with dynamic limits
4. **Redis Backend** - Distributed storage for production environments
5. **In-Memory Fallback** - Development and fallback storage
6. **User & Subscription Integration** - Dynamic limits based on user tiers and usage patterns

### Rate Limiting Layers

```
Request → SlowAPI Decorator → Custom Rate Limiter → Subscription Limits → Endpoint Logic
```

## Configuration

### Environment Variables

```bash
# Redis Configuration
REDIS_URL=redis://localhost:6379/0
REDIS_CLUSTER_ENABLED=false

# Rate Limiting Configuration
LINKSHIELD_RATE_LIMIT_ENABLED=true
LINKSHIELD_RATE_LIMIT_DEFAULT="100/hour"
LINKSHIELD_RATE_LIMIT_AUTH="1000/hour"
LINKSHIELD_RATE_LIMIT_CHECK="50/hour"
LINKSHIELD_RATE_LIMIT_REQUESTS_PER_MINUTE=60
LINKSHIELD_RATE_LIMIT_BURST_SIZE=10
RATE_LIMIT_STORAGE_BACKEND=redis  # redis, memory
RATE_LIMIT_DEFAULT_WINDOW=3600      # 1 hour in seconds
RATE_LIMIT_MAX_REQUESTS=100         # Default requests per window

# Subscription Limits
SUBSCRIPTION_RATE_LIMIT_ENABLED=true
SUBSCRIPTION_CHECK_DAILY_LIMIT=10   # Free tier daily limit
SUBSCRIPTION_CHECK_MONTHLY_LIMIT=100 # Free tier monthly limit
```

### Advanced Rate Limit Configuration

The system supports multiple rate limiting strategies and configurations:

```python
# Rate Limit Strategies
RATE_LIMIT_STRATEGIES = {
    "sliding_window": "Sliding window counter with precise timing",
    "fixed_window": "Fixed time window with counter reset",
    "token_bucket": "Token bucket algorithm for burst handling"
}

# Endpoint-Specific Limits
ENDPOINT_RATE_LIMITS = {
    "project_creation": {"requests": 10, "window": 3600},      # 10 per hour
    "project_modification": {"requests": 50, "window": 3600},    # 50 per hour
    "api_authenticated": {"requests": 100, "window": 3600},    # 100 per hour
    "api_anonymous": {"requests": 20, "window": 3600}          # 20 per hour
}
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

### URL Analysis (/api/v1/url-check)

Operational limits per current documentation and implementation:
- Single URL Analysis (POST /check):
  - Authenticated users: up to 100 checks/hour
  - Anonymous users: no enforced hourly cap in current implementation; stricter broken-link parameters apply (e.g., scan_depth=1, max_links=10). Operational policy recommendation: 10/hour if global middleware is enabled.
  - Broken link scans: additional limits apply based on subscription (scan_depth 1–5; max_links up to 1000)
- Bulk URL Analysis (POST /bulk-check):
  - Free: 10 URLs per batch, 5 batches/hour
  - Pro: 50 URLs per batch, 20 batches/hour
  - Enterprise: 100 URLs per batch, unlimited batches
- History (GET /history): JWT required; typical 100/hour per user
- Reputation (GET /reputation/{domain}): Anonymous allowed; typical 20/hour per IP
- Stats (GET /stats): JWT required; typical 100/hour per user

Rate limit headers are returned on rate-limited endpoints, e.g.:
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1642262400
X-RateLimit-Scope: user
```

### Bot Integration (/api/v1/bots)

Default limits (current implementation):
- Per user per platform: 50 requests/hour (sliding window) enforced via BotRateLimit (see src/models/bot.py)
- Platform verification and provider-side throttling still apply (Discord, Telegram, Twitter)
- Quick responses: platform handlers optimized for low latency; typical 3-second timeout targets

Webhook endpoints are subject to platform-specific throttling and verification challenges.

### Social Protection Bot (/api/v1/social-protection/bot)

Applies standard per-user limits according to subscription plan. Recommended defaults:
- Analyze endpoints: 100/hour per user
- Batch analyze: Max 50 items per request

Note: Health endpoint (GET /health) is public and not rate-limited at the user level.

Implement additional quotas as needed for compliance and platform rules.

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

## Advanced Rate Limiting Service

Implementation note: In the current codebase, SlowAPI decorators are not used and the global rate-limit middleware is not active. Rate limits are primarily enforced within controllers/services (e.g., SecurityService and URLCheckController) and via the BotRateLimit model. Header injection (X-RateLimit-*) occurs only when the advanced limiter is enabled.

### Core Service Architecture

```python
from src.services.advanced_rate_limiter import AdvancedRateLimiter, RateLimitConfig

class AdvancedRateLimiter:
    """
    Advanced rate limiting service with multiple strategies and user integration.
    """
    
    def __init__(self, redis_client=None, storage_backend="memory"):
        """Initialize with Redis or in-memory storage."""
        
    async def check_rate_limit(
        self, 
        identifier: str, 
        limit_type: str, 
        user=None,
        endpoint: str = None
    ) -> RateLimitResult:
        """Check if request is within rate limits with user context."""
        
    def get_user_rate_limits(self, user) -> Dict[str, int]:
        """Get dynamic rate limits based on user subscription tier."""
        
    def get_rate_limit_status(self, identifier: str, limit_type: str) -> Dict[str, Any]:
        """Get current rate limit status for identifier."""
        
    def reset_rate_limit(self, identifier: str, limit_type: str) -> bool:
        """Reset rate limit counter for specific identifier."""
```

### Rate Limiting Strategies

The service supports three advanced algorithms:

1. **Sliding Window**: Most accurate, tracks exact time windows
2. **Fixed Window**: Simple counter with periodic reset
3. **Token Bucket**: Handles burst traffic patterns

```python
# Strategy configuration
RATE_LIMIT_STRATEGIES = {
    "sliding_window": {
        "class": SlidingWindowStrategy,
        "description": "Precise sliding window with millisecond accuracy",
        "use_case": "High-precision rate limiting"
    },
    "fixed_window": {
        "class": FixedWindowStrategy,
        "description": "Simple fixed time window",
        "use_case": "Basic rate limiting with lower overhead"
    },
    "token_bucket": {
        "class": TokenBucketStrategy,
        "description": "Token bucket for burst handling",
        "use_case": "APIs that need burst capacity"
    }
}
```

### Rate Limit Types

| Type | Description | Default Limit | Strategy | User Scalable |
|------|-------------|---------------|----------|---------------|
| `api_requests` | General API calls | 60/minute | Sliding Window | Yes |
| `url_checks` | URL checking operations | 100/hour | Sliding Window | Yes |
| `failed_logins` | Failed authentication attempts | 5/15min | Fixed Window | No |
| `ai_analysis` | AI-powered analysis | 10/minute | Token Bucket | Yes |
| `report_generation` | Report creation | 20/minute | Sliding Window | Yes |
| `project_creation` | Project creation | 10/hour | Sliding Window | Yes |
| `project_modification` | Project updates/deletes | 50/hour | Sliding Window | Yes |
| `api_authenticated` | Authenticated API calls | 100/hour | Sliding Window | Yes |
| `api_anonymous` | Anonymous API calls | 20/hour | Sliding Window | No |

## FastAPI Integration

### @rate_limit Decorator

The system provides a convenient decorator for FastAPI endpoints:

```python
from src.services.advanced_rate_limiter import rate_limit

@app.post("/api/v1/projects")
@rate_limit("project_creation")
async def create_project(request: Request, current_user: User = Depends(get_current_user)):
    """Create a new project with rate limiting."""
    # Endpoint logic here
    pass

@app.put("/api/v1/projects/{project_id}")
@rate_limit("project_modification")
async def update_project(project_id: int, request: Request, current_user: User = Depends(get_current_user)):
    """Update project with rate limiting."""
    # Endpoint logic here
    pass
```

### Decorator Features

- **Automatic User Detection**: Extracts user from FastAPI dependencies
- **Dynamic Limits**: Adjusts limits based on user subscription tier
- **Header Injection**: Automatically adds rate limit headers to responses
- **Error Handling**: Provides detailed rate limit exceeded responses
- **Redis Integration**: Uses Redis for distributed rate limiting
- **Fallback Support**: Falls back to in-memory storage if Redis unavailable

## Storage Backends

### Redis Backend (Production)

```python
import redis
from datetime import datetime

class RedisStorage:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        
    async def increment_counter(self, key: str, window: int) -> int:
        """Increment counter and return current count."""
        pipeline = self.redis.pipeline()
        
        # Remove expired entries for sliding window
        current_time = datetime.now().timestamp()
        pipeline.zremrangebyscore(key, 0, current_time - window)
        
        # Add current request
        pipeline.zadd(key, {str(current_time): current_time})
        
        # Count current requests
        pipeline.zcard(key)
        
        # Set expiration
        pipeline.expire(key, window)
        
        results = pipeline.execute()
        return results[2]  # Current count
        
    async def get_counter(self, key: str) -> int:
        """Get current counter value."""
        return self.redis.zcard(key)
        
    async def reset_counter(self, key: str) -> bool:
        """Reset counter for specific key."""
        return bool(self.redis.delete(key))
```

### In-Memory Backend (Development)

```python
import threading
from datetime import datetime

class InMemoryStorage:
    def __init__(self):
        self._storage = {}
        self._lock = threading.Lock()
        
    async def increment_counter(self, key: str, window: int) -> int:
        """Increment counter with thread safety."""
        with self._lock:
            current_time = datetime.now().timestamp()
            
            if key not in self._storage:
                self._storage[key] = []
            
            # Clean expired entries
            self._storage[key] = [
                timestamp for timestamp in self._storage[key]
                if current_time - timestamp < window
            ]
            
            # Add current request
            self._storage[key].append(current_time)
            
            return len(self._storage[key])
    
    async def get_counter(self, key: str) -> int:
        """Get current counter value."""
        with self._lock:
            return len(self._storage.get(key, []))
    
    async def reset_counter(self, key: str) -> bool:
        """Reset counter for specific key."""
        with self._lock:
            if key in self._storage:
                del self._storage[key]
                return True
            return False
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
## Extension Endpoints Rate Limits

The browser extension integrates with dedicated endpoints that use the AdvancedRateLimiter via the `@rate_limit` decorator. These endpoints have per-minute limits that scale with subscription tiers:

- Scope `extension_url_check` (POST /api/v1/extension/url/check)
  - Base: 12 requests per 60s window
  - Tier multipliers: free x1.0, basic x1.5, premium x5.0, enterprise x10.0

- Scope `extension_bulk_url_check` (POST /api/v1/extension/url/bulk-check)
  - Base: 6 requests per 60s window
  - Tier multipliers: free x1.0, basic x1.5, premium x5.0, enterprise x10.0

- Scope `extension_content_analyze` (POST /api/v1/extension/content/analyze)
  - Base: 12 requests per 60s window
  - Tier multipliers: free x1.0, basic x1.5, premium x5.0, enterprise x10.0

Authentication requirements:
- Quick URL check: optional JWT (anonymous allowed, limited by client IP)
- Bulk URL check: JWT required
- Content analyze: JWT required

Response headers include standard rate limit metadata:
```
X-RateLimit-Limit: <limit>
X-RateLimit-Remaining: <remaining>
X-RateLimit-Reset: <unix_timestamp_seconds>
Retry-After: <seconds>  # only present when 429 is returned
```

Implementation references:
- src/services/advanced_rate_limiter.py (RateLimitScope and DEFAULT_RATE_LIMITS)
- src/routes/extension.py (@rate_limit decorator usage and auth dependencies)