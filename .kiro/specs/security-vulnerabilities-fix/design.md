# Security Vulnerabilities Fix - Design Document

## Architecture Overview

This design addresses critical security vulnerabilities in the LinkShield backend through a layered security approach that maintains system performance while significantly enhancing security posture.

## System Architecture

### Security Layer Stack
```
┌─────────────────────────────────────────┐
│           Client Requests               │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│         Security Middleware             │
│  ┌─────────────────────────────────────┐ │
│  │    CSRF Protection Middleware       │ │
│  └─────────────────────────────────────┘ │
│  ┌─────────────────────────────────────┐ │
│  │   Enhanced Rate Limiting            │ │
│  └─────────────────────────────────────┘ │
│  ┌─────────────────────────────────────┐ │
│  │   CSP Header Enforcement            │ │
│  └─────────────────────────────────────┘ │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│      Authentication Layer               │
│  ┌─────────────────────────────────────┐ │
│  │   JWT Token Blacklist Check        │ │
│  └─────────────────────────────────────┘ │
│  ┌─────────────────────────────────────┐ │
│  │   Enhanced Session Validation      │ │
│  └─────────────────────────────────────┘ │
│  ┌─────────────────────────────────────┐ │
│  │   Bot Authentication Security      │ │
│  └─────────────────────────────────────┘ │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│        Application Layer                │
└─────────────────────────────────────────┘
```

## Component Design

### 1. JWT Token Blacklist System

#### Architecture
- **Storage**: Redis-based distributed blacklist
- **Key Pattern**: `jwt_blacklist:{token_jti}`
- **TTL**: Matches token expiration time
- **Cleanup**: Automatic Redis expiration

#### Implementation Components
```python
# New Components to Create:
src/security/jwt_blacklist.py          # Core blacklist logic
src/middleware/jwt_validation.py       # Enhanced JWT middleware
src/routes/admin/token_management.py   # Admin token management
src/services/token_service.py          # Token lifecycle management
```

#### Data Flow
```
Token Revocation Request
    ↓
Extract JWT Claims (jti, exp)
    ↓
Store in Redis: jwt_blacklist:{jti} = timestamp, TTL = exp
    ↓
Return Success Response

Token Validation Request
    ↓
Extract JWT Claims (jti)
    ↓
Check Redis: EXISTS jwt_blacklist:{jti}
    ↓
If exists: Reject (401)
If not exists: Continue validation
```

### 2. CSRF Protection System

#### Architecture
- **Pattern**: Double Submit Cookie
- **Token Storage**: Secure HTTP-only cookies + request headers
- **Validation**: Server-side token comparison
- **Exemptions**: API endpoints with proper bearer token auth

#### Implementation Components
```python
# New Components to Create:
src/security/csrf_protection.py        # CSRF token generation/validation
src/middleware/csrf_middleware.py      # CSRF validation middleware
src/utils/csrf_utils.py               # CSRF utility functions
```

#### Token Flow
```
Initial Request (GET)
    ↓
Generate CSRF Token (cryptographically secure)
    ↓
Set Secure Cookie: csrftoken={token}
    ↓
Include in Response Headers: X-CSRFToken={token}

State-Changing Request (POST/PUT/DELETE)
    ↓
Extract Token from Cookie and Header
    ↓
Compare Tokens (constant-time comparison)
    ↓
If match: Continue processing
If mismatch: Return 403 Forbidden
```

### 3. Enhanced Content Security Policy

#### Policy Configuration
```python
# Strict CSP Configuration
CSP_POLICY = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'nonce-{nonce}'"],
    'style-src': ["'self'", "'nonce-{nonce}'"],
    'img-src': ["'self'", "data:", "https:"],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'frame-ancestors': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"]
}
```

#### Implementation Components
```python
# Enhanced Components:
src/security/middleware.py             # Update existing CSP implementation
src/utils/csp_nonce.py                # Nonce generation utilities
src/templates/base.html               # Template updates for nonce support
```

### 4. Bot Authentication Security

#### Discord Ed25519 Verification
```python
# Implementation Architecture
class DiscordWebhookVerifier:
    def __init__(self):
        self.public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(settings.DISCORD_PUBLIC_KEY)
        )
    
    def verify_signature(self, signature: str, timestamp: str, body: bytes) -> bool:
        # Native Ed25519 verification
        # Timestamp validation (prevent replay attacks)
        # Proper error handling
```

#### Service Token Persistence
```python
# Redis-based Token Storage
class ServiceTokenManager:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.key_prefix = "service_tokens:"
    
    async def store_token(self, token_id: str, token_data: dict, ttl: int):
        # Store in Redis with TTL
        
    async def validate_token(self, token_id: str) -> bool:
        # Check Redis existence and validity
```

### 5. Enhanced Rate Limiting

#### Multi-Layer Rate Limiting
```python
# Rate Limiting Tiers
RATE_LIMITS = {
    'auth_login': {'requests': 5, 'window': 300},      # 5 per 5 minutes
    'auth_register': {'requests': 3, 'window': 3600},  # 3 per hour
    'password_reset': {'requests': 2, 'window': 3600}, # 2 per hour
    'api_general': {'requests': 1000, 'window': 3600}, # 1000 per hour
    'webhook': {'requests': 100, 'window': 60}          # 100 per minute
}
```

#### Secure IP Detection
```python
class SecureIPDetector:
    def __init__(self, trusted_proxies: List[str]):
        self.trusted_networks = [ipaddress.ip_network(proxy) for proxy in trusted_proxies]
    
    def get_client_ip(self, request: Request) -> str:
        # Validate proxy headers against trusted networks
        # Fallback to direct connection IP
        # Log potential spoofing attempts
```

### 6. Session Security Enhancement

#### Concurrent Session Management
```python
# Session Tracking Architecture
class SessionManager:
    def __init__(self, redis_client, max_sessions: int = 5):
        self.redis = redis_client
        self.max_sessions = max_sessions
        self.session_key_prefix = "user_sessions:"
    
    async def create_session(self, user_id: str, session_data: dict):
        # Check current session count
        # Remove oldest session if limit exceeded
        # Create new session with metadata
    
    async def validate_session(self, user_id: str, session_id: str) -> bool:
        # Validate session existence and metadata
        # Check for suspicious activity patterns
```

#### Device Fingerprinting
```python
class DeviceFingerprinter:
    def generate_fingerprint(self, request: Request) -> str:
        # Combine User-Agent, Accept headers, IP subnet
        # Generate stable but privacy-respecting fingerprint
        
    def detect_anomaly(self, stored_fingerprint: str, current_fingerprint: str) -> bool:
        # Compare fingerprints for significant changes
        # Account for legitimate browser updates
```

## Database Schema Changes

### New Tables
```sql
-- JWT Token Blacklist (Redis - no SQL table needed)

-- Enhanced Session Tracking
CREATE TABLE user_sessions_enhanced (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    device_fingerprint VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    location_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    security_flags JSONB DEFAULT '{}'::jsonb
);

-- CSRF Token Storage (Redis - no SQL table needed)

-- Security Event Log
CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id),
    ip_address INET,
    user_agent TEXT,
    event_data JSONB,
    severity VARCHAR(20) DEFAULT 'INFO',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API Key Rotation History
CREATE TABLE api_key_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    old_key_hash VARCHAR(255),
    new_key_hash VARCHAR(255),
    rotation_reason VARCHAR(100),
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_by UUID REFERENCES users(id)
);
```

### Index Optimizations
```sql
-- Performance indexes for security queries
CREATE INDEX idx_user_sessions_enhanced_user_id ON user_sessions_enhanced(user_id);
CREATE INDEX idx_user_sessions_enhanced_active ON user_sessions_enhanced(user_id, is_active);
CREATE INDEX idx_security_events_type_time ON security_events(event_type, created_at);
CREATE INDEX idx_security_events_user_time ON security_events(user_id, created_at);
```

## Redis Schema Design

### Key Patterns
```
# JWT Blacklist
jwt_blacklist:{jti} = {
    "revoked_at": "2024-01-15T10:30:00Z",
    "reason": "user_logout",
    "admin_id": "uuid"
}
TTL: token_exp - current_time

# CSRF Tokens
csrf_token:{token_id} = {
    "user_id": "uuid",
    "created_at": "2024-01-15T10:30:00Z",
    "ip_address": "192.168.1.1"
}
TTL: 3600 seconds

# Service Tokens
service_token:{platform}:{token_id} = {
    "created_at": "2024-01-15T10:30:00Z",
    "last_used": "2024-01-15T10:35:00Z",
    "usage_count": 42
}
TTL: 86400 seconds

# Rate Limiting
rate_limit:{scope}:{identifier} = {
    "count": 5,
    "window_start": "2024-01-15T10:30:00Z"
}
TTL: window_duration

# User Sessions
user_sessions:{user_id} = [
    {
        "session_id": "uuid",
        "created_at": "2024-01-15T10:30:00Z",
        "device_fingerprint": "hash",
        "ip_address": "192.168.1.1"
    }
]
TTL: session_duration
```

## Security Monitoring

### Event Types
```python
SECURITY_EVENTS = {
    'AUTH_FAILURE': 'Authentication failure',
    'TOKEN_REVOKED': 'JWT token revoked',
    'CSRF_VIOLATION': 'CSRF token validation failed',
    'RATE_LIMIT_EXCEEDED': 'Rate limit exceeded',
    'SESSION_ANOMALY': 'Suspicious session activity',
    'IP_SPOOFING_ATTEMPT': 'Potential IP spoofing detected',
    'BOT_AUTH_FAILURE': 'Bot authentication failed',
    'CONCURRENT_SESSION_LIMIT': 'Concurrent session limit exceeded'
}
```

### Alerting Thresholds
```python
ALERT_THRESHOLDS = {
    'AUTH_FAILURE': {'count': 10, 'window': 300},      # 10 failures in 5 minutes
    'CSRF_VIOLATION': {'count': 5, 'window': 300},     # 5 violations in 5 minutes
    'RATE_LIMIT_EXCEEDED': {'count': 50, 'window': 60}, # 50 rate limits in 1 minute
    'IP_SPOOFING_ATTEMPT': {'count': 1, 'window': 60}   # Any spoofing attempt
}
```

## Performance Considerations

### Caching Strategy
- **JWT Blacklist**: Redis with automatic expiration
- **CSRF Tokens**: Redis with 1-hour TTL
- **Session Data**: Redis with session-based TTL
- **Rate Limit Counters**: Redis with sliding window

### Database Optimization
- **Connection Pooling**: Maintain optimal pool size for security queries
- **Query Optimization**: Use prepared statements and proper indexing
- **Batch Operations**: Group security log writes for better performance

### Memory Management
- **Redis Memory**: Monitor and configure appropriate memory limits
- **Token Storage**: Implement efficient serialization for complex token data
- **Session Cleanup**: Automated cleanup of expired sessions and tokens

## Deployment Strategy

### Rollout Phases
1. **Phase 1**: Deploy JWT blacklist and enhanced session validation
2. **Phase 2**: Implement CSRF protection and CSP hardening
3. **Phase 3**: Deploy bot authentication fixes and rate limiting enhancements
4. **Phase 4**: Add API key rotation and advanced monitoring

### Rollback Plan
- **Database Migrations**: Reversible migrations for all schema changes
- **Feature Flags**: Toggle security features without deployment
- **Monitoring**: Real-time monitoring during rollout with automatic rollback triggers

### Testing Strategy
- **Unit Tests**: Comprehensive test coverage for all security components
- **Integration Tests**: End-to-end security flow testing
- **Load Testing**: Performance impact assessment under load
- **Security Testing**: Penetration testing and vulnerability scanning