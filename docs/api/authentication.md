# Authentication Guide

LinkShield API provides comprehensive authentication and authorization mechanisms to secure access to all endpoints. This guide covers all authentication methods, security features, and implementation details.

## Overview

LinkShield supports two primary authentication methods:

1. **JWT Tokens** - Recommended for web applications and user-facing integrations
2. **API Keys** - Recommended for server-to-server integrations and automated systems

Both methods provide secure access to the API with different use cases and security characteristics.

## JWT Token Authentication

### Overview

JWT (JSON Web Token) authentication is the primary method for user-facing applications. It provides session-based authentication with automatic expiration and refresh capabilities.

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Database
    participant Security

    Client->>API: POST /api/v1/user/register
    API->>Database: Create User
    API->>Client: User Created (Email Verification Required)
    
    Client->>API: POST /api/v1/user/login
    API->>Security: Validate Credentials
    Security->>Database: Create Session
    API->>Client: JWT Token + Session Info
    
    Client->>API: API Request with Bearer Token
    API->>Security: Verify JWT Token
    Security->>Database: Validate Session
    API->>Client: Protected Resource
```

### Registration

Register a new user account:

```bash
curl -X POST "http://localhost:8000/api/v1/user/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "full_name": "John Doe",
    "company": "Example Corp",
    "accept_terms": true,
    "marketing_consent": false
  }'
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "full_name": "John Doe",
  "company": "Example Corp",
  "role": "USER",
  "subscription_plan": {
    "id": 1,
    "name": "Free",
    "price": 0.0,
    "active": true
  },
  "is_active": true,
  "is_verified": false,
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Login

Authenticate and receive JWT token:

```bash
curl -X POST "http://localhost:8000/api/v1/user/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "remember_me": true,
    "device_info": {
      "browser": "Chrome",
      "os": "Windows 10"
    }
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 604800,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "USER",
    "is_verified": true
  },
  "session_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

### Using JWT Tokens

Include the JWT token in the Authorization header:

```bash
curl -X GET "http://localhost:8000/api/v1/user/profile" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Password Requirements

Passwords must meet the following criteria:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one digit
- At least one special character (`!@#$%^&*()_+-=[]{}|;:,.<>?`)

### Session Management

#### Session Properties
- **Duration**: 7 days (default) or 30 days (with `remember_me`)
- **Automatic Refresh**: Sessions are refreshed on each API call
- **Device Tracking**: Sessions track IP address, user agent, and device info
- **Concurrent Sessions**: Multiple active sessions per user are supported

#### Session Endpoints

**List Active Sessions:**
```bash
curl -X GET "http://localhost:8000/api/v1/user/sessions" \
  -H "Authorization: Bearer <jwt_token>"
```

**Revoke Specific Session:**
```bash
curl -X DELETE "http://localhost:8000/api/v1/user/sessions/{session_id}" \
  -H "Authorization: Bearer <jwt_token>"
```

**Terminate All Sessions:**
```bash
curl -X DELETE "http://localhost:8000/api/v1/user/sessions" \
  -H "Authorization: Bearer <jwt_token>"
```

### Logout

Invalidate current session:

```bash
curl -X POST "http://localhost:8000/api/v1/user/logout" \
  -H "Authorization: Bearer <jwt_token>"
```

## API Key Authentication

### Overview

API keys provide programmatic access to LinkShield API without user sessions. They're ideal for server-to-server integrations, automated systems, and long-running applications.

### Creating API Keys

Create a new API key:

```bash
curl -X POST "http://localhost:8000/api/v1/user/api-keys" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Integration",
    "description": "API key for production URL scanning",
    "expires_at": "2024-12-31T23:59:59Z",
    "permissions": ["url_check", "ai_analysis"]
  }'
```

**Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "name": "Production Integration",
  "description": "API key for production URL scanning",
  "api_key": "lsk_live_1234567890abcdef1234567890abcdef12345678",
  "key_preview": "lsk_live_12345678...",
  "permissions": ["url_check", "ai_analysis"],
  "is_active": true,
  "expires_at": "2024-12-31T23:59:59Z",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Using API Keys

Include the API key in the `X-API-Key` header:

```bash
curl -X POST "http://localhost:8000/api/v1/url-check/check" \
  -H "X-API-Key: lsk_live_1234567890abcdef1234567890abcdef12345678" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "scan_type": "comprehensive"
  }'
```

### API Key Management

**List API Keys:**
```bash
curl -X GET "http://localhost:8000/api/v1/user/api-keys" \
  -H "Authorization: Bearer <jwt_token>"
```

**Delete API Key:**
```bash
curl -X DELETE "http://localhost:8000/api/v1/user/api-keys/{key_id}" \
  -H "Authorization: Bearer <jwt_token>"
```

### API Key Permissions

Available permissions for API keys:

| Permission | Description | Endpoints |
|------------|-------------|-----------|
| `url_check` | URL analysis and scanning | `/api/v1/url-check/*` |
| `ai_analysis` | AI-powered content analysis | `/api/v1/ai-analysis/*` |
| `reports` | Community reporting system | `/api/v1/reports/*` |
| `profile` | User profile management | `/api/v1/user/profile` |
| `admin` | Administrative functions | Admin endpoints |

## Security Features

### Rate Limiting

## Per-Endpoint Authentication Requirements

This section summarizes authentication requirements across major API groups based on current implementations.

### URL Analysis (/api/v1/url-check)

- POST /check: Optional (anonymous allowed with stricter rate limits). Supports JWT or API Key.
- POST /bulk-check: Required (JWT).
- GET /check/{check_id}: Optional.
- GET /check/{check_id}/results: Optional.
- GET /check/{check_id}/broken-links: Optional (only available when broken-link scan was performed).
- GET /history: Required (JWT).
- GET /reputation/{domain}: Optional.
- GET /stats: Required (JWT).

### Bot Webhooks (/api/v1/bots)

- POST /discord/webhook: Platform signature headers required.
  - Headers: X-Signature-Ed25519, X-Signature-Timestamp
- POST /telegram/webhook: Platform secret token required.
  - Header: X-Telegram-Bot-Api-Secret-Token
- POST /twitter/webhook: Platform signature required.
  - Header: X-Twitter-Webhooks-Signature
- GET /twitter/webhook: CRC challenge response (query param `crc_token`). No JWT.
- GET /discord/webhook, GET /telegram/webhook: Endpoint verification. No JWT.
- GET /status, GET /health, POST /commands/register, POST /platforms/{platform}/restart, GET /platforms/{platform}/info: No JWT required in current implementation.

Note: Management endpoints are unauthenticated in the current codebase. Ensure network-level protection and proper deployment controls if exposed.

### Social Protection Bot (/api/v1/social-protection/bot)

Authentication: JWT is required for all endpoints except the health check.
- POST /analyze
- POST /account-safety
- POST /compliance
- POST /followers
- POST /batch-analyze
- POST /webhook (requires header X-Bot-Signature and JWT)
- GET /health (public; no JWT required)
- GET /stats

### Header Naming Conventions

FastAPI Header dependencies use snake_case parameter names that map to HTTP header names by converting underscores to hyphens and capitalizing appropriately. Examples:
- `x_signature_ed25519` → `X-Signature-Ed25519`
- `x_signature_timestamp` → `X-Signature-Timestamp`
- `x_telegram_bot_api_secret_token` → `X-Telegram-Bot-Api-Secret-Token`
- `x_twitter_webhooks_signature` → `X-Twitter-Webhooks-Signature`

LinkShield implements comprehensive rate limiting per authentication method:

| Endpoint Type | JWT Token Limit | API Key Limit | Scope |
|---------------|----------------|---------------|-------|
| Authentication | 5/minute | N/A | Per IP |
| URL Analysis | 30/minute | 100/minute | Per user |
| AI Analysis | 10/minute | 50/minute | Per user |
| Reports | 20/minute | 20/minute | Per user |
| General API | 100/minute | 200/minute | Per user |

Rate limit headers are included in all responses:

```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1642262400
```

### Security Headers

LinkShield includes comprehensive security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

### CORS Configuration

**Development Environment:**
- Allowed Origins: `http://localhost:3000`, `http://127.0.0.1:3000`
- Allowed Methods: All methods
- Allowed Headers: All headers
- Credentials: Enabled

**Production Environment:**
- Allowed Origins: Configured via `ALLOWED_ORIGINS` environment variable
- Allowed Methods: All methods
- Allowed Headers: `Authorization`, `Content-Type`
- Credentials: Enabled
- Trusted Hosts: Configured via `ALLOWED_HOSTS`

### Password Security

- **Hashing**: bcrypt with salt rounds
- **Reset Tokens**: Cryptographically secure, 1-hour expiration
- **Account Lockout**: 5 failed attempts, 30-minute lockout
- **Password History**: Previous passwords cannot be reused

### Email Verification

Email verification is required for new accounts:

**Verify Email:**
```bash
curl -X POST "http://localhost:8000/api/v1/user/verify-email/{token}"
```

**Resend Verification:**
```bash
curl -X POST "http://localhost:8000/api/v1/user/resend-verification" \
  -H "Authorization: Bearer <jwt_token>"
```

## Error Handling

### Authentication Errors

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Invalid email/password |
| `ACCOUNT_LOCKED` | 423 | Account locked due to failed attempts |
| `EMAIL_NOT_VERIFIED` | 403 | Email verification required |
| `TOKEN_EXPIRED` | 401 | JWT token has expired |
| `INVALID_TOKEN` | 401 | Malformed or invalid token |
| `SESSION_EXPIRED` | 401 | Session no longer valid |
| `INSUFFICIENT_PERMISSIONS` | 403 | API key lacks required permissions |
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "details": {
      "field": "password",
      "attempts_remaining": 3
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Best Practices

### For Web Applications
1. Use JWT tokens for user authentication
2. Implement automatic token refresh
3. Store tokens securely (httpOnly cookies recommended)
4. Handle token expiration gracefully
5. Implement proper logout functionality

### For Server Integrations
1. Use API keys for automated systems
2. Rotate API keys regularly
3. Use minimal required permissions
4. Monitor API key usage
5. Implement proper error handling

### Security Recommendations
1. Always use HTTPS in production
2. Validate all input data
3. Implement proper CORS policies
4. Monitor authentication logs
5. Use strong, unique passwords
6. Enable email verification
7. Implement rate limiting on client side

## Code Examples

### JavaScript/TypeScript

```typescript
class LinkShieldClient {
  private baseUrl: string;
  private apiKey?: string;
  private token?: string;

  constructor(baseUrl: string, apiKey?: string) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  async login(email: string, password: string): Promise<LoginResponse> {
    const response = await fetch(`${this.baseUrl}/api/v1/user/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();
    if (data.access_token) {
      this.token = data.access_token;
    }
    return data;
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    } else if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    return headers;
  }

  async checkUrl(url: string): Promise<any> {
    const response = await fetch(`${this.baseUrl}/api/v1/url-check/check`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ url, scan_type: 'comprehensive' })
    });

    return response.json();
  }
}
```

### Python

```python
import requests
from typing import Optional, Dict, Any

class LinkShieldClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key
        self.token: Optional[str] = None
        self.session = requests.Session()

    def login(self, email: str, password: str) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}/api/v1/user/login",
            json={"email": email, "password": password}
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get("access_token"):
            self.token = data["access_token"]
            
        return data

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.api_key:
            headers["X-API-Key"] = self.api_key
            
        return headers

    def check_url(self, url: str) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.base_url}/api/v1/url-check/check",
            json={"url": url, "scan_type": "comprehensive"},
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
```

---

**Next Steps:**
- Review [URL Analysis Endpoints](endpoints/url-analysis.md) for core functionality
- Check [Rate Limiting](rate-limiting.md) for detailed quota information
- See [Error Handling](error-handling.md) for comprehensive error reference