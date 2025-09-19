# User Management Endpoints

LinkShield's user management system provides comprehensive account operations including registration, authentication, profile management, API key management, session control, and email verification. This guide covers all user-related endpoints and their functionality.

## Overview

The user management system handles:

- **Account Registration**: User signup with email verification
- **Authentication**: Login/logout with JWT tokens and sessions
- **Profile Management**: User profile updates and preferences
- **API Key Management**: Create, list, and delete API keys
- **Session Management**: Active session tracking and control
- **Password Management**: Password changes and reset functionality
- **Email Verification**: Account verification and re-verification

## Base URL

```
https://api.linkshield.com/api/v1/user
```

## Authentication

Most user management endpoints require authentication via JWT token:

```
Authorization: Bearer <jwt_token>
```

Public endpoints (registration, login, password reset) do not require authentication.

## Endpoints

### 1. User Registration

Create a new user account with email verification.

**Endpoint:** `POST /register`

**Authentication:** Not required

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "full_name": "John Doe",
  "company": "Example Corp",
  "accept_terms": true,
  "marketing_consent": false
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Valid email address |
| `password` | string | Yes | Password meeting security requirements |
| `full_name` | string | Yes | User's full name (2-100 characters) |
| `company` | string | No | Company name (optional) |
| `accept_terms` | boolean | Yes | Must be `true` to accept terms |
| `marketing_consent` | boolean | No | Opt-in for marketing emails |

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

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

**Status Codes:**
- `201 Created`: User registered successfully
- `400 Bad Request`: Invalid input data
- `409 Conflict`: Email already exists
- `422 Unprocessable Entity`: Validation errors

**Example Request:**
```bash
curl -X POST "https://api.linkshield.com/api/v1/user/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!",
    "full_name": "John Doe",
    "company": "Example Corp",
    "accept_terms": true,
    "marketing_consent": false
  }'
```

### 2. User Login

Authenticate user and receive JWT token.

**Endpoint:** `POST /login`

**Authentication:** Not required

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "remember_me": true,
  "device_info": {
    "browser": "Chrome",
    "os": "Windows 10",
    "ip_address": "192.168.1.100"
  }
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User's email address |
| `password` | string | Yes | User's password |
| `remember_me` | boolean | No | Extend session duration (30 days vs 7 days) |
| `device_info` | object | No | Device information for session tracking |

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
    "is_verified": true,
    "subscription_plan": {
      "name": "Pro",
      "active": true
    }
  },
  "session_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

**Status Codes:**
- `200 OK`: Login successful
- `400 Bad Request`: Invalid credentials
- `401 Unauthorized`: Authentication failed
- `403 Forbidden`: Account locked or unverified
- `423 Locked`: Account temporarily locked

### 3. User Logout

Invalidate current session and JWT token.

**Endpoint:** `POST /logout`

**Authentication:** Required

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

**Example Request:**
```bash
curl -X POST "https://api.linkshield.com/api/v1/user/logout" \
  -H "Authorization: Bearer <jwt_token>"
```

### 4. Get User Profile

Retrieve current user's profile information.

**Endpoint:** `GET /profile`

**Authentication:** Required

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "full_name": "John Doe",
  "company": "Example Corp",
  "role": "USER",
  "subscription_plan": {
    "id": 2,
    "name": "Pro",
    "price": 29.99,
    "active": true,
    "features": ["unlimited_scans", "api_access", "priority_support"]
  },
  "is_active": true,
  "is_verified": true,
  "email_notifications": true,
  "marketing_consent": false,
  "timezone": "UTC",
  "language": "en",
  "created_at": "2024-01-15T10:30:00Z",
  "last_login": "2024-01-20T14:22:00Z",
  "usage_stats": {
    "total_scans": 1250,
    "scans_this_month": 89,
    "api_calls_this_month": 456
  }
}
```

### 5. Update User Profile

Update user profile information.

**Endpoint:** `PUT /profile`

**Authentication:** Required

**Request Body:**
```json
{
  "full_name": "John Smith",
  "company": "New Company Inc",
  "email_notifications": true,
  "marketing_consent": false,
  "timezone": "America/New_York",
  "language": "en"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `full_name` | string | No | User's full name |
| `company` | string | No | Company name |
| `email_notifications` | boolean | No | Enable email notifications |
| `marketing_consent` | boolean | No | Marketing email consent |
| `timezone` | string | No | User's timezone |
| `language` | string | No | Preferred language |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "full_name": "John Smith",
  "company": "New Company Inc",
  "email_notifications": true,
  "marketing_consent": false,
  "timezone": "America/New_York",
  "language": "en",
  "updated_at": "2024-01-20T15:30:00Z"
}
```

### 6. Change Password

Change user's password with current password verification.

**Endpoint:** `POST /change-password`

**Authentication:** Required

**Request Body:**
```json
{
  "current_password": "OldPassword123!",
  "new_password": "NewSecurePass456!",
  "confirm_password": "NewSecurePass456!"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `current_password` | string | Yes | Current password for verification |
| `new_password` | string | Yes | New password meeting requirements |
| `confirm_password` | string | Yes | Must match new_password |

**Response:**
```json
{
  "message": "Password changed successfully",
  "password_changed_at": "2024-01-20T15:45:00Z"
}
```

**Status Codes:**
- `200 OK`: Password changed successfully
- `400 Bad Request`: Invalid current password
- `422 Unprocessable Entity`: Password validation failed

### 7. Request Password Reset

Request password reset for forgotten passwords.

**Endpoint:** `POST /request-password-reset`

**Authentication:** Not required

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "message": "Password reset email sent if account exists",
  "email": "user@example.com"
}
```

**Note:** For security, this endpoint always returns success even if the email doesn't exist.

### 8. Reset Password

Reset password using the token from email.

**Endpoint:** `POST /reset-password`

**Authentication:** Not required

**Request Body:**
```json
{
  "token": "reset_token_from_email",
  "new_password": "NewSecurePass456!",
  "confirm_password": "NewSecurePass456!"
}
```

**Response:**
```json
{
  "message": "Password reset successfully",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## API Key Management

### 9. Create API Key

Generate a new API key for programmatic access.

**Endpoint:** `POST /api-keys`

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Production Integration",
  "description": "API key for production URL scanning",
  "expires_at": "2024-12-31T23:59:59Z",
  "permissions": ["url_check", "ai_analysis"]
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Descriptive name for the API key |
| `description` | string | No | Optional description |
| `expires_at` | datetime | No | Expiration date (max 1 year) |
| `permissions` | array | No | Specific permissions (default: all) |

**Available Permissions:**
- `url_check`: URL analysis endpoints
- `ai_analysis`: AI content analysis
- `reports`: Community reporting
- `profile`: Profile management
- `admin`: Administrative functions (admin users only)

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

**Important:** The full API key is only shown once during creation. Store it securely.

### 10. List API Keys

Retrieve all API keys for the authenticated user.

**Endpoint:** `GET /api-keys`

**Authentication:** Required

**Response:**
```json
[
  {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "Production Integration",
    "description": "API key for production URL scanning",
    "key_preview": "lsk_live_12345678...",
    "permissions": ["url_check", "ai_analysis"],
    "is_active": true,
    "expires_at": "2024-12-31T23:59:59Z",
    "last_used": "2024-01-20T14:30:00Z",
    "usage_count": 1250,
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

### 11. Delete API Key

Permanently delete an API key.

**Endpoint:** `DELETE /api-keys/{key_id}`

**Authentication:** Required

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key_id` | UUID | Yes | API key ID to delete |

**Response:**
```json
{
  "message": "API key deleted successfully",
  "deleted_key_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

## Session Management

### 12. List Active Sessions

Get all active sessions for the authenticated user.

**Endpoint:** `GET /sessions`

**Authentication:** Required

**Response:**
```json
[
  {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "device_info": {
      "browser": "Chrome",
      "os": "Windows 10",
      "ip_address": "192.168.1.100"
    },
    "location": {
      "country": "United States",
      "city": "New York",
      "region": "NY"
    },
    "is_current": true,
    "created_at": "2024-01-20T10:00:00Z",
    "last_activity": "2024-01-20T15:30:00Z",
    "expires_at": "2024-01-27T10:00:00Z"
  },
  {
    "id": "456e7890-e89b-12d3-a456-426614174001",
    "device_info": {
      "browser": "Safari",
      "os": "macOS",
      "ip_address": "192.168.1.101"
    },
    "location": {
      "country": "United States",
      "city": "San Francisco",
      "region": "CA"
    },
    "is_current": false,
    "created_at": "2024-01-19T14:00:00Z",
    "last_activity": "2024-01-19T18:45:00Z",
    "expires_at": "2024-01-26T14:00:00Z"
  }
]
```

### 13. Revoke Session

Terminate a specific session.

**Endpoint:** `DELETE /sessions/{session_id}`

**Authentication:** Required

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_id` | UUID | Yes | Session ID to revoke |

**Response:**
```json
{
  "message": "Session revoked successfully",
  "revoked_session_id": "456e7890-e89b-12d3-a456-426614174001"
}
```

### 14. Terminate All Sessions

Revoke all sessions except the current one.

**Endpoint:** `DELETE /sessions`

**Authentication:** Required

**Response:**
```json
{
  "message": "All sessions terminated successfully",
  "terminated_count": 3,
  "current_session_preserved": true
}
```

## Email Verification

### 15. Verify Email Address

Verify email address using token from verification email.

**Endpoint:** `POST /verify-email/{token}`

**Authentication:** Not required

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | Yes | Verification token from email |

**Response:**
```json
{
  "message": "Email verified successfully",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "verified_at": "2024-01-15T11:00:00Z"
}
```

**Status Codes:**
- `200 OK`: Email verified successfully
- `400 Bad Request`: Invalid or expired token
- `409 Conflict`: Email already verified

### 16. Resend Verification Email

Request a new verification email.

**Endpoint:** `POST /resend-verification`

**Authentication:** Required

**Response:**
```json
{
  "message": "Verification email sent",
  "email": "user@example.com",
  "sent_at": "2024-01-15T11:15:00Z"
}
```

## Rate Limits

User management endpoints have specific rate limits to prevent abuse:

| Endpoint | Limit | Scope | Window |
|----------|-------|-------|--------|
| Registration | 5 attempts | Per IP | 1 hour |
| Login | 10 attempts | Per IP | 15 minutes |
| Password Reset | 3 requests | Per email | 1 hour |
| Email Verification | 5 requests | Per user | 1 hour |
| Profile Updates | 20 requests | Per user | 1 hour |
| API Key Operations | 10 requests | Per user | 1 hour |
| Session Management | 50 requests | Per user | 1 hour |

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1642262400
X-RateLimit-Scope: ip
```

## Security Features

### Account Protection
- **Password Complexity**: Enforced strong password requirements
- **Account Lockout**: Temporary lockout after failed login attempts
- **Session Security**: Secure session management with device tracking
- **Email Verification**: Required for account activation
- **API Key Security**: Scoped permissions and expiration dates

### Privacy Protection
- **Data Encryption**: All sensitive data encrypted at rest
- **Secure Transmission**: HTTPS required for all endpoints
- **Session Isolation**: Sessions are isolated per device/browser
- **Audit Logging**: All account activities are logged
- **GDPR Compliance**: Data protection and user rights

### Abuse Prevention
- **Rate Limiting**: Comprehensive rate limiting per endpoint
- **IP Tracking**: Suspicious IP activity monitoring
- **Device Fingerprinting**: Unusual device access detection
- **Automated Blocking**: Automatic blocking of malicious requests

## Error Handling

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Invalid email or password |
| `ACCOUNT_LOCKED` | 423 | Account temporarily locked |
| `EMAIL_NOT_VERIFIED` | 403 | Email verification required |
| `EMAIL_ALREADY_EXISTS` | 409 | Email already registered |
| `WEAK_PASSWORD` | 422 | Password doesn't meet requirements |
| `INVALID_TOKEN` | 400 | Invalid or expired token |
| `SESSION_EXPIRED` | 401 | Session no longer valid |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INSUFFICIENT_PERMISSIONS` | 403 | Action not allowed |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "WEAK_PASSWORD",
    "message": "Password does not meet security requirements",
    "details": {
      "requirements": [
        "At least 8 characters",
        "At least one uppercase letter",
        "At least one digit",
        "At least one special character"
      ],
      "missing": ["uppercase", "digit"]
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Code Examples

### JavaScript/TypeScript

```typescript
interface UserRegistration {
  email: string;
  password: string;
  full_name: string;
  company?: string;
  accept_terms: boolean;
  marketing_consent?: boolean;
}

interface LoginRequest {
  email: string;
  password: string;
  remember_me?: boolean;
  device_info?: {
    browser: string;
    os: string;
    ip_address?: string;
  };
}

class UserManagementClient {
  private baseUrl: string;
  private token?: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async register(userData: UserRegistration): Promise<any> {
    const response = await fetch(`${this.baseUrl}/api/v1/user/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData)
    });

    if (!response.ok) {
      throw new Error(`Registration failed: ${response.statusText}`);
    }

    return response.json();
  }

  async login(credentials: LoginRequest): Promise<any> {
    const response = await fetch(`${this.baseUrl}/api/v1/user/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });

    if (!response.ok) {
      throw new Error(`Login failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.token = data.access_token;
    return data;
  }

  async getProfile(): Promise<any> {
    if (!this.token) {
      throw new Error('Not authenticated');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/user/profile`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });

    if (!response.ok) {
      throw new Error(`Failed to get profile: ${response.statusText}`);
    }

    return response.json();
  }

  async updateProfile(updates: Partial<any>): Promise<any> {
    if (!this.token) {
      throw new Error('Not authenticated');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/user/profile`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(updates)
    });

    if (!response.ok) {
      throw new Error(`Failed to update profile: ${response.statusText}`);
    }

    return response.json();
  }

  async createApiKey(keyData: any): Promise<any> {
    if (!this.token) {
      throw new Error('Not authenticated');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/user/api-keys`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(keyData)
    });

    if (!response.ok) {
      throw new Error(`Failed to create API key: ${response.statusText}`);
    }

    return response.json();
  }

  async listApiKeys(): Promise<any[]> {
    if (!this.token) {
      throw new Error('Not authenticated');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/user/api-keys`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });

    if (!response.ok) {
      throw new Error(`Failed to list API keys: ${response.statusText}`);
    }

    return response.json();
  }

  async logout(): Promise<void> {
    if (!this.token) {
      return;
    }

    await fetch(`${this.baseUrl}/api/v1/user/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.token}` }
    });

    this.token = undefined;
  }
}

// Usage example
const client = new UserManagementClient('https://api.linkshield.com');

// Register new user
const user = await client.register({
  email: 'john@example.com',
  password: 'SecurePass123!',
  full_name: 'John Doe',
  company: 'Example Corp',
  accept_terms: true,
  marketing_consent: false
});

// Login
const loginResult = await client.login({
  email: 'john@example.com',
  password: 'SecurePass123!',
  remember_me: true,
  device_info: {
    browser: 'Chrome',
    os: 'Windows 10'
  }
});

// Get profile
const profile = await client.getProfile();
console.log(`Welcome, ${profile.full_name}!`);

// Create API key
const apiKey = await client.createApiKey({
  name: 'My Integration',
  description: 'API key for my application',
  permissions: ['url_check', 'ai_analysis']
});

console.log(`API Key: ${apiKey.api_key}`);
```

### Python

```python
import requests
from typing import Dict, Any, Optional, List

class UserManagementClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.token: Optional[str] = None
        self.session = requests.Session()

    def register(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new user account."""
        response = self.session.post(
            f'{self.base_url}/api/v1/user/register',
            json=user_data
        )
        response.raise_for_status()
        return response.json()

    def login(self, email: str, password: str, remember_me: bool = False, 
              device_info: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Login and get JWT token."""
        payload = {
            'email': email,
            'password': password,
            'remember_me': remember_me
        }
        
        if device_info:
            payload['device_info'] = device_info

        response = self.session.post(
            f'{self.base_url}/api/v1/user/login',
            json=payload
        )
        response.raise_for_status()
        
        data = response.json()
        self.token = data['access_token']
        self.session.headers.update({
            'Authorization': f'Bearer {self.token}'
        })
        
        return data

    def get_profile(self) -> Dict[str, Any]:
        """Get user profile information."""
        self._ensure_authenticated()
        
        response = self.session.get(f'{self.base_url}/api/v1/user/profile')
        response.raise_for_status()
        return response.json()

    def update_profile(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update user profile."""
        self._ensure_authenticated()
        
        response = self.session.put(
            f'{self.base_url}/api/v1/user/profile',
            json=updates
        )
        response.raise_for_status()
        return response.json()

    def change_password(self, current_password: str, new_password: str) -> Dict[str, Any]:
        """Change user password."""
        self._ensure_authenticated()
        
        response = self.session.post(
            f'{self.base_url}/api/v1/user/change-password',
            json={
                'current_password': current_password,
                'new_password': new_password,
                'confirm_password': new_password
            }
        )
        response.raise_for_status()
        return response.json()

    def create_api_key(self, name: str, description: str = None, 
                      permissions: List[str] = None, 
                      expires_at: str = None) -> Dict[str, Any]:
        """Create a new API key."""
        self._ensure_authenticated()
        
        payload = {'name': name}
        if description:
            payload['description'] = description
        if permissions:
            payload['permissions'] = permissions
        if expires_at:
            payload['expires_at'] = expires_at

        response = self.session.post(
            f'{self.base_url}/api/v1/user/api-keys',
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def list_api_keys(self) -> List[Dict[str, Any]]:
        """List all API keys."""
        self._ensure_authenticated()
        
        response = self.session.get(f'{self.base_url}/api/v1/user/api-keys')
        response.raise_for_status()
        return response.json()

    def delete_api_key(self, key_id: str) -> Dict[str, Any]:
        """Delete an API key."""
        self._ensure_authenticated()
        
        response = self.session.delete(
            f'{self.base_url}/api/v1/user/api-keys/{key_id}'
        )
        response.raise_for_status()
        return response.json()

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List active sessions."""
        self._ensure_authenticated()
        
        response = self.session.get(f'{self.base_url}/api/v1/user/sessions')
        response.raise_for_status()
        return response.json()

    def revoke_session(self, session_id: str) -> Dict[str, Any]:
        """Revoke a specific session."""
        self._ensure_authenticated()
        
        response = self.session.delete(
            f'{self.base_url}/api/v1/user/sessions/{session_id}'
        )
        response.raise_for_status()
        return response.json()

    def terminate_all_sessions(self) -> Dict[str, Any]:
        """Terminate all sessions except current."""
        self._ensure_authenticated()
        
        response = self.session.delete(f'{self.base_url}/api/v1/user/sessions')
        response.raise_for_status()
        return response.json()

    def logout(self) -> None:
        """Logout and clear token."""
        if self.token:
            try:
                self.session.post(f'{self.base_url}/api/v1/user/logout')
            except:
                pass  # Ignore errors during logout
            
            self.token = None
            if 'Authorization' in self.session.headers:
                del self.session.headers['Authorization']

    def _ensure_authenticated(self) -> None:
        """Ensure user is authenticated."""
        if not self.token:
            raise ValueError('Not authenticated. Please login first.')

# Usage example
client = UserManagementClient('https://api.linkshield.com')

# Register new user
user = client.register({
    'email': 'john@example.com',
    'password': 'SecurePass123!',
    'full_name': 'John Doe',
    'company': 'Example Corp',
    'accept_terms': True,
    'marketing_consent': False
})

print(f"User registered: {user['id']}")

# Login
login_result = client.login(
    email='john@example.com',
    password='SecurePass123!',
    remember_me=True,
    device_info={
        'browser': 'Chrome',
        'os': 'Linux'
    }
)

print(f"Logged in successfully. Token expires in {login_result['expires_in']} seconds")

# Get profile
profile = client.get_profile()
print(f"Welcome, {profile['full_name']}!")

# Create API key
api_key = client.create_api_key(
    name='My Integration',
    description='API key for my Python application',
    permissions=['url_check', 'ai_analysis']
)

print(f"API Key created: {api_key['key_preview']}")
print(f"Full key (store securely): {api_key['api_key']}")

# List sessions
sessions = client.list_sessions()
print(f"Active sessions: {len(sessions)}")

for session in sessions:
    print(f"Session {session['id']}: {session['device_info']['browser']} on {session['device_info']['os']}")
```

## Best Practices

### Security
1. **Store JWT tokens securely** (httpOnly cookies recommended for web apps)
2. **Implement proper logout** to invalidate sessions
3. **Use strong passwords** and enforce password policies
4. **Rotate API keys regularly** and use minimal permissions
5. **Monitor session activity** for suspicious behavior
6. **Implement proper error handling** without exposing sensitive information

### User Experience
1. **Provide clear error messages** for validation failures
2. **Implement password strength indicators** during registration
3. **Show session information** to help users manage their accounts
4. **Send email notifications** for important account changes
5. **Provide easy password reset** functionality

### Integration
1. **Handle rate limits gracefully** with exponential backoff
2. **Implement proper token refresh** for long-running applications
3. **Use webhooks** for real-time account updates
4. **Cache user profile data** to reduce API calls
5. **Implement proper logging** for debugging and monitoring

---

**Next Steps:**
- Review [Authentication Guide](../authentication.md) for detailed security information
- Check [Rate Limiting](../rate-limiting.md) for quota management
- See [Error Handling](../error-handling.md) for comprehensive error reference