# Admin Configuration Management API Documentation

## Overview

The Admin Configuration Management API provides comprehensive system configuration capabilities for LinkShield administrators. These endpoints allow administrators to manage system settings, security policies, feature flags, notification preferences, integration settings, and performance parameters.

**Base URL**: `/api/v1/admin/configuration`  
**Authentication**: Required (Admin or Super Admin role)  
**Content-Type**: `application/json`

## Authentication

All configuration endpoints require authentication with a valid JWT token and Admin or Super Admin role:

```http
Authorization: Bearer <jwt_token>
```

### Role Requirements
- **Admin**: Read access to most configurations, limited write access
- **Super Admin**: Full read/write access to all configuration categories

## Configuration Categories

The system supports six main configuration categories:

1. **System Settings** - Core system parameters and operational settings
2. **Security Policies** - Security rules, rate limits, and access controls
3. **Feature Flags** - Feature toggles and experimental functionality
4. **Notification Settings** - Email, SMS, and webhook notification preferences
5. **Integration Settings** - Third-party service configurations and API keys
6. **Performance Settings** - Caching, timeouts, and resource limits

## Endpoints

### 1. Get All Configurations

Retrieve all configuration categories and their current values.

**Endpoint**: `GET /api/v1/admin/configuration`

#### Request

```http
GET /api/v1/admin/configuration HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "system_settings": {
      "app_name": "LinkShield",
      "app_version": "2.1.0",
      "maintenance_mode": false,
      "max_users": 100000,
      "default_user_quota": 1000,
      "session_timeout_minutes": 60,
      "timezone": "UTC",
      "date_format": "YYYY-MM-DD",
      "time_format": "24h"
    },
    "security_policies": {
      "password_min_length": 8,
      "password_require_special": true,
      "password_require_numbers": true,
      "password_require_uppercase": true,
      "max_login_attempts": 5,
      "lockout_duration_minutes": 30,
      "jwt_expiry_hours": 24,
      "rate_limit_per_minute": 100,
      "enable_2fa": true,
      "allowed_domains": ["linkshield.com", "*.linkshield.com"]
    },
    "feature_flags": {
      "enable_batch_processing": true,
      "enable_api_v2": false,
      "enable_advanced_analytics": true,
      "enable_real_time_scanning": true,
      "enable_machine_learning": true,
      "enable_custom_rules": false,
      "beta_features_enabled": false
    },
    "notification_settings": {
      "email_enabled": true,
      "sms_enabled": false,
      "webhook_enabled": true,
      "admin_email": "admin@linkshield.com",
      "smtp_host": "smtp.linkshield.com",
      "smtp_port": 587,
      "smtp_use_tls": true,
      "notification_frequency": "immediate",
      "digest_enabled": true,
      "digest_frequency": "daily"
    },
    "integration_settings": {
      "virustotal_enabled": true,
      "virustotal_api_key": "vt_***masked***",
      "urlvoid_enabled": true,
      "urlvoid_api_key": "uv_***masked***",
      "safebrowsing_enabled": true,
      "safebrowsing_api_key": "sb_***masked***",
      "webhook_url": "https://hooks.linkshield.com/admin",
      "webhook_secret": "***masked***",
      "external_logging": false
    },
    "performance_settings": {
      "cache_ttl_seconds": 3600,
      "max_concurrent_scans": 50,
      "scan_timeout_seconds": 30,
      "database_pool_size": 20,
      "redis_pool_size": 10,
      "worker_processes": 4,
      "memory_limit_mb": 2048,
      "cpu_limit_percent": 80
    }
  },
  "metadata": {
    "last_updated": "2024-01-15T10:30:00Z",
    "updated_by": "admin@linkshield.com",
    "version": "1.2.3"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 2. Get Configuration by Category

Retrieve configuration settings for a specific category.

**Endpoint**: `GET /api/v1/admin/configuration/{category}`

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `category` | string | Yes | Configuration category name |

#### Valid Categories

- `system_settings`
- `security_policies`
- `feature_flags`
- `notification_settings`
- `integration_settings`
- `performance_settings`

#### Request

```http
GET /api/v1/admin/configuration/security_policies HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "category": "security_policies",
    "settings": {
      "password_min_length": 8,
      "password_require_special": true,
      "password_require_numbers": true,
      "password_require_uppercase": true,
      "max_login_attempts": 5,
      "lockout_duration_minutes": 30,
      "jwt_expiry_hours": 24,
      "rate_limit_per_minute": 100,
      "enable_2fa": true,
      "allowed_domains": ["linkshield.com", "*.linkshield.com"]
    },
    "schema": {
      "password_min_length": {
        "type": "integer",
        "min": 6,
        "max": 32,
        "description": "Minimum password length requirement"
      },
      "password_require_special": {
        "type": "boolean",
        "description": "Require special characters in passwords"
      },
      "max_login_attempts": {
        "type": "integer",
        "min": 3,
        "max": 10,
        "description": "Maximum failed login attempts before lockout"
      }
    }
  },
  "metadata": {
    "last_updated": "2024-01-15T09:15:00Z",
    "updated_by": "admin@linkshield.com"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 3. Update Configuration Category

Update configuration settings for a specific category.

**Endpoint**: `PUT /api/v1/admin/configuration/{category}`

#### Request Body Schema

```json
{
  "settings": {
    "password_min_length": 10,
    "max_login_attempts": 3,
    "enable_2fa": true
  },
  "reason": "Strengthening security policies per security audit recommendations"
}
```

#### Request

```http
PUT /api/v1/admin/configuration/security_policies HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "settings": {
    "password_min_length": 10,
    "max_login_attempts": 3,
    "lockout_duration_minutes": 60
  },
  "reason": "Enhanced security requirements"
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "category": "security_policies",
    "updated_settings": {
      "password_min_length": 10,
      "max_login_attempts": 3,
      "lockout_duration_minutes": 60
    },
    "previous_values": {
      "password_min_length": 8,
      "max_login_attempts": 5,
      "lockout_duration_minutes": 30
    },
    "validation_results": {
      "valid": true,
      "warnings": [
        "Reduced max_login_attempts may increase support requests"
      ]
    }
  },
  "metadata": {
    "updated_at": "2024-01-15T10:30:00Z",
    "updated_by": "admin@linkshield.com",
    "change_id": "cfg_change_12345"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 4. Update Individual Setting

Update a single configuration setting within a category.

**Endpoint**: `PATCH /api/v1/admin/configuration/{category}/{setting}`

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `category` | string | Yes | Configuration category name |
| `setting` | string | Yes | Setting key name |

#### Request Body Schema

```json
{
  "value": "new_value",
  "reason": "Explanation for the change"
}
```

#### Request

```http
PATCH /api/v1/admin/configuration/system_settings/maintenance_mode HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "value": true,
  "reason": "Scheduled maintenance for database migration"
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "category": "system_settings",
    "setting": "maintenance_mode",
    "new_value": true,
    "previous_value": false,
    "effective_immediately": true
  },
  "metadata": {
    "updated_at": "2024-01-15T10:30:00Z",
    "updated_by": "admin@linkshield.com",
    "change_id": "cfg_change_12346"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 5. Reset Configuration Category

Reset a configuration category to default values.

**Endpoint**: `POST /api/v1/admin/configuration/{category}/reset`

#### Request Body Schema

```json
{
  "confirm": true,
  "reason": "Resetting to defaults after testing"
}
```

#### Request

```http
POST /api/v1/admin/configuration/feature_flags/reset HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "confirm": true,
  "reason": "Reverting experimental features after testing phase"
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "category": "feature_flags",
    "reset_settings": {
      "enable_batch_processing": true,
      "enable_api_v2": false,
      "enable_advanced_analytics": true,
      "beta_features_enabled": false
    },
    "previous_values": {
      "enable_batch_processing": false,
      "enable_api_v2": true,
      "enable_advanced_analytics": false,
      "beta_features_enabled": true
    }
  },
  "metadata": {
    "reset_at": "2024-01-15T10:30:00Z",
    "reset_by": "admin@linkshield.com",
    "change_id": "cfg_reset_12347"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 6. Get Configuration History

Retrieve change history for configuration settings.

**Endpoint**: `GET /api/admin/configuration/history`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `category` | string | No | all | Filter by category |
| `setting` | string | No | all | Filter by specific setting |
| `days` | integer | No | 30 | Number of days to retrieve (1-365) |
| `limit` | integer | No | 50 | Maximum number of records (1-500) |

#### Request

```http
GET /api/admin/configuration/history?category=security_policies&days=7 HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "changes": [
      {
        "id": "cfg_change_12345",
        "category": "security_policies",
        "setting": "password_min_length",
        "old_value": 8,
        "new_value": 10,
        "changed_by": "admin@linkshield.com",
        "changed_at": "2024-01-15T10:30:00Z",
        "reason": "Enhanced security requirements",
        "change_type": "update"
      },
      {
        "id": "cfg_change_12344",
        "category": "security_policies",
        "setting": "enable_2fa",
        "old_value": false,
        "new_value": true,
        "changed_by": "superadmin@linkshield.com",
        "changed_at": "2024-01-14T15:20:00Z",
        "reason": "Mandatory 2FA implementation",
        "change_type": "update"
      }
    ],
    "pagination": {
      "total": 15,
      "page": 1,
      "per_page": 50,
      "has_more": false
    }
  },
  "metadata": {
    "filters": {
      "category": "security_policies",
      "days": 7
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 7. Validate Configuration

Validate configuration settings before applying changes.

**Endpoint**: `POST /api/admin/configuration/validate`

#### Request Body Schema

```json
{
  "category": "security_policies",
  "settings": {
    "password_min_length": 4,
    "max_login_attempts": 15,
    "jwt_expiry_hours": 168
  }
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "valid": false,
    "errors": [
      {
        "setting": "password_min_length",
        "error": "Value must be at least 6",
        "current_value": 4,
        "min_value": 6
      },
      {
        "setting": "max_login_attempts",
        "error": "Value exceeds maximum allowed",
        "current_value": 15,
        "max_value": 10
      }
    ],
    "warnings": [
      {
        "setting": "jwt_expiry_hours",
        "warning": "Long JWT expiry may pose security risks",
        "current_value": 168,
        "recommended_max": 72
      }
    ],
    "valid_settings": {
      "jwt_expiry_hours": 168
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Configuration Schema Details

### System Settings

| Setting | Type | Default | Description | Constraints |
|---------|------|---------|-------------|-------------|
| `app_name` | string | "LinkShield" | Application display name | 1-50 characters |
| `app_version` | string | "2.1.0" | Current application version | Semantic version format |
| `maintenance_mode` | boolean | false | Enable maintenance mode | - |
| `max_users` | integer | 100000 | Maximum user limit | 1000-1000000 |
| `default_user_quota` | integer | 1000 | Default URL check quota | 100-10000 |
| `session_timeout_minutes` | integer | 60 | User session timeout | 15-480 |
| `timezone` | string | "UTC" | System timezone | Valid timezone identifier |

### Security Policies

| Setting | Type | Default | Description | Constraints |
|---------|------|---------|-------------|-------------|
| `password_min_length` | integer | 8 | Minimum password length | 6-32 |
| `password_require_special` | boolean | true | Require special characters | - |
| `password_require_numbers` | boolean | true | Require numeric characters | - |
| `password_require_uppercase` | boolean | true | Require uppercase letters | - |
| `max_login_attempts` | integer | 5 | Max failed login attempts | 3-10 |
| `lockout_duration_minutes` | integer | 30 | Account lockout duration | 5-1440 |
| `jwt_expiry_hours` | integer | 24 | JWT token expiry time | 1-168 |
| `rate_limit_per_minute` | integer | 100 | API rate limit per user | 10-1000 |
| `enable_2fa` | boolean | true | Enable two-factor auth | - |
| `allowed_domains` | array | ["linkshield.com"] | Allowed email domains | Valid domain patterns |

### Feature Flags

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable_batch_processing` | boolean | true | Enable batch URL processing |
| `enable_api_v2` | boolean | false | Enable API version 2 |
| `enable_advanced_analytics` | boolean | true | Enable advanced analytics |
| `enable_real_time_scanning` | boolean | true | Enable real-time URL scanning |
| `enable_machine_learning` | boolean | true | Enable ML-based detection |
| `enable_custom_rules` | boolean | false | Enable custom detection rules |
| `beta_features_enabled` | boolean | false | Enable beta features |

### Notification Settings

| Setting | Type | Default | Description | Constraints |
|---------|------|---------|-------------|-------------|
| `email_enabled` | boolean | true | Enable email notifications | - |
| `sms_enabled` | boolean | false | Enable SMS notifications | - |
| `webhook_enabled` | boolean | true | Enable webhook notifications | - |
| `admin_email` | string | "admin@linkshield.com" | Admin email address | Valid email format |
| `smtp_host` | string | "smtp.linkshield.com" | SMTP server hostname | Valid hostname |
| `smtp_port` | integer | 587 | SMTP server port | 1-65535 |
| `smtp_use_tls` | boolean | true | Use TLS for SMTP | - |
| `notification_frequency` | string | "immediate" | Notification frequency | immediate, hourly, daily |

### Integration Settings

| Setting | Type | Default | Description | Constraints |
|---------|------|---------|-------------|-------------|
| `virustotal_enabled` | boolean | true | Enable VirusTotal integration | - |
| `virustotal_api_key` | string | "" | VirusTotal API key | Masked in responses |
| `urlvoid_enabled` | boolean | true | Enable URLVoid integration | - |
| `urlvoid_api_key` | string | "" | URLVoid API key | Masked in responses |
| `safebrowsing_enabled` | boolean | true | Enable Safe Browsing API | - |
| `safebrowsing_api_key` | string | "" | Safe Browsing API key | Masked in responses |
| `webhook_url` | string | "" | Webhook endpoint URL | Valid URL format |
| `webhook_secret` | string | "" | Webhook secret key | Masked in responses |

### Performance Settings

| Setting | Type | Default | Description | Constraints |
|---------|------|---------|-------------|-------------|
| `cache_ttl_seconds` | integer | 3600 | Cache time-to-live | 300-86400 |
| `max_concurrent_scans` | integer | 50 | Max concurrent URL scans | 10-200 |
| `scan_timeout_seconds` | integer | 30 | URL scan timeout | 10-120 |
| `database_pool_size` | integer | 20 | Database connection pool | 5-100 |
| `redis_pool_size` | integer | 10 | Redis connection pool | 2-50 |
| `worker_processes` | integer | 4 | Background worker processes | 1-16 |
| `memory_limit_mb` | integer | 2048 | Memory limit per process | 512-8192 |
| `cpu_limit_percent` | integer | 80 | CPU usage limit | 50-95 |

## Error Handling

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Invalid or missing authentication token |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `INVALID_CATEGORY` | 400 | Invalid configuration category |
| `INVALID_SETTING` | 400 | Invalid setting name |
| `VALIDATION_FAILED` | 400 | Setting value validation failed |
| `SETTING_READONLY` | 403 | Attempting to modify read-only setting |
| `RATE_LIMITED` | 429 | Too many configuration changes |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Configuration validation failed",
    "details": {
      "setting": "password_min_length",
      "value": 4,
      "constraint": "Must be at least 6 characters"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Usage Examples

### cURL Examples

#### Get All Configurations

```bash
curl -X GET "https://api.linkshield.com/api/v1/admin/configuration" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

#### Update Security Policies

```bash
curl -X PUT "https://api.linkshield.com/api/v1/admin/configuration/security_policies" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "settings": {
      "password_min_length": 10,
      "enable_2fa": true
    },
    "reason": "Enhanced security requirements"
  }'
```

#### Enable Maintenance Mode

```bash
curl -X PATCH "https://api.linkshield.com/api/v1/admin/configuration/system" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "value": true,
    "reason": "Scheduled maintenance"
  }'
```

### JavaScript/Fetch Examples

```javascript
// Get configuration category
const getSecurityPolicies = async () => {
  const response = await fetch('/api/admin/configuration/security_policies', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  return await response.json();
};

// Update multiple settings
const updateFeatureFlags = async (settings, reason) => {
  const response = await fetch('/api/admin/configuration/feature_flags', {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ settings, reason })
  });
  
  return await response.json();
};

// Validate configuration before applying
const validateConfig = async (category, settings) => {
  const response = await fetch('/api/admin/configuration/validate', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ category, settings })
  });
  
  return await response.json();
};
```

## Security Considerations

### Access Control

- Configuration changes are logged in the audit system
- Sensitive values (API keys, secrets) are masked in responses
- Role-based access controls limit configuration modifications
- Super Admin role required for critical system settings

### Change Management

- All configuration changes require a reason/justification
- Previous values are stored for rollback capabilities
- Configuration history is maintained for audit purposes
- Validation prevents invalid or dangerous configurations

### Best Practices

1. **Test configurations** in a staging environment first
2. **Use validation endpoint** before applying changes
3. **Monitor system behavior** after configuration changes
4. **Keep configuration history** for compliance and debugging
5. **Implement gradual rollouts** for feature flag changes
6. **Regular backup** of configuration settings

---

*This documentation is maintained alongside the API implementation and should be updated with any endpoint changes.*