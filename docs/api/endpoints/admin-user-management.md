# Admin User Management API Documentation

## Overview

The Admin User Management API provides comprehensive user administration capabilities for LinkShield administrators. These endpoints allow administrators to view, search, filter, manage user accounts, handle user status changes, and perform bulk operations on user data.

**Base URL**: `/api/v1/admin/users`  
**Authentication**: Required (Admin or Super Admin role)  
**Content-Type**: `application/json`

## Authentication

All user management endpoints require authentication with a valid JWT token and Admin or Super Admin role:

```http
Authorization: Bearer <jwt_token>
```

### Role Requirements
- **Admin**: Full access to user management operations
- **Super Admin**: Full access plus ability to manage admin accounts

## Endpoints

### 1. List Users

Retrieve a paginated list of users with optional filtering and sorting.

**Endpoint**: `GET /api/v1/admin/users`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `page` | integer | No | 1 | Page number (1-based) |
| `per_page` | integer | No | 50 | Items per page (1-500) |
| `search` | string | No | - | Search in name, email, or username |
| `status` | string | No | "all" | Filter by status: "active", "inactive", "suspended", "pending", "all" |
| `subscription` | string | No | "all" | Filter by subscription: "free", "basic", "pro", "enterprise", "all" |
| `role` | string | No | "all" | Filter by role: "user", "admin", "super_admin", "all" |
| `created_after` | string | No | - | Filter users created after date (ISO 8601) |
| `created_before` | string | No | - | Filter users created before date (ISO 8601) |
| `last_active_after` | string | No | - | Filter by last activity after date (ISO 8601) |
| `sort_by` | string | No | "created_at" | Sort field: "created_at", "last_active", "email", "name" |
| `sort_order` | string | No | "desc" | Sort order: "asc", "desc" |

#### Request

```http
GET /api/v1/admin/users?page=1&per_page=25&status=active&subscription=pro&sort_by=last_active HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "user_12345",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "first_name": "John",
        "last_name": "Doe",
        "full_name": "John Doe",
        "status": "active",
        "role": "user",
        "subscription": {
          "plan": "pro",
          "status": "active",
          "expires_at": "2024-12-31T23:59:59Z",
          "auto_renew": true
        },
        "usage_stats": {
          "total_checks": 15420,
          "checks_this_month": 1205,
          "quota_used": 0.75,
          "quota_remaining": 500
        },
        "account_info": {
          "created_at": "2023-06-15T10:30:00Z",
          "last_active": "2024-01-15T09:45:00Z",
          "last_login": "2024-01-15T08:30:00Z",
          "email_verified": true,
          "two_factor_enabled": true,
          "login_count": 342
        },
        "profile": {
          "avatar_url": "https://cdn.linkshield.com/avatars/user_12345.jpg",
          "timezone": "America/New_York",
          "language": "en",
          "notifications_enabled": true
        }
      }
    ],
    "pagination": {
      "current_page": 1,
      "per_page": 25,
      "total_items": 15420,
      "total_pages": 617,
      "has_next": true,
      "has_previous": false,
      "next_page": 2,
      "previous_page": null
    },
    "filters_applied": {
      "status": "active",
      "subscription": "pro",
      "sort_by": "last_active",
      "sort_order": "desc"
    },
    "summary": {
      "total_users": 15420,
      "active_users": 12350,
      "inactive_users": 2234,
      "suspended_users": 567,
      "pending_users": 269
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 2. Get User Details

Retrieve detailed information about a specific user.

**Endpoint**: `GET /api/v1/admin/users/{user_id}`

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | User ID or email address |

#### Request

```http
GET /api/v1/admin/users/user_12345 HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user_12345",
      "email": "john.doe@example.com",
      "username": "johndoe",
      "first_name": "John",
      "last_name": "Doe",
      "full_name": "John Doe",
      "status": "active",
      "role": "user",
      "subscription": {
        "plan": "pro",
        "status": "active",
        "started_at": "2023-12-01T00:00:00Z",
        "expires_at": "2024-12-31T23:59:59Z",
        "auto_renew": true,
        "payment_method": "credit_card",
        "billing_cycle": "annual"
      },
      "usage_stats": {
        "total_checks": 15420,
        "checks_today": 45,
        "checks_this_week": 312,
        "checks_this_month": 1205,
        "quota_limit": 2000,
        "quota_used": 1500,
        "quota_remaining": 500,
        "quota_reset_date": "2024-02-01T00:00:00Z"
      },
      "account_info": {
        "created_at": "2023-06-15T10:30:00Z",
        "updated_at": "2024-01-14T16:20:00Z",
        "last_active": "2024-01-15T09:45:00Z",
        "last_login": "2024-01-15T08:30:00Z",
        "login_count": 342,
        "failed_login_attempts": 0,
        "email_verified": true,
        "email_verified_at": "2023-06-15T10:35:00Z",
        "two_factor_enabled": true,
        "two_factor_enabled_at": "2023-07-01T14:20:00Z"
      },
      "profile": {
        "avatar_url": "https://cdn.linkshield.com/avatars/user_12345.jpg",
        "timezone": "America/New_York",
        "language": "en",
        "date_format": "MM/DD/YYYY",
        "time_format": "12h",
        "notifications_enabled": true,
        "marketing_emails": false
      },
      "security": {
        "password_last_changed": "2023-11-15T10:30:00Z",
        "password_strength": "strong",
        "active_sessions": 2,
        "trusted_devices": 3,
        "recent_login_ips": [
          "192.168.1.100",
          "10.0.0.50"
        ]
      },
      "activity_summary": {
        "most_active_day": "Monday",
        "most_active_hour": 14,
        "avg_checks_per_day": 42.3,
        "favorite_features": [
          "url_check",
          "batch_check",
          "reports"
        ]
      }
    },
    "recent_activity": [
      {
        "id": "activity_789",
        "type": "url_check",
        "description": "Checked URL: https://example.com",
        "timestamp": "2024-01-15T09:45:00Z",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0..."
      }
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 3. Update User Status

Update a user's account status (active, inactive, suspended).

**Endpoint**: `PATCH /api/v1/admin/users/{user_id}/status`

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `user_id` | string | Yes | User ID or email address |

#### Request Body Schema

```json
{
  "status": "suspended",
  "reason": "Violation of terms of service",
  "notify_user": true,
  "suspension_duration_days": 30
}
```

#### Valid Status Values

- `active` - User can access all features
- `inactive` - User account is disabled but not suspended
- `suspended` - User account is temporarily suspended
- `pending` - User account is pending verification

#### Request

```http
PATCH /api/v1/admin/users/user_12345/status HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "status": "suspended",
  "reason": "Excessive API usage beyond fair use policy",
  "notify_user": true,
  "suspension_duration_days": 7
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "user_id": "user_12345",
    "previous_status": "active",
    "new_status": "suspended",
    "status_changed_at": "2024-01-15T10:30:00Z",
    "reason": "Excessive API usage beyond fair use policy",
    "suspension_details": {
      "duration_days": 7,
      "expires_at": "2024-01-22T10:30:00Z",
      "auto_reactivate": true
    },
    "notifications_sent": {
      "email": true,
      "in_app": true
    }
  },
  "metadata": {
    "changed_by": "admin@linkshield.com",
    "change_id": "status_change_12345"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 4. Update User Role

Update a user's role (user, admin, super_admin).

**Endpoint**: `PATCH /api/v1/admin/users/{user_id}/role`

#### Request Body Schema

```json
{
  "role": "admin",
  "reason": "Promoted to admin for customer support duties",
  "notify_user": true
}
```

#### Valid Role Values

- `user` - Standard user with basic access
- `admin` - Administrator with management capabilities
- `super_admin` - Super administrator with full system access (Super Admin only)

#### Request

```http
PATCH /api/v1/admin/users/user_12345/role HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "role": "admin",
  "reason": "Promoted to admin for customer support duties",
  "notify_user": true
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "user_id": "user_12345",
    "previous_role": "user",
    "new_role": "admin",
    "role_changed_at": "2024-01-15T10:30:00Z",
    "reason": "Promoted to admin for customer support duties",
    "permissions_granted": [
      "user_management",
      "system_monitoring",
      "configuration_read"
    ]
  },
  "metadata": {
    "changed_by": "superadmin@linkshield.com",
    "change_id": "role_change_12345"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 5. Reset User Password

Reset a user's password and optionally force password change on next login.

**Endpoint**: `POST /api/v1/admin/users/{user_id}/reset-password`

#### Request Body Schema

```json
{
  "force_change_on_login": true,
  "notify_user": true,
  "reason": "Password reset requested by user"
}
```

#### Request

```http
POST /api/v1/admin/users/user_12345/reset-password HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "force_change_on_login": true,
  "notify_user": true,
  "reason": "User forgot password"
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "user_id": "user_12345",
    "password_reset_at": "2024-01-15T10:30:00Z",
    "temporary_password_sent": true,
    "force_change_on_login": true,
    "reset_token_expires_at": "2024-01-15T22:30:00Z",
    "notifications_sent": {
      "email": true,
      "sms": false
    }
  },
  "metadata": {
    "reset_by": "admin@linkshield.com",
    "reset_id": "password_reset_12345"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 6. Update User Quota

Update a user's API usage quota.

**Endpoint**: `PATCH /api/v1/admin/users/{user_id}/quota`

#### Request Body Schema

```json
{
  "quota_limit": 5000,
  "reset_current_usage": false,
  "reason": "Increased quota for enterprise trial"
}
```

#### Request

```http
PATCH /api/v1/admin/users/user_12345/quota HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "quota_limit": 5000,
  "reset_current_usage": false,
  "reason": "Increased quota for enterprise trial"
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "user_id": "user_12345",
    "previous_quota": 2000,
    "new_quota": 5000,
    "current_usage": 1500,
    "remaining_quota": 3500,
    "quota_updated_at": "2024-01-15T10:30:00Z",
    "next_reset_date": "2024-02-01T00:00:00Z"
  },
  "metadata": {
    "updated_by": "admin@linkshield.com",
    "reason": "Increased quota for enterprise trial"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 7. Get User Activity Log

Retrieve a user's activity history and audit trail.

**Endpoint**: `GET /api/v1/admin/users/{user_id}/activity`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `page` | integer | No | 1 | Page number (1-based) |
| `per_page` | integer | No | 50 | Items per page (1-200) |
| `activity_type` | string | No | "all" | Filter by activity type |
| `date_from` | string | No | - | Start date (ISO 8601) |
| `date_to` | string | No | - | End date (ISO 8601) |
| `include_system` | boolean | No | false | Include system-generated activities |

#### Request

```http
GET /api/v1/admin/users/user_12345/activity?page=1&per_page=25&activity_type=login HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "activities": [
      {
        "id": "activity_789",
        "type": "login",
        "description": "User logged in successfully",
        "timestamp": "2024-01-15T08:30:00Z",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "location": {
          "country": "United States",
          "city": "New York",
          "region": "NY"
        },
        "metadata": {
          "session_id": "session_abc123",
          "device_type": "desktop",
          "browser": "Chrome"
        }
      },
      {
        "id": "activity_788",
        "type": "url_check",
        "description": "Checked URL: https://example.com",
        "timestamp": "2024-01-15T09:45:00Z",
        "ip_address": "192.168.1.100",
        "metadata": {
          "url": "https://example.com",
          "result": "safe",
          "scan_duration_ms": 245
        }
      }
    ],
    "pagination": {
      "current_page": 1,
      "per_page": 25,
      "total_items": 342,
      "total_pages": 14,
      "has_next": true,
      "has_previous": false
    },
    "activity_summary": {
      "total_activities": 342,
      "login_count": 89,
      "url_checks": 234,
      "profile_updates": 12,
      "password_changes": 3
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 8. Bulk User Operations

Perform bulk operations on multiple users.

**Endpoint**: `POST /api/v1/admin/users/bulk`

#### Request Body Schema

```json
{
  "operation": "update_status",
  "user_ids": ["user_12345", "user_12346", "user_12347"],
  "parameters": {
    "status": "inactive",
    "reason": "Bulk deactivation for inactive accounts"
  },
  "notify_users": false
}
```

#### Supported Operations

- `update_status` - Update status for multiple users
- `update_quota` - Update quota for multiple users
- `send_notification` - Send notification to multiple users
- `export_data` - Export user data

#### Request

```http
POST /api/v1/admin/users/bulk HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "operation": "update_status",
  "user_ids": ["user_12345", "user_12346", "user_12347"],
  "parameters": {
    "status": "inactive",
    "reason": "Bulk deactivation for inactive accounts"
  },
  "notify_users": false
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "operation": "update_status",
    "total_users": 3,
    "successful_operations": 2,
    "failed_operations": 1,
    "results": [
      {
        "user_id": "user_12345",
        "status": "success",
        "message": "Status updated successfully"
      },
      {
        "user_id": "user_12346",
        "status": "success",
        "message": "Status updated successfully"
      },
      {
        "user_id": "user_12347",
        "status": "error",
        "message": "User not found",
        "error_code": "USER_NOT_FOUND"
      }
    ],
    "operation_id": "bulk_op_12345"
  },
  "metadata": {
    "executed_by": "admin@linkshield.com",
    "executed_at": "2024-01-15T10:30:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 9. Search Users

Advanced user search with multiple criteria.

**Endpoint**: `POST /api/v1/admin/users/search`

#### Request Body Schema

```json
{
  "query": {
    "email": "john@example.com",
    "name": "John",
    "status": ["active", "inactive"],
    "subscription": ["pro", "enterprise"],
    "created_after": "2023-01-01T00:00:00Z",
    "last_active_before": "2024-01-01T00:00:00Z",
    "usage_above": 1000,
    "has_2fa": true
  },
  "sort": {
    "field": "last_active",
    "order": "desc"
  },
  "pagination": {
    "page": 1,
    "per_page": 25
  }
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "user_12345",
        "email": "john.doe@example.com",
        "full_name": "John Doe",
        "status": "active",
        "subscription": "pro",
        "last_active": "2024-01-15T09:45:00Z",
        "total_checks": 15420,
        "match_score": 0.95
      }
    ],
    "pagination": {
      "current_page": 1,
      "per_page": 25,
      "total_items": 1,
      "total_pages": 1
    },
    "search_metadata": {
      "query_time_ms": 45,
      "total_matches": 1,
      "filters_applied": 8
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Error Handling

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Invalid or missing authentication token |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `USER_NOT_FOUND` | 404 | User does not exist |
| `INVALID_STATUS` | 400 | Invalid user status value |
| `INVALID_ROLE` | 400 | Invalid role value |
| `ROLE_PERMISSION_DENIED` | 403 | Cannot assign role due to permissions |
| `BULK_OPERATION_FAILED` | 400 | Bulk operation partially or completely failed |
| `RATE_LIMITED` | 429 | Too many requests |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "USER_NOT_FOUND",
    "message": "User not found",
    "details": "No user found with ID: user_12345"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Usage Examples

### cURL Examples

#### List Active Pro Users

```bash
curl -X GET "https://api.linkshield.com/api/admin/users?status=active&subscription=pro&per_page=25" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

#### Suspend User Account

```bash
curl -X PATCH "https://api.linkshield.com/api/admin/users/user_12345/status" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "suspended",
    "reason": "Terms of service violation",
    "notify_user": true,
    "suspension_duration_days": 30
  }'
```

#### Bulk Update User Quotas

```bash
curl -X POST "https://api.linkshield.com/api/admin/users/bulk" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "update_quota",
    "user_ids": ["user_12345", "user_12346"],
    "parameters": {
      "quota_limit": 5000,
      "reason": "Quota increase for enterprise trial"
    }
  }'
```

### JavaScript/Fetch Examples

```javascript
// Get user details
const getUserDetails = async (userId) => {
  const response = await fetch(`/api/admin/users/${userId}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  return await response.json();
};

// Update user status
const updateUserStatus = async (userId, status, reason) => {
  const response = await fetch(`/api/admin/users/${userId}/status`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      status,
      reason,
      notify_user: true
    })
  });
  
  return await response.json();
};

// Search users with advanced criteria
const searchUsers = async (searchCriteria) => {
  const response = await fetch('/api/admin/users/search', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(searchCriteria)
  });
  
  return await response.json();
};
```

## Security Considerations

### Access Control

- All user management operations are logged in the audit system
- Role-based access controls prevent unauthorized user modifications
- Super Admin role required for admin role assignments
- Sensitive user data is masked in responses based on requester permissions

### Data Privacy

- Personal information access is logged and monitored
- User data export operations require additional authorization
- Password reset operations generate secure temporary passwords
- User activity logs respect data retention policies

### Best Practices

1. **Always provide reasons** for status changes and role modifications
2. **Use bulk operations** for efficiency when managing multiple users
3. **Monitor user activity** for suspicious patterns
4. **Implement proper pagination** for large user lists
5. **Validate user permissions** before making changes
6. **Use search functionality** to find users efficiently

---

*This documentation is maintained alongside the API implementation and should be updated with any endpoint changes.*