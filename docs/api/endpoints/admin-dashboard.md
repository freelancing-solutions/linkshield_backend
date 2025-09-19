# Admin Dashboard API Documentation

## Overview

The Admin Dashboard API provides comprehensive system analytics and monitoring capabilities for LinkShield administrators. These endpoints deliver real-time insights into system performance, user behavior, security threats, and traffic patterns.

**Base URL**: `/api/admin/dashboard`  
**Authentication**: Required (Admin or Super Admin role)  
**Content-Type**: `application/json`

## Authentication

All dashboard endpoints require authentication with a valid JWT token and Admin or Super Admin role:

```http
Authorization: Bearer <jwt_token>
```

### Role Requirements
- **Admin**: Access to all dashboard endpoints
- **Super Admin**: Full access with additional system-level metrics

## Endpoints

### 1. System Statistics

Retrieve comprehensive system statistics and key performance indicators.

**Endpoint**: `GET /api/admin/dashboard/statistics`

#### Request

```http
GET /api/admin/dashboard/statistics HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "overview": {
      "total_users": 15420,
      "active_users": 12350,
      "total_url_checks": 2847392,
      "total_threats_detected": 8934,
      "system_uptime_hours": 8760,
      "avg_response_time_ms": 245
    },
    "user_metrics": {
      "new_users_today": 45,
      "new_users_this_week": 312,
      "new_users_this_month": 1205,
      "active_users_today": 3420,
      "user_retention_rate": 0.78
    },
    "security_metrics": {
      "threats_blocked_today": 234,
      "threats_blocked_this_week": 1567,
      "threats_blocked_this_month": 6789,
      "false_positive_rate": 0.02,
      "detection_accuracy": 0.98
    },
    "performance_metrics": {
      "avg_response_time_24h": 245,
      "avg_response_time_7d": 238,
      "avg_response_time_30d": 252,
      "uptime_percentage": 99.97,
      "error_rate": 0.003
    },
    "subscription_metrics": {
      "free_users": 8420,
      "basic_users": 4200,
      "pro_users": 2100,
      "enterprise_users": 700,
      "conversion_rate": 0.45
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `overview.total_users` | integer | Total registered users |
| `overview.active_users` | integer | Users active in last 30 days |
| `overview.total_url_checks` | integer | Cumulative URL checks performed |
| `overview.total_threats_detected` | integer | Total threats detected |
| `overview.system_uptime_hours` | integer | System uptime in hours |
| `overview.avg_response_time_ms` | integer | Average API response time |
| `user_metrics.new_users_today` | integer | New registrations today |
| `user_metrics.user_retention_rate` | float | 30-day user retention rate |
| `security_metrics.threats_blocked_today` | integer | Threats blocked today |
| `security_metrics.detection_accuracy` | float | AI detection accuracy rate |
| `performance_metrics.uptime_percentage` | float | System uptime percentage |
| `subscription_metrics.conversion_rate` | float | Free to paid conversion rate |

#### Error Responses

```json
{
  "success": false,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Admin access required",
    "details": "User does not have admin privileges"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 2. Traffic Analytics

Retrieve detailed traffic analytics with configurable time periods.

**Endpoint**: `GET /api/admin/dashboard/traffic`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `days` | integer | No | 7 | Number of days to analyze (1-365) |
| `granularity` | string | No | "day" | Data granularity: "hour", "day", "week" |
| `include_bots` | boolean | No | false | Include bot traffic in analysis |

#### Request

```http
GET /api/admin/dashboard/traffic?days=30&granularity=day HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "summary": {
      "total_requests": 1847392,
      "unique_users": 12350,
      "avg_requests_per_user": 149.6,
      "peak_requests_per_hour": 15420,
      "geographic_distribution": {
        "US": 45.2,
        "EU": 32.1,
        "ASIA": 18.7,
        "OTHER": 4.0
      }
    },
    "time_series": [
      {
        "timestamp": "2024-01-01T00:00:00Z",
        "requests": 45230,
        "unique_users": 3420,
        "avg_response_time": 245,
        "error_rate": 0.002
      },
      {
        "timestamp": "2024-01-02T00:00:00Z",
        "requests": 48150,
        "unique_users": 3650,
        "avg_response_time": 238,
        "error_rate": 0.001
      }
    ],
    "top_endpoints": [
      {
        "endpoint": "/api/url-check",
        "requests": 892340,
        "percentage": 48.3
      },
      {
        "endpoint": "/api/user/profile",
        "requests": 234567,
        "percentage": 12.7
      }
    ],
    "user_agents": {
      "chrome": 45.2,
      "firefox": 23.1,
      "safari": 18.7,
      "edge": 8.9,
      "other": 4.1
    }
  },
  "metadata": {
    "period": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-30T23:59:59Z",
      "days": 30
    },
    "granularity": "day",
    "include_bots": false
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Validation Rules

- `days`: Must be between 1 and 365
- `granularity`: Must be one of "hour", "day", "week"
- `include_bots`: Must be boolean

### 3. Threat Intelligence

Retrieve threat detection summary and security analytics.

**Endpoint**: `GET /api/admin/dashboard/threats`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `days` | integer | No | 7 | Analysis period in days (1-90) |
| `severity` | string | No | "all" | Filter by severity: "low", "medium", "high", "critical", "all" |
| `include_resolved` | boolean | No | true | Include resolved threats |

#### Request

```http
GET /api/admin/dashboard/threats?days=7&severity=high HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "summary": {
      "total_threats": 8934,
      "threats_blocked": 8756,
      "threats_resolved": 8234,
      "active_threats": 178,
      "false_positives": 89,
      "detection_rate": 0.98
    },
    "severity_breakdown": {
      "critical": 45,
      "high": 234,
      "medium": 1567,
      "low": 7088
    },
    "threat_types": [
      {
        "type": "malware",
        "count": 3420,
        "percentage": 38.3,
        "trend": "decreasing"
      },
      {
        "type": "phishing",
        "count": 2890,
        "percentage": 32.4,
        "trend": "stable"
      },
      {
        "type": "suspicious_redirect",
        "count": 1567,
        "percentage": 17.5,
        "trend": "increasing"
      },
      {
        "type": "spam",
        "count": 1057,
        "percentage": 11.8,
        "trend": "decreasing"
      }
    ],
    "recent_threats": [
      {
        "id": "threat_12345",
        "url": "https://suspicious-site.com",
        "type": "phishing",
        "severity": "high",
        "detected_at": "2024-01-15T09:45:00Z",
        "status": "blocked",
        "confidence_score": 0.95
      }
    ],
    "geographic_sources": {
      "unknown": 35.2,
      "RU": 18.7,
      "CN": 15.3,
      "US": 12.1,
      "OTHER": 18.7
    }
  },
  "metadata": {
    "period": {
      "start": "2024-01-08T00:00:00Z",
      "end": "2024-01-15T23:59:59Z",
      "days": 7
    },
    "filters": {
      "severity": "high",
      "include_resolved": true
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 4. User Analytics

Retrieve comprehensive user behavior analytics and insights.

**Endpoint**: `GET /api/admin/dashboard/users`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `days` | integer | No | 30 | Analysis period in days (1-365) |
| `segment` | string | No | "all" | User segment: "new", "active", "churned", "all" |
| `subscription` | string | No | "all" | Filter by subscription: "free", "basic", "pro", "enterprise", "all" |

#### Request

```http
GET /api/admin/dashboard/users?days=30&segment=active HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "summary": {
      "total_users": 15420,
      "active_users": 12350,
      "new_users": 1205,
      "churned_users": 234,
      "avg_session_duration_minutes": 18.5,
      "avg_checks_per_user": 149.6
    },
    "engagement_metrics": {
      "daily_active_users": 3420,
      "weekly_active_users": 8950,
      "monthly_active_users": 12350,
      "session_frequency": 2.3,
      "feature_adoption": {
        "url_check": 0.98,
        "batch_check": 0.45,
        "api_access": 0.23,
        "reports": 0.67
      }
    },
    "subscription_analytics": {
      "conversion_funnel": {
        "free_trial_started": 2340,
        "trial_completed": 1872,
        "converted_to_paid": 843,
        "conversion_rate": 0.36
      },
      "churn_analysis": {
        "monthly_churn_rate": 0.05,
        "avg_lifetime_value": 245.67,
        "churn_reasons": {
          "price": 35.2,
          "features": 28.7,
          "competition": 18.3,
          "other": 17.8
        }
      }
    },
    "user_segments": [
      {
        "segment": "power_users",
        "count": 1234,
        "percentage": 8.0,
        "avg_checks_per_day": 45.2,
        "retention_rate": 0.95
      },
      {
        "segment": "casual_users",
        "count": 8950,
        "percentage": 58.1,
        "avg_checks_per_day": 3.2,
        "retention_rate": 0.72
      }
    ],
    "geographic_distribution": {
      "US": 6789,
      "UK": 2340,
      "DE": 1567,
      "FR": 1234,
      "OTHER": 3490
    }
  },
  "metadata": {
    "period": {
      "start": "2023-12-16T00:00:00Z",
      "end": "2024-01-15T23:59:59Z",
      "days": 30
    },
    "filters": {
      "segment": "active",
      "subscription": "all"
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
| `FORBIDDEN` | 403 | Insufficient permissions (non-admin user) |
| `INVALID_PARAMETERS` | 400 | Invalid query parameters |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "INVALID_PARAMETERS",
    "message": "Invalid days parameter",
    "details": "Days must be between 1 and 365",
    "field": "days"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Rate Limiting

Dashboard endpoints are subject to rate limiting:

- **Admin users**: 100 requests per minute
- **Super Admin users**: 200 requests per minute

Rate limit headers are included in responses:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248600
```

## Caching

Dashboard data is cached to improve performance:

- **Statistics**: Cached for 5 minutes
- **Traffic data**: Cached for 15 minutes
- **Threat data**: Cached for 2 minutes
- **User analytics**: Cached for 10 minutes

Cache headers indicate freshness:

```http
Cache-Control: max-age=300
ETag: "abc123def456"
Last-Modified: Mon, 15 Jan 2024 10:25:00 GMT
```

## Usage Examples

### cURL Examples

#### Get System Statistics

```bash
curl -X GET "https://api.linkshield.com/api/admin/dashboard/statistics" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

#### Get Traffic Analytics for Last 7 Days

```bash
curl -X GET "https://api.linkshield.com/api/admin/dashboard/traffic?days=7&granularity=day" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

#### Get High Severity Threats

```bash
curl -X GET "https://api.linkshield.com/api/admin/dashboard/threats?severity=high&days=7" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### JavaScript/Fetch Examples

```javascript
// Get dashboard statistics
const getStatistics = async () => {
  const response = await fetch('/api/admin/dashboard/statistics', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
  return await response.json();
};

// Get traffic analytics with parameters
const getTrafficAnalytics = async (days = 7, granularity = 'day') => {
  const params = new URLSearchParams({ days, granularity });
  const response = await fetch(`/api/admin/dashboard/traffic?${params}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  return await response.json();
};
```

## Integration Notes

### Dashboard Integration

These endpoints are designed to power comprehensive admin dashboards:

1. **Real-time Updates**: Use WebSocket connections for live data updates
2. **Data Visualization**: Integrate with charting libraries (Chart.js, D3.js)
3. **Export Functionality**: Combine with export endpoints for reporting
4. **Alerting**: Set up monitoring based on threshold values

### Performance Considerations

- Use appropriate time ranges to balance detail and performance
- Implement client-side caching for frequently accessed data
- Consider pagination for large datasets
- Monitor rate limits and implement backoff strategies

### Security Best Practices

- Always validate JWT tokens on the client side
- Implement proper error handling to avoid information leakage
- Use HTTPS for all API communications
- Log and monitor admin dashboard access

---

*This documentation is maintained alongside the API implementation and should be updated with any endpoint changes.*