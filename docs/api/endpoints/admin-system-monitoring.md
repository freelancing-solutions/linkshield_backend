# Admin System Monitoring API Documentation

## Overview

The Admin System Monitoring API provides comprehensive system health monitoring and logging capabilities for LinkShield administrators. These endpoints allow administrators to monitor system performance, check service health, view system logs, and receive real-time alerts about system status.

**Base URL**: `/api/admin/monitoring`  
**Authentication**: Required (Admin or Super Admin role)  
**Content-Type**: `application/json`

## Authentication

All monitoring endpoints require authentication with a valid JWT token and Admin or Super Admin role:

```http
Authorization: Bearer <jwt_token>
```

### Role Requirements
- **Admin**: Access to basic monitoring and health check endpoints
- **Super Admin**: Full access including detailed system logs and sensitive metrics

## Endpoints

### 1. System Health Check

Get overall system health status and key metrics.

**Endpoint**: `GET /api/admin/monitoring/health`

#### Request

```http
GET /api/admin/monitoring/health HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "overall_status": "healthy",
    "timestamp": "2024-01-15T10:30:00Z",
    "uptime_seconds": 2592000,
    "version": "2.1.0",
    "environment": "production",
    "components": {
      "api_server": {
        "status": "healthy",
        "response_time_ms": 45,
        "last_check": "2024-01-15T10:30:00Z",
        "details": {
          "active_connections": 234,
          "requests_per_minute": 1250,
          "error_rate": 0.002
        }
      },
      "database": {
        "status": "healthy",
        "response_time_ms": 12,
        "last_check": "2024-01-15T10:29:55Z",
        "details": {
          "connection_pool_usage": 0.65,
          "active_connections": 13,
          "slow_queries": 2,
          "disk_usage_percent": 45.2
        }
      },
      "redis_cache": {
        "status": "healthy",
        "response_time_ms": 3,
        "last_check": "2024-01-15T10:29:58Z",
        "details": {
          "memory_usage_mb": 512,
          "memory_usage_percent": 25.6,
          "connected_clients": 45,
          "cache_hit_rate": 0.94
        }
      },
      "url_scanner": {
        "status": "healthy",
        "response_time_ms": 234,
        "last_check": "2024-01-15T10:29:50Z",
        "details": {
          "active_scans": 12,
          "queue_size": 45,
          "avg_scan_time_ms": 1250,
          "success_rate": 0.98
        }
      },
      "external_apis": {
        "status": "degraded",
        "response_time_ms": 1250,
        "last_check": "2024-01-15T10:29:45Z",
        "details": {
          "virustotal": {
            "status": "healthy",
            "response_time_ms": 450,
            "rate_limit_remaining": 850
          },
          "urlvoid": {
            "status": "degraded",
            "response_time_ms": 2100,
            "rate_limit_remaining": 45
          },
          "safebrowsing": {
            "status": "healthy",
            "response_time_ms": 320,
            "rate_limit_remaining": 9850
          }
        }
      },
      "background_workers": {
        "status": "healthy",
        "last_check": "2024-01-15T10:30:00Z",
        "details": {
          "active_workers": 4,
          "queued_jobs": 23,
          "failed_jobs_last_hour": 2,
          "avg_job_duration_ms": 850
        }
      }
    },
    "system_metrics": {
      "cpu_usage_percent": 35.2,
      "memory_usage_percent": 68.5,
      "disk_usage_percent": 45.2,
      "network_io_mbps": 12.5,
      "load_average": [1.2, 1.5, 1.8]
    },
    "alerts": [
      {
        "id": "alert_123",
        "severity": "warning",
        "component": "external_apis",
        "message": "URLVoid API response time above threshold",
        "timestamp": "2024-01-15T10:25:00Z"
      }
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Health Status Values

- `healthy` - All systems operating normally
- `degraded` - Some components experiencing issues but system functional
- `unhealthy` - Critical issues affecting system functionality
- `maintenance` - System in maintenance mode

### 2. Detailed Component Health

Get detailed health information for a specific system component.

**Endpoint**: `GET /api/admin/monitoring/health/{component}`

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `component` | string | Yes | Component name to check |

#### Valid Components

- `api_server`
- `database`
- `redis_cache`
- `url_scanner`
- `external_apis`
- `background_workers`

#### Request

```http
GET /api/admin/monitoring/health/database HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "component": "database",
    "status": "healthy",
    "last_check": "2024-01-15T10:29:55Z",
    "response_time_ms": 12,
    "uptime_seconds": 2592000,
    "metrics": {
      "connection_pool": {
        "total_connections": 20,
        "active_connections": 13,
        "idle_connections": 7,
        "usage_percent": 65.0
      },
      "performance": {
        "queries_per_second": 145.2,
        "slow_queries_count": 2,
        "avg_query_time_ms": 8.5,
        "cache_hit_ratio": 0.92
      },
      "storage": {
        "total_size_gb": 500,
        "used_size_gb": 226,
        "free_size_gb": 274,
        "usage_percent": 45.2
      },
      "replication": {
        "status": "healthy",
        "lag_seconds": 0.5,
        "replicas_connected": 2
      }
    },
    "recent_errors": [
      {
        "timestamp": "2024-01-15T09:45:00Z",
        "error": "Connection timeout to replica",
        "severity": "warning",
        "resolved": true
      }
    ],
    "configuration": {
      "max_connections": 100,
      "query_timeout_seconds": 30,
      "backup_enabled": true,
      "monitoring_enabled": true
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 3. System Logs

Retrieve system logs with filtering and pagination.

**Endpoint**: `GET /api/admin/monitoring/logs`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `level` | string | No | "all" | Log level: "debug", "info", "warning", "error", "critical", "all" |
| `component` | string | No | "all" | Filter by component |
| `start_time` | string | No | - | Start time (ISO 8601) |
| `end_time` | string | No | - | End time (ISO 8601) |
| `search` | string | No | - | Search in log messages |
| `page` | integer | No | 1 | Page number (1-based) |
| `per_page` | integer | No | 100 | Items per page (1-1000) |
| `sort_order` | string | No | "desc" | Sort order: "asc", "desc" |

#### Request

```http
GET /api/admin/monitoring/logs?level=error&component=url_scanner&per_page=50 HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": "log_12345",
        "timestamp": "2024-01-15T10:25:30Z",
        "level": "error",
        "component": "url_scanner",
        "message": "Failed to scan URL: https://suspicious-site.com",
        "details": {
          "error_code": "SCAN_TIMEOUT",
          "url": "https://suspicious-site.com",
          "scan_id": "scan_789",
          "duration_ms": 30000,
          "retry_count": 3
        },
        "context": {
          "user_id": "user_12345",
          "request_id": "req_abc123",
          "ip_address": "192.168.1.100"
        },
        "stack_trace": "Traceback (most recent call last):\n  File \"scanner.py\", line 45..."
      },
      {
        "id": "log_12344",
        "timestamp": "2024-01-15T10:20:15Z",
        "level": "warning",
        "component": "url_scanner",
        "message": "High queue size detected",
        "details": {
          "queue_size": 150,
          "threshold": 100,
          "active_workers": 4
        }
      }
    ],
    "pagination": {
      "current_page": 1,
      "per_page": 50,
      "total_items": 234,
      "total_pages": 5,
      "has_next": true,
      "has_previous": false
    },
    "filters_applied": {
      "level": "error",
      "component": "url_scanner"
    },
    "summary": {
      "total_logs": 234,
      "error_count": 45,
      "warning_count": 89,
      "info_count": 100
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 4. System Metrics

Get detailed system performance metrics over time.

**Endpoint**: `GET /api/admin/monitoring/metrics`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `metric_type` | string | No | "all" | Metric type: "cpu", "memory", "disk", "network", "all" |
| `time_range` | string | No | "1h" | Time range: "5m", "15m", "1h", "6h", "24h", "7d" |
| `granularity` | string | No | "1m" | Data granularity: "10s", "1m", "5m", "15m", "1h" |

#### Request

```http
GET /api/admin/monitoring/metrics?metric_type=cpu&time_range=1h&granularity=5m HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "metrics": {
      "cpu": {
        "current_value": 35.2,
        "unit": "percent",
        "time_series": [
          {
            "timestamp": "2024-01-15T09:30:00Z",
            "value": 32.1
          },
          {
            "timestamp": "2024-01-15T09:35:00Z",
            "value": 34.5
          },
          {
            "timestamp": "2024-01-15T09:40:00Z",
            "value": 38.2
          }
        ],
        "statistics": {
          "min": 28.5,
          "max": 42.1,
          "avg": 35.8,
          "p95": 40.2,
          "p99": 41.8
        }
      }
    },
    "metadata": {
      "time_range": "1h",
      "granularity": "5m",
      "data_points": 12,
      "collection_interval": "10s"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 5. Performance Analytics

Get performance analytics and trends over time.

**Endpoint**: `GET /api/admin/monitoring/performance`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `days` | integer | No | 7 | Number of days to analyze (1-90) |
| `include_predictions` | boolean | No | false | Include performance predictions |

#### Request

```http
GET /api/admin/monitoring/performance?days=7&include_predictions=true HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "summary": {
      "avg_response_time_ms": 245,
      "avg_cpu_usage": 35.2,
      "avg_memory_usage": 68.5,
      "total_requests": 1847392,
      "error_rate": 0.002,
      "uptime_percentage": 99.97
    },
    "trends": {
      "response_time": {
        "trend": "stable",
        "change_percent": -2.1,
        "daily_averages": [
          {
            "date": "2024-01-09",
            "value": 252
          },
          {
            "date": "2024-01-10",
            "value": 248
          }
        ]
      },
      "cpu_usage": {
        "trend": "increasing",
        "change_percent": 5.3,
        "daily_averages": [
          {
            "date": "2024-01-09",
            "value": 33.4
          },
          {
            "date": "2024-01-10",
            "value": 35.2
          }
        ]
      }
    },
    "anomalies": [
      {
        "timestamp": "2024-01-14T15:30:00Z",
        "type": "response_time_spike",
        "severity": "medium",
        "description": "Response time increased to 1250ms for 5 minutes",
        "resolved": true
      }
    ],
    "predictions": {
      "next_24h": {
        "expected_load": "high",
        "predicted_response_time": 280,
        "confidence": 0.85
      },
      "capacity_planning": {
        "days_until_capacity_limit": 45,
        "recommended_scaling": "horizontal",
        "estimated_cost_increase": 15.2
      }
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 6. Alert Management

Get and manage system alerts.

**Endpoint**: `GET /api/admin/monitoring/alerts`

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `status` | string | No | "active" | Alert status: "active", "resolved", "acknowledged", "all" |
| `severity` | string | No | "all" | Alert severity: "low", "medium", "high", "critical", "all" |
| `component` | string | No | "all" | Filter by component |
| `days` | integer | No | 7 | Number of days to retrieve (1-90) |

#### Request

```http
GET /api/admin/monitoring/alerts?status=active&severity=high HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "alerts": [
      {
        "id": "alert_123",
        "title": "High CPU Usage",
        "description": "CPU usage has exceeded 80% for more than 10 minutes",
        "severity": "high",
        "status": "active",
        "component": "api_server",
        "created_at": "2024-01-15T10:15:00Z",
        "updated_at": "2024-01-15T10:25:00Z",
        "threshold": {
          "metric": "cpu_usage_percent",
          "operator": ">",
          "value": 80,
          "duration_minutes": 10
        },
        "current_value": 85.2,
        "actions_taken": [
          "notification_sent",
          "auto_scaling_triggered"
        ],
        "assigned_to": "admin@linkshield.com"
      }
    ],
    "summary": {
      "total_alerts": 15,
      "active_alerts": 3,
      "critical_alerts": 0,
      "high_alerts": 1,
      "medium_alerts": 2,
      "low_alerts": 0
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 7. Acknowledge Alert

Acknowledge a system alert.

**Endpoint**: `POST /api/admin/monitoring/alerts/{alert_id}/acknowledge`

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `alert_id` | string | Yes | Alert ID to acknowledge |

#### Request Body Schema

```json
{
  "message": "Investigating high CPU usage, scaling up resources",
  "estimated_resolution_time": "2024-01-15T11:00:00Z"
}
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "alert_id": "alert_123",
    "status": "acknowledged",
    "acknowledged_by": "admin@linkshield.com",
    "acknowledged_at": "2024-01-15T10:30:00Z",
    "message": "Investigating high CPU usage, scaling up resources",
    "estimated_resolution_time": "2024-01-15T11:00:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 8. System Status Page

Get public system status information (limited data for status page).

**Endpoint**: `GET /api/admin/monitoring/status-page`

#### Request

```http
GET /api/admin/monitoring/status-page HTTP/1.1
Host: api.linkshield.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Response Schema

```json
{
  "success": true,
  "data": {
    "overall_status": "operational",
    "last_updated": "2024-01-15T10:30:00Z",
    "services": [
      {
        "name": "API Service",
        "status": "operational",
        "description": "All API endpoints are functioning normally"
      },
      {
        "name": "URL Scanning",
        "status": "operational",
        "description": "URL scanning service is operating normally"
      },
      {
        "name": "Dashboard",
        "status": "operational",
        "description": "User dashboard is accessible and responsive"
      }
    ],
    "incidents": [
      {
        "id": "incident_456",
        "title": "Intermittent API Slowdowns",
        "status": "resolved",
        "severity": "minor",
        "started_at": "2024-01-14T15:30:00Z",
        "resolved_at": "2024-01-14T16:45:00Z",
        "description": "Some users experienced slower API response times"
      }
    ],
    "maintenance": [
      {
        "id": "maintenance_789",
        "title": "Database Maintenance",
        "status": "scheduled",
        "scheduled_start": "2024-01-20T02:00:00Z",
        "scheduled_end": "2024-01-20T04:00:00Z",
        "description": "Routine database maintenance and optimization"
      }
    ],
    "uptime_stats": {
      "last_24h": 99.98,
      "last_7d": 99.95,
      "last_30d": 99.97,
      "last_90d": 99.96
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
| `COMPONENT_NOT_FOUND` | 404 | Invalid component name |
| `INVALID_TIME_RANGE` | 400 | Invalid time range parameter |
| `ALERT_NOT_FOUND` | 404 | Alert does not exist |
| `MONITORING_UNAVAILABLE` | 503 | Monitoring service temporarily unavailable |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "COMPONENT_NOT_FOUND",
    "message": "Component not found",
    "details": "Invalid component name: invalid_component"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Usage Examples

### cURL Examples

#### Check System Health

```bash
curl -X GET "https://api.linkshield.com/api/admin/monitoring/health" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

#### Get Error Logs

```bash
curl -X GET "https://api.linkshield.com/api/admin/monitoring/logs?level=error&per_page=25" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

#### Acknowledge Alert

```bash
curl -X POST "https://api.linkshield.com/api/admin/monitoring/alerts/alert_123/acknowledge" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Investigating the issue",
    "estimated_resolution_time": "2024-01-15T11:00:00Z"
  }'
```

### JavaScript/Fetch Examples

```javascript
// Check system health
const getSystemHealth = async () => {
  const response = await fetch('/api/admin/monitoring/health', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  return await response.json();
};

// Get system logs with filters
const getSystemLogs = async (level, component, page = 1) => {
  const params = new URLSearchParams({
    level,
    component,
    page: page.toString(),
    per_page: '50'
  });
  
  const response = await fetch(`/api/admin/monitoring/logs?${params}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  return await response.json();
};

// Get performance metrics
const getPerformanceMetrics = async (timeRange = '1h') => {
  const response = await fetch(`/api/admin/monitoring/metrics?time_range=${timeRange}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  return await response.json();
};
```

## Monitoring Best Practices

### Health Check Integration

1. **Automated Monitoring**: Set up automated health checks every 30 seconds
2. **Alert Thresholds**: Configure appropriate thresholds for different metrics
3. **Escalation Policies**: Implement escalation for unacknowledged critical alerts
4. **Dashboard Integration**: Display health status on admin dashboards

### Log Management

1. **Log Retention**: Configure appropriate log retention policies
2. **Log Levels**: Use appropriate log levels for different types of events
3. **Structured Logging**: Ensure logs include relevant context and metadata
4. **Search and Filter**: Use search and filtering for efficient log analysis

### Performance Monitoring

1. **Baseline Metrics**: Establish baseline performance metrics
2. **Trend Analysis**: Monitor trends to identify gradual degradation
3. **Capacity Planning**: Use performance data for capacity planning
4. **Optimization**: Identify bottlenecks and optimization opportunities

### Alert Management

1. **Alert Fatigue**: Avoid too many low-priority alerts
2. **Actionable Alerts**: Ensure alerts are actionable and include context
3. **Response Procedures**: Document response procedures for different alert types
4. **Post-Incident Reviews**: Conduct reviews to improve monitoring and response

---

*This documentation is maintained alongside the API implementation and should be updated with any endpoint changes.*