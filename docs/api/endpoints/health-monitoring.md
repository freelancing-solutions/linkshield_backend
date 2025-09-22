# Health Monitoring API Documentation

## Overview

The Health Monitoring API provides comprehensive health check endpoints for monitoring the status and performance of the LinkShield service. These endpoints are designed for use by monitoring systems, load balancers, and operational teams to ensure service availability and performance.

**Base URL**: `/api/v1/health`  
**Authentication**: Not required for basic endpoints  
**Content-Type**: `application/json`

## Endpoints

### 1. Basic Health Check

**Endpoint:** `GET /api/v1/health`

**Description:** Returns basic health status of the application with essential system information.

**Response Format:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "environment": "production",
  "uptime": 3600.5,
  "checks": {
    "api": {
      "status": "healthy",
      "response_time": 0.001,
      "message": "API is running"
    }
  }
}
```

**Response Fields:**
- `status`: Overall health status (`healthy`, `degraded`, `unhealthy`)
- `timestamp`: Current timestamp in UTC
- `version`: Application version
- `environment`: Current environment (development, staging, production)
- `uptime`: Application uptime in seconds
- `checks`: Object containing individual component health checks

**Status Codes:**
- `200 OK`: Service is healthy
- `503 Service Unavailable`: Service is unhealthy

### 2. Detailed Health Check

**Endpoint:** `GET /api/v1/health/detailed`

**Description:** Comprehensive health check including database connectivity, Redis status, and external service configuration.

**Response Format:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "environment": "production",
  "uptime": 3600.5,
  "checks": {
    "api": {
      "status": "healthy",
      "response_time": 0.001,
      "message": "API is running",
      "details": {
        "uptime": 3600.5,
        "version": "1.0.0",
        "environment": "production"
      }
    },
    "database": {
      "status": "healthy",
      "response_time": 0.025,
      "message": "Database connection successful",
      "details": {
        "url": "localhost:5432/linkshield",
        "pool_size": 10
      }
    },
    "redis": {
      "status": "healthy",
      "response_time": 0.003,
      "message": "Redis connection successful",
      "details": {
        "url": "localhost:6379"
      }
    },
    "external_services": {
      "status": "healthy",
      "response_time": 0.001,
      "message": "External service configuration checked",
      "details": {
        "configured_services": ["openai", "virustotal", "stripe"],
        "total_configured": 3
      }
    }
  }
}
```

**Component Checks:**
- **API**: Basic API functionality
- **Database**: PostgreSQL connectivity and response time
- **Redis**: Redis connectivity (if configured)
- **External Services**: Configuration status of third-party APIs

**Status Codes:**
- `200 OK`: All components healthy or degraded
- `503 Service Unavailable`: Critical components unhealthy

### 3. Readiness Probe

**Endpoint:** `GET /api/v1/health/ready`

**Description:** Kubernetes-style readiness probe to determine if the service is ready to accept traffic.

**Response Format:**
```json
{
  "status": "ready",
  "timestamp": "2024-01-15T10:30:00Z",
  "message": "Service is ready to accept traffic"
}
```

**Readiness Criteria:**
- Database connectivity is established
- Essential services are accessible
- Application has completed initialization

**Status Codes:**
- `200 OK`: Service is ready to accept traffic
- `503 Service Unavailable`: Service is not ready

### 4. Liveness Probe

**Endpoint:** `GET /api/v1/health/live`

**Description:** Kubernetes-style liveness probe to determine if the service is alive and functioning.

**Response Format:**
```json
{
  "status": "alive",
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime": 3600.5,
  "message": "Service is alive"
}
```

**Liveness Criteria:**
- Application process is running
- Basic functionality is operational
- No deadlocks or critical failures

**Status Codes:**
- `200 OK`: Service is alive
- `503 Service Unavailable`: Service is not responding

### 5. Version Information

**Endpoint:** `GET /api/version`

**Description:** Returns detailed version and build information.

**Response Format:**
```json
{
  "version": "1.0.0",
  "environment": "production",
  "build_time": "2024-01-15T08:00:00Z",
  "commit_hash": "abc123def456",
  "python_version": "3.11.5"
}
```

**Response Fields:**
- `version`: Application version number
- `environment`: Deployment environment
- `build_time`: Build timestamp (if available)
- `commit_hash`: Git commit hash (if available)
- `python_version`: Python runtime version (if available)

**Status Codes:**
- `200 OK`: Version information retrieved successfully
- `500 Internal Server Error`: Failed to retrieve version information

### 6. Application Metrics

**Endpoint:** `GET /api/metrics`

**Description:** Returns application metrics and system statistics for monitoring and alerting.

**Response Format:**
```json
{
  "uptime_seconds": 3600.5,
  "timestamp": "2024-01-15T10:30:00Z",
  "environment": "production",
  "version": "1.0.0",
  "memory_usage": {
    "percent": 45.2,
    "available_mb": 2048.5
  },
  "cpu_usage": {
    "percent": 12.8
  },
  "disk_usage": {
    "percent": 67.3
  }
}
```

**Metrics Categories:**
- **Application**: Uptime, version, environment
- **Memory**: Usage percentage and available memory
- **CPU**: Current CPU utilization
- **Disk**: Disk usage percentage

**Note:** System metrics (memory, CPU, disk) are only available if `psutil` package is installed.

**Status Codes:**
- `200 OK`: Metrics retrieved successfully
- `500 Internal Server Error`: Failed to retrieve metrics

## Health Status Values

### Overall Status
- `healthy`: All components are functioning normally
- `degraded`: Some non-critical components have issues
- `unhealthy`: Critical components are failing

### Component Status
- `healthy`: Component is functioning normally
- `unhealthy`: Component has failed or is not responding

## Database Health Checks

The database health check performs the following validations:

1. **Connection Test**: Attempts to establish a connection to PostgreSQL
2. **Query Execution**: Executes a simple `SELECT 1` query
3. **Response Time**: Measures database response time
4. **Pool Status**: Reports connection pool configuration

**Implementation Details:**
- Uses async SQLAlchemy engine for connection testing
- Includes connection pool information in detailed checks
- Handles connection timeouts and errors gracefully

## Redis Health Checks

Redis health checks (when Redis is configured):

1. **Connection Test**: Attempts to connect to Redis instance
2. **Ping Command**: Executes a basic ping command
3. **Response Time**: Measures Redis response time

**Note:** Redis health check implementation is marked as TODO in the current codebase.

## External Service Configuration

The external services check validates the configuration of:

- **OpenAI API**: AI analysis capabilities
- **VirusTotal API**: URL reputation checking
- **Google Safe Browsing API**: Malicious URL detection
- **URLVoid API**: Additional URL analysis
- **Stripe API**: Payment processing

**Check Logic:**
- Verifies that API keys are configured (not null)
- Does not test actual connectivity to external services
- Reports count of configured services

## Monitoring Integration

### Kubernetes Integration

These endpoints are designed for Kubernetes health checks:

```yaml
# Deployment configuration
spec:
  containers:
  - name: linkshield-backend
    livenessProbe:
      httpGet:
        path: /api/v1/health/live
        port: 8000
      initialDelaySeconds: 30
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /api/v1/health/ready
        port: 8000
      initialDelaySeconds: 5
      periodSeconds: 5
```

### Prometheus Metrics

The `/api/metrics` endpoint can be configured for Prometheus scraping:

```yaml
# Prometheus configuration
scrape_configs:
- job_name: 'linkshield-backend'
  static_configs:
  - targets: ['linkshield-backend:8000']
  metrics_path: '/api/metrics'
  scrape_interval: 30s
```

### Alerting Rules

Example alerting rules based on health endpoints:

```yaml
# Alert when service is unhealthy
- alert: LinkShieldUnhealthy
  expr: up{job="linkshield-backend"} == 0
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "LinkShield backend is unhealthy"

# Alert on high response time
- alert: LinkShieldSlowResponse
  expr: http_request_duration_seconds > 5
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "LinkShield backend response time is high"
```

## Error Handling

All health endpoints implement consistent error handling:

1. **Graceful Degradation**: Individual component failures don't crash the entire health check
2. **Detailed Error Messages**: Specific error information in response messages
3. **Appropriate HTTP Status Codes**: 200 for healthy, 503 for unhealthy
4. **Logging**: All health check failures are logged for debugging

## Security Considerations

1. **No Sensitive Information**: Health endpoints don't expose sensitive configuration
2. **Rate Limiting**: Health endpoints are subject to standard rate limiting
3. **Authentication**: Health endpoints may require authentication in production
4. **Network Access**: Consider restricting access to internal networks only

## Best Practices

### For Monitoring Systems

1. **Use Appropriate Endpoints**: 
   - Use `/health` for basic monitoring
   - Use `/health/detailed` for comprehensive checks
   - Use `/health/ready` and `/health/live` for Kubernetes

2. **Set Reasonable Timeouts**: Health checks should complete within 5-10 seconds

3. **Monitor Trends**: Track response times and failure patterns over time

### For Development

1. **Test Health Endpoints**: Include health endpoint tests in your test suite
2. **Mock External Dependencies**: Use mocks for external service checks in tests
3. **Monitor During Deployment**: Check health endpoints during rolling deployments

## Troubleshooting

### Common Issues

1. **Database Connection Failures**:
   - Check database connectivity
   - Verify connection string configuration
   - Check database server status

2. **Redis Connection Issues**:
   - Verify Redis server is running
   - Check Redis URL configuration
   - Validate network connectivity

3. **High Response Times**:
   - Check database performance
   - Monitor system resources
   - Review application logs

### Debugging Steps

1. Check application logs for error details
2. Verify environment configuration
3. Test individual components separately
4. Monitor system resources (CPU, memory, disk)
5. Check network connectivity to external services

## Configuration

Health monitoring behavior can be configured through environment variables:

```bash
# Application settings
APP_VERSION=1.0.0
ENVIRONMENT=production

# Database settings
DATABASE_URL=postgresql://user:pass@localhost:5432/linkshield
DATABASE_POOL_SIZE=10

# Redis settings (optional)
REDIS_URL=redis://localhost:6379

# External API keys (for configuration checks)
OPENAI_API_KEY=your_openai_key
VIRUSTOTAL_API_KEY=your_virustotal_key
STRIPE_SECRET_KEY=your_stripe_key
```

## API Reference Summary

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---------------|
| `/api/health` | GET | Basic health check | No |
| `/api/health/detailed` | GET | Comprehensive health check | No |
| `/api/health/ready` | GET | Readiness probe | No |
| `/api/health/live` | GET | Liveness probe | No |
| `/api/version` | GET | Version information | No |
| `/api/metrics` | GET | Application metrics | No |

All endpoints return JSON responses and use standard HTTP status codes for indicating success or failure states.