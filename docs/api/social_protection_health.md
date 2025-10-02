# Social Protection Health Check Endpoint

## Overview

The social protection health check endpoint provides comprehensive monitoring of all social protection services, analyzers, and platform adapters.

## Endpoint

```
GET /api/v1/social-protection/health
```

## Response Format

### Successful Response (200 OK)

```json
{
  "status": "healthy",
  "timestamp": "2024-10-02T18:30:00.000Z",
  "response_time_seconds": 0.123,
  "checks": {
    "extension_data_processor": {
      "status": "healthy",
      "message": "Extension data processor operational"
    },
    "social_scan_service": {
      "status": "healthy",
      "message": "Social scan service operational"
    },
    "database": {
      "status": "healthy",
      "message": "Database connection successful"
    },
    "analyzers": {
      "status": "healthy",
      "message": "8/8 analyzers available",
      "details": [
        {
          "name": "content_risk_analyzer",
          "status": "available"
        },
        {
          "name": "link_penalty_detector",
          "status": "available"
        }
      ]
    },
    "platform_adapters": {
      "status": "healthy",
      "message": "7/7 platform adapters configured",
      "details": [
        {
          "platform": "twitter",
          "status": "available"
        },
        {
          "platform": "facebook",
          "status": "available"
        }
      ]
    },
    "crisis_detection": {
      "status": "available",
      "message": "Crisis detection system operational"
    }
  },
  "summary": {
    "total_checks": 6,
    "healthy": 6,
    "degraded": 0,
    "unhealthy": 0
  }
}
```

### Degraded Response (200 OK)

When some non-critical services are unavailable:

```json
{
  "status": "degraded",
  "timestamp": "2024-10-02T18:30:00.000Z",
  "response_time_seconds": 0.150,
  "checks": {
    "extension_data_processor": {
      "status": "unavailable",
      "message": "Service not initialized"
    },
    "social_scan_service": {
      "status": "healthy",
      "message": "Social scan service operational"
    },
    "database": {
      "status": "healthy",
      "message": "Database connection successful"
    }
  },
  "summary": {
    "total_checks": 3,
    "healthy": 2,
    "degraded": 1,
    "unhealthy": 0
  }
}
```

### Unhealthy Response (503 Service Unavailable)

When critical services (like database) are unavailable:

```json
{
  "status": "unhealthy",
  "timestamp": "2024-10-02T18:30:00.000Z",
  "response_time_seconds": 0.200,
  "checks": {
    "database": {
      "status": "unhealthy",
      "message": "Database connection failed: Connection refused"
    }
  },
  "summary": {
    "total_checks": 6,
    "healthy": 5,
    "degraded": 0,
    "unhealthy": 1
  }
}
```

## Status Codes

- **200 OK**: System is healthy or degraded but operational
- **503 Service Unavailable**: Critical services are unavailable

## Component Status Values

### Service Status
- `healthy`: Service is fully operational
- `degraded`: Service has issues but is partially operational
- `unhealthy`: Service is not operational
- `unavailable`: Service is not initialized
- `available`: Service is configured and available
- `not_configured`: Service is not configured
- `error`: Error checking service status

## Monitored Components

### Core Services
- **extension_data_processor**: Processes data from browser extensions
- **social_scan_service**: Handles social media profile scanning

### Analyzers
- content_risk_analyzer
- link_penalty_detector
- spam_pattern_detector
- community_notes_analyzer
- visibility_scorer
- engagement_analyzer
- penalty_detector
- shadow_ban_detector

### Platform Adapters
- Twitter
- Facebook (Meta)
- Instagram
- TikTok
- LinkedIn
- Telegram
- Discord

### Infrastructure
- **database**: PostgreSQL database connectivity
- **crisis_detection**: Crisis detection and alert system

## Usage Examples

### cURL

```bash
curl -X GET "https://api.linkshield.site/api/v1/social-protection/health"
```

### Python

```python
import requests

response = requests.get("https://api.linkshield.site/api/v1/social-protection/health")
health_data = response.json()

if health_data["status"] == "healthy":
    print("All systems operational")
elif health_data["status"] == "degraded":
    print(f"System degraded: {health_data['summary']['degraded']} issues")
else:
    print("System unhealthy")
```

### JavaScript

```javascript
fetch('https://api.linkshield.site/api/v1/social-protection/health')
  .then(response => response.json())
  .then(data => {
    console.log(`Status: ${data.status}`);
    console.log(`Healthy checks: ${data.summary.healthy}/${data.summary.total_checks}`);
  });
```

## Monitoring Integration

### Prometheus

The health check endpoint can be used with Prometheus for monitoring:

```yaml
scrape_configs:
  - job_name: 'social_protection_health'
    metrics_path: '/api/v1/social-protection/health'
    scrape_interval: 30s
    static_configs:
      - targets: ['api.linkshield.site']
```

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /api/v1/social-protection/health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /api/v1/social-protection/health
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Performance Considerations

- Response time typically < 200ms
- Database connectivity check adds ~10-50ms
- No external API calls are made
- Suitable for frequent polling (every 10-30 seconds)

## Related Endpoints

- `/api/v1/health` - General API health check
- `/api/v1/health/detailed` - Detailed system health check
- `/api/v1/health/ready` - Kubernetes readiness probe
- `/api/v1/health/live` - Kubernetes liveness probe
