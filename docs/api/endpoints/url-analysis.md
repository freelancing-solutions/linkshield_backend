# URL Analysis Endpoints

LinkShield's URL analysis system provides comprehensive security scanning, threat detection, and content analysis capabilities. This guide covers all URL analysis endpoints, scan types, security features, and integration patterns.

## Overview

The URL analysis system performs multi-layered security checks including:

- **Security Scanning**: Malware, phishing, and threat detection
- **Reputation Analysis**: Historical domain reputation and trust scores
- **Content Analysis**: AI-powered content quality and categorization
- **Technical Analysis**: SSL certificates, redirects, and hosting details

All endpoints support both authenticated and anonymous access with different rate limits and features.

## Base URL

```
https://api.linkshield.com/api/v1/url-check
```

## Authentication

URL analysis endpoints support multiple authentication methods:

- **JWT Token**: `Authorization: Bearer <token>` (recommended for web apps)
- **API Key**: `X-API-Key: <api_key>` (recommended for server integrations)
- **Anonymous**: Limited functionality without authentication

Authentication requirements per endpoint:
- `POST /check`: Optional (anonymous allowed, stricter rate limits)
- `POST /bulk-check`: Required (JWT)
- `GET /check/{check_id}`: Optional
- `GET /check/{check_id}/results`: Optional
- `GET /check/{check_id}/broken-links`: Optional (only available if broken-link scanning was performed)
- `GET /history`: Required (JWT)
- `GET /reputation/{domain}`: Optional
- `GET /stats`: Required (JWT)

## Endpoints

### 1. Analyze Single URL

Perform comprehensive analysis of a single URL.

**Endpoint:** `POST /check`

**Request Body:**
```json
{
  "url": "https://example.com",
  "scan_types": ["SECURITY", "REPUTATION", "CONTENT"],
  "priority": false,
  "callback_url": "https://your-app.com/webhooks/url-analysis"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | URL to analyze (1-2048 characters) |
| `scan_types` | array | No | Types of scans to perform (default: all) |
| `priority` | boolean | No | Prioritize this scan (premium feature) |
| `callback_url` | string | No | Webhook URL for async results |

**Scan Types:**

| Type | Description | Features |
|------|-------------|----------|
| `SECURITY` | Malware and threat detection | VirusTotal, Google Safe Browsing, custom engines |
| `REPUTATION` | Historical reputation analysis | Domain age, trust scores, blacklist checks |
| `CONTENT` | AI-powered content analysis | Quality scoring, categorization, sentiment |
| `TECHNICAL` | Technical infrastructure analysis | SSL, redirects, hosting, performance |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "original_url": "https://example.com",
  "normalized_url": "https://example.com/",
  "domain": "example.com",
  "status": "COMPLETED",
  "threat_level": "SAFE",
  "confidence_score": 95,
  "scan_started_at": "2024-01-15T10:30:00Z",
  "scan_completed_at": "2024-01-15T10:30:15Z",
  "analysis_results": {
    "security": {
      "is_malicious": false,
      "is_phishing": false,
      "is_malware": false,
      "is_spam": false,
      "threat_indicators": [],
      "safety_score": 95.5
    },
    "reputation": {
      "domain_age_days": 7300,
      "trust_score": 92,
      "reputation_score": 88,
      "blacklist_status": "clean"
    },
    "technical": {
      "http_status": 200,
      "response_time": 0.245,
      "ssl_valid": true,
      "ssl_expires_at": "2024-12-31T23:59:59Z",
      "redirect_count": 0,
      "final_url": "https://example.com/"
    },
    "content": {
      "page_title": "Example Domain",
      "content_type": "text/html",
      "content_length": 1256,
      "quality_score": 78,
      "categories": ["business", "technology"],
      "language": "en"
    }
  },
  "error_message": null,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Status Codes:**
- `200 OK`: Analysis completed successfully
- `202 Accepted`: Analysis started (async processing)
- `400 Bad Request`: Invalid URL or parameters
- `401 Unauthorized`: Authentication required
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Analysis failed

**Example Request:**
```bash
curl -X POST "https://api.linkshield.com/api/v1/url-check/check" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.com",
    "scan_types": ["SECURITY", "REPUTATION"],
    "priority": true
  }'
```

### 2. Bulk URL Analysis

Analyze multiple URLs in a single request for efficient batch processing.

**Endpoint:** `POST /bulk-check`

**Authentication:** Required (JWT or API Key)

**Request Body:**
```json
{
  "urls": [
    "https://example1.com",
    "https://example2.com",
    "https://example3.com"
  ],
  "scan_types": ["SECURITY", "REPUTATION"],
  "callback_url": "https://your-app.com/webhooks/bulk-analysis"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `urls` | array | Yes | URLs to analyze (1-100 items) |
| `scan_types` | array | No | Types of scans to perform |
| `callback_url` | string | No | Webhook URL for batch results |

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "original_url": "https://example1.com",
    "status": "COMPLETED",
    "threat_level": "SAFE",
    "confidence_score": 95
  },
  {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "original_url": "https://example2.com",
    "status": "COMPLETED",
    "threat_level": "HIGH",
    "confidence_score": 87
  }
]
```

**Rate Limits:**
- **Free Plan**: 10 URLs per batch, 5 batches per hour
- **Pro Plan**: 50 URLs per batch, 20 batches per hour
- **Enterprise**: 100 URLs per batch, unlimited batches

### 3. Get Analysis Results

Retrieve detailed results for a specific URL analysis.

**Endpoint:** `GET /check/{check_id}`

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `check_id` | UUID | Yes | URL check ID from analysis request |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "original_url": "https://example.com",
  "normalized_url": "https://example.com/",
  "domain": "example.com",
  "status": "COMPLETED",
  "threat_level": "SAFE",
  "confidence_score": 95,
  "analysis_results": {
    // Complete analysis results
  },
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Example Request:**
```bash
curl -X GET "https://api.linkshield.com/api/v1/url-check/check/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer <jwt_token>"
```

### 4. Get Detailed Scan Results

Retrieve granular scan results from individual security providers.

**Endpoint:** `GET /check/{check_id}/results`

**Response:**
```json
[
  {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "scan_type": "SECURITY",
    "provider": "VirusTotal",
    "threat_detected": false,
    "threat_types": [],
    "confidence_score": 95,
    "metadata": {
      "scan_date": "2024-01-15T10:30:00Z",
      "engines_detected": 0,
      "engines_total": 70,
      "scan_id": "vt_scan_123456"
    },
    "created_at": "2024-01-15T10:30:05Z"
  },
  {
    "id": "123e4567-e89b-12d3-a456-426614174001",
    "scan_type": "SECURITY",
    "provider": "Google Safe Browsing",
    "threat_detected": false,
    "threat_types": [],
    "confidence_score": 98,
    "metadata": {
      "threat_types_checked": ["MALWARE", "SOCIAL_ENGINEERING"],
      "platform_types": ["WINDOWS", "LINUX", "OSX"]
    },
    "created_at": "2024-01-15T10:30:08Z"
  }
]
```

### 5. Get Broken Link Details

Get detailed broken link information for a specific URL check.

**Endpoint:** `GET /check/{check_id}/broken-links`

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `check_id` | UUID | Yes | URL check ID from analysis request |

**Response:**
```json
[
  {
    "url": "https://example.com/broken-link",
    "status_code": 404,
    "status": "BROKEN",
    "error_message": "Not Found",
    "response_time": 0.123,
    "redirect_url": null,
    "depth_level": 1
  }
]
```

Notes:
- Only available if broken-link scanning was requested and performed.
- Response fields may include `null` values when data is not applicable.

### 6. Get Analysis History

Retrieve URL analysis history for the authenticated user.

**Endpoint:** `GET /history`

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | No | Filter by specific URL |
| `domain` | string | No | Filter by domain |
| `threat_level` | enum | No | Filter by threat level |
| `status` | enum | No | Filter by analysis status |
| `page` | integer | No | Page number (default: 1) |
| `page_size` | integer | No | Items per page (1-100, default: 20) |

**Response:**
```json
{
  "checks": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "original_url": "https://example.com",
      "normalized_url": "https://example.com/",
      "domain": "example.com",
      "status": "COMPLETED",
      "threat_level": "SAFE",
      "confidence_score": 95,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total_count": 150,
  "page": 1,
  "page_size": 20
}
```

**Example Request:**
```bash
curl -X GET "https://api.linkshield.com/api/v1/url-check/history?domain=example.com&threat_level=HIGH&page=1&page_size=50" \
  -H "Authorization: Bearer <jwt_token>"
```

### 7. Get Domain Reputation

Retrieve reputation information for a specific domain.

**Endpoint:** `GET /reputation/{domain}`

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | Yes | Domain to check reputation for |

**Response:**
```json
{
  "domain": "example.com",
  "reputation_score": 88,
  "total_checks": 1250,
  "malicious_count": 2,
  "last_threat_level": "LOW",
  "first_seen": "2004-01-15T00:00:00Z",
  "last_seen": "2024-01-15T10:30:00Z"
}
```

### 8. Get Analysis Statistics

Retrieve URL analysis statistics for the authenticated user.

**Endpoint:** `GET /stats`

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `days` | integer | No | Number of days to include (1-365, default: 30) |

**Response:**
```json
{
  "period": {
    "start_date": "2023-12-16T00:00:00Z",
    "end_date": "2024-01-15T23:59:59Z",
    "days": 30
  },
  "totals": {
    "total_checks": 245,
    "unique_domains": 89,
    "threats_detected": 12,
    "safe_urls": 233
  },
  "threat_breakdown": {
    "SAFE": 233,
    "LOW": 8,
    "MEDIUM": 3,
    "HIGH": 1,
    "CRITICAL": 0
  },
  "scan_types": {
    "SECURITY": 245,
    "REPUTATION": 198,
    "CONTENT": 156,
    "TECHNICAL": 89
  },
  "daily_stats": [
    {
      "date": "2024-01-15",
      "checks": 15,
      "threats": 1,
      "avg_confidence": 92.5
    }
  ]
}
```

## Threat Levels

LinkShield uses a five-tier threat classification system:

| Level | Score Range | Description | Recommended Action |
|-------|-------------|-------------|-------------------|
| `SAFE` | 80-100 | No threats detected | Proceed normally |
| `LOW` | 60-79 | Minor concerns or outdated content | Use with caution |
| `MEDIUM` | 40-59 | Suspicious indicators present | Investigate further |
| `HIGH` | 20-39 | Likely threats detected | Block or warn users |
| `CRITICAL` | 0-19 | Confirmed malicious content | Block immediately |

## Analysis Status

| Status | Description |
|--------|-------------|
| `PENDING` | Analysis queued for processing |
| `IN_PROGRESS` | Currently being analyzed |
| `COMPLETED` | Analysis finished successfully |
| `FAILED` | Analysis failed due to error |
| `TIMEOUT` | Analysis timed out |

## Rate Limits

### Authenticated Users

| Plan | Single URL | Bulk URLs | History | Reputation |
|------|------------|-----------|---------|------------|
| **Free** | 30/hour | 10/hour | 100/hour | 50/hour |
| **Pro** | 500/hour | 100/hour | 1000/hour | 500/hour |
| **Enterprise** | Unlimited | Unlimited | Unlimited | Unlimited |

### Anonymous Users

| Endpoint | Limit | Scope |
|----------|-------|-------|
| Single URL Analysis | 10/hour | Per IP |
| Get Results | 50/hour | Per IP |
| Domain Reputation | 20/hour | Per IP |

Implementation note: In the current codebase, anonymous single URL analysis does not have a hard hourly cap; only broken-link scan parameters are restricted (e.g., scan_depth=1, max_links=10). The 10/hour limit above is an operational recommendation that will apply when a global rate-limiting middleware is enabled.

Rate limit headers are included in all responses:

```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1642262400
X-RateLimit-Scope: user
```

## Webhooks

LinkShield supports webhook notifications for asynchronous analysis results.

### Single URL Webhook

**Event:** `url_check_completed`

**Payload:**
```json
{
  "event": "url_check_completed",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "url": "https://example.com",
    "threat_level": "SAFE",
    "confidence_score": 95,
    "status": "COMPLETED",
    "completed_at": "2024-01-15T10:30:15Z"
  }
}
```

### Bulk Analysis Webhook

**Event:** `bulk_url_check_completed`

**Payload:**
```json
{
  "event": "bulk_url_check_completed",
  "data": {
    "total_urls": 3,
    "completed_at": "2024-01-15T10:35:00Z",
    "results": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "url": "https://example1.com",
        "threat_level": "SAFE",
        "status": "COMPLETED"
      }
    ]
  }
}
```

## Error Handling

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_URL` | 400 | URL format is invalid |
| `URL_UNREACHABLE` | 400 | URL cannot be accessed |
| `ANALYSIS_FAILED` | 500 | Analysis service error |
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded |
| `INSUFFICIENT_CREDITS` | 402 | Not enough analysis credits |
| `CHECK_NOT_FOUND` | 404 | Analysis ID not found |
| `UNAUTHORIZED_ACCESS` | 403 | Cannot access this analysis |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "INVALID_URL",
    "message": "The provided URL format is invalid",
    "details": {
      "url": "invalid-url",
      "reason": "Missing protocol (http:// or https://)"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Security Features

### Input Validation
- URL format validation and normalization
- Maximum URL length enforcement (2048 characters)
- Protocol validation (HTTP/HTTPS only)
- Domain validation and sanitization

### Privacy Protection
- No URL content is stored permanently
- Analysis results are encrypted at rest
- User data is anonymized in logs
- GDPR compliance for EU users

### Abuse Prevention
- Rate limiting per user and IP
- Suspicious pattern detection
- Automated blocking of malicious requests
- Honeypot URL detection

## Code Examples

### JavaScript/TypeScript

```typescript
interface URLAnalysisRequest {
  url: string;
  scan_types?: string[];
  priority?: boolean;
  callback_url?: string;
}

interface URLAnalysisResponse {
  id: string;
  original_url: string;
  status: string;
  threat_level: string;
  confidence_score: number;
  analysis_results: any;
}

class URLAnalysisClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  async analyzeUrl(request: URLAnalysisRequest): Promise<URLAnalysisResponse> {
    const response = await fetch(`${this.baseUrl}/api/v1/url-check/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey
      },
      body: JSON.stringify(request)
    });

    if (!response.ok) {
      throw new Error(`Analysis failed: ${response.statusText}`);
    }

    return response.json();
  }

  async getResults(checkId: string): Promise<URLAnalysisResponse> {
    const response = await fetch(`${this.baseUrl}/api/v1/url-check/check/${checkId}`, {
      headers: {
        'X-API-Key': this.apiKey
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to get results: ${response.statusText}`);
    }

    return response.json();
  }

  async bulkAnalyze(urls: string[]): Promise<URLAnalysisResponse[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/url-check/bulk-check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey
      },
      body: JSON.stringify({ urls })
    });

    if (!response.ok) {
      throw new Error(`Bulk analysis failed: ${response.statusText}`);
    }

    return response.json();
  }
}

// Usage example
const client = new URLAnalysisClient('https://api.linkshield.com', 'your-api-key');

// Analyze single URL
const result = await client.analyzeUrl({
  url: 'https://suspicious-site.com',
  scan_types: ['SECURITY', 'REPUTATION'],
  priority: true
});

console.log(`Threat Level: ${result.threat_level}`);
console.log(`Confidence: ${result.confidence_score}%`);
```

### Python

```python
import requests
from typing import List, Dict, Any, Optional

class URLAnalysisClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({'X-API-Key': api_key})

    def analyze_url(
        self,
        url: str,
        scan_types: Optional[List[str]] = None,
        priority: bool = False,
        callback_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze a single URL for security threats."""
        payload = {
            'url': url,
            'priority': priority
        }
        
        if scan_types:
            payload['scan_types'] = scan_types
        if callback_url:
            payload['callback_url'] = callback_url

        response = self.session.post(
            f'{self.base_url}/api/v1/url-check/check',
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_results(self, check_id: str) -> Dict[str, Any]:
        """Get analysis results by check ID."""
        response = self.session.get(
            f'{self.base_url}/api/v1/url-check/check/{check_id}'
        )
        response.raise_for_status()
        return response.json()

    def bulk_analyze(
        self,
        urls: List[str],
        scan_types: Optional[List[str]] = None,
        callback_url: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Analyze multiple URLs in batch."""
        payload = {'urls': urls}
        
        if scan_types:
            payload['scan_types'] = scan_types
        if callback_url:
            payload['callback_url'] = callback_url

        response = self.session.post(
            f'{self.base_url}/api/v1/url-check/bulk-check',
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Get reputation information for a domain."""
        response = self.session.get(
            f'{self.base_url}/api/v1/url-check/reputation/{domain}'
        )
        response.raise_for_status()
        return response.json()

# Usage example
client = URLAnalysisClient('https://api.linkshield.com', 'your-api-key')

# Analyze single URL
result = client.analyze_url(
    url='https://suspicious-site.com',
    scan_types=['SECURITY', 'REPUTATION'],
    priority=True
)

print(f"Analysis ID: {result['id']}")
print(f"Status: {result['status']}")

# Check if analysis is complete
if result['status'] == 'COMPLETED':
    print(f"Threat Level: {result['threat_level']}")
    print(f"Confidence: {result['confidence_score']}%")
else:
    # Poll for results
    import time
    while True:
        updated_result = client.get_results(result['id'])
        if updated_result['status'] == 'COMPLETED':
            print(f"Threat Level: {updated_result['threat_level']}")
            break
        time.sleep(2)
```

## Best Practices

### Performance Optimization
1. **Use bulk analysis** for multiple URLs to reduce API calls
2. **Implement caching** for frequently analyzed domains
3. **Use webhooks** for asynchronous processing
4. **Batch requests** during off-peak hours when possible

### Security Considerations
1. **Validate URLs** on client-side before sending to API
2. **Implement rate limiting** on your application
3. **Store API keys securely** and rotate regularly
4. **Use HTTPS** for all API communications
5. **Sanitize URLs** before displaying to users

### Error Handling
1. **Implement retry logic** with exponential backoff
2. **Handle rate limits** gracefully with queuing
3. **Log errors** for debugging and monitoring
4. **Provide fallback mechanisms** for critical workflows

### Monitoring
1. **Track API usage** and quota consumption
2. **Monitor response times** and error rates
3. **Set up alerts** for unusual patterns
4. **Review threat detection** accuracy regularly

---

**Next Steps:**
- Review [User Management Endpoints](user-management.md) for account operations
- Check [Authentication Guide](../authentication.md) for security setup
- See [Rate Limiting](../rate-limiting.md) for quota management