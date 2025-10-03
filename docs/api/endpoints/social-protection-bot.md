# Social Protection Bot API

API routes for bot-integrated content analysis and safety checks.

## Base URL

```
/api/v1/social-protection/bot
```

## Authentication

JWT authentication is required for all endpoints except the health check.

```
Authorization: Bearer <jwt_token>
```

## Endpoints

### 1) Quick Content Analysis

**POST** `/analyze`

Provides fast content analysis optimized for bot integration.

#### Request Body
```json
{
  "content": "Text content to analyze",
  "platform": "twitter",
  "context": {},
  "response_format": "json"
}
```

#### Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | Yes | Content to analyze |
| `platform` | enum | No | Platform type (e.g., `twitter`, `discord`, `telegram`) |
| `context` | object | No | Optional context for analysis |
| `response_format` | string | No | One of `json`, `minimal`, `detailed` |

#### Response (example)
```json
{
  "success": true,
  "analysis": {
    "risk_level": "low",
    "threats_detected": [],
    "summary": "Content appears safe"
  }
}
```

### 2) Analyze Account Safety

**POST** `/account-safety`

Performs comprehensive safety assessment of a social media account.

#### Request Body
```json
{
  "platform": "twitter",
  "account_identifier": "@user",
  "check_followers": false,
  "check_content": true
}
```

#### Response (example)
```json
{
  "success": true,
  "account": "@user",
  "risk_level": "medium",
  "recommendations": ["Enable 2FA", "Review recent posts"]
}
```

### 3) Content Compliance Check

**POST** `/compliance`

Verifies content against platform policies and custom compliance rules.

#### Request Body
```json
{
  "content": "Text to validate",
  "platform": "twitter",
  "compliance_rules": ["no_hate_speech"],
  "strict_mode": false
}
```

#### Response (example)
```json
{
  "success": true,
  "compliant": true,
  "violations": []
}
```

### 4) Analyze Verified Followers

**POST** `/followers`

Analyzes follower quality and authenticity, optionally focusing on verified accounts.

#### Request Body
```json
{
  "platform": "twitter",
  "account_identifier": "@user",
  "sample_size": 100,
  "check_verified_only": false
}
```

#### Parameter constraints
- `sample_size`: integer, default 100, min 10, max 1000

#### Response (example)
```json
{
  "success": true,
  "sample_size": 100,
  "verified_ratio": 0.12,
  "suspected_bots": 3
}
```

### 5) Batch Content Analysis

**POST** `/batch-analyze`

Analyze multiple content items in a single request (max 50 items).

#### Request Body
```json
{
  "contents": ["text 1", "text 2"],
  "platform": "discord",
  "response_format": "json"
}
```

#### Response (example)
```json
{
  "success": true,
  "batch_size": 2,
  "results": [
    {"success": true, "analysis": {"risk_level": "low"}},
    {"success": true, "analysis": {"risk_level": "low"}}
  ],
  "failed_count": 0
}
```

### 6) Bot Webhook Handler

**POST** `/webhook`

Handles webhook events from bot integrations. Requires valid bot signature.

#### Headers
```
X-Bot-Signature: <signature>
```

#### Query Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | Yes | Event type identifier |

#### Request Body
`payload`: object containing event data.

#### Response (example)
```json
{
  "success": true,
  "event_type": "message",
  "processed": true,
  "message": "Webhook received and processed"
}
```

### 7) Health Check

**GET** `/health`

Returns health status of bot integration services.

Authentication: Public (no JWT required)

#### Response (example)
```json
{
  "healthy": true,
  "metrics": {}
}
```

### 8) Usage Statistics

**GET** `/stats`

Returns statistics about bot API usage.

#### Query Parameters
- `time_range`: string, one of `1h`, `24h`, `7d`, `30d` (default `24h`)

#### Response (example)
```json
{
  "success": true,
  "time_range": "24h",
  "stats": {
    "total_requests": 0,
    "analyses_performed": 0,
    "threats_detected": 0,
    "average_response_time": 0.0
  }
}
```

## Rate Limiting

Defaults vary by plan. Typical limits:
- Analyze endpoints: per-user limits apply
- Batch analysis: max 50 items per request

## Error Responses

Errors are returned with appropriate HTTP status codes and JSON payloads, e.g.:
```json
{
  "success": false,
  "error": "Failed to process request"
}
```