# Social Protection API Endpoints

## Overview

The Social Protection API provides comprehensive endpoints for social media account protection, content risk assessment, and real-time monitoring. This API enables browser extensions and client applications to integrate with LinkShield's social protection services.

## Base URL

```
/api/v1/social-protection
```

## Authentication

All endpoints require JWT authentication via the `Authorization` header:

```
Authorization: Bearer <jwt_token>
```

## Rate Limiting

- **Extension Data Processing**: 100 requests per hour per user
- **Social Scanning**: 50 requests per hour per user  
- **Content Assessment**: 200 requests per hour per user
- **Dashboard Queries**: 500 requests per hour per user

## Endpoints

### 1. Health Check

**GET** `/health`

Check the health status of the social protection service.

#### Response

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

### 2. Process Extension Data

**POST** `/extension/process`

Process data collected by browser extensions for social media protection analysis.

#### Request Body

```json
{
  "project_id": "550e8400-e29b-41d4-a716-446655440000",
  "platform": "twitter",
  "data": {
    "url": "https://twitter.com/user/status/123456789",
    "content": "Sample tweet content",
    "metadata": {
      "timestamp": "2024-01-15T10:30:00Z",
      "user_agent": "Mozilla/5.0...",
      "additional_context": {}
    }
  }
}
```

#### Response

```json
{
  "success": true,
  "scan_id": "660e8400-e29b-41d4-a716-446655440001",
  "risk_level": "medium",
  "recommendations": [
    "Review content for potential policy violations",
    "Consider adjusting privacy settings"
  ],
  "processed_at": "2024-01-15T10:30:15Z"
}
```

#### Error Responses

- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Missing or invalid authentication
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Processing failed

### 3. Initiate Social Media Scan

**POST** `/scans`

Start a comprehensive scan of a social media profile or content.

#### Request Body

```json
{
  "project_id": "550e8400-e29b-41d4-a716-446655440000",
  "platform": "twitter",
  "target": "https://twitter.com/username",
  "scan_type": "profile_analysis",
  "options": {
    "deep_scan": true,
    "include_followers": false,
    "analyze_content": true
  }
}
```

#### Response

```json
{
  "scan_id": "660e8400-e29b-41d4-a716-446655440002",
  "status": "initiated",
  "estimated_completion": "2024-01-15T10:35:00Z",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### 4. Get Scan Status

**GET** `/scans/{scan_id}`

Retrieve the current status and results of a social media scan.

#### Path Parameters

- `scan_id` (UUID): The unique identifier of the scan

#### Response

```json
{
  "scan_id": "660e8400-e29b-41d4-a716-446655440002",
  "status": "completed",
  "progress": 100,
  "results": {
    "risk_level": "high",
    "threats_detected": 3,
    "recommendations": [
      "Enable two-factor authentication",
      "Review recent login activity",
      "Update privacy settings"
    ],
    "detailed_analysis": {
      "account_security": {
        "score": 65,
        "issues": ["Weak password policy", "No 2FA enabled"]
      },
      "content_risks": {
        "score": 40,
        "issues": ["Potential doxxing information", "Sensitive data exposure"]
      },
      "privacy_settings": {
        "score": 80,
        "issues": ["Location sharing enabled"]
      }
    }
  },
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:33:45Z"
}
```

### 5. List User Scans

**GET** `/scans`

Retrieve a list of scans for the authenticated user.

#### Query Parameters

- `project_id` (UUID, optional): Filter by project
- `platform` (string, optional): Filter by platform (twitter, facebook, instagram, etc.)
- `status` (string, optional): Filter by status (pending, in_progress, completed, failed)
- `limit` (integer, optional): Number of results to return (default: 20, max: 100)
- `offset` (integer, optional): Number of results to skip (default: 0)

#### Response

```json
{
  "scans": [
    {
      "scan_id": "660e8400-e29b-41d4-a716-446655440002",
      "platform": "twitter",
      "status": "completed",
      "risk_level": "high",
      "created_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T10:33:45Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

### 6. Create Content Assessment

**POST** `/assessments`

Create a risk assessment for specific social media content.

#### Request Body

```json
{
  "project_id": "550e8400-e29b-41d4-a716-446655440000",
  "content_type": "post",
  "platform": "twitter",
  "content": {
    "text": "Sample post content to analyze",
    "media_urls": ["https://example.com/image.jpg"],
    "metadata": {
      "scheduled_time": "2024-01-15T15:00:00Z",
      "target_audience": "general"
    }
  },
  "assessment_type": "pre_publish"
}
```

#### Response

```json
{
  "assessment_id": "770e8400-e29b-41d4-a716-446655440003",
  "risk_level": "low",
  "confidence_score": 0.92,
  "risk_factors": [
    {
      "category": "content_policy",
      "severity": "low",
      "description": "Content appears compliant with platform policies"
    }
  ],
  "recommendations": [
    "Content is safe to publish",
    "Consider adding relevant hashtags for better engagement"
  ],
  "created_at": "2024-01-15T10:30:00Z"
}
```

### 7. List Content Assessments

**GET** `/assessments`

Retrieve a list of content assessments for the authenticated user.

#### Query Parameters

- `project_id` (UUID, optional): Filter by project
- `platform` (string, optional): Filter by platform
- `risk_level` (string, optional): Filter by risk level (low, medium, high, critical)
- `assessment_type` (string, optional): Filter by assessment type
- `limit` (integer, optional): Number of results to return (default: 20, max: 100)
- `offset` (integer, optional): Number of results to skip (default: 0)

#### Response

```json
{
  "assessments": [
    {
      "assessment_id": "770e8400-e29b-41d4-a716-446655440003",
      "content_type": "post",
      "platform": "twitter",
      "risk_level": "low",
      "confidence_score": 0.92,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

## Data Models

### Platform Types

- `twitter`
- `facebook`
- `instagram`
- `linkedin`
- `tiktok`
- `youtube`
- `other`

### Risk Levels

- `low`: Minimal risk detected
- `medium`: Moderate risk requiring attention
- `high`: Significant risk requiring immediate action
- `critical`: Severe risk requiring urgent intervention

### Scan Status

- `pending`: Scan queued for processing
- `in_progress`: Scan currently running
- `completed`: Scan finished successfully
- `failed`: Scan encountered an error
- `cancelled`: Scan was cancelled by user

### Content Types

- `post`: Social media post/tweet
- `story`: Temporary story content
- `profile`: Profile information
- `comment`: Comment or reply
- `message`: Direct message
- `media`: Image, video, or other media

### Assessment Types

- `pre_publish`: Assessment before content publication
- `post_publish`: Assessment of already published content
- `scheduled`: Assessment of scheduled content
- `real_time`: Real-time monitoring assessment

## Error Handling

All endpoints return consistent error responses:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request data",
    "details": {
      "field": "project_id",
      "issue": "Invalid UUID format"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Common Error Codes

- `VALIDATION_ERROR`: Request validation failed
- `AUTHENTICATION_ERROR`: Invalid or missing authentication
- `AUTHORIZATION_ERROR`: Insufficient permissions
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `RESOURCE_NOT_FOUND`: Requested resource not found
- `INTERNAL_ERROR`: Server-side error
- `SERVICE_UNAVAILABLE`: Service temporarily unavailable

## Security Considerations

1. **Data Privacy**: All social media data is encrypted in transit and at rest
2. **Access Control**: Users can only access their own scans and assessments
3. **Rate Limiting**: Prevents abuse and ensures fair usage
4. **Input Validation**: All inputs are validated and sanitized
5. **Audit Logging**: All API calls are logged for security monitoring

## Integration Examples

### Browser Extension Integration

```javascript
// Process extension data
const response = await fetch('/api/v1/social-protection/extension/process', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    project_id: projectId,
    platform: 'twitter',
    data: {
      url: window.location.href,
      content: document.querySelector('[data-testid="tweetText"]').textContent,
      metadata: {
        timestamp: new Date().toISOString(),
        user_agent: navigator.userAgent
      }
    }
  })
});
```

### Dashboard Integration

```javascript
// Get social protection overview
const overview = await fetch('/api/v1/dashboard/social-protection/overview', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

## Changelog

### Version 1.0.0 (2024-01-15)
- Initial release of Social Protection API
- Support for Twitter, Facebook, Instagram, LinkedIn, TikTok, and YouTube
- Real-time content assessment and profile scanning
- Dashboard integration endpoints
- Comprehensive rate limiting and security features