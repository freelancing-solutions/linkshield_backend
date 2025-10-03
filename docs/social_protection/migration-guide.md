# Social Protection API Migration Guide

## Overview

The Social Protection API has been refactored into specialized controllers and routes for better organization and maintainability. This guide will help you migrate from the deprecated endpoints to the new ones.

## Deprecation Timeline

- **Deprecation Date**: October 3, 2025
- **Sunset Date**: January 1, 2026
- **Support Period**: 3 months

## New API Structure

The old `/api/v1/social-protection/*` endpoints have been split into four specialized route groups:

### 1. User Routes (`/api/v1/social-protection/user/*`)
For user-facing dashboard operations, settings, and analytics.

### 2. Bot Routes (`/api/v1/social-protection/bot/*`)
For bot integration and automated analysis services.

### 3. Extension Routes (`/api/v1/social-protection/extension/*`)
For browser extension integration with real-time analysis.

### 4. Crisis Routes (`/api/v1/social-protection/crisis/*`)
For crisis detection and brand protection.

## Migration Mapping

### Extension Data Processing

**Old Endpoint:**
```
POST /api/v1/social-protection/extension/process
```

**New Endpoint:**
```
POST /api/v1/social-protection/extension/process
```

**Changes:**
- Enhanced request/response models
- Support for multiple analysis modes (REAL_TIME, BACKGROUND, ON_DEMAND, BATCH)
- Support for multiple response types (IMMEDIATE, PROGRESSIVE, CACHED, DEFERRED)
- Improved error handling

**Migration Example:**
```python
# Old
response = requests.post(
    "/api/v1/social-protection/extension/process",
    json={"data": extension_data}
)

# New
response = requests.post(
    "/api/v1/social-protection/extension/process",
    json={
        "event_type": "PAGE_LOAD",
        "platform": "twitter",
        "url": "https://twitter.com/example",
        "timestamp": "2025-10-03T12:00:00Z",
        "content": {...},
        "analysis_mode": "REAL_TIME",
        "response_type": "IMMEDIATE"
    }
)
```

### Social Profile Scanning

**Old Endpoint:**
```
POST /api/v1/social-protection/scans
```

**New Endpoint:**
```
POST /api/v1/social-protection/user/scan
```

**Changes:**
- Moved to user-specific routes
- Enhanced scan options
- Better progress tracking
- Improved result formatting

**Migration Example:**
```python
# Old
response = requests.post(
    "/api/v1/social-protection/scans",
    json={
        "platform": "twitter",
        "profile_url": "https://twitter.com/example"
    }
)

# New
response = requests.post(
    "/api/v1/social-protection/user/scan",
    json={
        "platform": "twitter",
        "profile_url": "https://twitter.com/example",
        "scan_options": {
            "include_content_analysis": true,
            "include_follower_analysis": true,
            "include_engagement_analysis": true
        }
    }
)
```

### Content Risk Assessment

**Old Endpoint:**
```
POST /api/v1/social-protection/assessments
```

**New Endpoint:**
```
POST /api/v1/social-protection/user/analyze
```

**Changes:**
- Moved to user-specific routes
- Enhanced analysis capabilities
- Better risk scoring
- More detailed recommendations

**Migration Example:**
```python
# Old
response = requests.post(
    "/api/v1/social-protection/assessments",
    json={
        "content": "Sample content",
        "content_type": "post"
    }
)

# New
response = requests.post(
    "/api/v1/social-protection/user/analyze",
    json={
        "content": "Sample content",
        "platform": "twitter",
        "content_type": "post",
        "metadata": {
            "author": "example_user",
            "timestamp": "2025-10-03T12:00:00Z"
        }
    }
)
```

### Bot Operations

**Old Endpoint:**
```
POST /api/v1/social-protection/bot-analyze
```

**New Endpoint:**
```
POST /api/v1/social-protection/bot/analyze
```

**Changes:**
- Dedicated bot routes
- Multiple response formats (json, minimal, detailed)
- Batch analysis support
- Webhook integration

**Migration Example:**
```python
# Old
response = requests.post(
    "/api/v1/social-protection/bot-analyze",
    json={"content": "Sample content"}
)

# New
response = requests.post(
    "/api/v1/social-protection/bot/analyze",
    json={
        "content": "Sample content",
        "platform": "twitter",
        "response_format": "minimal"  # or "json", "detailed"
    }
)
```

## New Features

### 1. User Dashboard

Access comprehensive protection analytics and settings:

```python
# Get protection settings
GET /api/v1/social-protection/user/settings

# Update protection settings
PUT /api/v1/social-protection/user/settings

# Get analytics
GET /api/v1/social-protection/user/analytics?time_range=30d

# Get algorithm health
GET /api/v1/social-protection/user/algorithm-health?platform=twitter&profile_identifier=example
```

### 2. Crisis Detection

New crisis detection and management capabilities:

```python
# Evaluate brand for crisis
POST /api/v1/social-protection/crisis/evaluate
{
    "brand": "YourBrand",
    "window_seconds": 3600
}

# Get crisis alerts
GET /api/v1/social-protection/crisis/alerts?brand=YourBrand&severity=HIGH

# Get crisis history
GET /api/v1/social-protection/crisis/history?brand=YourBrand&days=30

# Update alert status
PUT /api/v1/social-protection/crisis/alerts/{alert_id}
{
    "resolved": true,
    "resolution_notes": "Issue addressed"
}
```

### 3. Extension Features

Enhanced extension capabilities:

```python
# Real-time analysis
POST /api/v1/social-protection/extension/analyze

# Settings management
GET /api/v1/social-protection/extension/settings
PUT /api/v1/social-protection/extension/settings

# State synchronization
POST /api/v1/social-protection/extension/sync

# Analytics
GET /api/v1/social-protection/extension/analytics
```

### 4. Bot Integration

Comprehensive bot integration:

```python
# Quick analysis
POST /api/v1/social-protection/bot/analyze

# Account safety
POST /api/v1/social-protection/bot/account-safety

# Compliance check
POST /api/v1/social-protection/bot/compliance

# Follower analysis
POST /api/v1/social-protection/bot/followers

# Health check
GET /api/v1/social-protection/bot/health
```

## Authentication

Authentication remains the same - use JWT tokens in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

## Rate Limiting

Rate limits have been updated and are now subscription-based:

- **Free Tier**: 50 requests/hour for scans, 100 requests/hour for assessments
- **Premium Tier**: 500 requests/hour for scans, 1000 requests/hour for assessments

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1696348800
```

## Error Handling

Error responses now follow a standardized format:

```json
{
    "success": false,
    "error": {
        "code": "RATE_LIMIT_EXCEEDED",
        "message": "Rate limit exceeded",
        "details": {
            "limit": 100,
            "window_seconds": 3600,
            "retry_after": 1800
        }
    }
}
```

## Breaking Changes

### 1. Response Format Changes

All responses now include a `success` field:

```json
{
    "success": true,
    "data": {...}
}
```

### 2. Enum Value Changes

Some enum values have been standardized:
- `PlatformType`: Now uses lowercase values (e.g., "twitter" instead of "TWITTER")
- `RiskLevel`: Consistent across all endpoints

### 3. Timestamp Format

All timestamps now use ISO 8601 format with timezone:
```
2025-10-03T12:00:00+00:00
```

## Testing Your Migration

### 1. Update API Endpoints

Replace all old endpoint URLs with new ones according to the mapping above.

### 2. Update Request/Response Models

Update your client code to use the new request and response formats.

### 3. Test Authentication

Ensure your JWT tokens work with the new endpoints.

### 4. Test Rate Limiting

Verify that rate limiting works as expected with your subscription tier.

### 5. Test Error Handling

Ensure your error handling code works with the new error response format.

## Support

If you encounter issues during migration:

1. Check the [API Documentation](https://docs.linkshield.com/api)
2. Review the [Examples Repository](https://github.com/linkshield/examples)
3. Contact support at support@linkshield.com
4. Join our [Discord Community](https://discord.gg/linkshield)

## Deprecation Warnings

The old endpoints will return deprecation warnings in the response headers:

```
X-API-Deprecated: true
X-API-Deprecation-Date: 2025-10-03
X-API-Sunset-Date: 2026-01-01
Warning: 299 - "This API endpoint is deprecated. Please migrate to the new specialized endpoints."
```

## Timeline

- **Now - December 31, 2025**: Both old and new endpoints available
- **January 1, 2026**: Old endpoints removed

Please complete your migration before January 1, 2026 to avoid service disruption.
