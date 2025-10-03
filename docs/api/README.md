# LinkShield API Documentation

Welcome to the LinkShield API documentation. LinkShield is a comprehensive URL security analysis platform built with FastAPI, providing real-time threat detection, AI-powered content analysis, and subscription-based access control.

## Overview

LinkShield Backend API is a FastAPI-based REST API that provides:

- **URL Security Analysis**: Multi-provider threat detection using VirusTotal, Google Safe Browsing, and URLVoid
- **AI-Powered Content Analysis**: Advanced phishing detection and content quality scoring using OpenAI
- **User Authentication**: JWT-based authentication with API key support and session management
- **Subscription Management**: Tiered access control with usage quotas (Free, Basic, Pro, Enterprise)
- **Community Reporting**: User-driven threat intelligence and feedback system
- **Rate Limiting**: Configurable rate limiting and abuse prevention
- **Real-time Monitoring**: Health checks and comprehensive metrics collection

## Architecture

The LinkShield API is built using modern Python technologies:

- **Framework**: FastAPI 0.104.1 with automatic OpenAPI documentation
- **Database**: PostgreSQL with SQLAlchemy ORM and Alembic migrations
- **Cache**: Redis for session storage, rate limiting, and caching
- **Authentication**: JWT tokens with bcrypt password hashing
- **AI/ML**: OpenAI GPT integration for intelligent content analysis
- **Background Tasks**: Celery for asynchronous processing
- **Monitoring**: Prometheus metrics and comprehensive health checks

## Quick Start

### Base URLs

- **Development**: `https://www.linkshield.site`
- **Production**: `https://api.linkshield.site`

### Authentication

LinkShield API supports two authentication methods:

1. **JWT Tokens** (Recommended for web applications)
   ```bash
   Authorization: Bearer <jwt_token>
   ```

2. **API Keys** (Recommended for server-to-server integration)
   ```bash
   X-API-Key: <api_key>
   ```

### Basic Example

```bash
# Register a new user
curl -X POST "https://www.linkshield.site/api/v1/user/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure_password",
    "full_name": "John Doe"
  }'

# Login and get JWT token
curl -X POST "https://www.linkshield.site/api/v1/user/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure_password"
  }'

# Check a URL for threats
curl -X POST "https://www.linkshield.site/api/v1/url-check/" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "scan_type": "comprehensive"
  }'
```

## API Endpoints

The LinkShield API is organized into the following main sections:

### Core Services
- **[URL Analysis](endpoints/url-analysis.md)** - URL security scanning and threat detection
- **[User Management](endpoints/user-management.md)** - User registration, authentication, and profile management
- **[AI Analysis](endpoints/ai-analysis.md)** - AI-powered content analysis and insights
- **[Bot Integration](endpoints/bot-integration.md)** - Social media bot webhooks and analysis services

### Community Features
- **[Reports](endpoints/reports.md)** - Community reporting system with voting and moderation
- **[Health Monitoring](endpoints/health-monitoring.md)** - System health checks and monitoring

### System Documentation
- **[Authentication](authentication.md)** - Comprehensive authentication guide
- **[Data Models](data-models.md)** - Complete data model reference
- **[Error Handling](error-handling.md)** - Error codes and troubleshooting
- **[Rate Limiting](rate-limiting.md)** - Rate limiting policies and quotas

## Rate Limits

LinkShield implements comprehensive rate limiting to ensure fair usage:

| Endpoint Type | Rate Limit | Scope |
|---------------|------------|-------|
| URL Analysis | 30/minute | Per user/IP |
| AI Analysis | 10/minute | Per user/IP |
| Authentication | 5/minute | Per IP |
| Report Generation | 20/minute | Per user |
| General API | 100/minute | Per IP |

Rate limits vary by subscription plan. See [Rate Limiting](rate-limiting.md) for details.

## Subscription Plans

LinkShield offers tiered subscription plans with different usage quotas:

| Plan | Monthly URL Checks | AI Analysis | Priority Support |
|------|-------------------|-------------|------------------|
| Free | 100 | 10 | Community |
| Basic | 1,000 | 100 | Email |
| Pro | 10,000 | 1,000 | Priority Email |
| Enterprise | Unlimited | Unlimited | Dedicated Support |

## Response Format

All API responses follow a consistent JSON format:

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "message": "Operation completed successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

Error responses include additional error details:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_URL",
    "message": "The provided URL is not valid",
    "details": {
      "field": "url",
      "value": "invalid-url"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Interactive Documentation

When running in development mode, LinkShield provides interactive API documentation:

- **Swagger UI**: `https://www.linkshield.site/docs`
- **ReDoc**: `https://www.linkshield.site/redoc`
- **OpenAPI JSON**: `https://www.linkshield.site/openapi.json`

## SDKs and Integration

LinkShield provides official SDKs and integration guides:

- **Python SDK**: Coming soon
- **JavaScript/TypeScript SDK**: Coming soon
- **Frontend Integration Guide**: See [Frontend SDK](../integration/frontend-sdk.md)
- **Deployment Guide**: See [Deployment](../integration/deployment.md)

## Support

- **Documentation Issues**: Create an issue in the GitHub repository
- **API Support**: Contact support@linkshield.com
- **Community**: Join our Discord server for community support
- **Status Page**: Check system status at status.linkshield.com

## Changelog

See [CHANGELOG.md](../../CHANGELOG.md) for version history and updates.

---

**Next Steps:**
- Review the [Authentication Guide](authentication.md) to understand security implementation
- Explore [URL Analysis Endpoints](endpoints/url-analysis.md) for core functionality
- Check [Data Models](data-models.md) for complete schema reference