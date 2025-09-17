# API Reference

This document provides comprehensive documentation for LinkShield's REST API endpoints, including authentication, request/response formats, and usage examples.

## Base URL

```
Production: https://linkshield.com/api
Development: http://localhost:3000/api
```

## Authentication

LinkShield uses NextAuth.js for session-based authentication. Most endpoints require a valid authenticated session.

### Authentication Methods

1. **Session-based (Web)**: Automatic via NextAuth.js cookies
2. **Cookie Authentication**: Session cookies are automatically included in requests from the web application

### Session Requirements

```typescript
// Required session structure
interface Session {
  user: {
    id: string
    email: string
    name?: string
    plan: 'free' | 'pro' | 'enterprise'
  }
}
```

### Authentication Responses

```json
// Unauthorized (401)
{
  "success": false,
  "error": "Unauthorized"
}

// Forbidden - Premium required (403)
{
  "error": "Premium plan required"
}
```

## Rate Limiting

All API endpoints are protected by IP-based rate limiting:

- **Rate Limit**: 10 requests per minute per IP address
- **Scope**: Applied to all endpoints
- **Implementation**: In-memory rate limiting with automatic window reset

### Rate Limit Response

```json
// Rate limit exceeded (429)
{
  "error": "Too many requests. Please try again later."
}
```

## Usage Limits

Plan-based usage limits are enforced for authenticated users:

### Plan Limits

```typescript
const PLAN_LIMITS = {
  free: { 
    checksPerMonth: 5, 
    aiAnalysesPerMonth: 2 
  },
  pro: { 
    checksPerMonth: 500, 
    aiAnalysesPerMonth: 50 
  },
  enterprise: { 
    checksPerMonth: 2500, 
    aiAnalysesPerMonth: 500 
  }
}
```

## Core Endpoints

### URL Analysis

#### POST /api/check

Analyze a URL for security threats and content quality.

**Authentication**: Optional (anonymous users have limited functionality)

**Request Body:**
```json
{
  "url": "https://example.com",
  "includeAI": false
}
```

**Parameters:**
- `url` (string, required): The URL to analyze (must be valid HTTP/HTTPS URL)
- `includeAI` (boolean, optional): Include AI content analysis (requires Pro/Enterprise plan)

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "url": "https://example.com",
    "securityScore": 85,
    "statusCode": 200,
    "responseTimeMs": 245,
    "sslValid": true,
    "createdAt": "2024-01-15T10:30:00Z",
    "analysis": {
      "threats": [],
      "redirectChain": [],
      "metadata": {
        "title": "Example Site",
        "description": "Site description"
      }
    },
    "aiAnalysis": {
      "summary": "Content summary",
      "qualityMetrics": {
        "readabilityScore": 78,
        "contentDepthScore": 82,
        "overallQuality": 80
      },
      "topics": ["technology", "web development"]
    }
  },
  "cached": false
}
```

**Error Responses:**
```json
// Invalid URL (400)
{
  "success": false,
  "error": "Invalid URL provided"
}

// Usage limit exceeded (429)
{
  "success": false,
  "error": "Monthly check limit reached",
  "code": "LIMIT_EXCEEDED",
  "usage": {
    "checksThisMonth": 5,
    "checksLimit": 5,
    "checksRemaining": 0
  }
}

// AI limit exceeded (429)
{
  "success": false,
  "error": "Monthly AI analysis limit reached",
  "code": "AI_LIMIT_EXCEEDED",
  "usage": {
    "aiAnalysesThisMonth": 2,
    "aiAnalysesLimit": 2,
    "aiAnalysesRemaining": 0
  }
}
```

### Reports Management

#### GET /api/reports/[slug]

Retrieve a shareable report by its slug.

**Authentication**: Optional (public reports accessible to all)

**Parameters:**
- `slug` (string): The report's unique slug identifier

**Success Response (200):**
```json
{
  "id": "uuid",
  "slug": "abc123",
  "url": "https://example.com",
  "title": "Security Analysis Report",
  "description": "Comprehensive security analysis",
  "isPublic": true,
  "securityScore": 85,
  "createdAt": "2024-01-15T10:30:00Z",
  "analysis": {
    "statusCode": 200,
    "responseTimeMs": 245,
    "sslValid": true,
    "threats": [],
    "metadata": {}
  },
  "aiAnalysis": {
    "summary": "Content analysis summary",
    "qualityMetrics": {},
    "topics": []
  },
  "viewCount": 42
}
```

**Error Responses:**
```json
// Report not found (404)
{
  "error": "Report not found"
}

// Access denied to private report (403)
{
  "error": "Access denied"
}
```

#### PUT /api/reports/[slug]/privacy

Update report privacy settings.

**Authentication**: Required (must be report owner)

**Request Body:**
```json
{
  "isPublic": true
}
```

**Success Response (200):**
```json
{
  "message": "Report privacy updated successfully"
}
```

#### POST /api/reports/[slug]/view

Track a report view for analytics.

**Authentication**: Optional

**Success Response (200):**
```json
{
  "message": "Report view tracked"
}
```

#### POST /api/reports/[slug]/share

Share a report (create shareable version).

**Authentication**: Required (must be report owner)

**Success Response (200):**
```json
{
  "message": "Report shared successfully",
  "shareUrl": "https://linkshield.com/report/abc123"
}
```

### Dashboard Endpoints

#### GET /api/dashboard/stats

Get user dashboard statistics and usage metrics.

**Authentication**: Required

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "usage": {
      "checksThisMonth": 25,
      "checksLimit": 500,
      "checksRemaining": 475,
      "aiAnalysesThisMonth": 8,
      "aiAnalysesLimit": 50,
      "aiAnalysesRemaining": 42
    },
    "stats": {
      "totalChecks": 156,
      "totalAIAnalyses": 42,
      "averageSecurityScore": 78.5,
      "threatsDetected": 3
    },
    "recentActivity": [
      {
        "type": "check",
        "url": "https://example.com",
        "timestamp": "2024-01-15T10:30:00Z",
        "securityScore": 85
      }
    ]
  }
}
```

#### GET /api/dashboard/history

Get user's analysis history with pagination.

**Authentication**: Required

**Query Parameters:**
- `page` (number, optional): Page number (default: 1)
- `limit` (number, optional): Items per page (default: 10, max: 50)

**Success Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "url": "https://example.com",
      "securityScore": 85,
      "statusCode": 200,
      "responseTime": 245,
      "sslValid": true,
      "createdAt": "2024-01-15T10:30:00Z",
      "hasAIAnalysis": true
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 156,
    "pages": 16
  }
}
```

#### GET /api/dashboard/shareable-reports

Get user's shareable reports.

**Authentication**: Required

**Success Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "slug": "abc123",
      "title": "Security Analysis",
      "url": "https://example.com",
      "isPublic": true,
      "viewCount": 42,
      "createdAt": "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### POST /api/dashboard/shareable-reports

Create a new shareable report.

**Authentication**: Required

**Request Body:**
```json
{
  "checkId": "uuid",
  "title": "My Security Analysis",
  "description": "Detailed security analysis of my website",
  "isPublic": true
}
```

**Success Response (201):**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "slug": "abc123",
    "title": "My Security Analysis",
    "url": "https://example.com",
    "isPublic": true,
    "shareUrl": "https://linkshield.com/report/abc123"
  }
}
```

#### GET /api/dashboard/recent-reports

Get user's recent reports.

**Authentication**: Required

**Success Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "url": "https://example.com",
      "securityScore": 85,
      "createdAt": "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### DELETE /api/dashboard/[id]

Delete a user's check/report.

**Authentication**: Required (must be owner)

**Parameters:**
- `id` (string): The check/report ID to delete

**Success Response (200):**
```json
{
  "success": true,
  "message": "Check deleted successfully"
}
```

### Project Management (Pro/Enterprise)

#### GET /api/projects

Get user's projects.

**Authentication**: Required (Pro/Enterprise plans only)

**Success Response (200):**
```json
{
  "data": [
    {
      "id": "uuid",
      "name": "My Website",
      "domain": "example.com",
      "isVerified": true,
      "monitoringFrequency": "daily",
      "createdAt": "2024-01-15T10:30:00Z",
      "projectUrls": [
        {
          "id": "uuid",
          "url": "https://example.com/page1",
          "addedAt": "2024-01-15T10:30:00Z"
        }
      ],
      "_count": {
        "projectUrls": 25,
        "scanResults": 150
      }
    }
  ]
}
```

#### POST /api/projects

Create a new project.

**Authentication**: Required (Pro/Enterprise plans only)

**Request Body:**
```json
{
  "name": "My Website",
  "domain": "example.com"
}
```

**Validation Rules:**
- `name`: 1-100 characters, required
- `domain`: Valid domain format, 1-255 characters, required

**Success Response (201):**
```json
{
  "data": {
    "id": "uuid",
    "name": "My Website",
    "domain": "example.com",
    "isVerified": false,
    "verificationToken": "linkshield-abc123def456",
    "monitoringFrequency": "daily",
    "createdAt": "2024-01-15T10:30:00Z",
    "projectUrls": [],
    "_count": {
      "projectUrls": 0,
      "scanResults": 0
    }
  }
}
```

#### POST /api/projects/[id]/verify

Verify project domain ownership.

**Authentication**: Required (must be project owner)

**Parameters:**
- `id` (string): Project ID

**Success Response (200):**
```json
{
  "success": true,
  "message": "Domain verified successfully",
  "project": {
    "id": "uuid",
    "name": "My Website",
    "domain": "example.com",
    "isVerified": true
  }
}
```

#### GET /api/projects/[id]/urls

Get project URLs.

**Authentication**: Required (must be project owner)

**Parameters:**
- `id` (string): Project ID

**Success Response (200):**
```json
{
  "data": [
    {
      "id": "uuid",
      "url": "https://example.com/page1",
      "isActive": true,
      "addedAt": "2024-01-15T10:30:00Z",
      "lastScanned": "2024-01-15T12:00:00Z",
      "scanResults": [
        {
          "id": "uuid",
          "securityScore": 85,
          "createdAt": "2024-01-15T12:00:00Z"
        }
      ]
    }
  ]
}
```

#### POST /api/projects/[id]/urls

Add a URL to a project.

**Authentication**: Required (must be project owner)

**Parameters:**
- `id` (string): Project ID

**Request Body:**
```json
{
  "url": "https://example.com/new-page"
}
```

**Success Response (201):**
```json
{
  "data": {
    "id": "uuid",
    "url": "https://example.com/new-page",
    "isActive": true,
    "addedAt": "2024-01-15T10:30:00Z"
  }
}
```

#### POST /api/projects/[id]/scan

Trigger a manual scan of project URLs.

**Authentication**: Required (must be project owner)

**Parameters:**
- `id` (string): Project ID

**Success Response (200):**
```json
{
  "success": true,
  "message": "Scan initiated for project URLs",
  "scanId": "uuid"
}
```

### Payment Endpoints

#### POST /api/stripe/checkout

Create a Stripe checkout session.

**Authentication**: Required

**Request Body:**
```json
{
  "priceId": "price_1234567890",
  "plan": "pro"
}
```

**Success Response (200):**
```json
{
  "url": "https://checkout.stripe.com/pay/cs_test_..."
}
```

#### POST /api/stripe/webhook

Stripe webhook endpoint for payment events.

**Authentication**: Webhook signature verification

**Note**: This endpoint is called by Stripe and handles subscription events.

#### POST /api/paypal/checkout

Create a PayPal checkout session.

**Authentication**: Required

**Request Body:**
```json
{
  "plan": "pro"
}
```

**Success Response (200):**
```json
{
  "approvalUrl": "https://www.paypal.com/checkoutnow?token=..."
}
```

#### POST /api/paypal/webhook

PayPal webhook endpoint for payment events.

**Authentication**: Webhook signature verification

**Note**: This endpoint is called by PayPal and handles subscription events.

### Authentication Endpoints

#### POST /api/auth/register

Register a new user account.

**Authentication**: None required

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword",
  "name": "John Doe"
}
```

**Success Response (201):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe"
  }
}
```

### Analytics Endpoints

#### POST /api/analytics/sidebar-impression

Track sidebar impression for analytics.

**Authentication**: Optional

**Request Body:**
```json
{
  "page": "/dashboard",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Success Response (200):**
```json
{
  "success": true,
  "message": "Impression tracked"
}
```

### Open Graph Endpoints

#### GET /api/og/[slug]

Generate Open Graph image for a report.

**Authentication**: None required

**Parameters:**
- `slug` (string): Report slug

**Response**: Returns an image (PNG format) for social media sharing.

#### GET /api/og/default

Generate default Open Graph image.

**Authentication**: None required

**Response**: Returns a default Open Graph image (PNG format).

### Health Check

#### GET /api/health

Health check endpoint for monitoring.

**Authentication**: None required

**Success Response (200):**
```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

## Error Handling

### Standard Error Response Format

```json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE" // Optional
}
```

### Common HTTP Status Codes

- `200`: Success
- `201`: Created
- `400`: Bad Request (invalid input)
- `401`: Unauthorized (authentication required)
- `403`: Forbidden (insufficient permissions)
- `404`: Not Found
- `429`: Too Many Requests (rate limit or usage limit exceeded)
- `500`: Internal Server Error

### Error Codes

- `LIMIT_EXCEEDED`: Monthly usage limit reached
- `AI_LIMIT_EXCEEDED`: AI analysis limit reached
- `INVALID_URL`: URL format is invalid
- `PREMIUM_REQUIRED`: Feature requires premium plan

## Request/Response Guidelines

### Content Type

All API endpoints expect and return JSON data:

```http
Content-Type: application/json
```

### Request Headers

```http
Content-Type: application/json
Cookie: next-auth.session-token=...
```

### Response Headers

```http
Content-Type: application/json
Cache-Control: no-cache, no-store, must-revalidate
```

## Usage Examples

### Analyze a URL

```javascript
// Basic URL analysis
const response = await fetch('/api/check', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    url: 'https://example.com'
  })
})

const result = await response.json()
```

### Get Dashboard Stats

```javascript
// Fetch user dashboard statistics
const response = await fetch('/api/dashboard/stats')
const stats = await response.json()

console.log(`Checks used: ${stats.data.usage.checksThisMonth}/${stats.data.usage.checksLimit}`)
```

### Create a Project

```javascript
// Create a new project (Pro/Enterprise only)
const response = await fetch('/api/projects', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    name: 'My Website',
    domain: 'example.com'
  })
})

const project = await response.json()
```

## SDK and Integration

### JavaScript/TypeScript

```typescript
// Type definitions for API responses
interface CheckResult {
  id: string
  url: string
  securityScore: number
  statusCode: number
  responseTimeMs: number
  sslValid: boolean
  createdAt: string
  analysis: {
    threats: any[]
    redirectChain: any[]
    metadata: {
      title?: string
      description?: string
    }
  }
  aiAnalysis?: {
    summary: string
    qualityMetrics: {
      readabilityScore: number
      contentDepthScore: number
      overallQuality: number
    }
    topics: string[]
  }
}

// API client example
class LinkShieldAPI {
  async analyzeUrl(url: string, includeAI = false): Promise<CheckResult> {
    const response = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, includeAI })
    })
    
    const result = await response.json()
    if (!result.success) {
      throw new Error(result.error)
    }
    
    return result.data
  }
}
```

## Rate Limiting and Best Practices

### Rate Limiting Strategy

1. **Respect Rate Limits**: 10 requests per minute per IP
2. **Implement Backoff**: Use exponential backoff for 429 responses
3. **Cache Results**: Cache analysis results when possible
4. **Batch Operations**: Group multiple operations when supported

### Best Practices

1. **Error Handling**: Always check response status and handle errors gracefully
2. **Authentication**: Ensure session cookies are included in requests
3. **Input Validation**: Validate URLs and input data before sending requests
4. **Monitoring**: Monitor usage limits and plan accordingly
5. **Security**: Never expose API responses containing sensitive data

### Example Error Handling

```javascript
async function analyzeUrlSafely(url) {
  try {
    const response = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    })
    
    if (response.status === 429) {
      // Handle rate limiting
      throw new Error('Rate limit exceeded. Please try again later.')
    }
    
    if (response.status === 401) {
      // Handle authentication
      throw new Error('Authentication required')
    }
    
    const result = await response.json()
    
    if (!result.success) {
      throw new Error(result.error)
    }
    
    return result.data
  } catch (error) {
    console.error('API Error:', error.message)
    throw error
  }
}
```

This API reference reflects the current implementation of LinkShield's REST API as of the latest codebase version.
