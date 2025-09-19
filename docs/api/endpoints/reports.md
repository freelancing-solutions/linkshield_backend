# Community Reporting System Endpoints

LinkShield's community reporting system enables users to report suspicious URLs, malicious content, and security threats. This collaborative approach helps build a comprehensive threat intelligence database through community contributions and expert moderation.

## Overview

The reporting system provides:

- **Report Creation**: Submit security reports for URLs and content
- **Report Management**: View, update, and track report status
- **Community Voting**: Vote on report accuracy and helpfulness
- **Moderation Tools**: Admin tools for report review and resolution
- **Statistics & Analytics**: Comprehensive reporting metrics
- **Template System**: Pre-defined templates for common report types

## Base URL

```
https://api.linkshield.com/api/v1/reports
```

## Authentication

Most reporting endpoints require authentication via JWT token:

```
Authorization: Bearer <jwt_token>
```

Public endpoints (viewing reports, statistics) may be accessible without authentication but with limited functionality.

## Report Types

The system supports the following report types:

| Type | Description | Priority | Auto-Analysis |
|------|-------------|----------|---------------|
| `PHISHING` | Phishing or social engineering attempts | Critical | Yes |
| `MALWARE` | Malware distribution or infected sites | Critical | Yes |
| `SPAM` | Spam or unwanted content | Medium | No |
| `SCAM` | Fraudulent or scam websites | High | Yes |
| `INAPPROPRIATE_CONTENT` | Inappropriate or offensive content | Medium | No |
| `COPYRIGHT_VIOLATION` | Copyright infringement | Low | No |
| `FALSE_POSITIVE` | Incorrectly flagged content | Medium | No |
| `OTHER` | Other security or policy violations | Low | No |

## Report Status Workflow

Reports follow a structured workflow:

```
PENDING → UNDER_REVIEW → [APPROVED/REJECTED/RESOLVED/DUPLICATE]
```

| Status | Description | Who Can Set |
|--------|-------------|-------------|
| `PENDING` | Newly submitted, awaiting review | System |
| `UNDER_REVIEW` | Being reviewed by moderators | Moderators |
| `APPROVED` | Confirmed as valid threat | Moderators |
| `REJECTED` | Determined to be invalid | Moderators |
| `RESOLVED` | Issue has been addressed | Moderators |
| `DUPLICATE` | Duplicate of existing report | Moderators |

## Endpoints

### 1. Create Report

Submit a new security report for a URL or content.

**Endpoint:** `POST /`

**Authentication:** Required

**Request Body:**
```json
{
  "url": "https://suspicious-site.com/phishing-page",
  "report_type": "PHISHING",
  "title": "Fake Banking Login Page",
  "description": "This website is impersonating [Bank Name] and attempting to steal login credentials. The page looks identical to the real banking site but has a different domain.",
  "evidence_urls": [
    "https://imgur.com/screenshot1.png",
    "https://imgur.com/screenshot2.png"
  ],
  "severity": 9,
  "tags": ["banking", "credentials", "impersonation"],
  "is_anonymous": false
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | URL being reported (max 2048 chars) |
| `report_type` | enum | Yes | Type of security threat |
| `title` | string | Yes | Brief descriptive title (1-200 chars) |
| `description` | string | Yes | Detailed description (10-2000 chars) |
| `evidence_urls` | array | No | Supporting evidence URLs (max 10) |
| `severity` | integer | No | Severity rating from 1-10 |
| `tags` | array | No | Descriptive tags (max 20, alphanumeric) |
| `is_anonymous` | boolean | No | Submit report anonymously |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://suspicious-site.com/phishing-page",
  "domain": "suspicious-site.com",
  "report_type": "PHISHING",
  "title": "Fake Banking Login Page",
  "description": "This website is impersonating [Bank Name]...",
  "evidence_urls": [
    "https://imgur.com/screenshot1.png",
    "https://imgur.com/screenshot2.png"
  ],
  "severity": 9,
  "tags": ["banking", "credentials", "impersonation"],
  "status": "PENDING",
  "priority": "CRITICAL",
  "is_anonymous": false,
  "reporter_id": "123e4567-e89b-12d3-a456-426614174000",
  "reporter_name": "John Doe",
  "assignee_id": null,
  "assignee_name": null,
  "upvotes": 0,
  "downvotes": 0,
  "user_vote": null,
  "resolution_notes": null,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "resolved_at": null
}
```

**Status Codes:**
- `201 Created`: Report created successfully
- `400 Bad Request`: Invalid input data
- `401 Unauthorized`: Authentication required
- `422 Unprocessable Entity`: Validation errors
- `429 Too Many Requests`: Rate limit exceeded

**Example Request:**
```bash
curl -X POST "https://api.linkshield.com/api/v1/reports/" \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-site.com/phishing-page",
    "report_type": "PHISHING",
    "title": "Fake Banking Login Page",
    "description": "This website is impersonating [Bank Name] and attempting to steal login credentials.",
    "severity": 9,
    "tags": ["banking", "credentials", "impersonation"]
  }'
```

### 2. List Reports

Retrieve reports with filtering and pagination.

**Endpoint:** `GET /`

**Authentication:** Optional (enhanced features with authentication)

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `report_type` | enum | Filter by report type |
| `status` | enum | Filter by status |
| `priority` | enum | Filter by priority |
| `domain` | string | Filter by domain |
| `tag` | string | Filter by tag |
| `reporter_id` | UUID | Filter by reporter |
| `assignee_id` | UUID | Filter by assignee |
| `created_after` | datetime | Filter by creation date |
| `created_before` | datetime | Filter by creation date |
| `sort_by` | string | Sort field (default: created_at) |
| `sort_order` | string | Sort order: asc/desc (default: desc) |
| `page` | integer | Page number (default: 1) |
| `page_size` | integer | Items per page (1-100, default: 20) |

**Response:**
```json
{
  "reports": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "url": "https://suspicious-site.com/phishing-page",
      "domain": "suspicious-site.com",
      "report_type": "PHISHING",
      "title": "Fake Banking Login Page",
      "description": "This website is impersonating...",
      "evidence_urls": ["https://imgur.com/screenshot1.png"],
      "severity": 9,
      "tags": ["banking", "credentials"],
      "status": "UNDER_REVIEW",
      "priority": "CRITICAL",
      "is_anonymous": false,
      "reporter_id": "123e4567-e89b-12d3-a456-426614174000",
      "reporter_name": "John Doe",
      "assignee_id": "456e7890-e89b-12d3-a456-426614174001",
      "assignee_name": "Jane Smith",
      "upvotes": 5,
      "downvotes": 0,
      "user_vote": "UPVOTE",
      "resolution_notes": null,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T11:00:00Z",
      "resolved_at": null
    }
  ],
  "total_count": 1,
  "page": 1,
  "page_size": 20,
  "filters_applied": {
    "report_type": "PHISHING",
    "status": "UNDER_REVIEW"
  }
}
```

**Example Request:**
```bash
curl "https://api.linkshield.com/api/v1/reports/?report_type=PHISHING&status=PENDING&page=1&page_size=10" \
  -H "Authorization: Bearer <jwt_token>"
```

### 3. Get Report Details

Retrieve detailed information about a specific report.

**Endpoint:** `GET /{report_id}`

**Authentication:** Optional (enhanced details with authentication)

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `report_id` | UUID | Yes | Report ID |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://suspicious-site.com/phishing-page",
  "domain": "suspicious-site.com",
  "report_type": "PHISHING",
  "title": "Fake Banking Login Page",
  "description": "This website is impersonating [Bank Name] and attempting to steal login credentials. The page looks identical to the real banking site but has a different domain.",
  "evidence_urls": [
    "https://imgur.com/screenshot1.png",
    "https://imgur.com/screenshot2.png"
  ],
  "severity": 9,
  "tags": ["banking", "credentials", "impersonation"],
  "status": "APPROVED",
  "priority": "CRITICAL",
  "is_anonymous": false,
  "reporter_id": "123e4567-e89b-12d3-a456-426614174000",
  "reporter_name": "John Doe",
  "assignee_id": "456e7890-e89b-12d3-a456-426614174001",
  "assignee_name": "Jane Smith",
  "upvotes": 12,
  "downvotes": 1,
  "user_vote": "UPVOTE",
  "resolution_notes": "Confirmed as phishing site. Added to blocklist.",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T14:22:00Z",
  "resolved_at": "2024-01-15T14:22:00Z"
}
```

### 4. Update Report

Update an existing report. Only the reporter or administrators can update reports.

**Endpoint:** `PUT /{report_id}`

**Authentication:** Required

**Request Body:**
```json
{
  "title": "Updated: Fake Banking Login Page",
  "description": "Updated description with additional details about the phishing attempt.",
  "evidence_urls": [
    "https://imgur.com/screenshot1.png",
    "https://imgur.com/screenshot2.png",
    "https://imgur.com/screenshot3.png"
  ],
  "severity": 10,
  "tags": ["banking", "credentials", "impersonation", "urgent"]
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | string | No | Updated title (1-200 chars) |
| `description` | string | No | Updated description (10-2000 chars) |
| `evidence_urls` | array | No | Updated evidence URLs (max 10) |
| `severity` | integer | No | Updated severity rating (1-10) |
| `tags` | array | No | Updated tags (max 20) |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://suspicious-site.com/phishing-page",
  "domain": "suspicious-site.com",
  "report_type": "PHISHING",
  "title": "Updated: Fake Banking Login Page",
  "description": "Updated description with additional details...",
  "evidence_urls": [
    "https://imgur.com/screenshot1.png",
    "https://imgur.com/screenshot2.png",
    "https://imgur.com/screenshot3.png"
  ],
  "severity": 10,
  "tags": ["banking", "credentials", "impersonation", "urgent"],
  "status": "PENDING",
  "priority": "CRITICAL",
  "updated_at": "2024-01-15T15:30:00Z"
}
```

**Status Codes:**
- `200 OK`: Report updated successfully
- `400 Bad Request`: Invalid input data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Not authorized to update this report
- `404 Not Found`: Report not found
- `422 Unprocessable Entity`: Validation errors

## Community Voting

### 5. Vote on Report

Vote on the accuracy and helpfulness of a report.

**Endpoint:** `POST /{report_id}/vote`

**Authentication:** Required

**Request Body:**
```json
{
  "vote_type": "UPVOTE",
  "comment": "Confirmed - I encountered this same phishing site yesterday."
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vote_type` | enum | Yes | UPVOTE or DOWNVOTE |
| `comment` | string | No | Optional comment (max 500 chars) |

**Response:**
```json
{
  "id": "789e0123-e89b-12d3-a456-426614174002",
  "report_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "vote_type": "UPVOTE",
  "comment": "Confirmed - I encountered this same phishing site yesterday.",
  "created_at": "2024-01-15T16:00:00Z"
}
```

**Status Codes:**
- `201 Created`: Vote recorded successfully
- `400 Bad Request`: Invalid vote data
- `401 Unauthorized`: Authentication required
- `404 Not Found`: Report not found
- `409 Conflict`: User has already voted on this report

### 6. Remove Vote

Remove your vote from a report.

**Endpoint:** `DELETE /{report_id}/vote`

**Authentication:** Required

**Response:**
```json
{
  "message": "Vote removed successfully",
  "report_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Status Codes:**
- `200 OK`: Vote removed successfully
- `401 Unauthorized`: Authentication required
- `404 Not Found`: Report or vote not found

## Administrative Functions

### 7. Assign Report

Assign a report to a moderator or administrator for review.

**Endpoint:** `PUT /{report_id}/assign`

**Authentication:** Required (Admin/Moderator only)

**Request Body:**
```json
{
  "assignee_id": "456e7890-e89b-12d3-a456-426614174001"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `assignee_id` | UUID | Yes | ID of user to assign report to |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "assignee_id": "456e7890-e89b-12d3-a456-426614174001",
  "assignee_name": "Jane Smith",
  "assigned_at": "2024-01-15T17:00:00Z",
  "assigned_by": "Admin User"
}
```

**Status Codes:**
- `200 OK`: Report assigned successfully
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Admin permissions required
- `404 Not Found`: Report or assignee not found

### 8. Resolve Report

Mark a report as resolved with resolution notes.

**Endpoint:** `PUT /{report_id}/resolve`

**Authentication:** Required (Admin/Moderator only)

**Request Body:**
```json
{
  "resolution_notes": "Confirmed as phishing site. Added to blocklist and notified hosting provider. Site has been taken down."
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resolution_notes` | string | Yes | Resolution details (10-1000 chars) |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "RESOLVED",
  "resolution_notes": "Confirmed as phishing site. Added to blocklist and notified hosting provider. Site has been taken down.",
  "resolved_at": "2024-01-15T18:00:00Z",
  "resolved_by": "Jane Smith"
}
```

**Status Codes:**
- `200 OK`: Report resolved successfully
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Admin permissions required
- `404 Not Found`: Report not found

## Statistics & Analytics

### 9. Get Report Statistics

Retrieve comprehensive reporting statistics and metrics.

**Endpoint:** `GET /stats/overview`

**Authentication:** Optional (enhanced stats with authentication)

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `days` | integer | Number of days to include (1-365, default: 30) |

**Response:**
```json
{
  "total_reports": 1250,
  "pending_reports": 45,
  "resolved_reports": 1100,
  "reports_by_type": {
    "PHISHING": 450,
    "MALWARE": 320,
    "SPAM": 280,
    "SCAM": 150,
    "INAPPROPRIATE_CONTENT": 30,
    "COPYRIGHT_VIOLATION": 15,
    "FALSE_POSITIVE": 5
  },
  "reports_by_priority": {
    "CRITICAL": 770,
    "HIGH": 300,
    "MEDIUM": 150,
    "LOW": 30
  },
  "top_domains": [
    {"domain": "suspicious-site.com", "count": 25},
    {"domain": "fake-bank.net", "count": 18},
    {"domain": "phishing-example.org", "count": 12}
  ],
  "recent_activity": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "title": "Fake Banking Login Page",
      "type": "PHISHING",
      "status": "RESOLVED",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "user_contribution": {
    "reports_created": 5,
    "votes_cast": 23
  }
}
```

**Example Request:**
```bash
curl "https://api.linkshield.com/api/v1/reports/stats/overview?days=7" \
  -H "Authorization: Bearer <jwt_token>"
```

### 10. Get Report Templates

Retrieve pre-defined templates to help users create better reports.

**Endpoint:** `GET /templates/`

**Authentication:** Not required

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `report_type` | enum | Filter templates by report type |

**Response:**
```json
[
  {
    "id": "template-001",
    "name": "Phishing Report Template",
    "description": "Template for reporting phishing websites",
    "report_type": "PHISHING",
    "template_fields": {
      "title_suggestions": [
        "Fake [Service Name] Login Page",
        "Phishing Site Impersonating [Brand]",
        "Credential Harvesting Attempt"
      ],
      "description_template": "This website is impersonating [SERVICE/BRAND] and attempting to steal [TYPE OF CREDENTIALS]. Key indicators:\n\n1. Domain mismatch: [SUSPICIOUS DOMAIN] vs [LEGITIMATE DOMAIN]\n2. Visual similarities: [DESCRIBE SIMILARITIES]\n3. Suspicious elements: [LIST SUSPICIOUS ELEMENTS]\n\nEvidence: [DESCRIBE EVIDENCE]",
      "suggested_tags": ["phishing", "credentials", "impersonation", "banking", "social-media"],
      "severity_guidance": "Rate 8-10 for banking/financial sites, 6-8 for social media, 4-6 for other services"
    },
    "is_active": true,
    "usage_count": 245,
    "created_at": "2024-01-01T00:00:00Z"
  },
  {
    "id": "template-002",
    "name": "Malware Distribution Template",
    "description": "Template for reporting malware distribution sites",
    "report_type": "MALWARE",
    "template_fields": {
      "title_suggestions": [
        "Malware Download Site",
        "Infected Website Distributing [MALWARE TYPE]",
        "Drive-by Download Attack"
      ],
      "description_template": "This website is distributing malware or contains malicious code:\n\n1. Malware type: [TYPE IF KNOWN]\n2. Distribution method: [DOWNLOAD/DRIVE-BY/OTHER]\n3. Affected files: [LIST FILES IF APPLICABLE]\n4. Detection details: [ANTIVIRUS ALERTS/BEHAVIOR]\n\nEvidence: [SCREENSHOTS/SCAN RESULTS]",
      "suggested_tags": ["malware", "virus", "trojan", "download", "infected"],
      "severity_guidance": "Rate 9-10 for active malware distribution, 7-8 for infected sites, 5-6 for suspicious behavior"
    },
    "is_active": true,
    "usage_count": 156,
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

## Rate Limits

Reporting endpoints have specific rate limits to prevent abuse:

| Endpoint | Limit | Scope | Window |
|----------|-------|-------|--------|
| Create Report | 10 reports | Per user | 1 hour |
| Update Report | 20 updates | Per user | 1 hour |
| Vote on Reports | 100 votes | Per user | 1 hour |
| List Reports | 200 requests | Per IP | 1 hour |
| Get Report Details | 500 requests | Per IP | 1 hour |
| Admin Operations | 50 requests | Per user | 1 hour |

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1642262400
X-RateLimit-Scope: user
```

## Security Features

### Report Validation
- **URL Validation**: Comprehensive URL format and accessibility checks
- **Content Filtering**: Automatic filtering of inappropriate content
- **Duplicate Detection**: Prevention of duplicate reports for the same URL
- **Evidence Verification**: Validation of evidence URLs and content

### Anti-Abuse Measures
- **Rate Limiting**: Comprehensive rate limiting per user and IP
- **Spam Detection**: Automatic detection of spam reports
- **User Reputation**: User reputation system affects report priority
- **Moderation Queue**: All reports go through moderation workflow

### Privacy Protection
- **Anonymous Reporting**: Option to submit reports anonymously
- **Data Sanitization**: Automatic removal of sensitive information
- **Access Controls**: Role-based access to sensitive report data
- **Audit Logging**: Complete audit trail of all report activities

## Error Handling

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_URL` | 400 | URL format is invalid |
| `DUPLICATE_REPORT` | 409 | Report already exists for this URL |
| `INVALID_REPORT_TYPE` | 400 | Invalid or unsupported report type |
| `INSUFFICIENT_DESCRIPTION` | 422 | Description too short or generic |
| `INVALID_EVIDENCE` | 400 | Evidence URLs are invalid or inaccessible |
| `REPORT_NOT_FOUND` | 404 | Report does not exist |
| `UNAUTHORIZED_UPDATE` | 403 | Not authorized to update this report |
| `ALREADY_VOTED` | 409 | User has already voted on this report |
| `INVALID_ASSIGNMENT` | 400 | Cannot assign report to specified user |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "DUPLICATE_REPORT",
    "message": "A report for this URL already exists",
    "details": {
      "existing_report_id": "550e8400-e29b-41d4-a716-446655440000",
      "existing_report_url": "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000",
      "suggestion": "Consider voting on or commenting on the existing report instead"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Code Examples

### JavaScript/TypeScript

```typescript
interface ReportCreateRequest {
  url: string;
  report_type: 'PHISHING' | 'MALWARE' | 'SPAM' | 'SCAM' | 'INAPPROPRIATE_CONTENT' | 'COPYRIGHT_VIOLATION' | 'FALSE_POSITIVE' | 'OTHER';
  title: string;
  description: string;
  evidence_urls?: string[];
  severity?: number;
  tags?: string[];
  is_anonymous?: boolean;
}

interface ReportResponse {
  id: string;
  url: string;
  domain: string;
  report_type: string;
  title: string;
  description: string;
  evidence_urls: string[];
  severity?: number;
  tags: string[];
  status: string;
  priority: string;
  is_anonymous: boolean;
  reporter_id?: string;
  reporter_name?: string;
  assignee_id?: string;
  assignee_name?: string;
  upvotes: number;
  downvotes: number;
  user_vote?: 'UPVOTE' | 'DOWNVOTE';
  resolution_notes?: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
}

class ReportingClient {
  private baseUrl: string;
  private token?: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  setToken(token: string): void {
    this.token = token;
  }

  async createReport(reportData: ReportCreateRequest): Promise<ReportResponse> {
    if (!this.token) {
      throw new Error('Authentication required');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/reports/`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(reportData)
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Failed to create report: ${error.error?.message || response.statusText}`);
    }

    return response.json();
  }

  async listReports(filters: {
    report_type?: string;
    status?: string;
    priority?: string;
    domain?: string;
    page?: number;
    page_size?: number;
  } = {}): Promise<any> {
    const params = new URLSearchParams();
    
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined) {
        params.append(key, value.toString());
      }
    });

    const url = `${this.baseUrl}/api/v1/reports/?${params.toString()}`;
    const headers: Record<string, string> = {};
    
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(url, { headers });

    if (!response.ok) {
      throw new Error(`Failed to list reports: ${response.statusText}`);
    }

    return response.json();
  }

  async getReport(reportId: string): Promise<ReportResponse> {
    const headers: Record<string, string> = {};
    
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${this.baseUrl}/api/v1/reports/${reportId}`, {
      headers
    });

    if (!response.ok) {
      throw new Error(`Failed to get report: ${response.statusText}`);
    }

    return response.json();
  }

  async updateReport(reportId: string, updates: Partial<ReportCreateRequest>): Promise<ReportResponse> {
    if (!this.token) {
      throw new Error('Authentication required');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/reports/${reportId}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(updates)
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Failed to update report: ${error.error?.message || response.statusText}`);
    }

    return response.json();
  }

  async voteOnReport(reportId: string, voteType: 'UPVOTE' | 'DOWNVOTE', comment?: string): Promise<any> {
    if (!this.token) {
      throw new Error('Authentication required');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/reports/${reportId}/vote`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        vote_type: voteType,
        comment
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Failed to vote on report: ${error.error?.message || response.statusText}`);
    }

    return response.json();
  }

  async removeVote(reportId: string): Promise<void> {
    if (!this.token) {
      throw new Error('Authentication required');
    }

    const response = await fetch(`${this.baseUrl}/api/v1/reports/${reportId}/vote`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to remove vote: ${response.statusText}`);
    }
  }

  async getStatistics(days: number = 30): Promise<any> {
    const headers: Record<string, string> = {};
    
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${this.baseUrl}/api/v1/reports/stats/overview?days=${days}`, {
      headers
    });

    if (!response.ok) {
      throw new Error(`Failed to get statistics: ${response.statusText}`);
    }

    return response.json();
  }

  async getTemplates(reportType?: string): Promise<any[]> {
    const params = reportType ? `?report_type=${reportType}` : '';
    
    const response = await fetch(`${this.baseUrl}/api/v1/reports/templates/${params}`);

    if (!response.ok) {
      throw new Error(`Failed to get templates: ${response.statusText}`);
    }

    return response.json();
  }
}

// Usage example
const client = new ReportingClient('https://api.linkshield.com');
client.setToken('your-jwt-token');

// Create a phishing report
const report = await client.createReport({
  url: 'https://suspicious-site.com/fake-login',
  report_type: 'PHISHING',
  title: 'Fake Banking Login Page',
  description: 'This site is impersonating [Bank Name] to steal credentials.',
  evidence_urls: ['https://imgur.com/screenshot.png'],
  severity: 9,
  tags: ['banking', 'credentials', 'phishing'],
  is_anonymous: false
});

console.log(`Report created: ${report.id}`);

// Vote on the report
await client.voteOnReport(report.id, 'UPVOTE', 'Confirmed - encountered this site myself');

// Get statistics
const stats = await client.getStatistics(7);
console.log(`Total reports in last 7 days: ${stats.total_reports}`);
```

### Python

```python
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime

class ReportingClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.token: Optional[str] = None
        self.session = requests.Session()

    def set_token(self, token: str) -> None:
        """Set authentication token."""
        self.token = token
        self.session.headers.update({
            'Authorization': f'Bearer {token}'
        })

    def create_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security report."""
        self._ensure_authenticated()
        
        response = self.session.post(
            f'{self.base_url}/api/v1/reports/',
            json=report_data
        )
        response.raise_for_status()
        return response.json()

    def list_reports(self, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """List reports with optional filtering."""
        params = filters or {}
        
        response = self.session.get(
            f'{self.base_url}/api/v1/reports/',
            params=params
        )
        response.raise_for_status()
        return response.json()

    def get_report(self, report_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific report."""
        response = self.session.get(
            f'{self.base_url}/api/v1/reports/{report_id}'
        )
        response.raise_for_status()
        return response.json()

    def update_report(self, report_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing report."""
        self._ensure_authenticated()
        
        response = self.session.put(
            f'{self.base_url}/api/v1/reports/{report_id}',
            json=updates
        )
        response.raise_for_status()
        return response.json()

    def vote_on_report(self, report_id: str, vote_type: str, comment: str = None) -> Dict[str, Any]:
        """Vote on a report."""
        self._ensure_authenticated()
        
        payload = {'vote_type': vote_type}
        if comment:
            payload['comment'] = comment

        response = self.session.post(
            f'{self.base_url}/api/v1/reports/{report_id}/vote',
            json=payload
        )
        response.raise_for_status()
        return response.json()

    def remove_vote(self, report_id: str) -> None:
        """Remove vote from a report."""
        self._ensure_authenticated()
        
        response = self.session.delete(
            f'{self.base_url}/api/v1/reports/{report_id}/vote'
        )
        response.raise_for_status()

    def assign_report(self, report_id: str, assignee_id: str) -> Dict[str, Any]:
        """Assign report to a user (admin only)."""
        self._ensure_authenticated()
        
        response = self.session.put(
            f'{self.base_url}/api/v1/reports/{report_id}/assign',
            json={'assignee_id': assignee_id}
        )
        response.raise_for_status()
        return response.json()

    def resolve_report(self, report_id: str, resolution_notes: str) -> Dict[str, Any]:
        """Resolve a report (admin only)."""
        self._ensure_authenticated()
        
        response = self.session.put(
            f'{self.base_url}/api/v1/reports/{report_id}/resolve',
            json={'resolution_notes': resolution_notes}
        )
        response.raise_for_status()
        return response.json()

    def get_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get report statistics."""
        response = self.session.get(
            f'{self.base_url}/api/v1/reports/stats/overview',
            params={'days': days}
        )
        response.raise_for_status()
        return response.json()

    def get_templates(self, report_type: str = None) -> List[Dict[str, Any]]:
        """Get report templates."""
        params = {'report_type': report_type} if report_type else {}
        
        response = self.session.get(
            f'{self.base_url}/api/v1/reports/templates/',
            params=params
        )
        response.raise_for_status()
        return response.json()

    def _ensure_authenticated(self) -> None:
        """Ensure user is authenticated."""
        if not self.token:
            raise ValueError('Authentication required. Please set token first.')

# Usage example
client = ReportingClient('https://api.linkshield.com')
client.set_token('your-jwt-token')

# Create a phishing report
report = client.create_report({
    'url': 'https://suspicious-site.com/fake-login',
    'report_type': 'PHISHING',
    'title': 'Fake Banking Login Page',
    'description': 'This site is impersonating [Bank Name] to steal credentials.',
    'evidence_urls': ['https://imgur.com/screenshot.png'],
    'severity': 9,
    'tags': ['banking', 'credentials', 'phishing'],
    'is_anonymous': False
})

print(f"Report created: {report['id']}")

# List recent phishing reports
reports = client.list_reports({
    'report_type': 'PHISHING',
    'status': 'PENDING',
    'page': 1,
    'page_size': 10
})

print(f"Found {reports['total_count']} pending phishing reports")

# Vote on a report
client.vote_on_report(
    report['id'], 
    'UPVOTE', 
    'Confirmed - encountered this site myself'
)

# Get statistics for the last week
stats = client.get_statistics(7)
print(f"Total reports in last 7 days: {stats['total_reports']}")
print(f"Phishing reports: {stats['reports_by_type']['PHISHING']}")

# Get phishing report templates
templates = client.get_templates('PHISHING')
print(f"Available phishing templates: {len(templates)}")
```

## Best Practices

### For Report Creators
1. **Provide detailed descriptions** with specific indicators of malicious activity
2. **Include evidence** such as screenshots or additional URLs
3. **Use appropriate tags** to help categorize and search reports
4. **Set accurate severity levels** based on potential impact
5. **Check for duplicates** before creating new reports

### For Community Members
1. **Vote responsibly** based on report accuracy and evidence
2. **Provide constructive comments** when voting
3. **Report false positives** to maintain database quality
4. **Follow up on reports** you've submitted or voted on

### For Administrators
1. **Review reports promptly** to maintain community trust
2. **Provide clear resolution notes** for transparency
3. **Use assignment system** to distribute workload effectively
4. **Monitor statistics** to identify trends and patterns
5. **Update templates** based on common report patterns

### Integration Best Practices
1. **Handle rate limits gracefully** with exponential backoff
2. **Cache report data** to reduce API calls
3. **Implement proper error handling** for all scenarios
4. **Use webhooks** for real-time report updates (if available)
5. **Monitor API usage** to stay within quotas

---

**Next Steps:**
- Review [URL Analysis Endpoints](./url-analysis.md) for threat detection integration
- Check [User Management](./user-management.md) for authentication details
- See [Rate Limiting](../rate-limiting.md) for quota management
- Review [Error Handling](../error-handling.md) for comprehensive error reference