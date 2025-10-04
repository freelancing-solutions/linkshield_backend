# Requirements Document

## Introduction

The Community Reports feature enables users to submit security reports about suspicious URLs and domains, vote on report accuracy, and view community-driven threat intelligence. This feature creates a collaborative security ecosystem where users can share threat information and help protect the community.

## Requirements

### Requirement 1: Submit Security Report

**User Story:** As an authenticated user, I want to submit a security report about a suspicious URL, so that I can warn others and contribute to community safety.

#### Acceptance Criteria

1. WHEN a user navigates to submit report page THEN the system SHALL display report form with URL, report type, description, and evidence fields
2. WHEN a user enters URL THEN the system SHALL validate URL format
3. WHEN a user selects report type THEN the system SHALL show type-specific fields (PHISHING, MALWARE, SPAM, SCAM, INAPPROPRIATE, COPYRIGHT, OTHER)
4. WHEN a user submits report THEN the system SHALL call POST /api/v1/reports/ with Bearer token
5. WHEN report is submitted successfully THEN the system SHALL display success message and report ID
6. WHEN report submission fails with 400 THEN the system SHALL display validation errors
7. WHEN report submission fails with 409 THEN the system SHALL display "Similar report already exists" with link to existing report
8. WHEN report is rate-limited (429) THEN the system SHALL display "Too many reports submitted. Please try again later"
9. WHEN user is not authenticated THEN the system SHALL redirect to login page

### Requirement 2: View Community Reports

**User Story:** As a user, I want to browse community reports with filtering, so that I can learn about threats and assess URL safety.

#### Acceptance Criteria

1. WHEN a user navigates to reports page THEN the system SHALL call GET /api/v1/reports/ with optional filters
2. WHEN reports are received THEN the system SHALL display list with URL, report type, priority, status, votes, and submission date
3. WHEN a user applies report type filter THEN the system SHALL update query with report_type parameter
4. WHEN a user applies status filter THEN the system SHALL update query with status parameter
5. WHEN a user applies priority filter THEN the system SHALL update query with priority parameter
6. WHEN a user applies domain filter THEN the system SHALL update query with domain parameter
7. WHEN a user applies tag filter THEN the system SHALL update query with tag parameter
8. WHEN pagination controls are used THEN the system SHALL update page and page_size parameters
9. WHEN a user clicks on report row THEN the system SHALL navigate to report detail page
10. WHEN no reports match filters THEN the system SHALL display "No reports found" empty state

### Requirement 3: View Report Details

**User Story:** As a user, I want to view detailed information about a report, so that I can assess its credibility and take appropriate action.

#### Acceptance Criteria

1. WHEN a user navigates to report detail page THEN the system SHALL call GET /api/v1/reports/{report_id}
2. WHEN report data is received THEN the system SHALL display URL, report type, description, evidence, priority, status, and metadata
3. WHEN report includes evidence THEN the system SHALL display evidence items with descriptions
4. WHEN report has votes THEN the system SHALL display vote count and vote breakdown (helpful, not helpful)
5. WHEN report has moderation notes THEN the system SHALL display moderation status and notes
6. WHEN report is verified THEN the system SHALL display "Verified" badge
7. WHEN report is dismissed THEN the system SHALL display "Dismissed" badge with reason
8. WHEN report fails with 404 THEN the system SHALL display "Report not found"

### Requirement 4: Vote on Report

**User Story:** As an authenticated user, I want to vote on report accuracy, so that I can help the community identify credible reports.

#### Acceptance Criteria

1. WHEN a user views report detail THEN the system SHALL display vote buttons (Helpful, Not Helpful)
2. WHEN a user clicks vote button THEN the system SHALL call POST /api/v1/reports/{report_id}/vote with Bearer token and vote_type
3. WHEN vote is successful THEN the system SHALL update vote count and highlight user's vote
4. WHEN user has already voted THEN the system SHALL allow changing vote
5. WHEN vote fails with 401 THEN the system SHALL redirect to login page
6. WHEN vote fails with 400 THEN the system SHALL display "Invalid vote type"
7. WHEN user is not authenticated THEN the system SHALL show "Login to vote" message

### Requirement 5: Use Report Templates

**User Story:** As a user, I want to use report templates, so that I can create comprehensive reports more easily.

#### Acceptance Criteria

1. WHEN a user clicks "Use Template" on submit report page THEN the system SHALL call GET /api/v1/reports/templates/
2. WHEN templates are received THEN the system SHALL display list of templates by report type
3. WHEN a user selects template THEN the system SHALL pre-fill form fields with template content
4. WHEN template includes suggested evidence THEN the system SHALL display evidence checklist
5. WHEN user modifies template THEN the system SHALL allow customization before submission

### Requirement 6: View Report Statistics

**User Story:** As a user, I want to view report statistics, so that I can understand threat trends and community activity.

#### Acceptance Criteria

1. WHEN a user navigates to reports stats page THEN the system SHALL call GET /api/v1/reports/stats/overview
2. WHEN stats are received THEN the system SHALL display total reports, pending, verified, dismissed counts
3. WHEN stats include report type distribution THEN the system SHALL display pie chart
4. WHEN stats include priority distribution THEN the system SHALL display bar chart
5. WHEN stats include trends THEN the system SHALL display line chart showing reports over time
6. WHEN stats include top domains THEN the system SHALL display list of most reported domains

## Base URLs

- **Client Base**: https://www.linkshield.site
- **API Base**: https://www.linkshield.site/api/v1

## API Endpoints

| Method | Endpoint | Auth Required | Rate Limit | Description |
|--------|----------|---------------|------------|-------------|
| POST | /reports/ | Yes | 20/hour | Submit new security report |
| GET | /reports/ | Optional | 100/hour | List reports with filters |
| GET | /reports/{report_id} | Optional | 100/hour | Get report details |
| POST | /reports/{report_id}/vote | Yes | 50/hour | Vote on report |
| GET | /reports/templates/ | No | 100/hour | Get report templates |
| GET | /reports/stats/overview | Optional | 100/hour | Get report statistics |

## Report Types

| Type | Description | Required Evidence |
|------|-------------|-------------------|
| PHISHING | Phishing or social engineering | Screenshots, email headers |
| MALWARE | Malware distribution | File hashes, behavior description |
| SPAM | Spam or unwanted content | Content samples |
| SCAM | Fraudulent websites | Transaction details, promises made |
| INAPPROPRIATE | Offensive content | Content description |
| COPYRIGHT | Copyright infringement | Original content proof |
| OTHER | Other violations | Detailed description |

## Error Handling

| Error Code | HTTP Status | User Message | Action |
|------------|-------------|--------------|--------|
| DUPLICATE_REPORT | 409 | Similar report already exists | Show link to existing |
| INVALID_REPORT_TYPE | 400 | Invalid report type selected | Show valid types |
| INSUFFICIENT_EVIDENCE | 400 | Please provide more evidence | Show evidence requirements |
| REPORT_NOT_FOUND | 404 | Report not found | Return to reports list |
| INVALID_VOTE_TYPE | 400 | Invalid vote type | Show error message |
| UNAUTHORIZED | 401 | Please log in to submit reports | Redirect to login |
| RATE_LIMIT_EXCEEDED | 429 | Too many reports submitted | Show retry-after time |

## Non-Functional Requirements

### Security
1. Report submissions SHALL be validated and sanitized
2. Evidence uploads SHALL be scanned for malware
3. User IP addresses SHALL be logged for abuse prevention
4. Spam detection SHALL be applied to report content

### Performance
1. Reports list SHALL load within 2 seconds
2. Report detail SHALL load within 1 second
3. Vote submission SHALL complete within 500ms
4. Statistics SHALL be cached for 5 minutes

### Accessibility
1. All forms SHALL be keyboard navigable
2. Report types SHALL have clear descriptions
3. Vote buttons SHALL have proper ARIA labels
4. Charts SHALL have text alternatives

### Usability
1. Report types SHALL have icons and color coding
2. Priority levels SHALL be clearly indicated
3. Moderation status SHALL be transparent
4. Templates SHALL be easy to find and use
5. Evidence requirements SHALL be clearly stated
