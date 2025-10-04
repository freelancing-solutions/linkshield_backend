# Requirements Document

## Introduction

The URL Analysis feature provides authenticated users with comprehensive tools to analyze URLs for security threats, view analysis history, perform bulk URL checks, lookup domain reputations, and track usage statistics. This feature extends the basic URL checking functionality with advanced capabilities including detailed provider results, broken link detection, and historical analysis tracking.

## Requirements

### Requirement 1: View URL Check History

**User Story:** As an authenticated user, I want to view my URL check history with filtering and pagination, so that I can review past analyses and track patterns.

#### Acceptance Criteria

1. WHEN a user navigates to the history page THEN the system SHALL call GET /api/v1/url-check/history with Bearer token
2. WHEN history data is received THEN the system SHALL display a table with columns: URL, domain, threat level, status, checked date, and actions
3. WHEN a user applies domain filter THEN the system SHALL update the query with domain parameter and refresh results
4. WHEN a user applies threat level filter THEN the system SHALL update the query with threat_level parameter and refresh results
5. WHEN a user applies status filter THEN the system SHALL update the query with status parameter and refresh results
6. WHEN a user applies date range filter THEN the system SHALL update the query with date parameters and refresh results
7. WHEN pagination controls are used THEN the system SHALL update page and page_size parameters
8. WHEN the request fails with 401 THEN the system SHALL redirect to login page
9. WHEN no results match filters THEN the system SHALL display "No URL checks found" empty state
10. WHEN a user clicks on a URL row THEN the system SHALL navigate to the check detail page

### Requirement 2: View URL Check Details

**User Story:** As an authenticated user, I want to view detailed results of a specific URL check, so that I can understand the security analysis in depth.

#### Acceptance Criteria

1. WHEN a user navigates to check detail page THEN the system SHALL call GET /api/v1/url-check/check/{check_id} with Bearer token
2. WHEN check data is received THEN the system SHALL display URL, domain, threat level, risk score, status, and checked date
3. WHEN check data includes scan results THEN the system SHALL call GET /api/v1/url-check/check/{check_id}/results to fetch provider details
4. WHEN provider results are received THEN the system SHALL display accordion with sections for each provider (VirusTotal, Google Safe Browsing, URLVoid)
5. WHEN a provider section is expanded THEN the system SHALL show detailed findings, threat indicators, and confidence scores
6. WHEN check includes broken link scan THEN the system SHALL call GET /api/v1/url-check/check/{check_id}/broken-links
7. WHEN broken links data is received THEN the system SHALL display table with URL, status code, error message, and depth
8. WHEN check detail fails with 404 THEN the system SHALL display "URL check not found" message
9. WHEN check detail fails with 403 THEN the system SHALL display "You don't have permission to view this check"

### Requirement 3: Perform Bulk URL Analysis

**User Story:** As an authenticated user, I want to analyze multiple URLs at once, so that I can efficiently check many URLs without submitting them individually.

#### Acceptance Criteria

1. WHEN a user navigates to bulk analysis page THEN the system SHALL display input options: textarea or file upload
2. WHEN a user enters URLs in textarea THEN the system SHALL validate each URL format (one per line)
3. WHEN a user uploads a file THEN the system SHALL validate file type (txt, csv) and size (max 1MB)
4. WHEN a user submits bulk analysis THEN the system SHALL call POST /api/v1/url-check/bulk-check with URLs array
5. WHEN bulk analysis is submitted THEN the system SHALL display progress indicator showing X of Y URLs analyzed
6. WHEN bulk analysis completes THEN the system SHALL display summary: total URLs, safe, suspicious, malicious, errors
7. WHEN bulk analysis results are displayed THEN the system SHALL show table with URL, threat level, and view details link
8. WHEN bulk analysis fails with 400 THEN the system SHALL display validation errors for invalid URLs
9. WHEN user is on Free plan THEN the system SHALL limit bulk analysis to 10 URLs per batch
10. WHEN user is on Pro plan THEN the system SHALL limit bulk analysis to 50 URLs per batch
11. WHEN user is on Enterprise plan THEN the system SHALL limit bulk analysis to 100 URLs per batch
12. WHEN bulk analysis is rate-limited (429) THEN the system SHALL display "Rate limit exceeded" with retry-after time

### Requirement 4: Lookup Domain Reputation

**User Story:** As a user, I want to lookup the reputation of a domain, so that I can assess its trustworthiness before visiting.

#### Acceptance Criteria

1. WHEN a user navigates to reputation lookup page THEN the system SHALL display domain input field
2. WHEN a user enters a domain THEN the system SHALL validate domain format
3. WHEN a user submits domain lookup THEN the system SHALL call GET /api/v1/url-check/reputation/{domain}
4. WHEN reputation data is received THEN the system SHALL display reputation score, trust level, and historical data
5. WHEN reputation includes check history THEN the system SHALL display chart showing threat levels over time
6. WHEN reputation includes community reports THEN the system SHALL display count and link to reports
7. WHEN domain has no reputation data THEN the system SHALL display "No reputation data available for this domain"
8. WHEN domain lookup fails with 400 THEN the system SHALL display "Invalid domain format"

### Requirement 5: View Usage Statistics

**User Story:** As an authenticated user, I want to view my URL check usage statistics, so that I can track my usage patterns and plan limits.

#### Acceptance Criteria

1. WHEN a user navigates to stats page THEN the system SHALL call GET /api/v1/url-check/stats with Bearer token and days parameter
2. WHEN stats data is received THEN the system SHALL display total checks, safe URLs, suspicious URLs, and malicious URLs
3. WHEN stats include time series data THEN the system SHALL display line chart showing checks per day
4. WHEN stats include threat distribution THEN the system SHALL display pie chart showing threat level breakdown
5. WHEN stats include scan type distribution THEN the system SHALL display bar chart showing scan types used
6. WHEN a user changes time range (7d, 30d, 90d, 365d) THEN the system SHALL update days parameter and refresh stats
7. WHEN stats include plan limits THEN the system SHALL display usage vs limit progress bar
8. WHEN user is approaching plan limit THEN the system SHALL display warning message with upgrade CTA

### Requirement 6: Export URL Check Data

**User Story:** As an authenticated user, I want to export my URL check history, so that I can analyze data externally or create reports.

#### Acceptance Criteria

1. WHEN a user clicks export button on history page THEN the system SHALL display export options modal
2. WHEN export options are displayed THEN the system SHALL show format options: CSV, JSON
3. WHEN a user selects export format THEN the system SHALL show date range selector
4. WHEN a user confirms export THEN the system SHALL generate file with filtered history data
5. WHEN export is ready THEN the system SHALL trigger download with filename: linkshield-history-{date}.{format}
6. WHEN export includes more than 1000 records THEN the system SHALL display warning about large file size
7. WHEN export fails THEN the system SHALL display "Export failed. Please try again" error message

## Base URLs

- **Client Base**: https://www.linkshield.site
- **API Base**: https://www.linkshield.site/api/v1

## API Endpoints

| Method | Endpoint | Auth Required | Rate Limit | Description |
|--------|----------|---------------|------------|-------------|
| GET | /url-check/history | Yes | 100/hour | Get user's URL check history with filters |
| GET | /url-check/check/{check_id} | Yes | 100/hour | Get specific URL check details |
| GET | /url-check/check/{check_id}/results | Yes | 100/hour | Get detailed scan results from providers |
| GET | /url-check/check/{check_id}/broken-links | Yes | 100/hour | Get broken link details if scan performed |
| POST | /url-check/bulk-check | Yes | 20/hour | Analyze multiple URLs (max 100) |
| GET | /url-check/reputation/{domain} | Optional | 20/hour | Get domain reputation data |
| GET | /url-check/stats | Yes | 100/hour | Get user's usage statistics |

## Error Handling

| Error Code | HTTP Status | User Message | Action |
|------------|-------------|--------------|--------|
| INVALID_URL_FORMAT | 422 | Invalid URL format | Show validation error |
| URL_TOO_LONG | 422 | URL exceeds maximum length | Show validation error |
| SCAN_TIMEOUT | 504 | URL analysis timed out | Offer retry option |
| SCAN_FAILED | 500 | Analysis could not be completed | Offer retry option |
| DAILY_LIMIT_EXCEEDED | 402 | Daily scan limit reached | Show upgrade CTA |
| CHECK_NOT_FOUND | 404 | URL check not found | Return to history |
| UNAUTHORIZED | 401 | Session expired | Redirect to login |
| FORBIDDEN | 403 | You don't have permission to view this check | Show error message |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests | Show retry-after time |
| BULK_LIMIT_EXCEEDED | 400 | Too many URLs in batch | Show plan limits |

## Non-Functional Requirements

### Security
1. All API requests SHALL include Bearer token authentication
2. URL inputs SHALL be validated and sanitized before submission
3. Sensitive URL data SHALL not be logged to console or error tracking
4. Export files SHALL not include sensitive user information

### Performance
1. History page SHALL load within 2 seconds under normal conditions
2. Check detail page SHALL load within 1 second
3. Bulk analysis SHALL process at least 10 URLs per second
4. Charts and visualizations SHALL render within 500ms
5. History list SHALL support virtual scrolling for large datasets

### Accessibility
1. All tables SHALL have proper headers and ARIA labels
2. Charts SHALL have text alternatives for screen readers
3. Filters SHALL be keyboard navigable
4. Loading states SHALL be announced to screen readers
5. Color coding SHALL not be the only indicator of threat level

### Usability
1. Filters SHALL persist across page refreshes
2. Threat levels SHALL use consistent color coding (green=safe, yellow=suspicious, red=malicious)
3. Empty states SHALL provide clear next actions
4. Error messages SHALL be specific and actionable
5. Export progress SHALL be visible to users
