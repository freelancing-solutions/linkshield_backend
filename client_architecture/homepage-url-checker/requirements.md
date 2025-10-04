# Requirements Document

## Introduction

The Homepage URL Checker is the public-facing entry point for LinkShield, providing anonymous users with quick URL security checks while showcasing premium features to encourage registration and subscription. For authenticated users, it serves as a quick-access tool with enhanced features and integration with Social Protection services.

## Requirements

### Requirement 1: Anonymous URL Checking

**User Story:** As a visitor, I want to check a URL for security threats without creating an account, so that I can quickly assess URL safety.

#### Acceptance Criteria

1. WHEN a visitor lands on homepage THEN the system SHALL display prominent URL input field with "Check URL" button
2. WHEN a visitor enters URL THEN the system SHALL validate URL format (1-2048 characters)
3. WHEN a visitor submits URL THEN the system SHALL call POST /api/v1/url-check/check without Bearer token
4. WHEN check is submitted THEN the system SHALL display loading state with estimated time
5. WHEN check completes THEN the system SHALL display risk score, threat level, and basic findings
6. WHEN check completes THEN the system SHALL display "Sign up for detailed analysis" CTA
7. WHEN anonymous check is rate-limited (10/hour) THEN the system SHALL display "Rate limit reached. Sign up for 100 checks/hour"
8. WHEN check fails THEN the system SHALL display error message with retry option

### Requirement 2: Scan Type Selection

**User Story:** As a user, I want to select different scan types, so that I can choose between speed and depth of analysis.

#### Acceptance Criteria

1. WHEN scan type selector is displayed THEN the system SHALL show Quick, Comprehensive, and Deep options
2. WHEN Quick is selected THEN the system SHALL set scan_type to SECURITY (fastest, basic threats)
3. WHEN Comprehensive is selected THEN the system SHALL set scan_type to SECURITY + REPUTATION + CONTENT
4. WHEN Deep is selected AND user is authenticated with Pro+ plan THEN the system SHALL enable BROKEN_LINKS scan
5. WHEN Deep is selected AND user is Free/Basic THEN the system SHALL display "Upgrade to Pro for deep scans" with upgrade CTA
6. WHEN scan type is selected THEN the system SHALL display estimated scan time
7. WHEN user is anonymous THEN the system SHALL only allow Quick scans

### Requirement 3: Results Display

**User Story:** As a user, I want to see clear, visual results of the URL check, so that I can quickly understand the security assessment.

#### Acceptance Criteria

1. WHEN results are received THEN the system SHALL display risk score (0-100) with color-coded gauge
2. WHEN results include threat level THEN the system SHALL display badge (Safe/Suspicious/Malicious) with icon
3. WHEN results include provider findings THEN the system SHALL display accordion with VirusTotal, Google Safe Browsing, URLVoid sections
4. WHEN provider section is expanded THEN the system SHALL show detailed findings and confidence scores
5. WHEN results include broken links THEN the system SHALL display broken links tab with count
6. WHEN user is anonymous THEN the system SHALL show limited provider details with "Sign up for full report" CTA
7. WHEN results are displayed THEN the system SHALL show action buttons: Save to History, Report URL, Analyze with AI

### Requirement 4: Domain Reputation Badge

**User Story:** As a user, I want to see domain reputation at a glance, so that I can quickly assess trustworthiness.

#### Acceptance Criteria

1. WHEN URL is entered THEN the system SHALL extract domain
2. WHEN domain is extracted THEN the system SHALL call GET /api/v1/url-check/reputation/{domain}
3. WHEN reputation data is received THEN the system SHALL display reputation badge (Trusted/Neutral/Suspicious/Malicious)
4. WHEN reputation includes score THEN the system SHALL display score (0-100)
5. WHEN reputation includes check history THEN the system SHALL display "X checks, Y% safe"
6. WHEN reputation request fails THEN the system SHALL hide reputation badge

### Requirement 5: Social Protection Integration (Authenticated)

**User Story:** As an authenticated user, I want to access Social Protection features from the homepage, so that I can quickly monitor my social media security.

#### Acceptance Criteria

1. WHEN user is authenticated THEN the system SHALL display Social Protection panel
2. WHEN Social Protection panel is displayed THEN the system SHALL show Extension Status, Algorithm Health, and Social Account Scan sections
3. WHEN Extension Status section is displayed THEN the system SHALL call GET /api/v1/social-protection/extension/status
4. WHEN extension status is received THEN the system SHALL display connection status, last activity, and link to analytics
5. WHEN Algorithm Health section is displayed THEN the system SHALL call GET /api/v1/social/algorithm-health/health
6. WHEN algorithm health is received THEN the system SHALL display visibility, engagement, and penalty scores with trend indicators
7. WHEN user clicks "Run Analysis" THEN the system SHALL navigate to full algorithm health page
8. WHEN Social Account Scan section is displayed THEN the system SHALL show "Scan Account" button for connected platforms
9. WHEN user is not authenticated THEN the system SHALL hide Social Protection panel

### Requirement 6: Extension Status Card (Authenticated)

**User Story:** As an authenticated user with browser extension, I want to see extension status on homepage, so that I can monitor extension activity.

#### Acceptance Criteria

1. WHEN extension status is received THEN the system SHALL display connection status (Connected/Disconnected)
2. WHEN extension is connected THEN the system SHALL display last activity timestamp
3. WHEN extension status includes analytics THEN the system SHALL display today's protection count
4. WHEN user clicks "View Analytics" THEN the system SHALL call GET /api/v1/social-protection/extension/analytics and navigate to analytics page
5. WHEN extension is disconnected THEN the system SHALL display "Install Extension" CTA
6. WHEN extension status fails THEN the system SHALL display "Unable to check extension status"

### Requirement 7: Algorithm Health Summary (Authenticated)

**User Story:** As an authenticated user, I want to see quick algorithm health summary, so that I can monitor my social media account health.

#### Acceptance Criteria

1. WHEN algorithm health is received THEN the system SHALL display visibility score, engagement score, and penalty indicators
2. WHEN scores include trends THEN the system SHALL display trend arrows (up/down/stable)
3. WHEN penalty is detected THEN the system SHALL display warning badge with penalty type
4. WHEN user clicks "Analyze Visibility" THEN the system SHALL call POST /api/v1/social/algorithm-health/visibility/analyze
5. WHEN user clicks "Analyze Engagement" THEN the system SHALL call POST /api/v1/social/algorithm-health/engagement/analyze
6. WHEN user clicks "Detect Penalties" THEN the system SHALL call POST /api/v1/social/algorithm-health/penalty/detect
7. WHEN analysis is triggered THEN the system SHALL show processing status and navigate to results

### Requirement 8: Subscription Plan Display (Authenticated)

**User Story:** As an authenticated user, I want to see my subscription plan and usage, so that I can understand my limits and upgrade if needed.

#### Acceptance Criteria

1. WHEN user is authenticated THEN the system SHALL call GET /api/v1/subscriptions
2. WHEN subscription data is received THEN the system SHALL display plan name, usage summary, and renewal date
3. WHEN usage is approaching limit (>80%) THEN the system SHALL display warning message
4. WHEN usage exceeds limit THEN the system SHALL display "Limit reached" with upgrade CTA
5. WHEN user is on Free plan THEN the system SHALL display "Upgrade to Pro" CTA with benefits
6. WHEN user clicks upgrade THEN the system SHALL navigate to subscriptions page
7. WHEN subscription request fails THEN the system SHALL hide subscription card

### Requirement 9: Quick Actions (Authenticated)

**User Story:** As an authenticated user, I want quick access to common actions, so that I can efficiently use LinkShield features.

#### Acceptance Criteria

1. WHEN user is authenticated THEN the system SHALL display quick actions panel
2. WHEN quick actions are displayed THEN the system SHALL show: Bulk URL Check, AI Analysis, View Reports, API Keys
3. WHEN user clicks "Bulk URL Check" THEN the system SHALL navigate to bulk analysis page
4. WHEN user clicks "AI Analysis" THEN the system SHALL navigate to AI analysis page
5. WHEN user clicks "View Reports" THEN the system SHALL navigate to reports page
6. WHEN user clicks "API Keys" THEN the system SHALL navigate to API keys page

### Requirement 10: Save to History (Authenticated)

**User Story:** As an authenticated user, I want to save URL checks to my history, so that I can review them later.

#### Acceptance Criteria

1. WHEN check completes AND user is authenticated THEN the system SHALL automatically save check to history
2. WHEN save is successful THEN the system SHALL display "Saved to history" toast
3. WHEN user clicks "View in History" THEN the system SHALL navigate to URL analysis history page with check highlighted
4. WHEN user is anonymous THEN the system SHALL hide "Save to History" button and show "Sign up to save checks" message

## Base URLs

- **Client Base**: https://www.linkshield.site
- **API Base**: https://www.linkshield.site/api/v1

## API Endpoints

| Method | Endpoint | Auth Required | Rate Limit | Description |
|--------|----------|---------------|------------|-------------|
| POST | /url-check/check | Optional | 10/hour (anon), 100/hour (auth) | Check URL for threats |
| GET | /url-check/reputation/{domain} | Optional | 20/hour | Get domain reputation |
| GET | /social-protection/extension/status | Yes | 100/hour | Get extension status |
| GET | /social-protection/extension/analytics | Yes | 100/hour | Get extension analytics |
| GET | /social/algorithm-health/health | Yes | 100/hour | Get algorithm health summary |
| POST | /social/algorithm-health/visibility/analyze | Yes | 10/hour | Analyze visibility |
| POST | /social/algorithm-health/engagement/analyze | Yes | 10/hour | Analyze engagement |
| POST | /social/algorithm-health/penalty/detect | Yes | 10/hour | Detect penalties |
| GET | /subscriptions | Yes | 100/hour | Get user subscriptions |
| GET | /subscriptions/{id}/usage | Yes | 100/hour | Get usage statistics |

## Error Handling

| Error Code | HTTP Status | User Message | Action |
|------------|-------------|--------------|--------|
| INVALID_URL_FORMAT | 422 | Invalid URL format | Show validation error |
| URL_TOO_LONG | 422 | URL exceeds maximum length | Show validation error |
| SCAN_TIMEOUT | 504 | URL analysis timed out | Offer retry |
| RATE_LIMIT_EXCEEDED | 429 | Rate limit reached. Sign up for more checks | Show signup CTA |
| FEATURE_NOT_AVAILABLE | 402 | Upgrade to access this feature | Show upgrade CTA |
| EXTENSION_NOT_CONNECTED | 404 | Extension not connected | Show install CTA |
| UNAUTHORIZED | 401 | Please log in to access this feature | Redirect to login |

## Non-Functional Requirements

### Security
1. Anonymous checks SHALL be rate-limited by IP address
2. URL inputs SHALL be validated and sanitized
3. Results SHALL not expose sensitive system information
4. Social Protection features SHALL only be visible to authenticated users

### Performance
1. Homepage SHALL load within 1 second
2. URL check SHALL complete within 5 seconds for Quick scan
3. Results SHALL display progressively as data arrives
4. Social Protection data SHALL be cached for 5 minutes

### Accessibility
1. URL input SHALL have proper label and placeholder
2. Results SHALL have proper heading structure
3. Color coding SHALL not be sole indicator of threat level
4. All interactive elements SHALL be keyboard accessible

### Usability
1. URL input SHALL accept paste from clipboard
2. Scan type descriptions SHALL be clear and concise
3. Results SHALL be easy to understand for non-technical users
4. Upgrade CTAs SHALL clearly state benefits
5. Social Protection features SHALL have tooltips explaining functionality
