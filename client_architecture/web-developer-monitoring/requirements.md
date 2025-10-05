# Requirements Document

## Introduction

The Web Developer Monitoring feature provides developers with comprehensive tools to monitor their websites for harmful content, malicious links, and security threats. Using the Projects feature, developers can set up automated monitoring, receive alerts, manage team access, track analytics, and integrate via API. This feature is specifically designed for web developers who need to protect their websites and users from security threats.

## Requirements

### Requirement 1: Dashboard Overview for Developers

**User Story:** As a web developer, I want to view my monitoring dashboard overview, so that I can see the health and security status of all my projects at a glance.

#### Acceptance Criteria

1. WHEN a developer navigates to dashboard THEN the system SHALL call GET /api/v1/dashboard/overview with Bearer token
2. WHEN overview data is received THEN the system SHALL display total_projects, active_projects, total_scans, total_alerts
3. WHEN overview includes recent_projects THEN the system SHALL display list with name, domain, last_scan_at, alert_count
4. WHEN overview includes recent_alerts THEN the system SHALL display list with severity, title, project_name, created_at
5. WHEN overview includes subscription_status THEN the system SHALL display plan, usage, limits
6. WHEN overview includes social_protection THEN the system SHALL display social protection metrics
7. WHEN dashboard request fails with 401 THEN the system SHALL redirect to login page
8. WHEN dashboard request fails with 500 THEN the system SHALL display error message with retry button
9. WHEN page loads THEN the system SHALL display loading skeleton for overview cards
10. WHEN developer has no projects THEN the system SHALL display onboarding prompt to create first project

### Requirement 2: Project Management

**User Story:** As a web developer, I want to create and manage monitoring projects, so that I can organize monitoring for different websites.

#### Acceptance Criteria

1. WHEN a developer clicks "Create Project" THEN the system SHALL display project creation modal
2. WHEN modal is displayed THEN the system SHALL show fields: name, description, website_url, settings
3. WHEN a developer enters website_url THEN the system SHALL validate URL format and extract domain
4. WHEN a developer submits project THEN the system SHALL call POST /api/v1/dashboard/projects with project data
5. WHEN project is created THEN the system SHALL display success toast and navigate to project details
6. WHEN project creation fails with 400 THEN the system SHALL display validation errors
7. WHEN a developer views projects list THEN the system SHALL call GET /api/v1/dashboard/projects with pagination
8. WHEN projects list is displayed THEN the system SHALL show name, domain, monitoring_enabled, last_scan_at, alert_count
9. WHEN a developer searches projects THEN the system SHALL filter by name or domain
10. WHEN a developer filters by status THEN the system SHALL show only active or inactive projects

### Requirement 3: Project Details and Configuration

**User Story:** As a web developer, I want to view and configure project details, so that I can customize monitoring for each website.

#### Acceptance Criteria

1. WHEN a developer clicks project THEN the system SHALL call GET /api/v1/dashboard/projects/{project_id}
2. WHEN project details are received THEN the system SHALL display name, description, website_url, domain, monitoring_enabled, settings
3. WHEN a developer clicks "Edit Project" THEN the system SHALL display edit modal with current values
4. WHEN a developer updates project THEN the system SHALL call PATCH /api/v1/dashboard/projects/{project_id}
5. WHEN update is successful THEN the system SHALL display success toast and refresh project details
6. WHEN update fails with 400 THEN the system SHALL display validation errors
7. WHEN project includes settings THEN the system SHALL display scan_frequency, scan_depth, max_links, exclude_patterns
8. WHEN a developer clicks "Delete Project" THEN the system SHALL display confirmation dialog
9. WHEN deletion is confirmed THEN the system SHALL call DELETE /api/v1/dashboard/projects/{project_id}
10. WHEN deletion is successful THEN the system SHALL navigate to projects list

### Requirement 4: Monitoring Control

**User Story:** As a web developer, I want to enable or disable monitoring for projects, so that I can control when my websites are scanned.

#### Acceptance Criteria

1. WHEN project details are displayed THEN the system SHALL show monitoring toggle switch
2. WHEN monitoring is enabled THEN the system SHALL display green "Active" badge
3. WHEN monitoring is disabled THEN the system SHALL display gray "Inactive" badge
4. WHEN a developer toggles monitoring THEN the system SHALL call POST /api/v1/dashboard/projects/{project_id}/monitoring/{enabled}
5. WHEN toggle is successful THEN the system SHALL update UI and display toast message
6. WHEN toggle fails with 403 THEN the system SHALL display "Insufficient permissions" error
7. WHEN monitoring is enabled THEN the system SHALL display next scan time
8. WHEN monitoring configuration is displayed THEN the system SHALL show scan_frequency_minutes, scan_depth_limit, max_links_per_scan
9. WHEN a developer updates monitoring config THEN the system SHALL validate settings before submission
10. WHEN config update is successful THEN the system SHALL display "Monitoring configuration updated" toast

### Requirement 5: Alert Management

**User Story:** As a web developer, I want to view and manage security alerts, so that I can respond to threats on my websites.

#### Acceptance Criteria

1. WHEN a developer navigates to project alerts THEN the system SHALL call GET /api/v1/dashboard/projects/{project_id}/alerts
2. WHEN alerts are received THEN the system SHALL display list with alert_type, severity, title, status, created_at
3. WHEN alerts list includes filters THEN the system SHALL show status filter (active/acknowledged/resolved/dismissed) and severity filter
4. WHEN a developer applies filter THEN the system SHALL update query params and refetch alerts
5. WHEN a developer clicks alert THEN the system SHALL call GET /api/v1/dashboard/projects/{project_id}/alerts/{alert_id}
6. WHEN alert details are displayed THEN the system SHALL show full description, context_data, affected_urls
7. WHEN a developer clicks "Acknowledge" THEN the system SHALL call POST /api/v1/dashboard/projects/{project_id}/alerts/{alert_id}/acknowledge
8. WHEN a developer clicks "Resolve" THEN the system SHALL call POST /api/v1/dashboard/projects/{project_id}/alerts/{alert_id}/resolve
9. WHEN a developer clicks "Dismiss" THEN the system SHALL call POST /api/v1/dashboard/projects/{project_id}/alerts/{alert_id}/dismiss
10. WHEN alert status changes THEN the system SHALL update UI and display success toast

### Requirement 6: Team Management

**User Story:** As a web developer, I want to invite team members to projects, so that we can collaborate on website monitoring.

#### Acceptance Criteria

1. WHEN a developer navigates to project team THEN the system SHALL call GET /api/v1/dashboard/projects/{project_id}/members
2. WHEN members are received THEN the system SHALL display list with email, full_name, role, joined_at, is_active
3. WHEN a developer clicks "Invite Member" THEN the system SHALL display invitation modal
4. WHEN modal is displayed THEN the system SHALL show fields: email, role (owner/admin/editor/viewer)
5. WHEN a developer submits invitation THEN the system SHALL call POST /api/v1/dashboard/projects/{project_id}/members/invite
6. WHEN invitation is successful THEN the system SHALL display "Invitation sent" toast and refresh members list
7. WHEN invitation fails with 400 THEN the system SHALL display validation errors
8. WHEN invitation fails with 409 THEN the system SHALL display "User already invited" error
9. WHEN member list is displayed THEN the system SHALL show role badges with different colors
10. WHEN a developer has owner role THEN the system SHALL show "Remove Member" button for other members

### Requirement 7: Analytics and Activity Logs

**User Story:** As a web developer, I want to view analytics and activity logs, so that I can track monitoring performance and team actions.

#### Acceptance Criteria

1. WHEN a developer navigates to analytics THEN the system SHALL call GET /api/v1/dashboard/analytics with date range
2. WHEN analytics are received THEN the system SHALL display total_scans, threats_detected, urls_checked, avg_response_time
3. WHEN analytics include time_series THEN the system SHALL display chart with daily/weekly/monthly data
4. WHEN a developer selects date range THEN the system SHALL update query params and refetch analytics
5. WHEN a developer navigates to activity logs THEN the system SHALL call GET /api/v1/dashboard/projects/{project_id}/activity-logs
6. WHEN activity logs are received THEN the system SHALL display list with action, user, timestamp, details
7. WHEN activity logs include pagination THEN the system SHALL show page controls with limit and offset
8. WHEN a developer clicks "Load More" THEN the system SHALL fetch next page and append to list
9. WHEN activity log entry is clicked THEN the system SHALL expand to show full details
10. WHEN activity logs are empty THEN the system SHALL display "No activity yet" message

### Requirement 8: URL Scanning Integration

**User Story:** As a web developer, I want to scan specific URLs from my project, so that I can check individual pages for threats.

#### Acceptance Criteria

1. WHEN project details are displayed THEN the system SHALL show "Scan URL" button
2. WHEN a developer clicks "Scan URL" THEN the system SHALL display URL input modal
3. WHEN modal is displayed THEN the system SHALL pre-fill domain from project website_url
4. WHEN a developer enters URL THEN the system SHALL validate URL belongs to project domain
5. WHEN a developer submits URL THEN the system SHALL call POST /api/v1/url-check/check with project context
6. WHEN scan is initiated THEN the system SHALL display progress indicator
7. WHEN scan is complete THEN the system SHALL display results with risk_score, threats_found, recommendations
8. WHEN scan finds threats THEN the system SHALL offer to create alert for project
9. WHEN a developer clicks "Create Alert" THEN the system SHALL call POST /api/v1/dashboard/projects/{project_id}/alerts
10. WHEN alert is created THEN the system SHALL display success toast and navigate to alerts

### Requirement 9: Bulk URL Scanning

**User Story:** As a web developer, I want to scan multiple URLs at once, so that I can efficiently check many pages on my website.

#### Acceptance Criteria

1. WHEN project details are displayed THEN the system SHALL show "Bulk Scan" button
2. WHEN a developer clicks "Bulk Scan" THEN the system SHALL display bulk scan modal
3. WHEN modal is displayed THEN the system SHALL show textarea for URL list and file upload option
4. WHEN a developer enters URLs THEN the system SHALL validate each URL format
5. WHEN a developer uploads file THEN the system SHALL parse CSV/TXT file and extract URLs
6. WHEN a developer submits bulk scan THEN the system SHALL call POST /api/v1/url-check/bulk-check
7. WHEN bulk scan is processing THEN the system SHALL display progress with completed/total count
8. WHEN bulk scan is complete THEN the system SHALL display summary: total_scanned, threats_found, clean_urls
9. WHEN results include threats THEN the system SHALL display list of URLs with risk scores
10. WHEN a developer clicks "Export Results" THEN the system SHALL download CSV with scan results

### Requirement 10: API Integration and Documentation

**User Story:** As a web developer, I want to integrate monitoring via API, so that I can automate security checks in my CI/CD pipeline.

#### Acceptance Criteria

1. WHEN a developer navigates to API section THEN the system SHALL display API documentation
2. WHEN documentation is displayed THEN the system SHALL show authentication methods: Bearer token, API key
3. WHEN documentation includes endpoints THEN the system SHALL show: scan URL, bulk scan, get alerts, create project
4. WHEN a developer clicks "Generate API Key" THEN the system SHALL navigate to API keys page
5. WHEN documentation includes code examples THEN the system SHALL show cURL, JavaScript, Python examples
6. WHEN a developer clicks "Copy" on code example THEN the system SHALL copy to clipboard
7. WHEN documentation includes rate limits THEN the system SHALL show limits per plan
8. WHEN documentation includes webhooks THEN the system SHALL show how to configure alert webhooks
9. WHEN a developer clicks "Test API" THEN the system SHALL display interactive API tester
10. WHEN API tester is used THEN the system SHALL send request and display response with syntax highlighting

### Requirement 11: Alert Statistics and Insights

**User Story:** As a web developer, I want to view alert statistics, so that I can understand threat patterns on my websites.

#### Acceptance Criteria

1. WHEN a developer navigates to alert stats THEN the system SHALL call GET /api/v1/dashboard/projects/{project_id}/alerts/stats
2. WHEN stats are received THEN the system SHALL display total_alerts, active_alerts, resolved_alerts, dismissed_alerts
3. WHEN stats include severity breakdown THEN the system SHALL display chart with low/medium/high/critical counts
4. WHEN stats include alert types THEN the system SHALL display chart with malicious_link, phishing, malware, spam counts
5. WHEN stats include timeline THEN the system SHALL display line chart with alerts over time
6. WHEN a developer clicks chart segment THEN the system SHALL filter alerts by that category
7. WHEN stats include top threats THEN the system SHALL display list of most common threat types
8. WHEN stats include affected URLs THEN the system SHALL display list of URLs with most alerts
9. WHEN a developer clicks "Export Stats" THEN the system SHALL download PDF report
10. WHEN stats are empty THEN the system SHALL display "No alerts yet" with security tips

### Requirement 12: Monitoring Schedule Configuration

**User Story:** As a web developer, I want to configure monitoring schedules, so that I can control when and how often my websites are scanned.

#### Acceptance Criteria

1. WHEN project settings are displayed THEN the system SHALL show monitoring schedule section
2. WHEN schedule section is displayed THEN the system SHALL show scan_frequency options: hourly, every 6 hours, daily, weekly
3. WHEN a developer selects frequency THEN the system SHALL display next scan time
4. WHEN schedule includes scan_depth THEN the system SHALL show slider (1-10 levels)
5. WHEN schedule includes max_links THEN the system SHALL show input field with validation (1-10000)
6. WHEN schedule includes exclude_patterns THEN the system SHALL show textarea for URL patterns
7. WHEN a developer adds exclude pattern THEN the system SHALL validate regex format
8. WHEN a developer saves schedule THEN the system SHALL call PATCH /api/v1/dashboard/projects/{project_id}
9. WHEN save is successful THEN the system SHALL display "Schedule updated" toast
10. WHEN subscription limits are reached THEN the system SHALL display upgrade prompt

### Requirement 13: Notification Preferences

**User Story:** As a web developer, I want to configure notification preferences, so that I can control how I receive alerts.

#### Acceptance Criteria

1. WHEN project settings are displayed THEN the system SHALL show notifications section
2. WHEN notifications section is displayed THEN the system SHALL show toggles for email, slack, webhook
3. WHEN email notifications are enabled THEN the system SHALL show email address input
4. WHEN slack notifications are enabled THEN the system SHALL show "Connect Slack" button
5. WHEN webhook notifications are enabled THEN the system SHALL show webhook URL input
6. WHEN a developer enters webhook URL THEN the system SHALL validate URL format
7. WHEN a developer clicks "Test Webhook" THEN the system SHALL send test notification
8. WHEN test is successful THEN the system SHALL display "Test notification sent" toast
9. WHEN notifications include severity filter THEN the system SHALL show checkboxes for low/medium/high/critical
10. WHEN a developer saves preferences THEN the system SHALL update project settings

### Requirement 14: Project Health Score

**User Story:** As a web developer, I want to see a health score for my projects, so that I can quickly assess security status.

#### Acceptance Criteria

1. WHEN project details are displayed THEN the system SHALL show health score (0-100)
2. WHEN health score is displayed THEN the system SHALL use color coding: green (80-100), yellow (60-79), orange (40-59), red (0-39)
3. WHEN health score includes breakdown THEN the system SHALL show: url_safety_score, social_protection_score, risk_breakdown
4. WHEN health score includes trend THEN the system SHALL display: improving, stable, declining
5. WHEN a developer clicks health score THEN the system SHALL expand to show detailed metrics
6. WHEN detailed metrics are displayed THEN the system SHALL show: last_scan_date, threats_detected, clean_urls, response_time
7. WHEN health score includes recommendations THEN the system SHALL display actionable items
8. WHEN a developer clicks recommendation THEN the system SHALL navigate to relevant settings
9. WHEN health score is low THEN the system SHALL display warning banner
10. WHEN health score improves THEN the system SHALL display celebration animation

### Requirement 15: Quick Actions and Shortcuts

**User Story:** As a web developer, I want quick access to common actions, so that I can efficiently manage monitoring.

#### Acceptance Criteria

1. WHEN dashboard is displayed THEN the system SHALL show quick actions panel
2. WHEN quick actions include "Scan URL" THEN the system SHALL open scan modal with project selector
3. WHEN quick actions include "Create Project" THEN the system SHALL open project creation modal
4. WHEN quick actions include "View Alerts" THEN the system SHALL navigate to alerts with active filter
5. WHEN quick actions include "API Docs" THEN the system SHALL navigate to API documentation
6. WHEN project card is displayed THEN the system SHALL show action menu with: Scan Now, View Alerts, Settings, Delete
7. WHEN a developer clicks "Scan Now" THEN the system SHALL initiate immediate scan
8. WHEN scan is initiated THEN the system SHALL display progress toast
9. WHEN keyboard shortcuts are enabled THEN the system SHALL support: Ctrl+N (new project), Ctrl+S (scan URL), Ctrl+A (alerts)
10. WHEN a developer presses "?" THEN the system SHALL display keyboard shortcuts help modal

## Base URLs

- **Client Base**: https://www.linkshield.site
- **API Base**: https://www.linkshield.site/api/v1

## API Endpoints

| Method | Endpoint | Auth Required | Rate Limit | Description |
|--------|----------|---------------|------------|-------------|
| GET | /dashboard/overview | Yes | 100/hour | Get dashboard overview |
| GET | /dashboard/projects | Yes | 100/hour | List projects with pagination |
| POST | /dashboard/projects | Yes | 20/hour | Create new project |
| GET | /dashboard/projects/{project_id} | Yes | 100/hour | Get project details |
| PATCH | /dashboard/projects/{project_id} | Yes | 50/hour | Update project |
| DELETE | /dashboard/projects/{project_id} | Yes | 10/hour | Delete project |
| POST | /dashboard/projects/{project_id}/monitoring/{enabled} | Yes | 50/hour | Toggle monitoring |
| GET | /dashboard/projects/{project_id}/members | Yes | 100/hour | List team members |
| POST | /dashboard/projects/{project_id}/members/invite | Yes | 20/hour | Invite team member |
| GET | /dashboard/projects/{project_id}/alerts | Yes | 100/hour | List project alerts |
| POST | /dashboard/projects/{project_id}/alerts | Yes | 50/hour | Create alert |
| GET | /dashboard/projects/{project_id}/alerts/{alert_id} | Yes | 100/hour | Get alert details |
| PATCH | /dashboard/projects/{project_id}/alerts/{alert_id} | Yes | 50/hour | Update alert |
| POST | /dashboard/projects/{project_id}/alerts/{alert_id}/acknowledge | Yes | 50/hour | Acknowledge alert |
| POST | /dashboard/projects/{project_id}/alerts/{alert_id}/resolve | Yes | 50/hour | Resolve alert |
| POST | /dashboard/projects/{project_id}/alerts/{alert_id}/dismiss | Yes | 50/hour | Dismiss alert |
| GET | /dashboard/projects/{project_id}/alerts/stats | Yes | 100/hour | Get alert statistics |
| GET | /dashboard/projects/{project_id}/activity-logs | Yes | 100/hour | Get activity logs |
| GET | /dashboard/analytics | Yes | 100/hour | Get analytics data |

## Data Models

### Dashboard Overview
| Field | Type | Description |
|-------|------|-------------|
| total_projects | Integer | Total number of projects |
| active_projects | Integer | Number of active projects |
| total_scans | Integer | Total scans performed |
| total_alerts | Integer | Total alerts generated |
| recent_projects | Array | List of recent project objects |
| recent_alerts | Array | List of recent alert objects |
| subscription_status | Object | Subscription plan and usage |
| social_protection | Object | Social protection metrics |

### Project
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique project identifier |
| name | String | Project name |
| description | String | Project description |
| website_url | String | Website URL to monitor |
| domain | String | Extracted domain |
| is_active | Boolean | Project active status |
| monitoring_enabled | Boolean | Monitoring status |
| settings | Object | Monitoring configuration |
| member_count | Integer | Number of team members |
| created_at | DateTime | Creation timestamp |
| updated_at | DateTime | Last update timestamp |
| last_scan_at | DateTime | Last scan timestamp |

### Alert
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique alert identifier |
| project_id | UUID | Associated project ID |
| alert_type | String | Type of alert |
| severity | String | Alert severity (low/medium/high/critical) |
| title | String | Alert title |
| description | String | Alert description |
| context_data | Object | Additional context |
| affected_urls | Array | List of affected URLs |
| status | String | Alert status (active/acknowledged/resolved/dismissed) |
| created_at | DateTime | Creation timestamp |
| acknowledged_at | DateTime | Acknowledgment timestamp |
| resolved_at | DateTime | Resolution timestamp |

### Team Member
| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique member identifier |
| user_id | UUID | User ID |
| email | String | Member email |
| full_name | String | Member name |
| role | String | Project role (owner/admin/editor/viewer) |
| is_active | Boolean | Member active status |
| joined_at | DateTime | Join timestamp |
| invited_at | DateTime | Invitation timestamp |

## Error Handling

| Error Code | HTTP Status | User Message | Action |
|------------|-------------|--------------|--------|
| PROJECT_NOT_FOUND | 404 | Project not found | Redirect to projects list |
| INVALID_URL | 400 | Invalid website URL | Show URL format |
| DUPLICATE_PROJECT | 409 | Project already exists for this domain | Show existing project |
| INSUFFICIENT_PERMISSIONS | 403 | You don't have permission for this action | Show role requirements |
| MEMBER_ALREADY_EXISTS | 409 | User already invited to project | Show member list |
| MONITORING_LIMIT_REACHED | 403 | Monitoring limit reached for your plan | Show upgrade options |
| ALERT_NOT_FOUND | 404 | Alert not found | Refresh alerts list |
| INVALID_SCHEDULE | 400 | Invalid monitoring schedule | Show valid options |
| WEBHOOK_TEST_FAILED | 502 | Webhook test failed | Check webhook URL |
| UNAUTHORIZED | 401 | Session expired | Redirect to login |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests | Show retry-after time |
| SERVER_ERROR | 500 | Unable to process request | Show retry option |

## Non-Functional Requirements

### Security
1. Project data SHALL be isolated per user/team
2. API keys SHALL have project-specific scopes
3. Webhook URLs SHALL be validated and sanitized
4. Team invitations SHALL require email verification
5. All requests SHALL use HTTPS and Bearer token authentication

### Performance
1. Dashboard overview SHALL load within 2 seconds
2. Project list SHALL support pagination with 20 items per page
3. Alert list SHALL use virtual scrolling for 100+ items
4. Analytics charts SHALL cache data for 5 minutes
5. Bulk scans SHALL process up to 1000 URLs

### Accessibility
1. All dashboard panels SHALL be keyboard navigable
2. Alert severity SHALL not rely solely on color
3. Charts SHALL have text alternatives
4. Forms SHALL have proper labels and ARIA attributes
5. Keyboard shortcuts SHALL be documented

### Usability
1. Project creation SHALL guide users through setup
2. Alert notifications SHALL be actionable
3. Analytics SHALL provide export options
4. API documentation SHALL include interactive examples
5. Health scores SHALL include improvement recommendations
