# Requirements Document

## Introduction

The Session Management feature enables authenticated users to view, monitor, and manage all active sessions across different devices and locations. This feature provides users with visibility into their account access and the ability to revoke unauthorized or suspicious sessions, enhancing account security and control.

## Requirements

### Requirement 1: View Active Sessions

**User Story:** As an authenticated user, I want to view all my active sessions, so that I can see which devices and locations are currently accessing my account.

#### Acceptance Criteria

1. WHEN a user navigates to sessions page THEN the system SHALL call GET /api/v1/user/sessions with Bearer token
2. WHEN session data is received THEN the system SHALL display list of sessions with id, device_info, ip_address, user_agent, is_active, expires_at, last_activity_at, created_at
3. WHEN current session is in the list THEN the system SHALL mark it with "Current Session" badge
4. WHEN session includes location data THEN the system SHALL display city and country
5. WHEN session is expired THEN the system SHALL NOT display it in the list
6. WHEN sessions list is empty THEN the system SHALL display "No active sessions found"
7. WHEN sessions request fails with 401 THEN the system SHALL redirect to login page
8. WHEN sessions request fails with 500 THEN the system SHALL display error message with retry button
9. WHEN page loads THEN the system SHALL display loading skeleton for sessions list
10. WHEN sessions are displayed THEN the system SHALL sort by last_activity_at descending

### Requirement 2: Display Session Details

**User Story:** As an authenticated user, I want to see detailed information about each session, so that I can identify devices and assess security.

#### Acceptance Criteria

1. WHEN session has device_info THEN the system SHALL display device type and operating system
2. WHEN session has user_agent THEN the system SHALL parse and display browser name and version
3. WHEN session has ip_address THEN the system SHALL display IP address
4. WHEN session has location THEN the system SHALL display location with flag icon
5. WHEN session has last_activity_at THEN the system SHALL display relative time (e.g., "2 hours ago")
6. WHEN session has created_at THEN the system SHALL display creation date
7. WHEN session has expires_at THEN the system SHALL display expiration time
8. WHEN session is current THEN the system SHALL highlight it with distinct styling
9. WHEN session is_active is false THEN the system SHALL display "Inactive" badge
10. WHEN device_info is missing THEN the system SHALL display "Unknown Device"

### Requirement 3: Revoke Specific Session

**User Story:** As an authenticated user, I want to revoke a specific session, so that I can terminate access from a device I no longer use or trust.

#### Acceptance Criteria

1. WHEN a user clicks "Revoke" on a session THEN the system SHALL display confirmation dialog
2. WHEN confirmation dialog is displayed THEN the system SHALL show session details and warning message
3. WHEN a user confirms revocation THEN the system SHALL call DELETE /api/v1/user/sessions/{session_id} with Bearer token
4. WHEN revocation is successful THEN the system SHALL remove session from list and display "Session revoked successfully" toast
5. WHEN revocation fails with 404 THEN the system SHALL display "Session not found or already expired"
6. WHEN revocation fails with 401 THEN the system SHALL redirect to login page
7. WHEN revocation is in progress THEN the system SHALL disable revoke button and show loading state
8. WHEN current session revoke is attempted THEN the system SHALL disable revoke button and show tooltip "Cannot revoke current session"
9. WHEN revocation is successful THEN the system SHALL update sessions list without full page reload
10. WHEN revocation fails with 500 THEN the system SHALL display error message with retry option

### Requirement 4: Terminate All Sessions

**User Story:** As an authenticated user, I want to terminate all other sessions at once, so that I can quickly secure my account if I suspect unauthorized access.

#### Acceptance Criteria

1. WHEN a user clicks "Terminate All Other Sessions" THEN the system SHALL display confirmation dialog
2. WHEN confirmation dialog is displayed THEN the system SHALL show count of sessions to be terminated and warning message
3. WHEN a user confirms termination THEN the system SHALL call DELETE /api/v1/user/sessions with Bearer token
4. WHEN termination is successful THEN the system SHALL display "All other sessions terminated successfully" toast
5. WHEN termination is successful THEN the system SHALL refresh sessions list showing only current session
6. WHEN termination fails with 401 THEN the system SHALL redirect to login page
7. WHEN termination is in progress THEN the system SHALL disable button and show loading state
8. WHEN only current session exists THEN the system SHALL disable "Terminate All" button
9. WHEN termination fails with 500 THEN the system SHALL display error message with retry option
10. WHEN termination is successful THEN the system SHALL log security event

### Requirement 5: Session Security Indicators

**User Story:** As an authenticated user, I want to see security indicators for each session, so that I can identify potentially suspicious activity.

#### Acceptance Criteria

1. WHEN session location differs from usual locations THEN the system SHALL display "New Location" badge
2. WHEN session was created recently (< 24 hours) THEN the system SHALL display "New" badge
3. WHEN session has been inactive for long period (> 7 days) THEN the system SHALL display "Inactive" warning
4. WHEN session is about to expire (< 1 hour) THEN the system SHALL display "Expiring Soon" warning
5. WHEN session IP address is suspicious THEN the system SHALL display security warning icon
6. WHEN multiple sessions from same IP exist THEN the system SHALL group them visually
7. WHEN session device is unrecognized THEN the system SHALL display "Unrecognized Device" badge
8. WHEN session is current THEN the system SHALL display green "Active Now" indicator
9. WHEN session has unusual user_agent THEN the system SHALL display warning icon with tooltip
10. WHEN security indicators are displayed THEN the system SHALL provide explanatory tooltips

### Requirement 6: Session Filtering and Search

**User Story:** As an authenticated user with many sessions, I want to filter and search sessions, so that I can quickly find specific sessions.

#### Acceptance Criteria

1. WHEN sessions page has search box THEN the system SHALL filter sessions by device_info, ip_address, or location
2. WHEN a user types in search box THEN the system SHALL debounce input (300ms) and filter results
3. WHEN search has no results THEN the system SHALL display "No sessions match your search"
4. WHEN a user clears search THEN the system SHALL show all sessions again
5. WHEN filter dropdown is available THEN the system SHALL show options: All, Active, Inactive, Current Device
6. WHEN a user selects filter THEN the system SHALL update displayed sessions immediately
7. WHEN filter is applied THEN the system SHALL show active filter badge with count
8. WHEN a user clicks "Clear Filters" THEN the system SHALL reset all filters and search
9. WHEN sessions are filtered THEN the system SHALL maintain sort order
10. WHEN filter results in empty list THEN the system SHALL show helpful message

### Requirement 7: Session Refresh and Auto-Update

**User Story:** As an authenticated user, I want sessions list to stay current, so that I see accurate information about active sessions.

#### Acceptance Criteria

1. WHEN sessions page is open THEN the system SHALL auto-refresh sessions list every 60 seconds
2. WHEN a user clicks "Refresh" button THEN the system SHALL immediately fetch latest sessions
3. WHEN refresh is in progress THEN the system SHALL show loading indicator on refresh button
4. WHEN new session is detected THEN the system SHALL highlight it with animation
5. WHEN session is removed THEN the system SHALL animate its removal from list
6. WHEN auto-refresh fails THEN the system SHALL display non-intrusive error notification
7. WHEN page is not visible (tab inactive) THEN the system SHALL pause auto-refresh
8. WHEN page becomes visible again THEN the system SHALL resume auto-refresh and fetch latest data
9. WHEN network is offline THEN the system SHALL pause auto-refresh and show offline indicator
10. WHEN network is restored THEN the system SHALL resume auto-refresh automatically

### Requirement 8: Session Activity Timeline

**User Story:** As an authenticated user, I want to see activity timeline for sessions, so that I can understand usage patterns.

#### Acceptance Criteria

1. WHEN session details are expanded THEN the system SHALL display activity timeline
2. WHEN timeline is displayed THEN the system SHALL show created_at, last_activity_at, and expires_at
3. WHEN session has multiple activities THEN the system SHALL display them chronologically
4. WHEN activity timestamp is displayed THEN the system SHALL show both relative and absolute time
5. WHEN session is current THEN the system SHALL show "Active now" in timeline
6. WHEN session has no recent activity THEN the system SHALL display "Last active [time] ago"
7. WHEN timeline is displayed THEN the system SHALL use visual indicators (dots, lines)
8. WHEN session is expired THEN the system SHALL show expiration in timeline
9. WHEN timeline is long THEN the system SHALL provide scroll or collapse functionality
10. WHEN timeline is displayed THEN the system SHALL be accessible to screen readers

### Requirement 9: Mobile and Responsive Design

**User Story:** As an authenticated user on mobile device, I want sessions management to work well on small screens, so that I can manage sessions from any device.

#### Acceptance Criteria

1. WHEN sessions page is viewed on mobile THEN the system SHALL display sessions in card layout
2. WHEN session card is displayed THEN the system SHALL show essential info: device, location, last active
3. WHEN a user taps session card THEN the system SHALL expand to show full details
4. WHEN revoke button is displayed on mobile THEN the system SHALL be easily tappable (min 44x44px)
5. WHEN confirmation dialog is shown on mobile THEN the system SHALL be properly sized and scrollable
6. WHEN sessions list is long on mobile THEN the system SHALL implement virtual scrolling
7. WHEN mobile keyboard is open THEN the system SHALL adjust layout appropriately
8. WHEN orientation changes THEN the system SHALL adapt layout smoothly
9. WHEN touch gestures are used THEN the system SHALL support swipe to reveal actions
10. WHEN mobile view is displayed THEN the system SHALL maintain all functionality from desktop

### Requirement 10: Session Notifications

**User Story:** As an authenticated user, I want to receive notifications about session events, so that I'm aware of account access.

#### Acceptance Criteria

1. WHEN new session is created from new location THEN the system SHALL send email notification
2. WHEN new session is created from new device THEN the system SHALL send email notification
3. WHEN session is revoked THEN the system SHALL send confirmation email
4. WHEN all sessions are terminated THEN the system SHALL send security alert email
5. WHEN notification email is sent THEN the system SHALL include session details: device, location, time
6. WHEN notification email is sent THEN the system SHALL include "Wasn't you?" link to secure account
7. WHEN suspicious session is detected THEN the system SHALL send immediate security alert
8. WHEN notification preferences allow THEN the system SHALL send in-app notifications
9. WHEN session is about to expire THEN the system SHALL show in-app warning
10. WHEN notification is displayed THEN the system SHALL provide action buttons (Revoke, Dismiss)

## Base URLs

- **Client Base**: https://www.linkshield.site
- **API Base**: https://www.linkshield.site/api/v1

## API Endpoints

| Method | Endpoint | Auth Required | Rate Limit | Description |
|--------|----------|---------------|------------|-------------|
| GET | /user/sessions | Yes | 100/hour | List active sessions |
| DELETE | /user/sessions/{session_id} | Yes | 100/hour | Revoke specific session |
| DELETE | /user/sessions | Yes | 100/hour | Terminate all sessions except current |

## Session Fields

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Unique session identifier |
| device_info | String | Device type and OS information |
| ip_address | String | IP address of the session |
| user_agent | String | Browser and client information |
| is_active | Boolean | Whether session is currently active |
| expires_at | DateTime | When session will expire |
| last_activity_at | DateTime | Last activity timestamp |
| created_at | DateTime | Session creation timestamp |
| location | Object | Optional location data (city, country, coordinates) |

## Error Handling

| Error Code | HTTP Status | User Message | Action |
|------------|-------------|--------------|--------|
| SESSION_NOT_FOUND | 404 | Session not found or already expired | Remove from list |
| CANNOT_REVOKE_CURRENT | 400 | Cannot revoke current session | Disable button |
| UNAUTHORIZED | 401 | Session expired | Redirect to login |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests | Show retry-after time |
| SERVER_ERROR | 500 | Unable to manage sessions | Show retry option |

## Non-Functional Requirements

### Security
1. Current session SHALL NOT be revocable through UI
2. Session revocation SHALL require confirmation
3. Terminate all SHALL require explicit confirmation
4. Session IDs SHALL never be logged in client
5. All requests SHALL use HTTPS and Bearer token authentication
6. Session data SHALL be refreshed after any revocation action

### Performance
1. Sessions list SHALL load within 1 second
2. Session revocation SHALL complete within 2 seconds
3. Auto-refresh SHALL not impact UI responsiveness
4. Large session lists (>50) SHALL use virtual scrolling
5. Session filtering SHALL be instant (< 100ms)

### Accessibility
1. All actions SHALL be keyboard navigable
2. Session cards SHALL have proper ARIA labels
3. Confirmation dialogs SHALL trap focus
4. Status changes SHALL be announced to screen readers
5. Color SHALL not be sole indicator of session status
6. All interactive elements SHALL meet WCAG AA contrast requirements

### Usability
1. Current session SHALL be clearly distinguished
2. Session details SHALL be easily scannable
3. Dangerous actions SHALL require confirmation
4. Success/error messages SHALL be clear and actionable
5. Loading states SHALL provide feedback
6. Empty states SHALL provide helpful guidance
7. Session information SHALL be displayed in user's timezone
8. Relative timestamps SHALL update in real-time
