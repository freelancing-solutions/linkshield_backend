# Requirements Document

## Introduction

The API Key Management feature enables authenticated users to create, view, and manage API keys for programmatic access to LinkShield services. API keys provide an alternative authentication method for server-to-server integrations and automated systems, with scoped permissions and optional expiration dates.

## Requirements

### Requirement 1: List API Keys

**User Story:** As an authenticated user, I want to view all my API keys, so that I can manage my programmatic access credentials.

#### Acceptance Criteria

1. WHEN a user navigates to the API keys page THEN the system SHALL call GET /api/v1/user/api-keys with Bearer token
2. WHEN API keys are retrieved THEN the system SHALL display a table showing id, name, description, key_preview, permissions, is_active, expires_at, last_used_at, and created_at for each key
3. WHEN no API keys exist THEN the system SHALL display an empty state with "Create your first API key" message
4. WHEN the request fails with 401 THEN the system SHALL redirect to login page
5. WHEN key_preview is displayed THEN the system SHALL show only the first 8 characters followed by "..."
6. WHEN a key is expired THEN the system SHALL display an "Expired" badge
7. WHEN a key is inactive THEN the system SHALL display an "Inactive" badge

### Requirement 2: Create API Key

**User Story:** As an authenticated user, I want to create a new API key with specific permissions, so that I can integrate LinkShield services into my applications.

#### Acceptance Criteria

1. WHEN a user clicks "Create API Key" THEN the system SHALL display a creation modal with form fields
2. WHEN the creation form is displayed THEN the system SHALL show fields for name (required), description (optional), expires_at (optional), and permissions (multi-select)
3. WHEN a user submits the form THEN the system SHALL call POST /api/v1/user/api-keys with name, description, expires_at, and permissions array
4. WHEN creation is successful THEN the system SHALL display the full API key in a reveal modal with copy-to-clipboard button
5. WHEN the full API key is displayed THEN the system SHALL show a warning: "This is the only time you will see this key. Copy it now."
6. WHEN the user closes the reveal modal THEN the system SHALL never display the full key again
7. WHEN creation fails with 400 and limit reached THEN the system SHALL display "API key limit reached for your plan. Delete unused keys or upgrade your plan."
8. WHEN permissions are selected THEN the system SHALL only allow: url_check, ai_analysis, reports, profile
9. WHEN the user is on Free tier THEN the system SHALL limit to 3 API keys maximum
10. WHEN the user is on Premium tier THEN the system SHALL limit to 10 API keys maximum

### Requirement 3: Delete API Key

**User Story:** As an authenticated user, I want to delete an API key I no longer need, so that I can maintain security and manage my credentials.

#### Acceptance Criteria

1. WHEN a user clicks delete on an API key THEN the system SHALL display a confirmation dialog
2. WHEN the confirmation dialog is displayed THEN the system SHALL show the key name and warning: "This action cannot be undone. Applications using this key will lose access immediately."
3. WHEN the user confirms deletion THEN the system SHALL call DELETE /api/v1/user/api-keys/{key_id} with Bearer token
4. WHEN deletion is successful THEN the system SHALL remove the key from the list and display "API key deleted successfully"
5. WHEN deletion fails with 404 THEN the system SHALL display "API key not found or already deleted"
6. WHEN deletion fails with 403 THEN the system SHALL display "You don't have permission to delete this key"

### Requirement 4: Copy API Key

**User Story:** As a user who just created an API key, I want to easily copy the key to my clipboard, so that I can use it in my application.

#### Acceptance Criteria

1. WHEN the full API key is displayed THEN the system SHALL show a "Copy to Clipboard" button
2. WHEN the user clicks "Copy to Clipboard" THEN the system SHALL copy the full key to clipboard
3. WHEN copy is successful THEN the system SHALL display "API key copied to clipboard" toast message
4. WHEN copy fails THEN the system SHALL display "Failed to copy. Please copy manually" and select the key text

### Requirement 5: View API Key Details

**User Story:** As an authenticated user, I want to view details about an API key, so that I can understand its usage and permissions.

#### Acceptance Criteria

1. WHEN a user clicks on an API key row THEN the system SHALL expand to show full details
2. WHEN details are displayed THEN the system SHALL show full description, all permissions, creation date, expiration date, and last used timestamp
3. WHEN last_used_at is null THEN the system SHALL display "Never used"
4. WHEN expires_at is within 7 days THEN the system SHALL display a warning: "This key will expire soon"

### Requirement 6: API Key Permissions

**User Story:** As a user creating an API key, I want to select specific permissions, so that I can limit the key's access to only what's needed.

#### Acceptance Criteria

1. WHEN selecting permissions THEN the system SHALL display checkboxes for: url_check, ai_analysis, reports, profile
2. WHEN url_check is selected THEN the system SHALL show description: "Access URL analysis endpoints"
3. WHEN ai_analysis is selected THEN the system SHALL show description: "Access AI-powered content analysis"
4. WHEN reports is selected THEN the system SHALL show description: "Create and view community reports"
5. WHEN profile is selected THEN the system SHALL show description: "View and update user profile"
6. WHEN no permissions are selected THEN the system SHALL prevent form submission and display "Select at least one permission"
7. WHEN admin permission is attempted THEN the system SHALL not display it as an option (admin-only)

## Base URLs

- **Client Base**: https://www.linkshield.site
- **API Base**: https://www.linkshield.site/api/v1

## API Endpoints

| Method | Endpoint | Auth Required | Rate Limit | Description |
|--------|----------|---------------|------------|-------------|
| GET | /user/api-keys | Yes | 100/hour | List user's API keys |
| POST | /user/api-keys | Yes | 10/hour | Create new API key |
| DELETE | /user/api-keys/{key_id} | Yes | 100/hour | Delete specific API key |

## Error Handling

| Error Code | HTTP Status | User Message | Action |
|------------|-------------|--------------|--------|
| API_KEY_LIMIT_REACHED | 400 | API key limit reached for your plan | Show upgrade CTA |
| INVALID_PERMISSION | 400 | Invalid permission specified | Show valid permissions |
| API_KEY_NOT_FOUND | 404 | API key not found or already deleted | Refresh list |
| UNAUTHORIZED | 401 | Session expired. Please log in again | Redirect to login |
| FORBIDDEN | 403 | You don't have permission to perform this action | Show error message |

## Non-Functional Requirements

### Security
1. Full API keys SHALL never be stored in client-side storage (localStorage, sessionStorage, cookies)
2. Full API keys SHALL only be displayed once immediately after creation
3. API keys SHALL never be logged to console or error tracking services
4. Clipboard operations SHALL be performed securely without exposing keys in DOM

### Performance
1. API key list SHALL load within 1 second under normal conditions
2. API key creation SHALL complete within 2 seconds
3. List SHALL support pagination if user has more than 50 keys

### Accessibility
1. All forms SHALL be keyboard navigable
2. Confirmation dialogs SHALL trap focus
3. Copy button SHALL have proper ARIA labels
4. Success/error messages SHALL be announced to screen readers

### Usability
1. Key preview SHALL clearly indicate it's truncated (show "...")
2. Expiration warnings SHALL be displayed prominently
3. Permission descriptions SHALL be clear and concise
4. Deletion confirmation SHALL require explicit user action
