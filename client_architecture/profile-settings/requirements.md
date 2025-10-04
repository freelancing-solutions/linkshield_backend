# Requirements Document

## Introduction

The Profile & Account Settings feature enables authenticated users to view and manage their personal information, preferences, security settings, and account details. This feature provides a centralized location for users to customize their LinkShield experience and maintain their account security.

## Requirements

### Requirement 1: View User Profile

**User Story:** As an authenticated user, I want to view my complete profile information, so that I can see my current account details and settings.

#### Acceptance Criteria

1. WHEN a user navigates to profile settings page THEN the system SHALL call GET /api/v1/user/profile with Bearer token
2. WHEN profile data is received THEN the system SHALL display id, email, full_name, company, role, subscription_plan, is_active, is_verified, created_at
3. WHEN profile includes profile_picture_url THEN the system SHALL display user avatar
4. WHEN profile includes timezone THEN the system SHALL display user's timezone setting
5. WHEN profile includes language THEN the system SHALL display user's language preference
6. WHEN profile includes marketing_consent THEN the system SHALL display consent status
7. WHEN is_verified is false THEN the system SHALL display "Email not verified" warning with resend verification option
8. WHEN subscription_plan is included THEN the system SHALL display plan name, price, and active status
9. WHEN profile request fails with 401 THEN the system SHALL redirect to login page
10. WHEN profile request fails with 500 THEN the system SHALL display error message with retry button

### Requirement 2: Update Profile Information

**User Story:** As an authenticated user, I want to update my profile information, so that I can keep my account details current and accurate.

#### Acceptance Criteria

1. WHEN a user clicks "Edit Profile" THEN the system SHALL display editable form with current values
2. WHEN editable form is displayed THEN the system SHALL show fields: full_name, company, profile_picture_url, timezone, language, marketing_consent
3. WHEN a user modifies full_name THEN the system SHALL validate length (1-100 characters)
4. WHEN a user modifies company THEN the system SHALL validate length (max 100 characters)
5. WHEN a user modifies profile_picture_url THEN the system SHALL validate URL format and length (max 500 characters)
6. WHEN a user selects timezone THEN the system SHALL provide dropdown with standard timezone options
7. WHEN a user selects language THEN the system SHALL provide dropdown with supported languages
8. WHEN a user submits profile updates THEN the system SHALL call PUT /api/v1/user/profile with Bearer token and updated fields
9. WHEN update is successful THEN the system SHALL display success toast and update displayed profile
10. WHEN update fails with 400 THEN the system SHALL display field-specific validation errors
11. WHEN update fails with 401 THEN the system SHALL redirect to login page
12. WHEN update is in progress THEN the system SHALL disable form and show loading state

### Requirement 3: Upload Profile Picture

**User Story:** As an authenticated user, I want to upload a profile picture, so that I can personalize my account.

#### Acceptance Criteria

1. WHEN a user clicks on avatar THEN the system SHALL display upload options: Upload Image, Enter URL, Remove Picture
2. WHEN a user selects "Upload Image" THEN the system SHALL open file picker for image files (jpg, png, gif)
3. WHEN a user selects image file THEN the system SHALL validate file size (max 5MB) and dimensions (max 2000x2000px)
4. WHEN image is valid THEN the system SHALL upload to storage and get URL
5. WHEN upload is successful THEN the system SHALL update profile_picture_url via PUT /api/v1/user/profile
6. WHEN a user selects "Enter URL" THEN the system SHALL display URL input field
7. WHEN a user enters URL THEN the system SHALL validate URL format and accessibility
8. WHEN a user selects "Remove Picture" THEN the system SHALL set profile_picture_url to null
9. WHEN upload fails THEN the system SHALL display error message with retry option

### Requirement 4: Manage Preferences

**User Story:** As an authenticated user, I want to manage my preferences, so that I can customize my LinkShield experience.

#### Acceptance Criteria

1. WHEN preferences section is displayed THEN the system SHALL show timezone, language, and marketing_consent settings
2. WHEN a user changes timezone THEN the system SHALL update all displayed times to new timezone
3. WHEN a user changes language THEN the system SHALL update UI language (if supported)
4. WHEN a user toggles marketing_consent THEN the system SHALL update consent status
5. WHEN preferences are changed THEN the system SHALL enable "Save Changes" button
6. WHEN a user clicks "Save Changes" THEN the system SHALL call PUT /api/v1/user/profile with updated preferences
7. WHEN save is successful THEN the system SHALL display "Preferences saved" toast
8. WHEN user navigates away with unsaved changes THEN the system SHALL display confirmation dialog

### Requirement 5: Change Password

**User Story:** As an authenticated user, I want to change my password, so that I can maintain account security.

#### Acceptance Criteria

1. WHEN a user clicks "Change Password" THEN the system SHALL display password change modal
2. WHEN modal is displayed THEN the system SHALL show fields: current_password, new_password, confirm_password
3. WHEN a user enters new_password THEN the system SHALL display password strength indicator
4. WHEN a user enters new_password THEN the system SHALL validate: min 8 chars, max 128 chars, contains uppercase, lowercase, digit, special character
5. WHEN a user enters confirm_password THEN the system SHALL validate it matches new_password
6. WHEN a user submits password change THEN the system SHALL call POST /api/v1/user/change-password with current_password and new_password
7. WHEN password change is successful THEN the system SHALL display success message and inform user that all sessions will be invalidated
8. WHEN password change is successful THEN the system SHALL redirect to login page after 3 seconds
9. WHEN current_password is incorrect THEN the system SHALL display "Current password is incorrect"
10. WHEN new_password is too weak THEN the system SHALL display password requirements
11. WHEN new_password matches current_password THEN the system SHALL display "New password must be different from current password"
12. WHEN password change is rate-limited THEN the system SHALL display "Too many attempts. Please try again later"

### Requirement 6: View Account Information

**User Story:** As an authenticated user, I want to view my account information, so that I can see my account status and history.

#### Acceptance Criteria

1. WHEN account information section is displayed THEN the system SHALL show email, role, account status, created date
2. WHEN email is displayed THEN the system SHALL show verification status badge
3. WHEN account is active THEN the system SHALL display "Active" badge
4. WHEN account is inactive THEN the system SHALL display "Inactive" badge with reason
5. WHEN created date is displayed THEN the system SHALL format as "Member since [date]"
6. WHEN role is displayed THEN the system SHALL show role badge (User/Admin)

### Requirement 7: View Subscription Information

**User Story:** As an authenticated user, I want to view my subscription information in profile settings, so that I can see my current plan and usage.

#### Acceptance Criteria

1. WHEN subscription section is displayed THEN the system SHALL show current plan name, price, and status
2. WHEN subscription is active THEN the system SHALL display renewal date
3. WHEN subscription is canceled THEN the system SHALL display end date
4. WHEN subscription is in trial THEN the system SHALL display trial end date
5. WHEN a user clicks "Manage Subscription" THEN the system SHALL navigate to subscriptions page
6. WHEN a user clicks "Upgrade Plan" THEN the system SHALL navigate to plans page

### Requirement 8: Manage Notification Preferences

**User Story:** As an authenticated user, I want to manage my notification preferences, so that I can control what emails I receive.

#### Acceptance Criteria

1. WHEN notification preferences section is displayed THEN the system SHALL show toggles for different notification types
2. WHEN notification types are displayed THEN the system SHALL show: Security Alerts, URL Check Results, Team Invitations, Product Updates, Marketing Emails
3. WHEN a user toggles notification preference THEN the system SHALL update preference via PUT /api/v1/user/profile
4. WHEN update is successful THEN the system SHALL display "Preferences updated" toast
5. WHEN Security Alerts toggle is disabled THEN the system SHALL display warning "We recommend keeping security alerts enabled"

### Requirement 9: Delete Account

**User Story:** As an authenticated user, I want to delete my account, so that I can remove my data from LinkShield.

#### Acceptance Criteria

1. WHEN a user clicks "Delete Account" THEN the system SHALL display confirmation dialog
2. WHEN confirmation dialog is displayed THEN the system SHALL show warning about data deletion and require typing "DELETE" to confirm
3. WHEN a user confirms deletion THEN the system SHALL call DELETE /api/v1/user/account
4. WHEN deletion is successful THEN the system SHALL display "Account deleted" message and redirect to homepage
5. WHEN deletion fails THEN the system SHALL display error message
6. WHEN user has active subscription THEN the system SHALL require canceling subscription first

### Requirement 10: Export Account Data

**User Story:** As an authenticated user, I want to export my account data, so that I can have a copy of my information.

#### Acceptance Criteria

1. WHEN a user clicks "Export Data" THEN the system SHALL display export options modal
2. WHEN modal is displayed THEN the system SHALL show data types: Profile, URL Checks, AI Analyses, Reports
3. WHEN a user selects data types THEN the system SHALL show format options: JSON, CSV
4. WHEN a user confirms export THEN the system SHALL call POST /api/v1/user/export-data
5. WHEN export is ready THEN the system SHALL trigger download with filename: linkshield-data-{date}.{format}
6. WHEN export is processing THEN the system SHALL display progress indicator
7. WHEN export fails THEN the system SHALL display error message with retry option

## Base URLs

- **Client Base**: https://www.linkshield.site
- **API Base**: https://www.linkshield.site/api/v1

## API Endpoints

| Method | Endpoint | Auth Required | Rate Limit | Description |
|--------|----------|---------------|------------|-------------|
| GET | /user/profile | Yes | 100/hour | Get user profile |
| PUT | /user/profile | Yes | 100/hour | Update user profile |
| POST | /user/change-password | Yes | 5/hour | Change user password |
| DELETE | /user/account | Yes | 1/day | Delete user account |
| POST | /user/export-data | Yes | 3/day | Export user data |

## Profile Fields

| Field | Type | Editable | Validation | Description |
|-------|------|----------|------------|-------------|
| id | UUID | No | - | User ID |
| email | String | No | - | User email (change via separate flow) |
| full_name | String | Yes | 1-100 chars | User's full name |
| company | String | Yes | Max 100 chars | Company name |
| role | String | No | - | User role (USER/ADMIN) |
| profile_picture_url | String | Yes | Valid URL, max 500 chars | Avatar URL |
| timezone | String | Yes | Valid timezone | User timezone |
| language | String | Yes | Supported language code | UI language |
| marketing_consent | Boolean | Yes | - | Marketing email consent |
| is_active | Boolean | No | - | Account active status |
| is_verified | Boolean | No | - | Email verified status |
| subscription_plan | Object | No | - | Current subscription |
| created_at | DateTime | No | - | Account creation date |
| updated_at | DateTime | No | - | Last update date |

## Error Handling

| Error Code | HTTP Status | User Message | Action |
|------------|-------------|--------------|--------|
| INVALID_FIELD | 400 | Invalid value for {field} | Show field error |
| PASSWORD_INCORRECT | 400 | Current password is incorrect | Allow retry |
| PASSWORD_TOO_WEAK | 400 | Password does not meet requirements | Show requirements |
| PASSWORD_SAME | 400 | New password must be different | Show error |
| FILE_TOO_LARGE | 400 | Image file is too large (max 5MB) | Show error |
| INVALID_URL | 400 | Invalid profile picture URL | Show error |
| UNAUTHORIZED | 401 | Session expired | Redirect to login |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests | Show retry-after time |
| SERVER_ERROR | 500 | Unable to update profile | Show retry option |

## Non-Functional Requirements

### Security
1. Password fields SHALL use type="password" and autocomplete attributes
2. Current password SHALL be required for password changes
3. Profile picture URLs SHALL be validated and sanitized
4. Sensitive data SHALL never be logged
5. All requests SHALL use HTTPS and Bearer token authentication

### Performance
1. Profile page SHALL load within 1 second
2. Profile updates SHALL complete within 2 seconds
3. Image uploads SHALL show progress indicator
4. Form changes SHALL be debounced (300ms)

### Accessibility
1. All forms SHALL be keyboard navigable
2. Form fields SHALL have proper labels and ARIA attributes
3. Error messages SHALL be announced to screen readers
4. Password strength indicator SHALL have text alternative
5. Color SHALL not be sole indicator of validation state

### Usability
1. Form fields SHALL show current values
2. Validation errors SHALL be specific and actionable
3. Success messages SHALL auto-dismiss after 5 seconds
4. Unsaved changes SHALL trigger confirmation dialog
5. Password requirements SHALL be clearly displayed