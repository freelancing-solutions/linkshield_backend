Feature: Profile & Account Settings

Scope
- View and update profile; change password; manage preferences.

Base URLs
- Client base: https://www.linkshield.site
- API base: https://api.linkshield.site/api/v1/user

Functional Requirements
- View profile: GET /profile (JWT required).
- Update profile: PUT /profile (JWT required).
- Change password: POST /change-password (JWT required).
- Preferences: timezone, language, email_notifications, marketing_consent.
- Display usage_stats returned by profile.

User Stories
- As an authenticated user, I can view and update my profile and preferences.
- As an authenticated user, I can change my password securely.

Non-Functional Requirements
- Strong validation and secure handling of sensitive fields.
- Clear feedback messages and error handling.