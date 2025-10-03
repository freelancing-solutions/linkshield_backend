# Profile & Account Settings — Tasks

Scope: Implement user profile viewing/updating and password change, plus preferences UI. Base URL: https://api.linkshield.com/api/v1/user

1) Profile Overview
- Build ProfileOverview component to display fields from GET /api/v1/user/profile
  - full_name, email, company, avatar_url, timezone, language, marketing_consent
- Add UsageStatsCards if available in response (optional)
- Error/empty states: handle 401 (redirect to login), 5xx (retry banner)

2) Edit Profile
- Implement PreferencesForm for editable fields
  - full_name (1–100 chars), company (<=100), profile_picture_url (<=500), timezone, language (<=10), marketing_consent (bool)
- Integrate PUT /api/v1/user/profile
  - Client-side validation
  - Optimistic UI update with rollback on error
  - Show success toast
- Handle validation errors (400) and auth (401)

3) Change Password
- Implement ChangePasswordModal
  - Fields: current_password, new_password (8–128 chars, strength meter)
- Call POST /api/v1/user/change-password
  - On success: close modal, show toast
  - On error: inline error messages (incorrect current password, too weak, rate limit)
- Keyboard accessibility and focus management

4) Preferences UX
- Add timezone and language pickers (pre-populated list)
- Add marketing_consent toggle
- Confirm navigation if unsaved changes
- Show last updated timestamp

5) Networking & State
- Profile slice/state: {profile, loading, error}
- Re-fetch profile after successful PUT/change-password (if server returns updated data)
- Retry logic with exponential backoff on intermittent failures

6) Security & Privacy
- Never log password values
- Sanitize avatar URL and strip scripts
- Use secure form handling; disable submit while pending

7) Tests
- Unit: form validation, reducers, API clients
- Integration: fetch + render profile, successful update, failed update rollback
- Modal: change-password success and error flows
- Accessibility: tab order, focus trap in modal

8) Observability
- Instrument profile fetch/update timings
- Log non-PII error events for diagnostics

Deliverables
- Components: ProfileOverview, PreferencesForm, ChangePasswordModal, UsageStatsCards
- API: userProfileClient (getProfile, updateProfile, changePassword)
- Routes: /settings/profile