Feature: Authentication

Scope
- Implement user registration, login, logout, email verification, resend verification, profile view, and session management.

Base URLs
- Client base: https://www.linkshield.site
- API base: https://api.linkshield.site

User Stories
- As a user, I can register and verify my email.
- As a user, I can log in and maintain sessions.
- As a user, I can view my profile and manage sessions (revoke one, terminate all).

Functional Requirements
- Registration form with required fields and password strength.
- Login with remember_me option.
- Verify email via token route.
- Resend verification request.
- Profile page (read-only from current API).
- Session list, revoke session, terminate all sessions.

Endpoints
- POST /api/v1/user/register
- POST /api/v1/user/login
- POST /api/v1/user/logout
- POST /api/v1/user/verify-email/{token}
- POST /api/v1/user/resend-verification
- GET /api/v1/user/profile
- GET /api/v1/user/sessions
- DELETE /api/v1/user/sessions/{session_id}
- DELETE /api/v1/user/sessions

Non-Functional Requirements
- JWT handling via httpOnly cookies (recommended).
- Secure error handling and CSRF mitigation if applicable.
- Accessibility and responsiveness.