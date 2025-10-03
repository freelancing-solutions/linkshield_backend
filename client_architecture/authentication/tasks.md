Tasks: Authentication

Setup
- Create (auth) route group with pages: /login, /register, /verify-email/[token].
- Implement AuthProvider and route protection.

Implementation
- RegisterForm with validation (Zod) and password strength.
- LoginForm with remember_me; handle error states.
- VerifyEmailStatus page calling POST /user/verify-email/{token}.
- Resend verification action; display feedback.
- ProfileSummary page reading GET /user/profile.
- SessionsTable with GET /user/sessions; revoke and terminate-all.

Testing
- Unit tests for forms and API calls.
- Integration tests for route guards and session actions.

Docs
- Document flows, endpoints, and expected responses.