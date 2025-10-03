Design: Authentication

UI
- Register page: email, password, full name, company (optional), terms, marketing consent.
- Login page: email, password, remember_me.
- Verify email page: reads token from route; success/error display.
- Resend verification action from profile or login.
- Sessions page: table of sessions with revoke and terminate-all.

Data Flow
- Axios client posts to https://api.linkshield.site endpoints.
- Store auth state in provider; refresh session on activity.
- Protect dashboard routes; redirect unauthenticated to login.

Components
- RegisterForm, LoginForm, VerifyEmailStatus.
- ProfileSummary (read-only), SessionsTable.

State
- Zustand or context for auth state (user, token flags).
- TanStack Query for profile and sessions fetching.

Security
- httpOnly cookies for JWT (backend controlled).
- Interceptors for 401/403 handling and soft-refresh logic.