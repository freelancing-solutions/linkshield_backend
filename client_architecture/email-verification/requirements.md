# Email Verification — Requirements

Scope: Verify email via token and support resending verification emails.
Base URL: https://api.linkshield.com/api/v1/user

Functional Requirements
- Verify email: POST /api/v1/user/verify-email
  - Body: { token: string }
  - Response: updated UserResponse (email_verified=true)
- Resend verification: POST /api/v1/user/resend-verification
  - Body: { email: string }
  - Sends new verification email if eligible
- Display success/failure states and guidance

Authentication
- Verify: anonymous (if token-based) per backend route; current implementation accepts token in body and returns user
- Resend: may require authentication or email ownership checks; handle 401 accordingly

Error Handling
- 400 Invalid/expired token → show actionable message
- 403 Not allowed to resend (already verified) → show info
- 429 Rate limit → cooldown UI
- 5xx → retry banner

User Stories
- As a new user, I can verify my email using the link I received
- As a user, I can request a new verification email if the original expired

Non-Functional Requirements
- Secure handling of tokens (never log)
- Accessible messaging and forms
- Internationalization-ready copy