# Email Verification — Design

UI
- VerifyEmailPage
  - Reads `token` from query or input box
  - Calls POST /verify-email
  - Shows success (verified) or error with next steps
- ResendVerificationPanel
  - Email input
  - Calls POST /resend-verification
  - Success toast and info about rate limits
- Banner on login/register prompting verification if required

Data Flow
- Verify: POST /api/v1/user/verify-email { token }
- Resend: POST /api/v1/user/resend-verification { email }

Components
- VerifyEmailPage
- ResendVerificationPanel
- VerificationStatusBanner

State Management
- verificationState: {status: idle|pending|success|error, message}
- resendState: {pending, error}

Accessibility
- Form labels, validation messages, focus management

Error Handling
- Token invalid/expired: guidance to resend
- Already verified: informational state