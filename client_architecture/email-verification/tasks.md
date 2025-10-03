# Email Verification — Tasks

1) Routing
- Add /verify-email route that accepts ?token= param

2) Verify Flow
- Component: VerifyEmailPage
- Read token; call POST /api/v1/user/verify-email
- Show success or error; provide link to resend

3) Resend Flow
- Component: ResendVerificationPanel
- Input validation for email
- Call POST /api/v1/user/resend-verification
- Handle 401/403/429 errors

4) UX & Accessibility
- Status banner prompting verification on login/register
- Clear error messages; focus management

5) Tests
- Successful verify
- Invalid/expired token
- Resend success and rate-limited retry

Deliverables
- VerifyEmailPage, ResendVerificationPanel, VerificationStatusBanner
- Routes: /verify-email