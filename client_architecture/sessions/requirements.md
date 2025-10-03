# Sessions Management — Requirements

Scope: Allow users to view and manage active sessions/devices. JWT required.
Base URL: https://api.linkshield.com/api/v1/user

Functional Requirements
- List active sessions: GET /api/v1/user/sessions
  - Returns array of SessionResponse: id, device_info, ip_address, user_agent, created_at, last_active, location (if available)
- Revoke a session: DELETE /api/v1/user/sessions/{session_id}
- Revoke all sessions: DELETE /api/v1/user/sessions
- Security: Confirm before revocation actions
- Feedback: Success and error toasts; update list immediately

Authentication
- JWT required for all endpoints

Rate Limits
- Reasonable defaults per backend (e.g., 30 actions/hour). Handle 429 gracefully.

Error Handling
- 401 Unauthorized → redirect to login
- 404 Session not found → show non-blocking error
- 429 Too Many Requests → cooldown UI
- 5xx → retry banner

User Stories
- As a user, I can see all devices currently logged into my account
- As a user, I can revoke a specific session if I don’t recognize it
- As a user, I can log out everywhere except my current session

Non-Functional Requirements
- Accessible lists and dialog controls
- Safe defaults (no accidental mass logouts)
- Responsive design