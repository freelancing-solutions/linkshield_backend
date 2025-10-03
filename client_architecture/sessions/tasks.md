# Sessions Management — Tasks

1) API Client
- Implement getSessions(), revokeSession(id), revokeAllSessions() using JWT

2) UI Components
- SessionsList: fetch/render, loading and empty states
- SessionRow: details and Revoke button
- RevokeConfirmationDialog: confirm single/all revocations

3) Flows
- Single revoke: confirm → DELETE /sessions/{session_id} → update list
- Revoke all: confirm → DELETE /sessions → update list, indicate current session remains if backend preserves it

4) State & Errors
- Optimistic remove; rollback on failure
- Handle 401/404/429/5xx

5) Tests
- API client mocks
- Revoke single and all flows
- Error surfaces (404, 429)
- Accessibility checks for dialog

Deliverables
- Components: SessionsList, SessionRow, RevokeConfirmationDialog
- Route: /settings/sessions