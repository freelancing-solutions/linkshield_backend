# Sessions Management — Design

UI
- SessionsList page under Settings
  - Table/List: Device name, location, IP, user agent, created_at, last_active
  - Actions: Revoke (per row), Revoke All (toolbar)
  - Current session indicator (badge)
- RevokeConfirmationDialog
- Empty state: “No active sessions”

Data Flow
- GET /api/v1/user/sessions on mount
- DELETE /api/v1/user/sessions/{session_id}
- DELETE /api/v1/user/sessions
- Update local state after successful revocation

Components
- SessionsList
- SessionRow
- RevokeConfirmationDialog

State Management
- sessionsState: {items, loading, error}
- pendingAction: {type, sessionId}
- Optimistic remove on success, rollback on error

Accessibility
- Dialog focus trap, keyboard shortcuts
- Semantic table markup

Error & Rate Limit Handling
- 429: disable actions with helper text
- 5xx: retry button