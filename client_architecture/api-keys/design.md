Design: API Key Management

UI
- Keys List: table showing name, key_preview, permissions, status, last_used, expires_at.
- Create Key Modal: name, description, optional expires_at, permissions multi-select.
- Delete Key Confirmation.
- Post-Create Reveal: show full api_key once with copy button and warning.

Data Flow
- List: GET /api-keys.
- Create: POST /api-keys → display returned api_key once.
- Delete: DELETE /api-keys/{key_id} → refresh list.

Components
- ApiKeysList, CreateApiKeyModal, DeleteApiKeyDialog, ApiKeyRevealPane.

State
- Query caching for list; local modal state; ephemeral storage for reveal (no persistence).