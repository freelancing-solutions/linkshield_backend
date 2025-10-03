Tasks: API Key Management

List
- Implement ApiKeysList: GET /api-keys; render table with actions.

Create
- Implement CreateApiKeyModal: POST /api-keys; form validation; handle api_key reveal once.

Delete
- Implement DeleteApiKeyDialog: DELETE /api-keys/{key_id}; confirm & refresh.

Permissions
- Ensure permissions selection matches documented options; validate expiration limits.

Testing
- Unit tests for form validation and reveal logic; integration tests for CRUD flows.