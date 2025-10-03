Feature: API Key Management

Scope
- Create, list, and delete API keys for programmatic access.

Base URLs
- Client base: https://www.linkshield.site
- API base: https://api.linkshield.site/api/v1/user

Functional Requirements
- Create API key: POST /api-keys (JWT required).
- List API keys: GET /api-keys (JWT required).
- Delete API key: DELETE /api-keys/{key_id} (JWT required).
- Permissions: url_check, ai_analysis, reports, profile (admin excluded).
- Show full API key only once on creation; afterwards show key_preview.

User Stories
- As an authenticated user, I can create an API key with scoped permissions.
- As an authenticated user, I can list and manage my API keys.
- As an authenticated user, I can delete a key that I no longer need.

Non-Functional Requirements
- Secure handling: never log or persist full key in client storage.
- Confirmation dialog for deletions.