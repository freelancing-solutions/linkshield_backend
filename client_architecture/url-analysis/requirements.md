Feature: URL Analysis (Authenticated)

Scope
- Provide authenticated users with history, detailed check results, bulk analysis, and stats.

Base URLs
- Client base: https://www.linkshield.site
- API base: https://api.linkshield.site

Functional Requirements
- History view: GET /api/v1/url-check/history with filters/pagination.
- Check detail view: GET /api/v1/url-check/check/{check_id}, results, and broken-links (if available).
- Bulk analysis: POST /api/v1/url-check/bulk-check (JWT required).
- Domain reputation lookup: GET /api/v1/url-check/reputation/{domain} (optional auth).
- User stats: GET /api/v1/url-check/stats.

User Stories
- As a user, I can view my past checks and drill into details.
- As a user, I can run bulk checks and receive status/summary.
- As a user, I can look up domain reputation and see indicators.
- As a user, I can view my usage stats and trends.

Non-Functional Requirements
- Efficient pagination and caching.
- Clear rate-limit messaging; handle 429.
- Accessible tables and visualizations.