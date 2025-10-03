Feature: Community Reports

Scope
- Allow users to submit reports on URLs/domains and view community reports.

Base URLs
- Client base: https://www.linkshield.site
- API base: https://api.linkshield.site

Functional Requirements
- Submit report: POST /api/v1/reports/ (JWT required).
- List reports: GET /api/v1/reports/ with filters and pagination (optional auth with enhanced features).
- View report details: GET /api/v1/reports/{report_id}.
- Vote on report helpfulness/accuracy: POST /api/v1/reports/{report_id}/vote (JWT required).
- View report templates: GET /api/v1/reports/templates/.
- View report statistics overview: GET /api/v1/reports/stats/overview (optional auth).

User Stories
- As an authenticated user, I can report suspicious content.
- As a user, I can browse and filter community reports.
- As an authenticated user, I can vote on reports to indicate helpfulness/accuracy.
- As a user, I can use templates to create better reports.
- As a user, I can view report statistics and trends.

Non-Functional Requirements
- Clear moderation status and feedback messages.
- Pagination and filters for lists.