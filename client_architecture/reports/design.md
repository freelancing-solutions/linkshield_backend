Design: Community Reports

UI
- Report form with URL field, type, title, description, optional evidence URLs, severity, tags.
- Reports list with filters (type, status, priority, domain, tag, date range), sort and pagination.
- Report detail view: full report info, vote actions (up/down), comments (if supported), moderation status.
- Templates: dropdown or modal to pick a template.
- Stats overview: cards and charts for totals, pending/resolved, top domains.

Data Flow
- Create: POST / (JWT) → show success and link to detail.
- List: GET / with query params and pagination.
- Detail: GET /{report_id}.
- Vote: POST /{report_id}/vote (JWT) with vote_type and optional comment.
- Templates: GET /templates/.
- Stats: GET /stats/overview.

Components
- ReportForm, ReportsList, ReportDetail, ReportTemplatesPicker, ReportStatsOverview.

State
- Query-based lists/details; local form state; optimistic update for votes.