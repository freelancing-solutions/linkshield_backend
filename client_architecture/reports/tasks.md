Tasks: Community Reports

Form
- Implement ReportForm with validation (url, type, description, severity range, tags).
- Integrate POST /api/v1/reports/.

List
- Implement ReportsList with GET /api/v1/reports/ and pagination + filters.

Detail
- Implement ReportDetail with GET /api/v1/reports/{report_id}.
- Implement vote action: POST /api/v1/reports/{report_id}/vote (optimistic update).

Testing
- Unit and integration tests for form, list, vote action, and stats.
Templates
- Implement ReportTemplatesPicker: GET /api/v1/reports/templates/.

Stats
- Implement ReportStatsOverview: GET /api/v1/reports/stats/overview.