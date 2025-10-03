Design: URL Analysis (Authenticated)

UI
- History page: table of checks with filters (domain, threat level, date range), pagination.
- Check detail page: summary, providers, results accordion; broken-links tab if present.
- Bulk analysis page: upload/textarea input; progress and results summary.
- Reputation page: domain input and reputation result panel.
- Stats page: charts for usage, threats detected, scan types.

Data Flow
- Axios calls against https://api.linkshield.site endpoints.
- TanStack Query handles caching and pagination.

Components
- UrlHistoryTable, CheckDetailView, BulkAnalysisForm, ReputationPanel, StatsCharts.

State
- Query state for lists; local state for forms.

Rate Limits
- Parse X-RateLimit-* headers if present; otherwise generic guidance.