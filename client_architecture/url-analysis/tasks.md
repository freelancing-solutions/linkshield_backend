Tasks: URL Analysis (Authenticated)

History
- Implement UrlHistoryTable with filters and pagination.
- Integrate GET /api/v1/url-check/history.

Check Detail
- Build CheckDetailView with providers and accordion.
- Integrate GET /api/v1/url-check/{check_id}, /{check_id}/results, /{check_id}/broken-links.

Bulk Analysis
- Build BulkAnalysisForm; validate inputs.
- Integrate POST /api/v1/url-check/bulk-check.
- Render progress and summary.

Reputation
- Build ReputationPanel; integrate GET /api/v1/url-check/reputation/{domain}.

Stats
- Build StatsCharts; integrate GET /api/v1/url-check/stats.

Testing
- Tests for filtering, pagination, and endpoints.