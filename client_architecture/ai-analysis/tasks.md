Tasks: AI Analysis

Submit
- Create AiAnalysisForm; validate url, content length, analysis_types.
- Integrate POST /api/v1/ai-analysis/analyze.
- Implement polling for processing_status until COMPLETED/FAILED.

Results
- Implement AiAnalysisResults component; GET /analysis/{id}.
- Add sections for quality_metrics, topic_categories, sentiment_analysis, seo_metrics.

Similar
- Implement SimilarContentList; GET /analysis/{id}/similar with threshold and limit params.

Testing
- Unit tests for form validation, polling logic, and data fetching.
- Integration tests for history pagination and retry flow.
History
- Implement AiHistoryList; GET /history with pagination.

Domain Stats
- Implement AiDomainStats; GET /domain/{domain}/stats.

Retry
- Add retry button on failed analysis detail; POST /analysis/{id}/retry.

Status
- Implement AiStatusBanner; GET /status.