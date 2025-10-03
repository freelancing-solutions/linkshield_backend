Design: AI Analysis

UI
- Analyze form: URL + content textarea, optional analysis_types, optional callback_url.
- Results view: sections for categorization, sentiment, quality scoring, SEO, reading level.
- Similar content panel: list with similarity score, type, matching elements; threshold slider.
- History page: paginated list of analyses with status chips (PENDING/PROCESSING/COMPLETED/FAILED).
- Domain stats page: summary stats and charts for a domain.
- Service status banner: current status and model health indicators.
- Retry action: button on failed analysis detail (visible when allowed).

Data Flow
- Submit: POST /analyze → receive analysis id and initial data; poll or subscribe until COMPLETED.
- Results: GET /analysis/{id}.
- Similar: GET /analysis/{id}/similar with query params (similarity_threshold, limit).
- History: GET /history with pagination params.
- Domain stats: GET /domain/{domain}/stats.
- Retry: POST /analysis/{id}/retry.
- Status: GET /status.

Components
- AiAnalysisForm, AiAnalysisResults, SimilarContentList, AiHistoryList, AiDomainStats, AiStatusBanner.

State
- Query-based data fetching and caching; local state for form inputs; polling for processing states.