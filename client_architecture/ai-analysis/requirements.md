Feature: AI Analysis

Scope
- Submit content for AI-powered analysis and view results; find similar content.

Base URLs
- Client base: https://www.linkshield.site
- API base: https://api.linkshield.site

Functional Requirements
- Analyze content: POST /api/v1/ai-analysis/analyze (optional auth; enhanced features with auth).
- View analysis results: GET /api/v1/ai-analysis/analysis/{analysis_id}.
- Find similar content: GET /api/v1/ai-analysis/analysis/{analysis_id}/similar.
- View analysis history: GET /api/v1/ai-analysis/history (JWT required).
- Domain analysis statistics: GET /api/v1/ai-analysis/domain/{domain}/stats.
- Retry failed analysis: POST /api/v1/ai-analysis/analysis/{analysis_id}/retry (JWT required).
- Service status: GET /api/v1/ai-analysis/status.

User Stories
- As a user, I can analyze content with AI and review insights.
- As a user, I can discover similar content to an analysis.
- As an authenticated user, I can view my AI analysis history.
- As a user, I can check analysis statistics for a domain.
- As an authenticated user, I can retry failed analyses when allowed.
- As a user, I can see whether AI services are operational.

Non-Functional Requirements
- Clear loading states and error handling.
- Plan-aware gating for AI features and rate limits.
- Respect documented rate limits and surface X-RateLimit headers.