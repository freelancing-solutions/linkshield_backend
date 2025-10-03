LinkShield Client Application Specification (Non-Admin)

Scope
- Defines the non-admin client application aligned with current backend API at https://api.linkshield.site/api/v1.
- Includes: Homepage URL Checker, Authentication & Sessions, Profile & Account Settings, API Key Management, URL Analysis (Authenticated), AI Analysis, Community Reports, Dashboard, Subscriptions.

Architecture & Navigation
- Public routes: Home (URL Checker), Register, Login, Verify Email, Resend Verification, Privacy & Terms.
- Authenticated routes: Dashboard, URL Analysis, AI Analysis, Community Reports, API Keys, Profile & Settings, Subscriptions.
- Layout: Top nav (feature tabs), side panel (contextual filters), main content area, global notifications.

Authentication
- JWT-based auth (Bearer) per docs. Store access token in memory; refresh via login when expired; API-key auth only for URL Analysis endpoints where permitted.
- Email verification flow (POST /user/verify-email/{token}, POST /user/resend-verification).
- Sessions management (GET /user/sessions, DELETE /user/sessions/{session_id}, DELETE /user/sessions).

Feature Modules & API Mapping
- Homepage URL Checker (Anonymous)
  - POST /url-check/check (anonymous allowed) — quick check, soft rate limits.
  - GET /url-check/reputation/{domain} — show reputation badge.

- Authentication & Sessions
  - POST /user/register, POST /user/login, POST /user/logout.
  - Email verification endpoints; sessions list/revoke as above.

- Profile & Account Settings
  - GET /user/profile, PUT /user/profile — update name, company, role, preferences.
  - POST /user/change-password.

- API Key Management
  - POST /user/api-keys, GET /user/api-keys, DELETE /user/api-keys/{key_id}.

- URL Analysis (Authenticated)
  - POST /url-check/check, POST /url-check/bulk-check.
  - GET /url-check/check/{check_id} (detail), GET /url-check/history (pagination & filters), GET /url-check/reputation/{domain}, GET /url-check/stats.

- AI Analysis
  - POST /ai-analysis/analyze, GET /ai-analysis/history, GET /ai-analysis/domain/{domain}/stats, POST /ai-analysis/{analysis_id}/retry, GET /ai-analysis/status.

- Community Reports
  - POST /reports/, GET /reports/ (filters, sort), GET /reports/{report_id}, POST /reports/{report_id}/vote, GET /reports/templates/, GET /reports/stats/overview.

- Dashboard (User)
  - GET /dashboard/overview.
  - Projects: GET/POST /dashboard/projects; GET/PATCH/DELETE /dashboard/projects/{project_id}.
  - Monitoring: POST /dashboard/projects/{project_id}/monitoring/{enabled}.
  - Team: GET /dashboard/projects/{project_id}/members; POST /dashboard/projects/{project_id}/members/invite.
  - Alerts: GET /dashboard/projects/{project_id}/alerts; GET /dashboard/projects/{project_id}/alerts/{alert_id}; POST /dashboard/projects/{project_id}/alerts/{alert_id}/resolve.
  - Social Protection overview: GET /dashboard/social-protection/overview?project_id=.

- Social Protection (User, Extension, Crisis, Algorithm Health, Bot Webhooks)
  - Extension: GET /api/v1/social-protection/extension/status; GET /api/v1/social-protection/extension/analytics; GET/PUT /api/v1/social-protection/extension/settings; POST /api/v1/social-protection/extension/process; POST /api/v1/social-protection/extension/analyze.
  - User: GET /api/v1/social-protection/user/dashboard; POST /api/v1/social-protection/user/analyze; GET /api/v1/social-protection/user/algorithm-health.
  - Crisis: GET /api/v1/social-protection/crisis/alerts; PUT /api/v1/social-protection/crisis/alerts/{alert_id}; GET /api/v1/social-protection/crisis/alerts/{alert_id}/recommendations; GET /api/v1/social-protection/crisis/dashboard; GET /api/v1/social-protection/crisis/stats.
  - Algorithm Health: POST /api/v1/social/algorithm-health/visibility/analyze; POST /engagement/analyze; POST /penalty/detect; POST /batch/analyze; GET /health.
  - Bot Webhooks: GET /api/v1/bots/health (read-only status display in client).

- Subscriptions
  - Typical flows (based on routes): create, retrieve, update, cancel, usage, list plans under /subscriptions.*
  - Exact endpoints per backend: POST /subscriptions (create), GET /subscriptions (list), GET /subscriptions/{id}, PATCH /subscriptions/{id}, POST /subscriptions/{id}/cancel, GET /subscriptions/{id}/usage, GET /subscriptions/plans (if available).

State Management
- Global auth store; per-feature query caches with pagination and filters.
- Optimistic updates for votes, profile edits, project updates.
- Polling for AI analysis processing states and alert updates where applicable.
 - Subscription-aware feature flags: advanced algorithm health, batch analyses, detailed extension analytics gated by plan.

Error Handling & Rate Limits
- Surface backend error codes/messages from docs; map 401→login, 403→insufficient permissions, 404→not found, 429→rate-limited with retry hint.
- Display per-feature banners (service status, subscription usage nearing limit).

Security & Privacy
- API Keys: only reveal on creation; never persist in logs; copy-to-clipboard UI.
- JWT storage in memory; CSRF protection not required for pure API client but ensure safe redirects.
- Input validation: URL format, content length limits, safe HTML rendering for report details.

Accessibility & i18n
- WCAG AA target; keyboard-friendly forms; ARIA labels for dynamic lists.
- Language preference from profile; default English; future locale strings via i18n provider.

Performance
- Debounced search/filter; list virtualization for long histories; request cancellation on route changes.
 - Prefer lazy-loading panels for Social Protection modules; cache analytics by selected time range.

Testing
- Unit tests for form validation and reducers; integration tests around API flows; e2e for critical paths (login, URL check, create report, API key create/delete).

Environment & Config
- Base API: https://api.linkshield.site/api/v1
- Use environment config for base URLs; feature flags for beta modules (analytics, social protection dashboards) as they may be partial.
 - Configure subscription plans and gating thresholds via server-provided metadata where available.

Out of Scope (Admin)
- Admin dashboards, admin routes, paddle webhooks management, algorithm health admin endpoints.
 - Direct webhook management UI; payment webhook processing handled server-side.