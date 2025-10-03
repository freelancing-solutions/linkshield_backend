Tasks: Homepage URL Checker

Setup
- Create HeroURLChecker and ScanResults components.
- Add route in (marketing) group for homepage.

Implementation
- Validate URL input (Zod + RHF).
- Implement scan type tabs and gating by auth/plan.
- Integrate POST /api/v1/url-check/check with Axios client.
- Render results: risk score, indicators, provider sections.
- Handle errors and 429 with RateLimitNotice.
- Add CTAUpgrade for anonymous users/deep scans.
- Authenticated-only sidecards:
  - ExtensionStatusCard (GET /api/v1/social-protection/extension/status; link to analytics).
  - AlgorithmHealthSummary (GET /api/v1/social/algorithm-health/health; buttons call POST analyses).
  - SubscriptionPlanCard (GET /subscriptions, GET /subscriptions/usage; Upgrade CTA opens subscriptions page).

Testing
- Unit tests for input validation and API integration.
- UI tests for results display and error handling.
- Sidecards tests: extension status badge states; algorithm health badge and action calls; subscription plan/usage mapping and upgrade CTA.

Docs
- Usage notes on supported scan types and rate-limit behavior.
- Notes on social protection integration and plan-gated features surfaced on the homepage.