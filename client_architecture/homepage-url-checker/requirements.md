Feature: Homepage URL Checker

Scope
- Provide a public landing page with a prominent URL checker.
- Allow anonymous URL checks with plan-aware messaging and limits.
- Support authenticated users with additional scan types and actions.
- Surface Social Protection features for authenticated users: connect browser extension, quick algorithm health, social account scan CTA.

Base URLs
- Client base: https://www.linkshield.site
- API base: https://api.linkshield.site

User Stories
- As a visitor, I can submit a URL for a quick safety check without logging in.
- As an authenticated user, I can choose comprehensive or deep scans and see richer results.
- As a user, I can view risk scores, providers’ findings, and detailed results inline.
- As a user, I receive clear feedback for rate limits, errors, and scan progress.
- As an authenticated user, I can see my extension status and a link to analytics.
- As a user, I can run a quick algorithm health check and navigate to full analysis.
- As a user, I can connect a social account for protection or start a scan.
- As a user, I can see my subscription plan and upgrade CTA for gated features.

Functional Requirements
- URL input with validation (length 1-2048, proper URL formatting).
- Scan type selector: quick, comprehensive, deep (deep gated by subscription tier).
- Submit request to POST /api/v1/url-check/check.
- Display response: risk score, threat indicators, provider details, expandable sections.
- Actions: save to history (if backend records automatically), report URL, analyze with AI (when available).
- Anonymous allowed; show upgrade CTA for enhanced features.
- Social Protection on landing (authenticated only):
  - Extension status card: GET /api/v1/social-protection/extension/status; link to analytics GET /api/v1/social-protection/extension/analytics.
  - Quick algorithm health summary: GET /api/v1/social/algorithm-health/health; buttons to run analyses (POST /visibility/analyze, /engagement/analyze, /penalty/detect).
  - Social account scan CTA: link to Social Protection User flows (POST /api/v1/social-protection/user/analyze or platform scan).
  - Subscription plan card: GET /subscriptions, GET /subscriptions/usage; upgrade CTA via /subscriptions/plans.

Non-Functional Requirements
- Fast feedback with loading/progress states.
- Accessible controls and readable results.
- Resilient to backend rate limiting (429) and network errors.
- Mobile responsive and performant.
- Plan-aware feature gating: show limited previews to free users, enable full features for premium.

Dependencies
- URL Analysis API: POST /api/v1/url-check/check.
- Auth state for gating features.
- Social Protection APIs: /api/v1/social-protection/extension/*, /api/v1/social/algorithm-health/*, /api/v1/social-protection/user/*.
- Subscriptions APIs: /subscriptions/*.