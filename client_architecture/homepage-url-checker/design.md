Design: Homepage URL Checker

UI
- Hero section with large URL input and scan button.
- Scan type tabs: Quick (default), Comprehensive, Deep (Pro+).
- Result area shows: risk score gauge, badges for threats, provider panels (VirusTotal, GSB, URLVoid), and an accordion for details.
- Inline notifications for errors (network, 429), and plan requirements.
- Authenticated-only sidecards:
  - ExtensionStatusCard: shows connection, last activity; link to analytics.
  - AlgorithmHealthSummary: simple health badge + actions to run quick checks.
  - SubscriptionPlanCard: shows current plan and usage with Upgrade CTA.

Data Flow
- Input -> validate -> POST https://api.linkshield.site/api/v1/url-check/check.
- On success -> render results; on 429 -> show rate limit info (if X-RateLimit-* headers present) or generic guidance.
- If user authenticated -> enable comprehensive/deep; otherwise show sign-up prompts.
- ExtensionStatusCard -> GET /api/v1/social-protection/extension/status; Analytics link -> GET /api/v1/social-protection/extension/analytics?time_range.
- AlgorithmHealthSummary -> GET /api/v1/social/algorithm-health/health; buttons call POST analyses.
- SubscriptionPlanCard -> GET /subscriptions, GET /subscriptions/usage; Upgrade opens subscriptions feature.

Components
- HeroURLChecker: URL input, scan types, submit.
- ScanResults: visualization and provider details.
- RateLimitNotice: parses headers and shows remaining/reset.
- CTAUpgrade: contextual prompts for signup/upgrade.
- ExtensionStatusCard, AlgorithmHealthSummary, SubscriptionPlanCard.

State
- Local state for form and loading.
- Server state via TanStack Query for result caching.
- Auth state via provider to gate features.
- Plan gating: render placeholders with Upgrade CTA for gated features.

Accessibility
- Proper labels, keyboard navigation, color contrast.