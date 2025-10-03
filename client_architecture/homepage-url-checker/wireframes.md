Wireframes: Homepage URL Checker

Layout (desktop)
- Hero section (full width):
  - URL input, scan type tabs (Quick, Comprehensive, Deep), Scan button
  - RateLimitNotice inline
- Right sidecards (authenticated):
  - ExtensionStatusCard (connection, last activity, link to analytics)
  - AlgorithmHealthSummary (health badge, quick analyze buttons)
  - SubscriptionPlanCard (plan, usage bar, Upgrade CTA)
- Results area (below hero):
  - Risk score gauge
  - Threat badges
  - Provider panels (VirusTotal, GSB, URLVoid)
  - Details accordion

Layout (mobile)
- Hero → Results → sidecards stacked vertically (Extension → Algorithm Health → Subscription).

Interactions
- Scan triggers POST /api/v1/url-check/check; show loading and errors.
- ExtensionStatusCard links to extension analytics.
- AlgorithmHealthSummary triggers analyze endpoints.
- SubscriptionPlanCard Upgrade opens subscriptions.
- Plan gating renders CTA or disabled actions for free users.

Endpoints referenced
- URL check: POST /api/v1/url-check/check.
- Extension: GET /api/v1/social-protection/extension/status, GET /api/v1/social-protection/extension/analytics.
- Algorithm Health: GET /api/v1/social/algorithm-health/health; POST /visibility/analyze, /engagement/analyze, /penalty/detect.
- Subscriptions: GET /subscriptions, GET /subscriptions/usage, GET /subscriptions/plans.