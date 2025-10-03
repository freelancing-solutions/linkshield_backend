Component API Docs: Homepage Panels

URLScanHero
- Props: { defaultScanType?: "quick" | "comprehensive" | "deep" }
- Action: POST /api/v1/url-check/check { url, scan_type }
- Displays: risk score, badges, provider panels, errors

ExtensionStatusCard (authenticated)
- Props: { status: "connected" | "disconnected", lastActivity?: string }
- Fetch: GET /api/v1/social-protection/extension/status
- Link: analytics page

AlgorithmHealthSummary (authenticated)
- Props: { accountId?: string, platform?: string }
- Actions:
  - GET /api/v1/social/algorithm-health/health
  - POST /api/v1/social/algorithm-health/visibility/analyze
  - POST /api/v1/social/algorithm-health/engagement/analyze
  - POST /api/v1/social/algorithm-health/penalty/detect

SubscriptionPlanCard (authenticated)
- Props: { plan: string, usage?: { used: number, limit: number } }
- Fetch: GET /subscriptions, GET /subscriptions/usage, GET /subscriptions/plans
- Actions: Upgrade CTA

PlanGatingWrapper
- Props: { requiredPlan: string }
- Behavior: if user plan < requiredPlan, render CTA; else render children.