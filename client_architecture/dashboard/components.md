Component API Docs: User Dashboard Panels

ExtensionStatusCard
- Props: {
  status: "connected" | "disconnected",
  subscriptionPlan: string,
  featuresAvailable: { real_time_analysis: boolean, advanced_warnings: boolean, batch_analysis: boolean },
  lastActivity?: string
}
- Data: GET /api/v1/social-protection/extension/status

ExtensionAnalyticsPanel
- Props: { timeRange: "1h" | "24h" | "7d" | "30d", includeDetails?: boolean }
- Fetch: GET /api/v1/social-protection/extension/analytics?time_range={timeRange}&include_details={includeDetails}
- Renders: counts, threats detected, performance metrics, platform breakdown

AlgorithmHealthPanel
- Props: { accountId?: string, platform?: string }
- Actions:
  - POST /api/v1/social/algorithm-health/visibility/analyze
  - POST /api/v1/social/algorithm-health/engagement/analyze
  - POST /api/v1/social/algorithm-health/penalty/detect
  - Optional: POST /api/v1/social/algorithm-health/batch/analyze (gated)
- Health badge: GET /api/v1/social/algorithm-health/health

CrisisAlertList
- Props: { filters: { brand?: string, severity?: string, resolved?: boolean }, pagination: { limit?: number, offset?: number } }
- Fetch: GET /api/v1/social-protection/crisis/alerts
- Item actions: PUT /api/v1/social-protection/crisis/alerts/{alert_id} (resolved)
- Recommendations: GET /api/v1/social-protection/crisis/alerts/{alert_id}/recommendations

CrisisStatsChart
- Props: { timeRange: "7d" | "30d" | "90d" }
- Fetch: GET /api/v1/social-protection/crisis/stats?time_range={timeRange}

BotWebhookHealthBadge
- Props: { healthy: boolean, details?: object }
- Fetch: GET /api/v1/bots/health

SubscriptionPlanCard
- Props: { plan: string, usage?: { used: number, limit: number }, renewalDate?: string }
- Fetch: GET /subscriptions, GET /subscriptions/usage, GET /subscriptions/plans
- Actions: Upgrade CTA → navigate to Subscriptions feature

SocialProtectionOverview
- Props: { projectId?: string }
- Fetch: GET /api/v1/dashboard/social-protection/overview?project_id={projectId}

Notes
- All endpoints require JWT unless explicitly public.
- Apply plan gating for batch analysis and advanced warnings.