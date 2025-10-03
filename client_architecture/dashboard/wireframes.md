Wireframes: User Dashboard

Layout (desktop)
- Top: Overview KPIs (Projects, Alerts, Scans, Protection Status)
- Main grid:
  - Left column:
    - ExtensionStatusCard (compact)
    - ExtensionAnalyticsPanel (time-range selector 1h/24h/7d/30d)
    - AlgorithmHealthPanel (Visibility/Engagement/Penalties mini cards)
  - Right column:
    - CrisisStatsChart (severity distribution)
    - CrisisAlertList (filterable list with Resolve and Recommendations)
    - BotWebhookHealthBadge (service health)
    - SubscriptionPlanCard (current plan, usage, Upgrade CTA)
- Lower sections:
  - Projects table (search/pagination)
  - Alerts table (status, severity filters)
  - TeamList + InviteMemberModal

Layout (mobile)
- Stacked cards: KPIs → Extension status → Analytics → Algorithm health → Crisis stats → Crisis alerts → Bot health → Subscription → Projects → Alerts → Team.

Interactions
- ExtensionAnalyticsPanel: time range changes re-query analytics; link to full extension settings.
- AlgorithmHealthPanel: quick actions to trigger analyze endpoints; show trends.
- CrisisAlertList: Resolve action (optimistic), open Recommendations drawer.
- SubscriptionPlanCard: Upgrade opens subscriptions page.
- Feature gating: show Upgrade CTA when actions are restricted.

Endpoints referenced
- Extension: GET /api/v1/social-protection/extension/status, GET /api/v1/social-protection/extension/analytics, GET/PUT /api/v1/social-protection/extension/settings.
- Algorithm Health: POST /api/v1/social/algorithm-health/visibility/analyze, /engagement/analyze, /penalty/detect, /batch/analyze; GET /health.
- Crisis: GET /api/v1/social-protection/crisis/alerts, PUT /alerts/{alert_id}, GET /alerts/{alert_id}/recommendations, GET /dashboard, GET /stats.
- Bot: GET /api/v1/bots/health.
- Subscriptions: GET /subscriptions, GET /subscriptions/plans, GET /subscriptions/usage.