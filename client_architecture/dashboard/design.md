Design: User Dashboard

UI
- Overview page: KPI cards (projects, alerts, scans), recent activity list.
- Projects list: table with search, pagination; project detail view with settings.
- Monitoring toggle: switch in project detail.
- Team members: list with invite modal.
- Alerts: list with filters (status, severity), alert detail drawer; resolve action.
- Social Protection overview: metrics panel; optional project filter.
- Extension panel: connection/status card, analytics chart with time-range selector (1h/24h/7d/30d), platform breakdown.
- Algorithm Health panel: mini cards for Visibility, Engagement, Penalties with trend arrows and link to full analysis.
- Crisis Alerts: severity distribution chart and list; quick actions to mark resolved and view recommendations.
- Bot/Webhook Health: service health badge; link to detailed logs if available.
- Subscription Plan card: current plan, usage bar, renewal/cancel state, Upgrade button.

Data Flow
- GET /overview → render KPIs & activity.
- Projects: GET/POST /projects; GET/PATCH/DELETE /projects/{id}; POST /projects/{id}/monitoring/{enabled}.
- Team: GET /projects/{id}/members; POST /projects/{id}/members/invite.
- Alerts: GET /projects/{id}/alerts; GET /projects/{id}/alerts/{alert_id}; POST /projects/{id}/alerts/{alert_id}/resolve.
- Social Protection: GET /social-protection/overview?project_id=.
 - Extension: GET /api/v1/social-protection/extension/status; GET /api/v1/social-protection/extension/analytics?time_range=24h&include_details=true; GET /api/v1/social-protection/extension/settings.
 - Algorithm Health: POST /api/v1/social/algorithm-health/visibility/analyze; POST /engagement/analyze; POST /penalty/detect; POST /batch/analyze; GET /health.
 - Crisis: GET /api/v1/social-protection/crisis/alerts; PUT /alerts/{alert_id}; GET /alerts/{alert_id}/recommendations; GET /dashboard; GET /stats?time_range=30d.
 - Bot/Webhooks: GET /api/v1/bots/health.
 - Subscriptions: GET /subscriptions/plans; GET /subscriptions; GET /subscriptions/usage; integrate webhook-derived activity via /webhooks/paddle.

Components
- DashboardOverview, ProjectList, ProjectDetail, MonitoringToggle, TeamList, InviteMemberModal, AlertList, AlertDetailDrawer, SocialProtectionOverview,
  ExtensionAnalyticsPanel, ExtensionStatusCard, AlgorithmHealthPanel, CrisisAlertList, CrisisStatsChart, BotWebhookHealthBadge, SubscriptionPlanCard.

State
- Query caches per section; optimistic update for monitoring toggle and alert resolve; error banners; skeleton loaders.
- Feature gating by subscription plan for advanced features (batch analysis, advanced warnings, detailed analytics). Render Upgrade CTA when gated.