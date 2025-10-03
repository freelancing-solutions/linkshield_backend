Tasks: User Dashboard

Overview
- Implement DashboardOverview component
  - Integrate GET /api/v1/dashboard/overview.
  - Render KPI cards and recent activity list.

Projects
- ProjectList with search/pagination (GET /dashboard/projects).
- Create Project form (POST /dashboard/projects).
- ProjectDetail (GET/PATCH/DELETE /dashboard/projects/{id}).
- MonitoringToggle (POST /dashboard/projects/{id}/monitoring/{enabled}).

Team
- TeamList (GET /dashboard/projects/{id}/members).
- InviteMemberModal (POST /dashboard/projects/{id}/members/invite).

Alerts
- AlertList (GET /dashboard/projects/{id}/alerts) with filters.
- AlertDetailDrawer (GET /dashboard/projects/{id}/alerts/{alert_id}).
- Resolve action (POST /dashboard/projects/{id}/alerts/{alert_id}/resolve) with optimistic UI.

Social Protection Overview
- SocialProtectionOverview component (GET /dashboard/social-protection/overview?project_id=).

Testing
- API integration tests per endpoint; optimistic update tests; pagination & filters; error states.

Extension Monitoring & Analytics
- ExtensionStatusCard (GET /api/v1/social-protection/extension/status).
- ExtensionAnalyticsPanel (GET /api/v1/social-protection/extension/analytics?time_range=24h&include_details=true).
- ExtensionSettings link (GET /api/v1/social-protection/extension/settings).

Algorithm Health
- AlgorithmHealthPanel displaying mini metrics and trends.
- Trigger analyses (POST /api/v1/social/algorithm-health/visibility/analyze, /engagement/analyze, /penalty/detect).
- Optional batch analysis flow (POST /api/v1/social/algorithm-health/batch/analyze) gated by plan.
- Health badge (GET /api/v1/social/algorithm-health/health).

Crisis Alerts
- CrisisAlertList with filters (GET /api/v1/social-protection/crisis/alerts).
- Alert resolve (PUT /api/v1/social-protection/crisis/alerts/{alert_id}).
- Recommendations drawer (GET /api/v1/social-protection/crisis/alerts/{alert_id}/recommendations).
- Stats chart (GET /api/v1/social-protection/crisis/stats?time_range=30d).

Bot/Webhook Health
- BotWebhookHealthBadge (GET /api/v1/bots/health).

Subscriptions & Payment
- SubscriptionPlanCard (GET /subscriptions, GET /subscriptions/usage).
- Upgrade CTA with deep link to Subscriptions feature (GET /subscriptions/plans).
- Surface payment events in activity via /webhooks/paddle (read-only display).

Gating & UX
- Feature flags based on subscription plan; render Upgrade CTA where actions are gated.

Additional Testing
- Plan-gating tests (free vs premium) for algorithm health batch analysis and advanced warnings.
- Extension analytics time-range tests; settings fetch and status badges.
- Crisis alert resolve optimistic update and recommendations fetch.
- Bot health badge states; subscription card data mapping and upgrade CTA.