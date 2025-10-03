Feature: User Dashboard

Scope
- Overview, projects, monitoring, team, alerts, social protection overview.
- Social Media Protection modules: extension analytics & status, algorithm health, crisis alerts, bot webhook health.
- Payment and subscription plan integration: show plan, usage, upgrade/change plan.

Base URL
- API: https://api.linkshield.site/api/v1/dashboard

Additional route prefixes leveraged by the Dashboard
- Extension (general): /api/v1/extension
- Social Protection Extension: /api/v1/social-protection/extension
- Social Protection User: /api/v1/social-protection/user
- Social Protection Crisis: /api/v1/social-protection/crisis
- Algorithm Health: /api/v1/social/algorithm-health
- Bot Webhooks: /api/v1/bots
- Subscriptions: /subscriptions (and payment webhooks at /webhooks/paddle)

Functional Requirements
- Overview: GET /overview — stats & recent activity.
- Projects: list/create/get/update/delete.
- Monitoring toggle: POST /projects/{project_id}/monitoring/{enabled}.
- Team: list members, invite.
- Alerts: list, detail, resolve.
- Social Protection overview: GET /social-protection/overview (optional project_id).
- Extension analytics and status panel
  - Show connection status, features by plan, last activity
  - Time-range analytics (1h, 24h, 7d, 30d) with platform breakdown
  - Endpoints: GET /api/v1/social-protection/extension/status; GET /api/v1/social-protection/extension/analytics; GET /api/v1/social-protection/extension/settings
- Algorithm Health panel
  - Visibility/Engagement/Penalty summaries and trends
  - Deep links to full analysis views
  - Endpoints: POST /api/v1/social/algorithm-health/visibility/analyze; POST /engagement/analyze; POST /penalty/detect; POST /batch/analyze; GET /health
- Crisis Alerts
  - List alerts, mark resolved, recommendations, stats
  - Endpoints: GET /api/v1/social-protection/crisis/alerts; PUT /alerts/{alert_id}; GET /alerts/{alert_id}/recommendations; GET /dashboard; GET /stats
- Bot/Webhook Health: GET /api/v1/bots/health
- Social Protection (User) summary: GET /api/v1/social-protection/user/dashboard
- Payment and Subscription integration
  - Show current plan, usage, renewal/cancel state
  - CTA to upgrade/downgrade, deep link to Subscriptions page
  - Endpoints: GET /subscriptions/plans; GET /subscriptions; GET /subscriptions/usage; payment webhooks at /webhooks/paddle

User Stories
- As a user, I see my dashboard overview with key stats.
- As a user, I manage projects and monitoring settings.
- As a user, I invite teammates.
- As a user, I review and resolve alerts.
- As a user, I monitor my browser extension’s activity and status.
- As a user, I check my social accounts’ algorithm health and get recommendations.
- As a user, I manage brand crises and resolutions.
- As a user, I verify bot/webhook services are healthy.
- As a user, I see my subscription plan/usage and upgrade when needed.

Non-Functional
- JWT required; pagination for lists; error handling; loading states.
- Feature gating by subscription plan:
  - Free/basic: limited analytics windows, no batch analysis, standard warnings
  - Premium: advanced warnings, batch analysis, detailed analytics, extended time ranges
- Avoid deprecated routes under /api/v1/social-protection (use specialized routes).