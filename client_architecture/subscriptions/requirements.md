# Subscriptions — Requirements

Scope: Manage user subscriptions (view, create, update, cancel) and usage limits.
Base URL: https://api.linkshield.com/subscriptions

Functional Requirements
- View current subscription: GET /subscriptions/me (JWT)
- Create subscription: POST /subscriptions/
  - Body: { plan_name: string, billing_interval: 'MONTHLY'|'YEARLY'|'LIFETIME', trial_days?: number }
- Update subscription (upgrade/downgrade): PUT /subscriptions/me
  - Body: { new_plan_name: string, billing_interval?: 'MONTHLY'|'YEARLY'|'LIFETIME' }
- Cancel subscription: DELETE /subscriptions/me
  - Body optional: { cancel_at_period_end?: boolean, reason?: string }
- View usage: GET /subscriptions/me/usage (JWT)
  - Daily/monthly limits, current usage counters (e.g., url_check, ai_analysis)
- List available plans: GET /subscriptions/plans (no auth required)
  - Names, descriptions, pricing, feature matrix

Authentication
- All /me endpoints require JWT
- /plans is public per backend route

Rate Limits & Errors
- 402 Payment Required: feature not available at current plan
- 409 Conflict: already has active subscription (on create)
- 404 Not found: no subscription
- 429 Too Many Requests: surface cooldown
- 5xx: retry banner

User Stories
- As a user, I can subscribe to a plan
- As a user, I can see my plan details and usage
- As a user, I can upgrade or downgrade my plan
- As a user, I can cancel my subscription
- As a visitor, I can view available plans

Non-Functional Requirements
- Secure handling of billing actions
- Clear disclosures about plan changes taking effect next cycle
- Accessible dialogs and forms