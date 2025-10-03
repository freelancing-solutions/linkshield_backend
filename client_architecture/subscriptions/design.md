# Subscriptions — Design

UI
- SubscriptionOverview
  - Current plan card: name, status, billing interval, next_billing_date
  - Usage card: daily/monthly limits and current usage
  - Actions: Change Plan, Cancel Subscription
- PlansList
  - Grid of available plans with features and pricing
  - Select plan → opens Create/Update modal
- ChangePlanModal
- CancelSubscriptionDialog

Data Flow
- GET /subscriptions/me on mount (if authenticated)
- GET /subscriptions/me/usage for usage details
- GET /subscriptions/plans for plan list
- POST /subscriptions/ to create new subscription
- PUT /subscriptions/me to change plan
- DELETE /subscriptions/me to cancel

Components
- SubscriptionOverview
- PlansList
- ChangePlanModal
- CancelSubscriptionDialog

State Management
- subscriptionState: {data, usage, plans, loading, error}
- pendingAction: {type, plan}
- Optimistic UI only for non-billing display changes; rely on server confirmation

Error Handling
- 402 gating: show upgrade prompts on gated features
- Show detailed errors for invalid plan changes

Accessibility
- Dialog focus trap and keyboard controls
- Clear copy for trial, proration (if applicable)