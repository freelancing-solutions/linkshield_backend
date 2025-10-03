# Subscriptions — Tasks

1) API Client
- getSubscriptionMe(), getSubscriptionUsage(), getPlans()
- createSubscription({ plan_name, billing_interval, trial_days? })
- updateSubscription({ new_plan_name, billing_interval? })
- cancelSubscription({ cancel_at_period_end?, reason? })

2) UI Components
- SubscriptionOverview: current plan + usage
- PlansList: browse and select plans
- ChangePlanModal: upgrade/downgrade flow
- CancelSubscriptionDialog: confirm cancellation

3) Flows
- If no subscription: prompt to choose plan (POST /subscriptions/)
- If subscribed: show plan details and usage; allow PUT/DELETE actions
- Refresh state after each action

4) Errors & Edge Cases
- 409 on create: show info that subscription exists
- 404 on me/usage: handle gracefully
- 402/429: display gating or cooldown messages

5) Tests
- Fetch and render subscription
- Create, update, cancel flows
- Plans listing
- Error handling (402/404/409)

Deliverables
- Components: SubscriptionOverview, PlansList, ChangePlanModal, CancelSubscriptionDialog
- Route: /settings/subscription