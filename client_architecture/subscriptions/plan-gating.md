Subscription Plan Gating Matrix

Plans
- Free: baseline features only, limited quotas
- Pro: advanced features, higher quotas
- Business: full features, highest quotas, priority support

Feature matrix (examples)
- URL Check
  - Free: Quick scan only; daily limit 20
  - Pro: Quick/Comprehensive; daily limit 200
  - Business: Quick/Comprehensive/Deep; daily limit 2000
- Extension Monitoring
  - Free: Status only
  - Pro: Status + 24h analytics
  - Business: Status + 7d/30d analytics + advanced warnings
- Algorithm Health
  - Free: Health badge
  - Pro: Visibility/Engagement analyze (single)
  - Business: Batch analyze, penalty detect
- Crisis Management
  - Free: View alerts (last 7d)
  - Pro: Resolve alerts; recommendations limited
  - Business: Full recommendations + dashboard + stats
- Bot/Webhook Health
  - Free: Not available
  - Pro: Available (basic)
  - Business: Available (+ SLA details)

Implementation notes
- Client must check user plan via GET /subscriptions before enabling actions.
- Use PlanGatingWrapper to render CTA for insufficient plan.
- Endpoints should enforce gates server-side; client gates are UX only.
- Environment config should include numeric ranks for plans: free=0, pro=1, business=2.
- Quotas: display usage via GET /subscriptions/usage and block when exceeded.