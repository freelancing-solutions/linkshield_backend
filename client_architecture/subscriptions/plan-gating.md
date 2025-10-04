Subscription Plan Gating Matrix

Plans (Six-Tier System)
- Free: baseline features only, limited quotas
- Starter: basic features, moderate quotas
- Creator: enhanced features for content creators
- Professional: advanced features, high quotas
- Business: full features, highest quotas, priority support
- Enterprise: custom features, unlimited quotas, dedicated support

Feature matrix (updated for six tiers)
- URL Check
  - Free: Quick scan only; daily limit 20
  - Starter: Quick scan; daily limit 100
  - Creator: Quick/Comprehensive; daily limit 500
  - Professional: Quick/Comprehensive/Deep; daily limit 1000
  - Business: Quick/Comprehensive/Deep; daily limit 2000
  - Enterprise: All scan types; unlimited
- Extension Monitoring
  - Free: Status only
  - Starter: Status + 24h analytics
  - Creator: Status + 7d analytics
  - Professional: Status + 30d analytics + basic warnings
  - Business: Status + 30d analytics + advanced warnings
  - Enterprise: Full analytics + custom alerts
- Algorithm Health
  - Free: Health badge
  - Starter: Health badge + basic metrics
  - Creator: Visibility/Engagement analyze (single)
  - Professional: Batch analyze, penalty detect
  - Business: Advanced batch analyze + trend analysis
  - Enterprise: Custom algorithms + dedicated analysis
- Crisis Management
  - Free: View alerts (last 7d)
  - Starter: View alerts (last 14d)
  - Creator: Resolve alerts; basic recommendations
  - Professional: Full recommendations + dashboard
  - Business: Full recommendations + dashboard + stats
  - Enterprise: Crisis team + custom protocols
- Bot/Webhook Health
  - Free: Not available
  - Starter: Basic status
  - Creator: Available (basic)
  - Professional: Available (+ detailed metrics)
  - Business: Available (+ SLA details)
  - Enterprise: Custom integrations + monitoring

Usage Limits by Tier
- Deep Scans per Month:
  - Free: 0, Starter: 50, Creator: 200, Professional: 500, Business: 1000, Enterprise: unlimited
- Bulk Checks per Month:
  - Free: 0, Starter: 100, Creator: 500, Professional: 1000, Business: 5000, Enterprise: unlimited
- API Calls per Day:
  - Free: 100, Starter: 500, Creator: 1000, Professional: 2000, Business: 5000, Enterprise: unlimited
- Projects Limit:
  - Free: 1, Starter: 3, Creator: 10, Professional: 50, Business: 200, Enterprise: unlimited

Implementation notes
- Client must check user plan via GET /subscriptions before enabling actions.
- Use PlanGatingWrapper to render CTA for insufficient plan.
- Endpoints should enforce gates server-side; client gates are UX only.
- Environment config should include numeric ranks for plans: free=0, starter=1, creator=2, professional=3, business=4, enterprise=5.
- Quotas: display usage via GET /subscriptions/usage and block when exceeded.
- New usage fields: deep_scans_per_month, bulk_checks_per_month, api_calls_per_day, projects_limit.