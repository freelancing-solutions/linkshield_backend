# Subscription Plans Specification

## 1. Executive Summary
- Redesign subscription plans to serve 5 demographics with 6 tiers.
- Gate services appropriately across URL analysis, social protection, bot services, dashboard, AI analysis, and API.
- Align pricing with market research and existing documentation.

## 2. User Demographics & Needs Analysis
- Normal Users/Shoppers: Basic URL safety checking.
- Social Media Users: Reputation protection and profile monitoring.
- Influencers/Social Media Managers: Content risk assessment, multi-platform monitoring, brand protection.
- Web Developers: API access, bulk checking, deep scans, integrations.
- Brand Managers: Multi-platform monitoring, team collaboration, crisis detection.

## 3. Proposed Subscription Tiers

### Tier 1: Free Plan
- Target: Normal Users/Shoppers
- Price: $0/month
- URL Analysis: 30 quick scans/day, 3 deep scans/month, no bulk checking
- Social Protection: 5 profile scans/month, no monitoring
- Bot Services: Not available
- Dashboard: 1 project, 1 team member, 3 alerts
- AI Analysis: Basic only
- API Access: No

### Tier 2: Starter Plan
- Target: Social Media Users
- Price: $9.99/month or $99/year
- URL Analysis: 100 quick scans/day, 10 deep scans/month, no bulk
- Social Protection: 50 profile scans/month, 20 content assessments/month, 3 monitored profiles
- Bot Services: 1 platform (100 requests/day)
- Dashboard: 3 projects, 3 team members, 10 alerts
- AI Analysis: Standard
- API Access: No

### Tier 3: Creator Plan
- Target: Influencers/Small Social Media Managers
- Price: $29.99/month or $299/year
- URL Analysis: 300 quick scans/day, 50 deep scans/month, 10 bulk checks/month (50 URLs each)
- Social Protection: 200 profile scans/month, 100 content assessments/month, 10 monitored profiles, crisis detection
- Bot Services: 2 platforms (500 requests/day each)
- Dashboard: 10 projects, 10 team members, 25 alerts, 6-hour monitoring frequency
- AI Analysis: Advanced (sentiment, engagement prediction)
- API Access: Read-only (100 requests/hour)

### Tier 4: Professional Plan
- Target: Web Developers
- Price: $79.99/month or $799/year
- URL Analysis: 1000 quick scans/day, 200 deep scans/month, 100 bulk checks/month (100 URLs each)
- Social Protection: 500 profile scans/month, 300 content assessments/month, 20 monitored profiles
- Bot Services: 3 platforms (1000 requests/day each)
- Dashboard: 25 projects, 25 team members, 50 alerts, 1-hour monitoring frequency
- AI Analysis: Advanced + custom models
- API Access: Full (500 requests/hour)
- Webhooks: Enabled

### Tier 5: Business Plan
- Target: Brand Managers/Agencies
- Price: $199.99/month or $1999/year
- URL Analysis: 5000 quick scans/day, 1000 deep scans/month, unlimited bulk checks (500 URLs each)
- Social Protection: 2000 profile scans/month, 1000 content assessments/month, 100 monitored profiles, radar lens (typo-squat detection), crisis detection with escalation
- Bot Services: All platforms (5000 requests/day each)
- Dashboard: 100 projects, 100 team members, 200 alerts, 30-minute monitoring frequency
- AI Analysis: Advanced + custom models + brand risk scoring
- API Access: Full (2000 requests/hour)
- Webhooks: Enabled
- White-label: Basic branding
- Team Features: Role-based access control, audit logs

### Tier 6: Enterprise Plan
- Target: Large Brands/Corporations/MSSPs
- Price: $499.99/month or $4999/year (custom pricing available)
- URL Analysis: Unlimited
- Social Protection: Unlimited profile scans, unlimited content assessments, unlimited monitored profiles, radar lens, crisis detection with emergency response
- Bot Services: All platforms (unlimited requests)
- Dashboard: Unlimited projects, team members, alerts, real-time monitoring
- AI Analysis: All features + custom training + threat intelligence feeds
- API Access: Unlimited
- Webhooks: Enabled
- White-label: Full customization
- Team Features: Advanced RBAC, SSO, audit logs, compliance reporting
- Support: Dedicated account manager, 24/7 priority support, SLA guarantees

## 4. Service-to-Tier Mapping Matrix
- See feature-matrix.md for comprehensive tables and limits per tier.

## 5. Usage Tracking Requirements
New usage types to track:
- url_quick_scan, url_deep_scan, url_bulk_check
- social_profile_scan, social_content_assessment, social_monitoring
- bot_request_twitter, bot_request_telegram, bot_request_discord
- api_call, webhook_delivery

## 6. Service Gating Rules
Summaries:
- URL: Quick—daily limit with 429; Deep—Starter+ and monthly limit; Bulk—Creator+ with batch size and monthly limit.
- Social: Scans/assessments—Starter+ monthly limits; Monitoring—Starter+ active profile cap; Crisis detection—Creator+; Radar lens—Business+.
- Bots: Starter+; per-platform daily limits; platform count checks; 402 if unsupported.
- Dashboard: Projects, team members, alerts, monitoring frequency enforced by plan.
- AI: Basic–all; Advanced–Creator+; Custom models–Professional+; Brand risk–Business+; Threat intel–Enterprise.

## 7. Pricing Strategy & Rationale
- Free: acquisition & growth; Starter ($9.99) for social users; Creator ($29.99) for influencers; Professional ($79.99) developer-focused; Business ($199.99) agencies; Enterprise ($499.99+) large orgs.

## 8. Migration Strategy
- free → Free; basic → Starter; pro → Creator; enterprise → Business or Enterprise.

## 9. Implementation Considerations
- Add fields in SubscriptionPlan model for new limits.
- Extend UsageRecord model and subscription service for new usage types.
- Middleware to check multiple limit types per request.
- Dashboard to display usage across categories.
- Paddle product/price IDs for new plans.

## 10. Success Metrics
- Conversion rate, ARPU, churn by tier, feature adoption rates, API usage growth.

## References
- docs/social_media_shield/pricing_strategy.md
- docs/features/linkshield.md, gen_1.md, gen_2.md, gen_3.md
- docs/api/endpoints/url-analysis.md, social-protection.md, bot-integration.md
- src/services/subscription_service.py, src/models/subscription.py, src/services/paddle_client.py

## Version History
- v1.0 (2024-01-15): Initial specification with 6 subscription tiers and comprehensive service gating rules