I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

I've analyzed the LinkShield codebase and documentation to understand the current subscription system and the services that need to be gated. The system currently has 4 basic plans (Free, Basic, Pro, Enterprise) with limits primarily focused on URL checking. However, the documentation reveals a much richer feature set including social protection, bot services, and advanced monitoring capabilities that aren't reflected in the current subscription plans.

The user has requested subscription plans designed for 5 specific demographics: Web Developers, Influencers/Social Media Managers, Normal Users/Shoppers, Social Media Users, and Brand Managers. The documentation (particularly `gen_3.md` and `pricing_strategy.md`) provides market research showing pricing ranges from €5/mo for micro-influencers to €500-5k/mo for enterprise SOC analysts.

The current subscription model tracks basic limits but lacks fields for:
- Social protection limits (profile scans, content assessments)
- Bot service limits (per platform)
- Advanced monitoring features
- Platform-specific limits

I need to create a comprehensive specification document that defines new subscription tiers, maps all services to appropriate tiers with specific limits, and provides clear gating rules for implementation.

### Approach

I will create a comprehensive subscription plan specification document that serves as the blueprint for the subsequent implementation phases. This specification will:

1. **Define 6 subscription tiers** that cater to all 5 user demographics, from free users to enterprise customers
2. **Map all services** (URL analysis, social protection, bot services, dashboard features, AI analysis) to appropriate tiers with specific limits
3. **Create a detailed feature matrix** showing exactly which services are available in each plan and their limits
4. **Provide pricing recommendations** based on market research from the documentation
5. **Define service gating rules** that will guide the middleware implementation
6. **Include usage tracking requirements** for new service types

The specification will be created as a new markdown document in `docs/specs/subscription-plans-spec/` following the existing specification structure used in other spec directories like `docs/specs/social-protection-spec/`.

### Reasoning

I started by reading all the documentation files provided by the user, including `pricing_strategy.md`, `linkshield.md`, `gen_1.md`, `gen_2.md`, `gen_3.md`, and the API endpoint documentation for URL analysis, social protection, and bot integration. This gave me a comprehensive understanding of the features, target markets, and pricing strategies.

I then read the current subscription service implementation in `src/services/subscription_service.py` and the subscription models in `src/models/subscription.py` to understand the existing technical infrastructure, including what limits are currently tracked and how the subscription system works.

By analyzing the gap between the documented features and the current implementation, I identified that the system needs expanded subscription plans with new limit types for social protection, bot services, and advanced monitoring features. I also identified 6 distinct user tiers based on the demographic analysis in the documentation.

## Proposed File Changes

### docs\specs\subscription-plans-spec(NEW)

Create a new directory to house the subscription plans specification documents, following the pattern established by other spec directories like `docs/specs/social-protection-spec/` and `docs/specs/dashboard-api-spec/`.

### docs\specs\subscription-plans-spec\specification.md(NEW)

References: 

- docs\social_media_shield\pricing_strategy.md
- docs\features\linkshield.md
- docs\features\gen_1.md
- docs\features\gen_2.md
- docs\features\gen_3.md
- docs\api\endpoints\url-analysis.md
- docs\api\endpoints\social-protection.md
- docs\api\endpoints\bot-integration.md
- src\services\subscription_service.py
- src\models\subscription.py

Create the comprehensive subscription plans specification document with the following sections:

## 1. Executive Summary
- Overview of the subscription plan redesign
- Goals: cater to 5 user demographics, gate services appropriately, align with market pricing
- Summary of 6 proposed tiers

## 2. User Demographics & Needs Analysis
Detailed analysis of each demographic:
- **Normal Users/Shoppers**: Basic URL safety checking, minimal features
- **Social Media Users**: Reputation protection, profile monitoring
- **Influencers/Social Media Managers**: Content risk assessment, multi-platform monitoring, brand protection
- **Web Developers**: API access, bulk checking, deep scans, technical integrations
- **Brand Managers**: Multi-platform monitoring, team collaboration, radar lens, crisis detection

## 3. Proposed Subscription Tiers
Define 6 tiers with complete details:

### Tier 1: Free Plan
- **Target**: Normal Users/Shoppers
- **Price**: $0/month
- **URL Analysis**: 30 quick scans/day, 3 deep scans/month, no bulk checking
- **Social Protection**: 5 profile scans/month, no monitoring
- **Bot Services**: Not available
- **Dashboard**: 1 project, 1 team member, 3 alerts
- **AI Analysis**: Basic only
- **API Access**: No

### Tier 2: Starter Plan
- **Target**: Social Media Users
- **Price**: $9.99/month or $99/year
- **URL Analysis**: 100 quick scans/day, 10 deep scans/month, no bulk
- **Social Protection**: 50 profile scans/month, 20 content assessments/month, 3 monitored profiles
- **Bot Services**: 1 platform (100 requests/day)
- **Dashboard**: 3 projects, 3 team members, 10 alerts
- **AI Analysis**: Standard
- **API Access**: No

### Tier 3: Creator Plan
- **Target**: Influencers/Small Social Media Managers
- **Price**: $29.99/month or $299/year
- **URL Analysis**: 300 quick scans/day, 50 deep scans/month, 10 bulk checks/month (50 URLs each)
- **Social Protection**: 200 profile scans/month, 100 content assessments/month, 10 monitored profiles, crisis detection
- **Bot Services**: 2 platforms (500 requests/day each)
- **Dashboard**: 10 projects, 10 team members, 25 alerts, 6-hour monitoring frequency
- **AI Analysis**: Advanced (sentiment, engagement prediction)
- **API Access**: Read-only (100 requests/hour)

### Tier 4: Professional Plan
- **Target**: Web Developers
- **Price**: $79.99/month or $799/year
- **URL Analysis**: 1000 quick scans/day, 200 deep scans/month, 100 bulk checks/month (100 URLs each)
- **Social Protection**: 500 profile scans/month, 300 content assessments/month, 20 monitored profiles
- **Bot Services**: 3 platforms (1000 requests/day each)
- **Dashboard**: 25 projects, 25 team members, 50 alerts, 1-hour monitoring frequency
- **AI Analysis**: Advanced + custom models
- **API Access**: Full (500 requests/hour)
- **Webhooks**: Enabled

### Tier 5: Business Plan
- **Target**: Brand Managers/Agencies
- **Price**: $199.99/month or $1999/year
- **URL Analysis**: 5000 quick scans/day, 1000 deep scans/month, unlimited bulk checks (500 URLs each)
- **Social Protection**: 2000 profile scans/month, 1000 content assessments/month, 100 monitored profiles, radar lens (typo-squat detection), crisis detection with escalation
- **Bot Services**: All platforms (5000 requests/day each)
- **Dashboard**: 100 projects, 100 team members, 200 alerts, 30-minute monitoring frequency
- **AI Analysis**: Advanced + custom models + brand risk scoring
- **API Access**: Full (2000 requests/hour)
- **Webhooks**: Enabled
- **White-label**: Basic branding
- **Team Features**: Role-based access control, audit logs

### Tier 6: Enterprise Plan
- **Target**: Large Brands/Corporations/MSSPs
- **Price**: $499.99/month or $4999/year (custom pricing available)
- **URL Analysis**: Unlimited
- **Social Protection**: Unlimited profile scans, unlimited content assessments, unlimited monitored profiles, radar lens, crisis detection with emergency response
- **Bot Services**: All platforms (unlimited requests)
- **Dashboard**: Unlimited projects, unlimited team members, unlimited alerts, real-time monitoring
- **AI Analysis**: All features + custom training + threat intelligence feeds
- **API Access**: Unlimited
- **Webhooks**: Enabled
- **White-label**: Full customization
- **Team Features**: Advanced RBAC, SSO, audit logs, compliance reporting
- **Support**: Dedicated account manager, 24/7 priority support, SLA guarantees

## 4. Service-to-Tier Mapping Matrix
Create a comprehensive table showing:
- Service categories (URL Analysis, Social Protection, Bot Services, Dashboard, AI Analysis)
- Specific features within each category
- Availability and limits for each tier (Free, Starter, Creator, Professional, Business, Enterprise)

## 5. Usage Tracking Requirements
Define new usage types that need to be tracked:
- `url_quick_scan` - Quick URL analysis
- `url_deep_scan` - Deep-link audit
- `url_bulk_check` - Bulk URL checking
- `social_profile_scan` - Social media profile scanning
- `social_content_assessment` - Content risk assessment
- `social_monitoring` - Active profile monitoring
- `bot_request_twitter` - Twitter bot requests
- `bot_request_telegram` - Telegram bot requests
- `bot_request_discord` - Discord bot requests
- `api_call` - API requests
- `webhook_delivery` - Webhook deliveries

## 6. Service Gating Rules
Define specific gating rules for each service:

### URL Analysis Gating
- Quick scans: Check daily limit, return 429 if exceeded with upgrade message
- Deep scans: Check monthly limit, require Starter+ plan
- Bulk checks: Require Creator+ plan, check monthly limit and per-batch size

### Social Protection Gating
- Profile scans: Check monthly limit, require Starter+ plan
- Content assessments: Check monthly limit, require Starter+ plan
- Monitoring: Check active monitored profiles count, require Starter+ plan
- Crisis detection: Require Creator+ plan
- Radar lens: Require Business+ plan

### Bot Services Gating
- Check if plan allows bot services (Starter+ only)
- Check per-platform daily limits
- Check number of connected platforms
- Return 402 Payment Required if plan doesn't support bots

### Dashboard Features Gating
- Projects: Check count against max_projects limit
- Team members: Check count per project against max_team_members_per_project
- Alerts: Check count per project against max_alerts_per_project
- Monitoring frequency: Enforce minimum frequency based on plan

### AI Analysis Gating
- Basic AI: Available to all plans
- Advanced AI (sentiment, engagement prediction): Require Creator+ plan
- Custom models: Require Professional+ plan
- Brand risk scoring: Require Business+ plan
- Threat intelligence feeds: Require Enterprise plan

## 7. Pricing Strategy & Rationale
Explain pricing decisions:
- Free tier: Acquisition and viral growth
- Starter ($9.99): Entry point for individual social media users, aligns with gen_3.md micro-influencer pricing
- Creator ($29.99): Sweet spot for influencers, competitive with social media management tools
- Professional ($79.99): Developer-focused, API access justifies higher price
- Business ($199.99): Agency/brand manager tier, team features and advanced monitoring
- Enterprise ($499.99+): Custom pricing for large organizations, includes SLA and dedicated support

## 8. Migration Strategy
Define how existing users will be migrated:
- Current "free" → New "Free"
- Current "basic" → New "Starter" (similar pricing, enhanced features)
- Current "pro" → New "Creator" (similar pricing, social protection focus)
- Current "enterprise" → New "Business" or "Enterprise" based on usage

## 9. Implementation Considerations
Technical notes for implementation:
- New fields needed in `SubscriptionPlan` model for social protection and bot limits
- New usage types in `UsageRecord` model
- Middleware needs to check multiple limit types per request
- Dashboard needs to display usage across all service categories
- Paddle price IDs need to be created for all new plans

## 10. Success Metrics
Define KPIs to measure success:
- Conversion rate from Free to Starter
- Average revenue per user (ARPU) by tier
- Churn rate by tier
- Feature adoption rates (social protection, bot services)
- API usage growth (Professional+ plans)

Reference the market research from `docs/social_media_shield/pricing_strategy.md`, feature descriptions from `docs/features/linkshield.md`, `docs/features/gen_1.md`, `docs/features/gen_2.md`, `docs/features/gen_3.md`, and API capabilities from `docs/api/endpoints/url-analysis.md`, `docs/api/endpoints/social-protection.md`, and `docs/api/endpoints/bot-integration.md`.

### docs\specs\subscription-plans-spec\feature-matrix.md(NEW)

References: 

- docs\specs\subscription-plans-spec\specification.md(NEW)
- src\services\subscription_service.py

Create a detailed feature comparison matrix document that provides a visual, easy-to-understand comparison of all features across all subscription tiers. This document will be used for:
- Marketing materials and pricing pages
- Sales team reference
- Customer decision-making
- Implementation validation

Structure:

## Feature Comparison Matrix

### URL Analysis Features
Table with columns: Feature | Free | Starter | Creator | Professional | Business | Enterprise

Rows:
- Quick URL Scans (per day)
- Deep-Link Audits (per month)
- Bulk URL Checking (per month)
- URLs per Bulk Check
- Domain Reputation Checks
- Historical Analysis
- Redirect Chain Analysis
- SSL Certificate Validation
- Malware Detection
- Phishing Detection
- Broken Link Detection

### Social Protection Features
Table with same column structure

Rows:
- Profile Scans (per month)
- Content Risk Assessments (per month)
- Monitored Profiles (active)
- Supported Platforms
- Real-time Monitoring
- Crisis Detection
- Radar Lens (Typo-squat Detection)
- Emergency Response
- Follower Authenticity Check
- Engagement Pattern Analysis
- Community Notes Detection
- Shadow Ban Detection
- Algorithm Health Scoring

### Bot Integration Features
Table with same column structure

Rows:
- Twitter Bot
- Telegram Bot
- Discord Bot
- Bot Requests per Day (per platform)
- Number of Platforms
- Custom Bot Commands
- Bot Analytics

### Dashboard & Monitoring Features
Table with same column structure

Rows:
- Projects
- Team Members per Project
- Alerts per Project
- Monitoring Frequency
- Scan Depth Limit
- Links per Scan
- Email Notifications
- Webhook Notifications
- Custom Dashboards
- Export to CSV/JSON
- Scheduled Reports

### AI & Analysis Features
Table with same column structure

Rows:
- Basic AI Analysis
- Advanced AI (Sentiment)
- Engagement Prediction
- Content Quality Scoring
- Brand Risk Scoring
- Custom AI Models
- Threat Intelligence Feeds
- Predictive Risk Modeling

### API & Integration Features
Table with same column structure

Rows:
- API Access
- API Rate Limit (per hour)
- Webhook Support
- Bulk API Endpoints
- Real-time Streaming API
- GraphQL API
- API Documentation
- SDK Support

### Team & Collaboration Features
Table with same column structure

Rows:
- User Roles & Permissions
- Activity Audit Logs
- Team Workspaces
- Shared Projects
- Comments & Annotations
- SSO (Single Sign-On)
- SAML Integration
- SCIM Provisioning

### Support & SLA Features
Table with same column structure

Rows:
- Email Support
- Priority Support
- 24/7 Support
- Dedicated Account Manager
- SLA Guarantee
- Uptime Guarantee
- Response Time SLA
- Custom Onboarding
- Training Sessions

### Branding & Customization
Table with same column structure

Rows:
- Custom Branding
- White-label Reports
- Custom Domain
- Branded Email Notifications
- Custom Logo
- Custom Color Scheme

Use visual indicators:
- ✅ = Included
- ❌ = Not included
- Numbers for limits
- "Unlimited" for no limits
- "Custom" for enterprise custom options

Reference the service limits defined in `docs/specs/subscription-plans-spec/specification.md` and align with the current limits in `src/services/subscription_service.py`.

### docs\specs\subscription-plans-spec\service-gating-rules.md(NEW)

References: 

- src\services\subscription_service.py
- src\models\subscription.py

Create a detailed technical specification for service gating rules that will guide the middleware implementation in the next phase. This document provides the exact logic for enforcing subscription limits across all services.

Structure:

## Service Gating Rules Specification

### 1. Overview
Explain the purpose of service gating:
- Enforce subscription limits
- Provide clear upgrade paths
- Track usage accurately
- Return appropriate HTTP status codes and error messages

### 2. Gating Middleware Architecture
Describe the middleware flow:
1. Extract user authentication from request
2. Load user's active subscription
3. Determine service type from endpoint
4. Check usage limits for service type
5. Allow or deny request with appropriate response
6. Increment usage counters on success

### 3. URL Analysis Gating Rules

#### Quick URL Scan (`POST /api/v1/url-check/check`)
```python
# Pseudo-code for gating logic
if not user.has_active_subscription():
    plan = "free"
    daily_limit = 30
else:
    plan = user.subscription.plan.name
    daily_limit = user.subscription.plan.daily_check_limit

if daily_limit != -1 and user.daily_usage >= daily_limit:
    return 429 Too Many Requests {
        "error": "daily_limit_exceeded",
        "message": f"Daily limit of {daily_limit} quick scans exceeded",
        "current_plan": plan,
        "upgrade_url": "/pricing",
        "reset_at": "tomorrow at midnight UTC"
    }

# Allow request and increment usage
```

#### Deep-Link Audit (`POST /api/v1/url-check/deep`)
```python
# Requires Starter+ plan
if not user.has_active_subscription() or user.subscription.plan.name == "free":
    return 402 Payment Required {
        "error": "feature_not_available",
        "message": "Deep-link audits require Starter plan or higher",
        "current_plan": "free",
        "required_plan": "starter",
        "upgrade_url": "/pricing"
    }

# Check monthly limit
monthly_limit = get_plan_limit(plan, "deep_scans_per_month")
if monthly_limit != -1 and user.monthly_deep_scans >= monthly_limit:
    return 429 Too Many Requests {
        "error": "monthly_limit_exceeded",
        "message": f"Monthly limit of {monthly_limit} deep scans exceeded",
        "current_plan": plan,
        "upgrade_url": "/pricing",
        "reset_at": "first day of next month"
    }
```

#### Bulk URL Checking (`POST /api/v1/url-check/bulk-check`)
```python
# Requires Creator+ plan
if user.subscription.plan.name not in ["creator", "professional", "business", "enterprise"]:
    return 402 Payment Required {
        "error": "feature_not_available",
        "message": "Bulk checking requires Creator plan or higher",
        "current_plan": user.subscription.plan.name,
        "required_plan": "creator",
        "upgrade_url": "/pricing"
    }

# Check batch size limit
max_urls_per_batch = get_plan_limit(plan, "max_urls_per_bulk_check")
if len(request.urls) > max_urls_per_batch:
    return 400 Bad Request {
        "error": "batch_size_exceeded",
        "message": f"Batch size of {len(request.urls)} exceeds plan limit of {max_urls_per_batch}",
        "current_plan": plan,
        "max_batch_size": max_urls_per_batch
    }

# Check monthly bulk check limit
monthly_bulk_limit = get_plan_limit(plan, "bulk_checks_per_month")
if monthly_bulk_limit != -1 and user.monthly_bulk_checks >= monthly_bulk_limit:
    return 429 Too Many Requests {
        "error": "monthly_limit_exceeded",
        "message": f"Monthly limit of {monthly_bulk_limit} bulk checks exceeded"
    }
```

Continue with detailed gating rules for:
- Social Protection (profile scans, content assessments, monitoring, crisis detection, radar lens)
- Bot Services (platform checks, daily limits, platform count)
- Dashboard Features (projects, team members, alerts, monitoring frequency)
- AI Analysis (basic, advanced, custom models, brand risk, threat intelligence)
- API Access (rate limiting, webhook access)

### 9. Error Response Standards
Define standard error response format for all gating errors

### 10. Usage Tracking
Define how to increment usage counters after successful requests

Reference the subscription service implementation in `src/services/subscription_service.py` and the usage tracking in `src/models/subscription.py`.

### docs\specs\subscription-plans-spec\usage-types.md(NEW)

References: 

- src\models\subscription.py
- src\services\subscription_service.py

Create a comprehensive document defining all usage types that need to be tracked across the LinkShield platform. This will guide the implementation of usage tracking in the subscription service and models.

Structure:

## Usage Types Specification

### 1. Overview
Explain the purpose of usage tracking

### 2. Usage Type Enumeration
Define a new enum `UsageType` to be added to `src/models/subscription.py`:

```python
class UsageType(enum.Enum):
    # URL Analysis
    URL_QUICK_SCAN = "url_quick_scan"
    URL_DEEP_SCAN = "url_deep_scan"
    URL_BULK_CHECK = "url_bulk_check"
    
    # Social Protection
    SOCIAL_PROFILE_SCAN = "social_profile_scan"
    SOCIAL_CONTENT_ASSESSMENT = "social_content_assessment"
    SOCIAL_MONITORING_ACTIVE = "social_monitoring_active"
    
    # Bot Services
    BOT_REQUEST_TWITTER = "bot_request_twitter"
    BOT_REQUEST_TELEGRAM = "bot_request_telegram"
    BOT_REQUEST_DISCORD = "bot_request_discord"
    
    # API & Webhooks
    API_CALL = "api_call"
    WEBHOOK_DELIVERY = "webhook_delivery"
```

### 3. Usage Type Details
For each usage type, define:
- Description
- Tracked against which limit
- Reset period
- Increment amount
- Available in which plans
- Related endpoints

### 4. New Fields Required in SubscriptionPlan Model
List all new fields needed:
- Social protection limits (profile_scans_per_month, content_assessments_per_month, max_monitored_profiles)
- URL analysis limits (deep_scans_per_month, bulk_checks_per_month, max_urls_per_bulk_check)
- Bot service limits (bot_requests_per_day_twitter, bot_requests_per_day_telegram, bot_requests_per_day_discord)
- Feature flags (crisis_detection_enabled, radar_lens_enabled, advanced_ai_enabled, etc.)

### 5. New Fields Required in UserSubscription Model
List all new usage tracking fields:
- monthly_profile_scans_used
- monthly_content_assessments_used
- active_monitored_profiles_count
- monthly_deep_scans_used
- monthly_bulk_checks_used
- daily_bot_requests_twitter
- daily_bot_requests_telegram
- daily_bot_requests_discord
- hourly_api_requests

### 6. Usage Reset Logic
Define when each usage counter should be reset (daily, monthly, hourly, or never)

### 7. Usage Tracking Implementation
Provide pseudo-code for tracking usage

### 8. Usage Analytics Queries
Provide example queries for common analytics needs

Reference the current usage tracking implementation in `src/services/subscription_service.py` and extend it to support all new usage types.

### docs\specs\subscription-plans-spec\paddle-integration.md(NEW)

References: 

- src\services\paddle_client.py
- src\routes\paddle_webhooks.py
- src\services\subscription_service.py

Create a document specifying how the new subscription plans will be integrated with Paddle Billing, including product and price creation, webhook handling, and subscription management.

Structure:

## Paddle Billing Integration Specification

### 1. Overview
Explain the Paddle integration approach

### 2. Paddle Products & Prices
Define the products and prices to create in Paddle:
- LinkShield Starter ($9.99/mo, $99/year)
- LinkShield Creator ($29.99/mo, $299/year)
- LinkShield Professional ($79.99/mo, $799/year)
- LinkShield Business ($199.99/mo, $1999/year)
- LinkShield Enterprise ($499.99/mo, $4999/year)

### 3. Paddle Price ID Mapping
Define how to map local plan names to Paddle price IDs

### 4. Subscription Creation Flow
Define the flow for creating a new subscription:
1. User selects plan
2. Backend creates local subscription record
3. Backend calls Paddle API to create subscription
4. Paddle returns checkout URL
5. User completes payment
6. Paddle sends webhook
7. Backend activates subscription

### 5. Webhook Events to Handle
List all Paddle webhook events:
- subscription.created
- subscription.activated
- subscription.updated
- subscription.canceled
- subscription.paused
- subscription.resumed
- transaction.completed
- transaction.payment_failed

### 6. Subscription Upgrade/Downgrade Flow
Define how plan changes work

### 7. Subscription Cancellation Flow
Define cancellation options (immediate vs. end of period)

### 8. Trial Period Handling
Define trial period logic for each plan

### 9. Webhook Signature Verification
Define security for webhook handling

### 10. Error Handling
Define error scenarios and recovery strategies

### 11. Testing
Define testing strategy for Paddle integration

Reference the existing Paddle integration in `src/services/paddle_client.py` and webhook handling in `src/routes/paddle_webhooks.py`.

### docs\specs\subscription-plans-spec\README.md(NEW)

References: 

- docs\specs\subscription-plans-spec\specification.md(NEW)
- docs\specs\subscription-plans-spec\feature-matrix.md(NEW)
- docs\specs\subscription-plans-spec\service-gating-rules.md(NEW)
- docs\specs\subscription-plans-spec\usage-types.md(NEW)
- docs\specs\subscription-plans-spec\paddle-integration.md(NEW)

Create a README file for the subscription plans specification directory that provides an overview and navigation guide.

Content:

# LinkShield Subscription Plans Specification

## Overview

This directory contains the comprehensive specification for LinkShield's subscription plan redesign. The new subscription system is designed to cater to 5 distinct user demographics while properly gating all services (URL analysis, social protection, bot services, dashboard features, and AI analysis) behind appropriate subscription tiers.

## Goals

1. **Demographic-Focused Plans**: Create subscription tiers that align with specific user needs
2. **Comprehensive Service Gating**: Ensure all services are properly gated with clear limits
3. **Market-Aligned Pricing**: Price plans based on market research and competitive analysis
4. **Paddle Integration**: Seamless integration with Paddle Billing for payment processing

## Documents

### 1. [specification.md](./specification.md)
The main specification document containing:
- Executive summary
- User demographics analysis
- Detailed subscription tier definitions (6 tiers)
- Service-to-tier mapping
- Usage tracking requirements
- Service gating rules
- Pricing strategy and rationale
- Migration strategy for existing users
- Implementation considerations

### 2. [feature-matrix.md](./feature-matrix.md)
A comprehensive feature comparison matrix showing all features across all tiers

### 3. [service-gating-rules.md](./service-gating-rules.md)
Detailed technical specification for service gating with pseudo-code examples

### 4. [usage-types.md](./usage-types.md)
Comprehensive usage tracking specification with new model fields and reset logic

### 5. [paddle-integration.md](./paddle-integration.md)
Paddle Billing integration specification with product definitions and webhook handling

## Implementation Phases

This specification supports the following implementation phases:

### Phase 1: Update Subscription Plans (LNKS-004)
- Update `src/services/subscription_service.py` with new plans
- Add new fields to `src/models/subscription.py`
- Update Paddle integration
- Create database migration

### Phase 2: Implement Service Gating Middleware (LNKS-005)
- Create `src/middleware/subscription_gate.py`
- Implement usage tracking for all service types
- Add helper functions for limit checking
- Create decorators for FastAPI routes

### Phase 3: Apply Gating to API Endpoints (LNKS-006)
- Update all API routes with subscription checks
- Update controllers with limit enforcement
- Add appropriate error responses
- Test all gating scenarios

### Phase 4: Update Documentation (LNKS-007)
- Update API documentation with subscription requirements
- Create subscription plan comparison pages
- Update README and getting started guides
- Create migration guides for existing users

## Key Decisions

### Subscription Tiers
- **6 tiers** instead of 4 to better serve all demographics
- **Free tier** remains generous to drive adoption
- **Starter tier** ($9.99) targets individual social media users
- **Creator tier** ($29.99) focuses on influencers with social protection
- **Professional tier** ($79.99) targets developers with API access
- **Business tier** ($199.99) serves agencies and brand managers
- **Enterprise tier** ($499.99+) for large organizations with custom needs

### Service Gating
- **URL Analysis**: Gated by daily/monthly limits, deep scans require Starter+
- **Social Protection**: Requires Starter+, advanced features require Creator+
- **Bot Services**: Requires Starter+, multiple platforms require higher tiers
- **API Access**: Requires Creator+ for read-only, Professional+ for full access
- **Advanced AI**: Requires Creator+ for advanced features, Professional+ for custom models

### Pricing Strategy
- Based on market research from `docs/social_media_shield/pricing_strategy.md`
- Competitive with social media management tools ($10-50/mo range)
- Higher tiers justified by API access and team features
- Annual billing offers 17-20% discount

## References

### Documentation
- [Pricing Strategy](../../social_media_shield/pricing_strategy.md)
- [LinkShield Features](../../features/linkshield.md)
- [URL Analysis API](../../api/endpoints/url-analysis.md)
- [Social Protection API](../../api/endpoints/social-protection.md)
- [Bot Integration API](../../api/endpoints/bot-integration.md)

### Implementation
- [Subscription Service](../../../src/services/subscription_service.py)
- [Subscription Models](../../../src/models/subscription.py)
- [Paddle Client](../../../src/services/paddle_client.py)

## Version History

- **v1.0** (2024-01-15): Initial specification with 6 subscription tiers and comprehensive service gating rules