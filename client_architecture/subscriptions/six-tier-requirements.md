# Six-Tier Subscription System - Client Requirements

## Introduction

This document outlines the client-side requirements for implementing the new six-tier subscription system (Free, Starter, Creator, Professional, Business, Enterprise) with enhanced usage tracking, feature gating, and admin pricing management capabilities.

## Updated Subscription Plans

### Plan Tiers and Pricing Structure

| Plan | Monthly Price | Yearly Price | Target Audience | Key Features |
|------|---------------|--------------|-----------------|--------------|
| Free | $0 | $0 | Individual users, testing | Basic protection, limited usage |
| Starter | $9.99 | $99.99 | Small businesses, freelancers | Enhanced protection, moderate limits |
| Creator | $19.99 | $199.99 | Content creators, influencers | Social media focus, creator tools |
| Professional | $39.99 | $399.99 | Professional services, agencies | Advanced features, high limits |
| Business | $79.99 | $799.99 | Medium businesses, teams | Full features, team collaboration |
| Enterprise | Custom | Custom | Large enterprises | Unlimited usage, custom features |

### Enhanced Usage Limits

| Feature | Free | Starter | Creator | Professional | Business | Enterprise |
|---------|------|---------|---------|--------------|----------|------------|
| URL Checks/Day | 20 | 100 | 500 | 1000 | 2000 | Unlimited |
| Deep Scans/Month | 0 | 50 | 200 | 500 | 1000 | Unlimited |
| Bulk Checks/Month | 0 | 100 | 500 | 1000 | 5000 | Unlimited |
| API Calls/Day | 100 | 500 | 1000 | 2000 | 5000 | Unlimited |
| Projects | 1 | 3 | 10 | 50 | 200 | Unlimited |
| Team Members | 1 | 3 | 5 | 20 | 100 | Unlimited |
| Data Retention | 7 days | 30 days | 90 days | 1 year | 2 years | Custom |

## Client-Side Implementation Requirements

### Requirement 1: Enhanced Plan Display

**User Story:** As a user, I want to see detailed information about all six subscription tiers, so that I can choose the plan that best fits my needs.

#### Acceptance Criteria

1. WHEN displaying plans THEN the system SHALL show all six tiers in a comparison grid
2. WHEN showing plan features THEN the system SHALL highlight tier-specific benefits
3. WHEN displaying pricing THEN the system SHALL show monthly/yearly options with savings calculation
4. WHEN showing Creator plan THEN the system SHALL emphasize social media features
5. WHEN showing Professional plan THEN the system SHALL highlight business features
6. WHEN showing Enterprise plan THEN the system SHALL display "Contact Sales" CTA

### Requirement 2: Advanced Usage Tracking

**User Story:** As a user, I want to see detailed usage metrics for all plan features, so that I can monitor my consumption and plan upgrades accordingly.

#### Acceptance Criteria

1. WHEN viewing usage THEN the system SHALL display progress bars for all usage types
2. WHEN usage approaches 80% THEN the system SHALL show warning indicators
3. WHEN usage exceeds limits THEN the system SHALL display upgrade prompts
4. WHEN showing usage THEN the system SHALL include reset dates and time remaining
5. WHEN displaying historical usage THEN the system SHALL show trends and patterns

### Requirement 3: Enhanced Feature Gating

**User Story:** As a user, I want to understand which features are available in my plan, so that I can make informed decisions about upgrades.

#### Acceptance Criteria

1. WHEN accessing gated features THEN the system SHALL show plan requirement tooltips
2. WHEN feature is unavailable THEN the system SHALL display upgrade CTA with specific plan recommendation
3. WHEN showing feature lists THEN the system SHALL use tier-based icons and badges
4. WHEN user attempts restricted action THEN the system SHALL show plan comparison modal

### Requirement 4: Dashboard Integration Updates

**User Story:** As a user, I want my dashboard to reflect my current plan's capabilities and usage, so that I can effectively manage my account.

#### Acceptance Criteria

1. WHEN dashboard loads THEN the system SHALL display current plan badge prominently
2. WHEN showing analytics THEN the system SHALL apply plan-based data retention limits
3. WHEN displaying features THEN the system SHALL show/hide based on plan tier
4. WHEN usage is high THEN the system SHALL show upgrade suggestions in relevant sections

## API Integration Updates

### New Endpoints Required

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/subscriptions/plans | Enhanced with six-tier details |
| GET | /api/v1/subscriptions/usage/detailed | Detailed usage breakdown |
| GET | /api/v1/subscriptions/recommendations | Plan upgrade recommendations |
| POST | /api/v1/subscriptions/preview-upgrade | Preview upgrade costs and benefits |

### Enhanced Response Models

```typescript
interface SubscriptionPlan {
  id: string;
  name: 'free' | 'starter' | 'creator' | 'professional' | 'business' | 'enterprise';
  display_name: string;
  description: string;
  monthly_price: number;
  yearly_price: number;
  features: PlanFeature[];
  limits: PlanLimits;
  target_audience: string;
  popular?: boolean;
  recommended?: boolean;
}

interface PlanLimits {
  url_checks_per_day: number;
  deep_scans_per_month: number;
  bulk_checks_per_month: number;
  api_calls_per_day: number;
  projects_limit: number;
  team_members_limit: number;
  data_retention_days: number;
}

interface DetailedUsage {
  current_period: UsagePeriod;
  daily_usage: DailyUsage[];
  monthly_usage: MonthlyUsage[];
  approaching_limits: LimitWarning[];
  upgrade_recommendations: UpgradeRecommendation[];
}
```

## Component Updates Required

### SubscriptionPlanCard Enhancements

```typescript
interface SubscriptionPlanCardProps {
  plan: SubscriptionPlan;
  currentPlan?: string;
  usage?: DetailedUsage;
  onUpgrade: (planId: string) => void;
  onPreview: (planId: string) => void;
  showComparison?: boolean;
}
```

### New Components Needed

1. **PlanComparisonGrid** - Six-tier comparison table
2. **UsageProgressPanel** - Enhanced usage tracking
3. **UpgradeRecommendationCard** - Smart upgrade suggestions
4. **PlanFeatureTooltip** - Feature explanations with gating info
5. **TierBadge** - Visual tier indicators

## Feature Gating Implementation

### Client-Side Gating Logic

```typescript
enum PlanTier {
  FREE = 0,
  STARTER = 1,
  CREATOR = 2,
  PROFESSIONAL = 3,
  BUSINESS = 4,
  ENTERPRISE = 5
}

interface FeatureGate {
  feature: string;
  required_tier: PlanTier;
  usage_type?: string;
  description: string;
}

const FEATURE_GATES: FeatureGate[] = [
  {
    feature: 'deep_scans',
    required_tier: PlanTier.STARTER,
    usage_type: 'deep_scans_per_month',
    description: 'Deep scanning requires Starter plan or higher'
  },
  {
    feature: 'bulk_checks',
    required_tier: PlanTier.STARTER,
    usage_type: 'bulk_checks_per_month',
    description: 'Bulk URL checking requires Starter plan or higher'
  },
  {
    feature: 'advanced_analytics',
    required_tier: PlanTier.CREATOR,
    description: 'Advanced analytics available for Creator plan and above'
  },
  {
    feature: 'team_collaboration',
    required_tier: PlanTier.PROFESSIONAL,
    description: 'Team features require Professional plan or higher'
  }
];
```

## Error Handling Updates

### New Error Scenarios

| Error Code | HTTP Status | User Message | Client Action |
|------------|-------------|--------------|---------------|
| TIER_INSUFFICIENT | 402 | Feature requires {required_plan} plan | Show upgrade modal |
| USAGE_EXCEEDED | 402 | {usage_type} limit exceeded | Show usage details + upgrade |
| PLAN_DEPRECATED | 400 | Plan no longer available | Show current plans |
| UPGRADE_PREVIEW_FAILED | 500 | Cannot preview upgrade | Retry or contact support |

## Testing Requirements

### Unit Tests Needed

1. Plan comparison logic
2. Feature gating functions
3. Usage calculation utilities
4. Upgrade recommendation algorithms

### Integration Tests Needed

1. Plan selection flow
2. Usage tracking accuracy
3. Feature gate enforcement
4. Upgrade preview functionality

### E2E Tests Needed

1. Complete subscription journey for each tier
2. Feature access validation per plan
3. Usage limit enforcement
4. Upgrade/downgrade flows

## Migration Strategy

### Phase 1: Backend Updates
- Update subscription service with six-tier plans
- Implement usage tracking for new metrics
- Add admin pricing management endpoints

### Phase 2: Client Updates
- Update plan display components
- Implement enhanced feature gating
- Add detailed usage tracking

### Phase 3: Testing & Rollout
- Comprehensive testing of all tiers
- Gradual rollout with feature flags
- Monitor usage patterns and adjust limits

## Success Metrics

1. **Conversion Rate**: Increase in free-to-paid conversions
2. **Upgrade Rate**: Users upgrading to higher tiers
3. **Feature Adoption**: Usage of tier-specific features
4. **User Satisfaction**: Feedback on plan clarity and value
5. **Revenue Growth**: Overall subscription revenue increase

This specification provides a comprehensive foundation for implementing the six-tier subscription system in the client application, ensuring proper feature gating, usage tracking, and user experience optimization.