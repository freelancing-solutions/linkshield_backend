# Requirements Document

## Introduction

The Subscriptions feature enables users to manage their LinkShield subscription plans, including viewing current subscriptions, upgrading or downgrading plans, tracking usage against limits, and canceling subscriptions. This feature is critical for revenue generation and provides tiered access to LinkShield services based on subscription level (Free, Basic, Pro, Enterprise).

## Requirements

### Requirement 1: View Available Plans

**User Story:** As a visitor or user, I want to view available subscription plans, so that I can compare features and pricing to choose the right plan.

#### Acceptance Criteria

1. WHEN a user navigates to plans page THEN the system SHALL call GET /api/v1/subscriptions/plans
2. WHEN plans are received THEN the system SHALL display plan cards with name, price, billing intervals, and features
3. WHEN plans include feature lists THEN the system SHALL display feature comparison table
4. WHEN a plan is recommended THEN the system SHALL display "Most Popular" or "Best Value" badge
5. WHEN user is not authenticated THEN the system SHALL show "Sign Up" CTA for each plan
6. WHEN user is authenticated THEN the system SHALL show "Subscribe" or "Current Plan" or "Upgrade" CTA based on current subscription
7. WHEN plans include trial periods THEN the system SHALL display trial duration prominently

### Requirement 2: View Current Subscription

**User Story:** As an authenticated user, I want to view my current subscription details, so that I can understand my plan benefits and renewal date.

#### Acceptance Criteria

1. WHEN a user navigates to subscription page THEN the system SHALL call GET /api/v1/subscriptions with Bearer token
2. WHEN subscription data is received THEN the system SHALL display plan name, billing interval, price, status, and renewal date
3. WHEN subscription is active THEN the system SHALL display "Active" badge
4. WHEN subscription is canceled THEN the system SHALL display "Canceled" badge with end date
5. WHEN subscription is in trial THEN the system SHALL display "Trial" badge with days remaining
6. WHEN subscription includes payment method THEN the system SHALL display last 4 digits of card
7. WHEN no subscription exists THEN the system SHALL display "No active subscription" with upgrade CTA

### Requirement 3: Create Subscription

**User Story:** As an authenticated user, I want to subscribe to a plan, so that I can access premium features.

#### Acceptance Criteria

1. WHEN a user clicks subscribe on a plan THEN the system SHALL display subscription creation modal
2. WHEN modal is displayed THEN the system SHALL show plan details, billing interval options, and payment form
3. WHEN a user selects billing interval THEN the system SHALL update price display (monthly, yearly, lifetime)
4. WHEN a user submits subscription THEN the system SHALL call POST /api/v1/subscriptions with plan_name, billing_interval, payment_method
5. WHEN subscription is created successfully THEN the system SHALL display success message and redirect to subscription page
6. WHEN subscription fails with 409 THEN the system SHALL display "You already have an active subscription"
7. WHEN payment fails THEN the system SHALL display payment error with retry option
8. WHEN subscription includes trial THEN the system SHALL display trial terms before confirmation

### Requirement 4: Update Subscription (Upgrade/Downgrade)

**User Story:** As an authenticated user, I want to upgrade or downgrade my subscription, so that I can adjust my plan based on my needs.

#### Acceptance Criteria

1. WHEN a user clicks upgrade/downgrade THEN the system SHALL display plan selection modal
2. WHEN modal is displayed THEN the system SHALL show current plan and available plans
3. WHEN a user selects new plan THEN the system SHALL display price difference and effective date
4. WHEN upgrade is immediate THEN the system SHALL display "Upgrade now and pay prorated amount"
5. WHEN downgrade is deferred THEN the system SHALL display "Downgrade at end of current billing period"
6. WHEN a user confirms change THEN the system SHALL call PATCH /api/v1/subscriptions/{id} with new_plan_name
7. WHEN update is successful THEN the system SHALL display confirmation and updated subscription details
8. WHEN update fails with 400 THEN the system SHALL display validation error

### Requirement 5: Cancel Subscription

**User Story:** As an authenticated user, I want to cancel my subscription, so that I can stop recurring charges.

#### Acceptance Criteria

1. WHEN a user clicks cancel subscription THEN the system SHALL display cancellation confirmation dialog
2. WHEN dialog is displayed THEN the system SHALL show cancellation terms and options
3. WHEN a user selects "Cancel at period end" THEN the system SHALL set cancel_at_period_end to true
4. WHEN a user selects "Cancel immediately" THEN the system SHALL set cancel_at_period_end to false
5. WHEN a user provides cancellation reason THEN the system SHALL include reason in request
6. WHEN a user confirms cancellation THEN the system SHALL call DELETE /api/v1/subscriptions/{id}
7. WHEN cancellation is successful THEN the system SHALL display confirmation and updated status
8. WHEN cancellation fails with 404 THEN the system SHALL display "No active subscription to cancel"

### Requirement 6: View Usage and Limits

**User Story:** As an authenticated user, I want to view my usage against plan limits, so that I can track my consumption and plan accordingly.

#### Acceptance Criteria

1. WHEN a user navigates to usage page THEN the system SHALL call GET /api/v1/subscriptions/{id}/usage with Bearer token
2. WHEN usage data is received THEN the system SHALL display usage for each feature (url_checks, ai_analysis, api_keys, etc.)
3. WHEN usage includes limits THEN the system SHALL display progress bars showing used vs limit
4. WHEN usage is approaching limit (>80%) THEN the system SHALL display warning message
5. WHEN usage exceeds limit THEN the system SHALL display "Limit reached" message with upgrade CTA
6. WHEN usage includes daily and monthly limits THEN the system SHALL display both with reset times
7. WHEN usage includes historical data THEN the system SHALL display usage chart over time

### Requirement 7: Manage Payment Method

**User Story:** As an authenticated user, I want to update my payment method, so that I can ensure uninterrupted service.

#### Acceptance Criteria

1. WHEN a user clicks update payment method THEN the system SHALL display payment form modal
2. WHEN modal is displayed THEN the system SHALL show current payment method (last 4 digits)
3. WHEN a user enters new payment details THEN the system SHALL validate card information
4. WHEN a user submits new payment method THEN the system SHALL call PATCH /api/v1/subscriptions/{id}/payment-method
5. WHEN update is successful THEN the system SHALL display success message and updated payment info
6. WHEN update fails THEN the system SHALL display payment error

## Base URLs

- **Client Base**: https://www.linkshield.site
- **API Base**: https://www.linkshield.site/api/v1

## API Endpoints

| Method | Endpoint | Auth Required | Rate Limit | Description |
|--------|----------|---------------|------------|-------------|
| GET | /subscriptions/plans | No | 100/hour | List available subscription plans |
| GET | /subscriptions | Yes | 100/hour | Get user's subscriptions |
| POST | /subscriptions | Yes | 10/hour | Create new subscription |
| GET | /subscriptions/{id} | Yes | 100/hour | Get subscription details |
| PATCH | /subscriptions/{id} | Yes | 10/hour | Update subscription |
| DELETE | /subscriptions/{id} | Yes | 5/hour | Cancel subscription |
| GET | /subscriptions/{id}/usage | Yes | 100/hour | Get usage statistics |
| PATCH | /subscriptions/{id}/payment-method | Yes | 10/hour | Update payment method |

## Subscription Plans

| Plan | Price (Monthly) | Price (Yearly) | URL Checks | AI Analysis | API Keys | Features |
|------|----------------|----------------|------------|-------------|----------|----------|
| Free | $0 | $0 | 100/month | 10/month | 3 | Basic features |
| Basic | $9.99 | $99/year | 1,000/month | 100/month | 5 | Standard features |
| Pro | $29.99 | $299/year | 10,000/month | 1,000/month | 10 | Advanced features |
| Enterprise | Custom | Custom | Unlimited | Unlimited | Unlimited | All features + support |

## Error Handling

| Error Code | HTTP Status | User Message | Action |
|------------|-------------|--------------|--------|
| SUBSCRIPTION_EXISTS | 409 | You already have an active subscription | Show current subscription |
| PAYMENT_FAILED | 402 | Payment processing failed | Retry payment |
| INVALID_PLAN | 400 | Selected plan is not available | Show available plans |
| SUBSCRIPTION_NOT_FOUND | 404 | No active subscription found | Show plans page |
| DOWNGRADE_NOT_ALLOWED | 400 | Cannot downgrade to this plan | Show restrictions |
| USAGE_LIMIT_EXCEEDED | 402 | Feature not available - limit reached | Show upgrade CTA |
| UNAUTHORIZED | 401 | Please log in to manage subscriptions | Redirect to login |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests | Show retry-after time |

## Non-Functional Requirements

### Security
1. Payment information SHALL be handled securely via Paddle integration
2. Subscription changes SHALL require confirmation
3. Cancellation SHALL include reason tracking for analytics
4. Payment methods SHALL never expose full card numbers

### Performance
1. Plans page SHALL load within 1 second
2. Subscription page SHALL load within 1 second
3. Usage data SHALL be cached for 5 minutes
4. Payment processing SHALL complete within 5 seconds

### Accessibility
1. All forms SHALL be keyboard navigable
2. Plan comparison SHALL be screen reader friendly
3. Usage progress bars SHALL have text alternatives
4. Confirmation dialogs SHALL trap focus

### Usability
1. Plan features SHALL be clearly listed
2. Billing intervals SHALL show savings for annual plans
3. Upgrade/downgrade SHALL show effective dates
4. Usage limits SHALL show reset times
5. Cancellation SHALL be clear about when access ends
