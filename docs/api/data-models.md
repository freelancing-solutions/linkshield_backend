# Data Models & Schemas

This document provides comprehensive documentation for all data models and schemas used in the LinkShield backend system.

## Overview

LinkShield uses SQLAlchemy ORM models for database entities and Pydantic models for request/response validation and serialization. The system is organized into several core domains:

- **User Management**: User accounts, authentication, and API keys
- **URL Checking**: URL analysis, scanning, and results
- **Community Reporting**: User-generated reports and moderation
- **AI Analysis**: Machine learning-powered content analysis
- **Subscriptions**: Billing, plans, and usage tracking
- **Email System**: Templates, logging, and notifications

## User Models

### User

Core user account model with authentication and profile information.

**Table**: `users`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `email` | String(255) | User email address | Required, Unique, Indexed |
| `username` | String(50) | Unique username | Required, Unique, Indexed |
| `password_hash` | String(255) | Hashed password | Required |
| `first_name` | String(100) | User's first name | Optional |
| `last_name` | String(100) | User's last name | Optional |
| `role` | UserRole | User role enum | Required, Default: USER |
| `is_active` | Boolean | Account active status | Required, Default: True |
| `is_verified` | Boolean | Email verification status | Required, Default: False |
| `last_login` | DateTime | Last login timestamp | Optional, Indexed |
| `created_at` | DateTime | Account creation time | Required, Auto-generated |
| `updated_at` | DateTime | Last update time | Required, Auto-updated |

**Enums**:
- `UserRole`: `USER`, `MODERATOR`, `ADMIN`, `SUPER_ADMIN`

**Relationships**:
- `api_keys`: One-to-many with APIKey
- `url_checks`: One-to-many with URLCheck
- `reports`: One-to-many with Report
- `subscription`: One-to-one with UserSubscription

**Methods**:
- `check_password(password: str) -> bool`: Verify password
- `set_password(password: str)`: Set new password hash
- `is_admin() -> bool`: Check admin privileges
- `get_full_name() -> str`: Get formatted full name
- `to_dict(include_sensitive: bool = False) -> dict`: Serialize to dictionary

### APIKey

API key model for programmatic access.

**Table**: `api_keys`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `user_id` | UUID | Foreign key to users | Required, Indexed |
| `name` | String(100) | Key name/description | Required |
| `key_hash` | String(255) | Hashed API key | Required, Unique |
| `key_prefix` | String(20) | Key prefix for identification | Required, Indexed |
| `permissions` | JSON | List of permissions | Optional |
| `is_active` | Boolean | Key active status | Required, Default: True |
| `last_used` | DateTime | Last usage timestamp | Optional |
| `expires_at` | DateTime | Expiration timestamp | Optional, Indexed |
| `created_at` | DateTime | Creation timestamp | Required |

**Methods**:
- `is_expired() -> bool`: Check if key is expired
- `has_permission(permission: str) -> bool`: Check specific permission
- `to_dict() -> dict`: Serialize to dictionary

## URL Check Models

### URLCheck

Core model for URL analysis and scanning results.

**Table**: `url_checks`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `user_id` | UUID | Foreign key to users | Optional, Indexed |
| `url` | String(2048) | Target URL | Required, Indexed |
| `domain` | String(255) | Extracted domain | Required, Indexed |
| `scan_type` | ScanType | Type of scan performed | Required |
| `status` | String(20) | Scan status | Required, Indexed |
| `is_safe` | Boolean | Safety determination | Optional |
| `risk_score` | Float | Risk score (0-1) | Optional |
| `scan_results` | JSON | Detailed scan results | Optional |
| `metadata` | JSON | Additional metadata | Optional |
| `user_agent` | String(500) | Client user agent | Optional |
| `ip_address` | String(45) | Client IP address | Optional |
| `created_at` | DateTime | Scan timestamp | Required, Indexed |
| `completed_at` | DateTime | Completion timestamp | Optional |

**Enums**:
- `ScanType`: `QUICK`, `DEEP`, `SCHEDULED`, `API`

**Relationships**:
- `user`: Many-to-one with User
- `reports`: One-to-many with Report
- `ai_analyses`: One-to-many with AIAnalysis

**Methods**:
- `is_completed() -> bool`: Check if scan is complete
- `get_age_minutes() -> int`: Get scan age in minutes
- `to_dict() -> dict`: Serialize to dictionary

## Report Models

### Report

Community reporting system for malicious URLs.

**Table**: `reports`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `user_id` | UUID | Foreign key to users | Required, Indexed |
| `url_check_id` | UUID | Foreign key to url_checks | Optional, Indexed |
| `report_type` | ReportType | Type of report | Required, Indexed |
| `status` | ReportStatus | Report status | Required, Indexed |
| `priority` | ReportPriority | Report priority | Required, Default: MEDIUM |
| `reported_url` | String(2048) | Reported URL | Required |
| `domain` | String(255) | Extracted domain | Required, Indexed |
| `title` | String(200) | Report title | Optional |
| `description` | Text | Report description | Required |
| `evidence` | JSON | Supporting evidence | Optional |
| `reporter_email` | String(255) | Reporter email | Optional |
| `reporter_ip` | String(45) | Reporter IP | Optional |
| `user_agent` | String(500) | Reporter user agent | Optional |
| `reviewed_by` | UUID | Reviewer user ID | Optional |
| `reviewed_at` | DateTime | Review timestamp | Optional |
| `review_notes` | Text | Review notes | Optional |
| `resolution` | String(50) | Resolution type | Optional |
| `resolved_at` | DateTime | Resolution timestamp | Optional |
| `is_verified` | Boolean | Verification status | Default: False |
| `confidence_score` | Float | Confidence score | Optional |
| `tags` | JSON | Report tags | Optional |
| `created_at` | DateTime | Creation timestamp | Required |
| `updated_at` | DateTime | Update timestamp | Required |

**Enums**:
- `ReportType`: `PHISHING`, `MALWARE`, `SCAM`, `SPAM`, `INAPPROPRIATE`, `COPYRIGHT`, `OTHER`
- `ReportStatus`: `PENDING`, `UNDER_REVIEW`, `RESOLVED`, `REJECTED`, `DUPLICATE`
- `ReportPriority`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

**Relationships**:
- `user`: Many-to-one with User
- `reviewer`: Many-to-one with User
- `url_check`: Many-to-one with URLCheck
- `votes`: One-to-many with ReportVote

**Methods**:
- `is_pending_review() -> bool`: Check if pending review
- `is_resolved() -> bool`: Check if resolved
- `get_age_days() -> int`: Get report age in days
- `get_vote_summary() -> dict`: Get voting statistics
- `calculate_priority() -> ReportPriority`: Calculate priority
- `to_dict() -> dict`: Serialize to dictionary

### ReportVote

Community voting system for reports.

**Table**: `report_votes`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `report_id` | UUID | Foreign key to reports | Required, Indexed |
| `user_id` | UUID | Foreign key to users | Required, Indexed |
| `vote_type` | VoteType | Type of vote | Required |
| `created_at` | DateTime | Vote timestamp | Required |

**Enums**:
- `VoteType`: `UPVOTE`, `DOWNVOTE`

**Unique Constraints**:
- `(report_id, user_id)`: One vote per user per report

## AI Analysis Models

### AIAnalysis

AI-powered content analysis results.

**Table**: `ai_analyses`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `url_check_id` | UUID | Foreign key to url_checks | Required, Indexed |
| `analysis_type` | AnalysisType | Type of analysis | Required, Indexed |
| `status` | ProcessingStatus | Processing status | Required, Indexed |
| `model_name` | String(100) | AI model used | Required |
| `model_version` | String(50) | Model version | Required |
| `confidence_score` | Float | Confidence score (0-1) | Optional |
| `risk_score` | Float | Risk assessment (0-1) | Optional |
| `quality_score` | Float | Content quality (0-1) | Optional |
| `results` | JSON | Analysis results | Optional |
| `metadata` | JSON | Analysis metadata | Optional |
| `processing_time_ms` | Integer | Processing time | Optional |
| `error_message` | Text | Error details | Optional |
| `created_at` | DateTime | Creation timestamp | Required |
| `completed_at` | DateTime | Completion timestamp | Optional |

**Enums**:
- `AnalysisType`: `PHISHING_DETECTION`, `MALWARE_SCAN`, `CONTENT_CLASSIFICATION`, `SENTIMENT_ANALYSIS`, `LANGUAGE_DETECTION`
- `ProcessingStatus`: `PENDING`, `PROCESSING`, `COMPLETED`, `FAILED`, `CANCELLED`

**Relationships**:
- `url_check`: Many-to-one with URLCheck
- `similar_content`: One-to-many with ContentSimilarity

**Methods**:
- `is_completed() -> bool`: Check completion status
- `get_processing_time() -> Optional[int]`: Get processing duration
- `to_dict() -> dict`: Serialize to dictionary

### ContentSimilarity

Content similarity matching results.

**Table**: `content_similarities`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `source_analysis_id` | UUID | Source analysis ID | Required, Indexed |
| `target_analysis_id` | UUID | Target analysis ID | Required, Indexed |
| `similarity_score` | Float | Similarity score (0-1) | Required |
| `similarity_type` | String(50) | Type of similarity | Required |
| `metadata` | JSON | Similarity metadata | Optional |
| `created_at` | DateTime | Creation timestamp | Required |

## Subscription Models

### SubscriptionPlan

Available subscription plans and features.

**Table**: `subscription_plans`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `name` | String(100) | Plan name | Required, Unique |
| `display_name` | String(100) | Display name | Required |
| `description` | Text | Plan description | Optional |
| `plan_type` | PlanType | Plan type enum | Required, Indexed |
| `monthly_price` | Decimal(10,2) | Monthly price | Required, Default: 0 |
| `yearly_price` | Decimal(10,2) | Yearly price | Required, Default: 0 |
| `currency` | String(3) | Currency code | Required, Default: USD |
| `daily_check_limit` | Integer | Daily check limit | Required, Default: 0 |
| `monthly_check_limit` | Integer | Monthly check limit | Required, Default: 0 |
| `api_rate_limit` | Integer | API rate limit (per minute) | Required, Default: 60 |
| `features` | JSON | Feature flags | Optional |
| `ai_analysis_enabled` | Boolean | AI analysis access | Default: False |
| `bulk_checking_enabled` | Boolean | Bulk checking access | Default: False |
| `api_access_enabled` | Boolean | API access | Default: False |
| `priority_support` | Boolean | Priority support | Default: False |
| `custom_branding` | Boolean | Custom branding | Default: False |
| `is_active` | Boolean | Plan active status | Default: True |
| `is_public` | Boolean | Public visibility | Default: True |
| `trial_days` | Integer | Trial period days | Optional, Default: 0 |
| `stripe_price_id_monthly` | String(100) | Stripe monthly price ID | Optional |
| `stripe_price_id_yearly` | String(100) | Stripe yearly price ID | Optional |
| `stripe_product_id` | String(100) | Stripe product ID | Optional |
| `created_at` | DateTime | Creation timestamp | Required |
| `updated_at` | DateTime | Update timestamp | Required |

**Enums**:
- `PlanType`: `FREE`, `BASIC`, `PRO`, `ENTERPRISE`, `CUSTOM`

**Methods**:
- `get_price(billing_interval: BillingInterval) -> Decimal`: Get price for interval
- `get_stripe_price_id(billing_interval: BillingInterval) -> Optional[str]`: Get Stripe price ID
- `has_feature(feature: str) -> bool`: Check feature availability
- `to_dict() -> dict`: Serialize to dictionary

### UserSubscription

User subscription tracking and billing.

**Table**: `user_subscriptions`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `user_id` | UUID | Foreign key to users | Required, Indexed |
| `plan_id` | UUID | Foreign key to subscription_plans | Required, Indexed |
| `status` | SubscriptionStatus | Subscription status | Required, Indexed |
| `billing_interval` | BillingInterval | Billing frequency | Required |
| `current_period_start` | DateTime | Current period start | Required |
| `current_period_end` | DateTime | Current period end | Required, Indexed |
| `next_billing_date` | DateTime | Next billing date | Optional, Indexed |
| `trial_start` | DateTime | Trial start date | Optional |
| `trial_end` | DateTime | Trial end date | Optional, Indexed |
| `is_trial` | Boolean | Trial status | Default: False |
| `cancelled_at` | DateTime | Cancellation date | Optional |
| `cancel_at_period_end` | Boolean | Cancel at period end | Default: False |
| `cancellation_reason` | Text | Cancellation reason | Optional |
| `stripe_subscription_id` | String(100) | Stripe subscription ID | Optional, Unique |
| `stripe_customer_id` | String(100) | Stripe customer ID | Optional |
| `daily_checks_used` | Integer | Daily checks used | Default: 0 |
| `monthly_checks_used` | Integer | Monthly checks used | Default: 0 |
| `last_usage_reset` | DateTime | Last usage reset | Required |
| `created_at` | DateTime | Creation timestamp | Required |
| `updated_at` | DateTime | Update timestamp | Required |

**Enums**:
- `SubscriptionStatus`: `ACTIVE`, `INACTIVE`, `CANCELLED`, `EXPIRED`, `SUSPENDED`, `TRIAL`, `PAST_DUE`
- `BillingInterval`: `MONTHLY`, `YEARLY`, `LIFETIME`

**Relationships**:
- `user`: One-to-one with User
- `plan`: Many-to-one with SubscriptionPlan
- `payments`: One-to-many with Payment
- `usage_records`: One-to-many with UsageRecord

**Methods**:
- `is_active() -> bool`: Check active status
- `is_expired() -> bool`: Check expiration
- `is_in_trial() -> bool`: Check trial status
- `days_until_renewal() -> int`: Days until renewal
- `can_use_feature(feature: str) -> bool`: Check feature access
- `get_usage_limits() -> Dict[str, int]`: Get usage limits
- `can_make_check() -> bool`: Check if can make URL check
- `increment_usage()`: Increment usage counters
- `reset_daily_usage()`: Reset daily usage
- `reset_monthly_usage()`: Reset monthly usage
- `to_dict(include_sensitive: bool = False) -> dict`: Serialize to dictionary

### Payment

Payment transaction tracking.

**Table**: `payments`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required, Indexed |
| `user_id` | UUID | Foreign key to users | Required, Indexed |
| `subscription_id` | UUID | Foreign key to user_subscriptions | Optional, Indexed |
| `amount` | Decimal(10,2) | Payment amount | Required |
| `currency` | String(3) | Currency code | Required, Default: USD |
| `status` | PaymentStatus | Payment status | Required, Indexed |
| `payment_method` | String(50) | Payment method | Optional |
| `payment_method_details` | JSON | Payment method details | Optional |
| `stripe_payment_intent_id` | String(100) | Stripe payment intent ID | Optional, Unique |
| `stripe_charge_id` | String(100) | Stripe charge ID | Optional |
| `processor_fee` | Decimal(10,2) | Processing fee | Optional |
| `description` | Text | Payment description | Optional |
| `invoice_number` | String(50) | Invoice number | Optional, Unique |
| `receipt_url` | String(500) | Receipt URL | Optional |
| `failure_code` | String(50) | Failure code | Optional |
| `failure_message` | Text | Failure message | Optional |
| `refunded_amount` | Decimal(10,2) | Refunded amount | Optional, Default: 0 |
| `refund_reason` | Text | Refund reason | Optional |
| `processed_at` | DateTime | Processing timestamp | Optional |
| `created_at` | DateTime | Creation timestamp | Required, Indexed |
| `updated_at` | DateTime | Update timestamp | Required |

**Enums**:
- `PaymentStatus`: `PENDING`, `COMPLETED`, `FAILED`, `REFUNDED`, `CANCELLED`

**Methods**:
- `is_successful() -> bool`: Check success status
- `is_refunded() -> bool`: Check refund status
- `get_net_amount() -> Decimal`: Get net amount after fees/refunds
- `to_dict(include_sensitive: bool = False) -> dict`: Serialize to dictionary

## Email Models

### EmailLog

Email delivery tracking and logging.

**Table**: `email_logs`

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key | Required |
| `recipient` | String(255) | Recipient email | Required, Indexed |
| `sender` | String(255) | Sender email | Optional |
| `subject` | String(500) | Email subject | Required |
| `email_type` | String(50) | Email type | Required, Indexed |
| `provider` | String(20) | Email provider | Required |
| `status` | EmailStatus | Delivery status | Required, Indexed |
| `external_id` | String(255) | Provider email ID | Optional, Indexed |
| `error_message` | Text | Error details | Optional |
| `email_metadata` | JSON | Email metadata | Optional |
| `created_at` | DateTime | Creation timestamp | Required |
| `sent_at` | DateTime | Send timestamp | Optional |
| `delivered_at` | DateTime | Delivery timestamp | Optional |
| `failed_at` | DateTime | Failure timestamp | Optional |
| `retry_count` | Integer | Retry attempts | Default: 0 |
| `max_retries` | Integer | Maximum retries | Default: 3 |

**Enums**:
- `EmailStatus`: `PENDING`, `SENT`, `DELIVERED`, `FAILED`, `BOUNCED`, `REJECTED`
- `EmailType`: `VERIFICATION`, `PASSWORD_RESET`, `WELCOME`, `NOTIFICATION`, `SECURITY_ALERT`, `BULK`
- `EmailProvider`: `SMTP`, `RESEND`

## Request/Response Models

### Pydantic Models

The system uses Pydantic models for API request/response validation:

#### URL Check Models
- `URLCheckRequest`: URL checking request
- `BulkURLCheckRequest`: Bulk URL checking request
- `ScanResultResponse`: Scan result response
- `URLCheckListResponse`: URL check list response

#### Report Models
- `ReportCreateRequest`: Report creation request
- `ReportUpdateRequest`: Report update request
- `ReportResponse`: Report response
- `ReportListResponse`: Report list response
- `ReportVoteRequest`: Report voting request
- `ReportResolveRequest`: Report resolution request
- `ReportAssignRequest`: Report assignment request
- `ReportStatsResponse`: Report statistics response

#### AI Analysis Models
- `AIAnalysisRequest`: AI analysis request
- `AIAnalysisResponse`: AI analysis response
- `SimilarContentResponse`: Similar content response
- `DomainStatsResponse`: Domain statistics response
- `AnalysisHistoryResponse`: Analysis history response

#### Email Models
- `EmailRequest`: Single email request
- `BulkEmailRequest`: Bulk email request
- `EmailTemplate`: Email template data
- `EmailLogResponse`: Email log response
- `EmailStats`: Email statistics
- `EmailPreferences`: User email preferences
- `EmailValidationResult`: Email validation result

## Validation Rules

### Common Validations
- **Email addresses**: RFC 5322 compliant
- **URLs**: Valid HTTP/HTTPS format, max 2048 characters
- **UUIDs**: Valid UUID4 format
- **Passwords**: Minimum 8 characters, complexity requirements
- **File uploads**: Size limits, type restrictions
- **Rate limits**: Per-user, per-endpoint limits

### Field Constraints
- **String lengths**: Enforced at database and API level
- **Numeric ranges**: Risk scores (0-1), priorities (1-5)
- **Enum values**: Strict validation against defined enums
- **Required fields**: Non-nullable database constraints
- **Unique constraints**: Email, username, API keys

## Relationships & Foreign Keys

### Key Relationships
- **User → URLCheck**: One-to-many (user can have multiple checks)
- **User → Report**: One-to-many (user can create multiple reports)
- **User → UserSubscription**: One-to-one (user has one active subscription)
- **URLCheck → Report**: One-to-many (URL can have multiple reports)
- **URLCheck → AIAnalysis**: One-to-many (URL can have multiple analyses)
- **Report → ReportVote**: One-to-many (report can have multiple votes)
- **SubscriptionPlan → UserSubscription**: One-to-many (plan can have multiple subscribers)
- **UserSubscription → Payment**: One-to-many (subscription can have multiple payments)

### Cascade Behaviors
- **User deletion**: Cascades to related records (URLCheck, Report, etc.)
- **Subscription deletion**: Sets foreign keys to NULL in payments
- **Report deletion**: Cascades to votes
- **URLCheck deletion**: Cascades to AI analyses

## Indexes & Performance

### Database Indexes
- **Primary keys**: Automatic UUID indexes
- **Foreign keys**: Indexed for join performance
- **Query fields**: Status, timestamps, email addresses
- **Composite indexes**: User+status, date ranges

### Query Optimization
- **Pagination**: Cursor-based for large datasets
- **Filtering**: Indexed fields for common filters
- **Sorting**: Indexed timestamp fields
- **Aggregations**: Optimized for statistics queries

## Security Considerations

### Data Protection
- **Password hashing**: bcrypt with salt
- **API key hashing**: Secure hash storage
- **PII encryption**: Sensitive data encryption at rest
- **Access control**: Role-based permissions

### Audit Trail
- **Timestamps**: Creation and update tracking
- **User tracking**: User ID on all user-generated content
- **IP logging**: Request source tracking
- **Change history**: Audit logs for sensitive operations

## Migration Strategy

### Schema Changes
- **Backward compatibility**: Non-breaking changes preferred
- **Migration scripts**: Automated database migrations
- **Data validation**: Post-migration integrity checks
- **Rollback procedures**: Safe rollback mechanisms

### Version Management
- **Model versioning**: Semantic versioning for API changes
- **Deprecation policy**: Gradual deprecation of old fields
- **Documentation updates**: Synchronized with code changes