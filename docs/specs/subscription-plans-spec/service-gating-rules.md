# Service Gating Rules Specification

## 1. Overview
Purpose:
- Enforce subscription limits consistently across services
- Provide clear upgrade paths in error responses
- Track usage accurately per service type
- Return appropriate HTTP status codes and structured error bodies

## 2. Gating Middleware Architecture
Flow:
1. Extract user authentication from request
2. Load user's active subscription (plan name, limits)
3. Determine service type from endpoint
4. Check usage limits for service type (daily/monthly/hourly and feature flags)
5. Allow or deny request with appropriate response
6. Increment usage counters on success

## 3. URL Analysis Gating Rules

### Quick URL Scan (POST /api/v1/url-check/check)
```python
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
```

### Deep-Link Audit (POST /api/v1/url-check/deep)
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

### Bulk URL Checking (POST /api/v1/url-check/bulk-check)
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

## 4. Social Protection Gating
- Profile scans: Starter+; monthly limit enforced
- Content assessments: Starter+; monthly limit enforced
- Monitoring: Starter+; enforce max_monitored_profiles
- Crisis detection: Creator+ required
- Radar lens: Business+ required

## 5. Bot Services Gating
- Check plan supports bots (Starter+)
- Per-platform daily limits: twitter/telegram/discord
- Number of connected platforms enforced by plan
- 402 Payment Required if plan does not support bots

## 6. Dashboard Features Gating
- Projects: enforce max_projects
- Team members per project: enforce max_team_members_per_project
- Alerts per project: enforce max_alerts_per_project
- Monitoring frequency: enforce minimum frequency by plan

## 7. AI Analysis Gating
- Basic AI: available to all
- Advanced AI (sentiment, engagement): Creator+
- Custom models: Professional+
- Brand risk scoring: Business+
- Threat intelligence feeds: Enterprise

## 8. Error Response Standards
Standard JSON format for gating errors:
```json
{
  "error": "<error_code>",
  "message": "<human_readable_message>",
  "current_plan": "<plan_name>",
  "required_plan": "<plan_name_optional>",
  "upgrade_url": "/pricing",
  "reset_at": "<reset_hint_optional>"
}
```

HTTP status codes:
- 402 Payment Required: feature not available at current plan
- 429 Too Many Requests: limit exceeded within plan
- 400 Bad Request: request exceeds per-operation constraints (e.g., batch size)

## 9. Usage Tracking
On successful requests:
- Increment corresponding usage counters (daily/monthly/hourly)
- Persist usage with timestamp for reset logic
- Emit analytics events for dashboards

References:
- src/services/subscription_service.py
- src/models/subscription.py