#!/usr/bin/env python3
"""
LinkShield Backend Subscription Schemas

Pydantic models for subscription API requests and responses.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid

from pydantic import BaseModel, Field


class BillingInterval(str, Enum):
    """Billing interval enumeration for subscription plans."""
    MONTHLY = "monthly"
    YEARLY = "yearly"


class SubscriptionStatus(str, Enum):
    """Subscription status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    PAST_DUE = "past_due"


class UsageType(str, Enum):
    """Usage type enumeration for tracking subscription usage."""
    LINK_CHECK = "link_check"
    BULK_CHECK = "bulk_check"
    AI_ANALYSIS = "ai_analysis"
    API_CALL = "api_call"
    MONITORING = "monitoring"


class SubscriptionCreate(BaseModel):
    """Request model for creating a new subscription."""
    
    plan_name: str = Field(
        ...,
        description="Name of the subscription plan to create",
        examples=["free", "basic", "pro", "enterprise"]
    )
    
    billing_interval: BillingInterval = Field(
        ...,
        description="Billing interval for the subscription",
        examples=["monthly", "yearly"]
    )
    
    trial_days: Optional[int] = Field(
        None,
        description="Optional trial period in days (overrides plan default)",
        ge=0,
        le=365
    )

    class Config:
        schema_extra = {
            "example": {
                "plan_name": "pro",
                "billing_interval": "monthly",
                "trial_days": 14
            }
        }


class SubscriptionUpdate(BaseModel):
    """Request model for updating an existing subscription."""
    
    new_plan_name: str = Field(
        ...,
        description="Name of the new subscription plan",
        examples=["free", "basic", "pro", "enterprise"]
    )
    
    billing_interval: Optional[BillingInterval] = Field(
        None,
        description="Optional new billing interval",
        examples=["monthly", "yearly"]
    )

    class Config:
        schema_extra = {
            "example": {
                "new_plan_name": "enterprise",
                "billing_interval": "yearly"
            }
        }


class SubscriptionCancel(BaseModel):
    """Request model for cancelling a subscription."""
    
    cancel_at_period_end: bool = Field(
        True,
        description="Whether to cancel at the end of the billing period or immediately"
    )
    
    reason: Optional[str] = Field(
        None,
        description="Optional reason for cancellation",
        max_length=500
    )

    class Config:
        schema_extra = {
            "example": {
                "cancel_at_period_end": True,
                "reason": "Switching to a different service"
            }
        }


class SubscriptionPlanResponse(BaseModel):
    """Response model for subscription plan details."""
    
    name: str = Field(..., description="Internal plan name")
    display_name: str = Field(..., description="Display name for the plan")
    description: Optional[str] = Field(None, description="Plan description")
    monthly_price: float = Field(..., description="Monthly price in USD")
    yearly_price: float = Field(..., description="Yearly price in USD")
    currency: str = Field(..., description="Currency code")
    daily_check_limit: int = Field(..., description="Daily link check limit")
    monthly_check_limit: int = Field(..., description="Monthly link check limit")
    api_rate_limit: int = Field(..., description="API rate limit (requests per minute)")
    max_projects: int = Field(..., description="Maximum projects allowed")
    max_team_members_per_project: int = Field(..., description="Maximum team members per project")
    max_alerts_per_project: int = Field(..., description="Maximum alerts per project")
    monitoring_frequency_minutes: int = Field(..., description="Minimum monitoring frequency in minutes")
    scan_depth_limit: int = Field(..., description="Maximum scan depth for link analysis")
    max_links_per_scan: int = Field(..., description="Maximum links processed per scan")
    ai_analysis_enabled: bool = Field(..., description="Whether AI analysis is enabled")
    bulk_checking_enabled: bool = Field(..., description="Whether bulk checking is enabled")
    api_access_enabled: bool = Field(..., description="Whether API access is enabled")
    priority_support: bool = Field(..., description="Whether priority support is included")
    custom_branding: bool = Field(..., description="Whether custom branding is allowed")
    trial_days: int = Field(..., description="Trial period in days")

    class Config:
        from_attributes = True


class SubscriptionResponse(BaseModel):
    """Response model for subscription details."""
    
    id: uuid.UUID = Field(..., description="Subscription ID")
    user_id: uuid.UUID = Field(..., description="User ID")
    plan_name: str = Field(..., description="Subscription plan name")
    status: SubscriptionStatus = Field(..., description="Subscription status")
    billing_interval: BillingInterval = Field(..., description="Billing interval")
    current_period_start: datetime = Field(..., description="Current billing period start")
    current_period_end: datetime = Field(..., description="Current billing period end")
    next_billing_date: Optional[datetime] = Field(None, description="Next billing date")
    is_trial: bool = Field(..., description="Whether subscription is in trial period")
    trial_start: Optional[datetime] = Field(None, description="Trial period start")
    trial_end: Optional[datetime] = Field(None, description="Trial period end")
    cancel_at_period_end: bool = Field(..., description="Whether to cancel at period end")
    cancelled_at: Optional[datetime] = Field(None, description="Cancellation date")
    cancellation_reason: Optional[str] = Field(None, description="Cancellation reason")
    daily_checks_used: int = Field(..., description="Daily checks used")
    monthly_checks_used: int = Field(..., description="Monthly checks used")
    last_usage_reset: datetime = Field(..., description="Last usage reset time")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    plan_details: Optional[SubscriptionPlanResponse] = Field(None, description="Plan details")

    class Config:
        from_attributes = True


class SubscriptionUsageResponse(BaseModel):
    """Response model for subscription usage information."""
    
    has_subscription: bool = Field(..., description="Whether user has an active subscription")
    plan_name: str = Field(..., description="Current plan name")
    daily_used: int = Field(..., description="Daily checks used")
    daily_limit: int = Field(..., description="Daily check limit")
    monthly_used: int = Field(..., description="Monthly checks used")
    monthly_limit: int = Field(..., description="Monthly check limit")
    has_daily_limit: bool = Field(..., description="Whether daily limit is enforced")
    has_monthly_limit: bool = Field(..., description="Whether monthly limit is enforced")
    daily_remaining: int = Field(..., description="Remaining daily checks")
    monthly_remaining: int = Field(..., description="Remaining monthly checks")
    is_over_limit: bool = Field(..., description="Whether usage is over limit")

    class Config:
        from_attributes = True


class SubscriptionCancellationResponse(BaseModel):
    """Response model for subscription cancellation."""
    
    id: uuid.UUID = Field(..., description="Subscription ID")
    status: SubscriptionStatus = Field(..., description="New subscription status")
    cancel_at_period_end: bool = Field(..., description="Whether cancellation is at period end")
    cancelled_at: Optional[datetime] = Field(None, description="Cancellation timestamp")
    cancellation_reason: Optional[str] = Field(None, description="Cancellation reason")
    current_period_end: datetime = Field(..., description="Current period end date")
    updated_at: datetime = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True


class SubscriptionListResponse(BaseModel):
    """Response model for listing available subscription plans."""
    
    plans: List[SubscriptionPlanResponse] = Field(..., description="List of available subscription plans")

    class Config:
        from_attributes = True


class ErrorResponse(BaseModel):
    """Standard error response model for subscription operations."""
    
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code for programmatic handling")

    class Config:
        schema_extra = {
            "example": {
                "detail": "Subscription not found",
                "error_code": "SUBSCRIPTION_NOT_FOUND"
            }
        }