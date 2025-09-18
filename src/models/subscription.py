#!/usr/bin/env python3
"""
LinkShield Backend Subscription Models

SQLAlchemy models for user subscriptions, billing, and plan management.
Includes subscription plans, user subscriptions, usage tracking, and billing history.
"""

import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Dict, Any, Optional, List

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    Numeric,
    String,
    Text,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.config.database import Base
import enum

class PlanType(enum.Enum):
    """
    Subscription plan type enumeration.
    """
    FREE = "free"
    BASIC = "basic"
    PRO = "pro"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class BillingInterval(enum.Enum):
    """
    Billing interval enumeration.
    """
    MONTHLY = "monthly"
    YEARLY = "yearly"
    LIFETIME = "lifetime"


class SubscriptionStatus(enum.Enum):
    """
    Subscription status enumeration.
    """
    ACTIVE = "active"
    INACTIVE = "inactive"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    PAST_DUE = "past_due"


class PaymentStatus(enum.Enum):
    """
    Payment status enumeration.
    """
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"


class SubscriptionPlan(Base):
    """
    Subscription plan model defining available plans and their features.
    """
    __tablename__ = "subscription_plans"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Plan information
    name = Column(String(100), nullable=False, unique=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    plan_type = Column(Enum(PlanType), nullable=False, index=True)
    
    # Pricing
    monthly_price = Column(Numeric(10, 2), nullable=False, default=0)
    yearly_price = Column(Numeric(10, 2), nullable=False, default=0)
    currency = Column(String(3), nullable=False, default="USD")
    
    # Usage limits
    daily_check_limit = Column(Integer, nullable=False, default=0)
    monthly_check_limit = Column(Integer, nullable=False, default=0)
    api_rate_limit = Column(Integer, nullable=False, default=60)  # requests per minute
    
    # Features
    features = Column(JSON, nullable=True)  # List of feature flags
    ai_analysis_enabled = Column(Boolean, default=False, nullable=False)
    bulk_checking_enabled = Column(Boolean, default=False, nullable=False)
    api_access_enabled = Column(Boolean, default=False, nullable=False)
    priority_support = Column(Boolean, default=False, nullable=False)
    custom_branding = Column(Boolean, default=False, nullable=False)
    
    # Configuration
    is_active = Column(Boolean, default=True, nullable=False)
    is_public = Column(Boolean, default=True, nullable=False)
    trial_days = Column(Integer, nullable=True, default=0)
    
    # External IDs for payment processors
    stripe_price_id_monthly = Column(String(100), nullable=True)
    stripe_price_id_yearly = Column(String(100), nullable=True)
    stripe_product_id = Column(String(100), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    subscriptions = relationship("UserSubscription", back_populates="plan")
    
    def __repr__(self) -> str:
        return f"<SubscriptionPlan(id={self.id}, name={self.name}, type={self.plan_type})>"
    
    def get_price(self, billing_interval: BillingInterval) -> Decimal:
        """
        Get price for specific billing interval.
        """
        if billing_interval == BillingInterval.MONTHLY:
            return self.monthly_price
        elif billing_interval == BillingInterval.YEARLY:
            return self.yearly_price
        else:
            return Decimal(0)
    
    def get_stripe_price_id(self, billing_interval: BillingInterval) -> Optional[str]:
        """
        Get Stripe price ID for specific billing interval.
        """
        if billing_interval == BillingInterval.MONTHLY:
            return self.stripe_price_id_monthly
        elif billing_interval == BillingInterval.YEARLY:
            return self.stripe_price_id_yearly
        return None
    
    def has_feature(self, feature: str) -> bool:
        """
        Check if plan has specific feature.
        """
        if not self.features:
            return False
        return feature in self.features
    
    def to_dict(self) -> dict:
        """
        Convert subscription plan to dictionary representation.
        """
        return {
            "id": str(self.id),
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "plan_type": self.plan_type.value,
            "monthly_price": float(self.monthly_price),
            "yearly_price": float(self.yearly_price),
            "currency": self.currency,
            "daily_check_limit": self.daily_check_limit,
            "monthly_check_limit": self.monthly_check_limit,
            "api_rate_limit": self.api_rate_limit,
            "features": self.features,
            "ai_analysis_enabled": self.ai_analysis_enabled,
            "bulk_checking_enabled": self.bulk_checking_enabled,
            "api_access_enabled": self.api_access_enabled,
            "priority_support": self.priority_support,
            "custom_branding": self.custom_branding,
            "is_active": self.is_active,
            "is_public": self.is_public,
            "trial_days": self.trial_days,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class UserSubscription(Base):
    """
    User subscription model tracking active subscriptions and billing.
    """
    __tablename__ = "user_subscriptions"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id = Column(UUID(as_uuid=True), ForeignKey("subscription_plans.id"), nullable=False, index=True)
    
    # Subscription details
    status = Column(Enum(SubscriptionStatus), default=SubscriptionStatus.ACTIVE, nullable=False, index=True)
    billing_interval = Column(Enum(BillingInterval), nullable=False)
    
    # Billing information
    current_period_start = Column(DateTime(timezone=True), nullable=False)
    current_period_end = Column(DateTime(timezone=True), nullable=False, index=True)
    next_billing_date = Column(DateTime(timezone=True), nullable=True, index=True)
    
    # Trial information
    trial_start = Column(DateTime(timezone=True), nullable=True)
    trial_end = Column(DateTime(timezone=True), nullable=True, index=True)
    is_trial = Column(Boolean, default=False, nullable=False)
    
    # Cancellation information
    cancelled_at = Column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end = Column(Boolean, default=False, nullable=False)
    cancellation_reason = Column(Text, nullable=True)
    
    # External IDs for payment processors
    stripe_subscription_id = Column(String(100), nullable=True, unique=True)
    stripe_customer_id = Column(String(100), nullable=True)
    
    # Usage tracking
    daily_checks_used = Column(Integer, default=0, nullable=False)
    monthly_checks_used = Column(Integer, default=0, nullable=False)
    last_usage_reset = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="subscription")
    plan = relationship("SubscriptionPlan", back_populates="subscriptions")
    payments = relationship("Payment", back_populates="subscription", cascade="all, delete-orphan")
    usage_records = relationship("UsageRecord", back_populates="subscription", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_user_subscriptions_user_status", "user_id", "status"),
        Index("idx_user_subscriptions_period_end", "current_period_end"),
    )
    
    def __repr__(self) -> str:
        return f"<UserSubscription(id={self.id}, user_id={self.user_id}, status={self.status})>"
    
    def is_active(self) -> bool:
        """
        Check if subscription is currently active.
        """
        return self.status in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL]
    
    def is_expired(self) -> bool:
        """
        Check if subscription is expired.
        """
        now = datetime.now(timezone.utc)
        return self.current_period_end < now and not self.cancel_at_period_end
    
    def is_in_trial(self) -> bool:
        """
        Check if subscription is in trial period.
        """
        if not self.is_trial or not self.trial_end:
            return False
        return datetime.now(timezone.utc) < self.trial_end
    
    def days_until_renewal(self) -> int:
        """
        Get days until next renewal.
        """
        if not self.next_billing_date:
            return 0
        delta = self.next_billing_date - datetime.now(timezone.utc)
        return max(0, delta.days)
    
    def can_use_feature(self, feature: str) -> bool:
        """
        Check if user can use specific feature based on their plan.
        """
        if not self.is_active():
            return False
        return self.plan.has_feature(feature)
    
    def get_usage_limits(self) -> Dict[str, int]:
        """
        Get current usage limits.
        """
        return {
            "daily_limit": self.plan.daily_check_limit,
            "monthly_limit": self.plan.monthly_check_limit,
            "daily_used": self.daily_checks_used,
            "monthly_used": self.monthly_checks_used,
            "daily_remaining": max(0, self.plan.daily_check_limit - self.daily_checks_used),
            "monthly_remaining": max(0, self.plan.monthly_check_limit - self.monthly_checks_used),
        }
    
    def can_make_check(self) -> bool:
        """
        Check if user can make another URL check based on limits.
        """
        if not self.is_active():
            return False
        
        # Check daily limit
        if self.plan.daily_check_limit > 0 and self.daily_checks_used >= self.plan.daily_check_limit:
            return False
        
        # Check monthly limit
        if self.plan.monthly_check_limit > 0 and self.monthly_checks_used >= self.plan.monthly_check_limit:
            return False
        
        return True
    
    def increment_usage(self) -> None:
        """
        Increment usage counters.
        """
        self.daily_checks_used += 1
        self.monthly_checks_used += 1
    
    def reset_daily_usage(self) -> None:
        """
        Reset daily usage counter.
        """
        self.daily_checks_used = 0
        self.last_usage_reset = datetime.now(timezone.utc)
    
    def reset_monthly_usage(self) -> None:
        """
        Reset monthly usage counter.
        """
        self.monthly_checks_used = 0
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user subscription to dictionary representation.
        """
        data = {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "plan_id": str(self.plan_id),
            "status": self.status.value,
            "billing_interval": self.billing_interval.value,
            "current_period_start": self.current_period_start.isoformat() if self.current_period_start else None,
            "current_period_end": self.current_period_end.isoformat() if self.current_period_end else None,
            "next_billing_date": self.next_billing_date.isoformat() if self.next_billing_date else None,
            "is_trial": self.is_trial,
            "trial_end": self.trial_end.isoformat() if self.trial_end else None,
            "cancel_at_period_end": self.cancel_at_period_end,
            "days_until_renewal": self.days_until_renewal(),
            "usage_limits": self.get_usage_limits(),
            "plan": self.plan.to_dict() if self.plan else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_sensitive:
            data.update({
                "stripe_subscription_id": self.stripe_subscription_id,
                "stripe_customer_id": self.stripe_customer_id,
                "cancelled_at": self.cancelled_at.isoformat() if self.cancelled_at else None,
                "cancellation_reason": self.cancellation_reason,
            })
        
        return data


class Payment(Base):
    """
    Payment model for tracking billing transactions.
    """
    __tablename__ = "payments"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    subscription_id = Column(UUID(as_uuid=True), ForeignKey("user_subscriptions.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Payment information
    amount = Column(Numeric(10, 2), nullable=False)
    currency = Column(String(3), nullable=False, default="USD")
    status = Column(Enum(PaymentStatus), nullable=False, index=True)
    
    # Payment method
    payment_method = Column(String(50), nullable=True)  # card, paypal, etc.
    payment_method_details = Column(JSON, nullable=True)  # Last 4 digits, brand, etc.
    
    # External payment processor information
    stripe_payment_intent_id = Column(String(100), nullable=True, unique=True)
    stripe_charge_id = Column(String(100), nullable=True)
    processor_fee = Column(Numeric(10, 2), nullable=True)
    
    # Transaction details
    description = Column(Text, nullable=True)
    invoice_number = Column(String(50), nullable=True, unique=True)
    receipt_url = Column(String(500), nullable=True)
    
    # Failure information
    failure_code = Column(String(50), nullable=True)
    failure_message = Column(Text, nullable=True)
    
    # Refund information
    refunded_amount = Column(Numeric(10, 2), nullable=True, default=0)
    refund_reason = Column(Text, nullable=True)
    
    # Timestamps
    processed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User")
    subscription = relationship("UserSubscription", back_populates="payments")
    
    def __repr__(self) -> str:
        return f"<Payment(id={self.id}, amount={self.amount}, status={self.status})>"
    
    def is_successful(self) -> bool:
        """
        Check if payment was successful.
        """
        return self.status == PaymentStatus.COMPLETED
    
    def is_refunded(self) -> bool:
        """
        Check if payment was refunded.
        """
        return self.status == PaymentStatus.REFUNDED or (self.refunded_amount and self.refunded_amount > 0)
    
    def get_net_amount(self) -> Decimal:
        """
        Get net amount after fees and refunds.
        """
        net = self.amount
        if self.processor_fee:
            net -= self.processor_fee
        if self.refunded_amount:
            net -= self.refunded_amount
        return net
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert payment to dictionary representation.
        """
        data = {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "subscription_id": str(self.subscription_id) if self.subscription_id else None,
            "amount": float(self.amount),
            "currency": self.currency,
            "status": self.status.value,
            "payment_method": self.payment_method,
            "description": self.description,
            "invoice_number": self.invoice_number,
            "receipt_url": self.receipt_url,
            "refunded_amount": float(self.refunded_amount) if self.refunded_amount else 0,
            "net_amount": float(self.get_net_amount()),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_sensitive:
            data.update({
                "stripe_payment_intent_id": self.stripe_payment_intent_id,
                "stripe_charge_id": self.stripe_charge_id,
                "processor_fee": float(self.processor_fee) if self.processor_fee else None,
                "payment_method_details": self.payment_method_details,
                "failure_code": self.failure_code,
                "failure_message": self.failure_message,
                "refund_reason": self.refund_reason,
            })
        
        return data


class UsageRecord(Base):
    """
    Usage record model for tracking detailed API usage.
    """
    __tablename__ = "usage_records"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    subscription_id = Column(UUID(as_uuid=True), ForeignKey("user_subscriptions.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Usage information
    usage_type = Column(String(50), nullable=False, index=True)  # url_check, api_call, etc.
    quantity = Column(Integer, default=1, nullable=False)
    
    # Time period
    usage_date = Column(DateTime(timezone=True), nullable=False, index=True)
    billing_period_start = Column(DateTime(timezone=True), nullable=False)
    billing_period_end = Column(DateTime(timezone=True), nullable=False)
    
    # Additional metadata
    metadata = Column(JSON, nullable=True)  # Additional usage details
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User")
    subscription = relationship("UserSubscription", back_populates="usage_records")
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_usage_records_user_date", "user_id", "usage_date"),
        Index("idx_usage_records_subscription_period", "subscription_id", "billing_period_start", "billing_period_end"),
        Index("idx_usage_records_type_date", "usage_type", "usage_date"),
    )
    
    def __repr__(self) -> str:
        return f"<UsageRecord(id={self.id}, type={self.usage_type}, quantity={self.quantity})>"
    
    def to_dict(self) -> dict:
        """
        Convert usage record to dictionary representation.
        """
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "subscription_id": str(self.subscription_id),
            "usage_type": self.usage_type,
            "quantity": self.quantity,
            "usage_date": self.usage_date.isoformat() if self.usage_date else None,
            "billing_period_start": self.billing_period_start.isoformat() if self.billing_period_start else None,
            "billing_period_end": self.billing_period_end.isoformat() if self.billing_period_end else None,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }