#!/usr/bin/env python3
"""
LinkShield Backend Subscription Exceptions

Custom exceptions for subscription and payment processing errors.
"""

from typing import Optional


class SubscriptionError(Exception):
    """Base exception for subscription-related errors."""
    
    def __init__(self, message: str, code: Optional[str] = None):
        self.message = message
        self.code = code
        super().__init__(message)


class PaymentProcessingError(SubscriptionError):
    """Exception raised for payment processing failures."""
    
    def __init__(self, message: str, code: Optional[str] = None, 
                 payment_id: Optional[str] = None):
        self.payment_id = payment_id
        super().__init__(message, code)


class PlanNotFoundError(SubscriptionError):
    """Exception raised when a subscription plan is not found."""
    
    def __init__(self, plan_name: str):
        super().__init__(f"Subscription plan '{plan_name}' not found", "PLAN_NOT_FOUND")


class SubscriptionNotFoundError(SubscriptionError):
    """Exception raised when a subscription is not found."""
    
    def __init__(self, subscription_id: str):
        super().__init__(f"Subscription '{subscription_id}' not found", "SUBSCRIPTION_NOT_FOUND")


class SubscriptionAlreadyExistsError(SubscriptionError):
    """Exception raised when a user already has an active subscription."""
    
    def __init__(self, user_id: str):
        super().__init__(f"User '{user_id}' already has an active subscription", "SUBSCRIPTION_EXISTS")


class InvalidSubscriptionStateError(SubscriptionError):
    """Exception raised for invalid subscription state transitions."""
    
    def __init__(self, message: str, current_status: str):
        self.current_status = current_status
        super().__init__(message, "INVALID_STATE")


class UsageLimitExceededError(SubscriptionError):
    """Exception raised when usage limits are exceeded."""
    
    def __init__(self, limit_type: str, current_usage: int, limit: int):
        self.limit_type = limit_type
        self.current_usage = current_usage
        self.limit = limit
        super().__init__(
            f"{limit_type} limit exceeded: {current_usage}/{limit}",
            "USAGE_LIMIT_EXCEEDED"
        )


class PaddleIntegrationError(SubscriptionError):
    """Exception raised for Paddle API integration errors."""
    
    def __init__(self, message: str, paddle_error_code: Optional[str] = None):
        self.paddle_error_code = paddle_error_code
        super().__init__(message, "PADDLE_INTEGRATION_ERROR")


class WebhookVerificationError(SubscriptionError):
    """Exception raised for webhook signature verification failures."""
    
    def __init__(self, message: str):
        super().__init__(message, "WEBHOOK_VERIFICATION_ERROR")


class TrialPeriodExpiredError(SubscriptionError):
    """Exception raised when trial period has expired."""
    
    def __init__(self, subscription_id: str):
        super().__init__(f"Trial period expired for subscription '{subscription_id}'", "TRIAL_EXPIRED")


class BillingInformationRequiredError(SubscriptionError):
    """Exception raised when billing information is required but not provided."""
    
    def __init__(self, message: str):
        super().__init__(message, "BILLING_INFO_REQUIRED")