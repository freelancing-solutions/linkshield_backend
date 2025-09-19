#!/usr/bin/env python3
"""
LinkShield Backend Models

Centralized imports for all SQLAlchemy models.
"""

from .user import User
from .url_check import URLCheck, URLCheckResult
from .subscription import Subscription, SubscriptionPlan
from .email import EmailVerification, PasswordReset
from .report import Report, ReportStats
from .ai_analysis import AIAnalysis, ContentSimilarity, AIModelMetrics, ProcessingStatus, AnalysisType

__all__ = [
    # User models
    "User",
    
    # URL checking models
    "URLCheck",
    "URLCheckResult",
    
    # Subscription models
    "Subscription",
    "SubscriptionPlan",
    
    # Email models
    "EmailVerification",
    "PasswordReset",
    
    # Report models
    "Report",
    "ReportStats",
    
    # AI analysis models
    "AIAnalysis",
    "ContentSimilarity",
    "AIModelMetrics",
    "ProcessingStatus",
    "AnalysisType",
]