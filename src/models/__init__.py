#!/usr/bin/env python3
"""
LinkShield Backend Models

Centralized imports for all SQLAlchemy models.
"""

# User models
from .user import User, UserSession, APIKey, PasswordResetToken, EmailVerificationToken

# URL checking models  
from .url_check import URLCheck, ScanResult, URLReputation

# Subscription models
from .subscription import SubscriptionPlan, UserSubscription, Payment, UsageRecord

# Email models
from .email import EmailLog

# Report models
from .report import Report, ReportVote, ReportTemplate, ReportStatistics

# AI analysis models
from .ai_analysis import AIAnalysis, ContentSimilarity, AIModelMetrics, ProcessingStatus, AnalysisType

__all__ = [
    # User models
    "User",
    "UserSession", 
    "APIKey",
    "PasswordResetToken",
    "EmailVerificationToken",
    
    # URL checking models
    "URLCheck",
    "ScanResult",
    "URLReputation",
    
    # Subscription models
    "SubscriptionPlan",
    "UserSubscription",
    "Payment", 
    "UsageRecord",
    
    # Email models
    "EmailLog",
    
    # Report models
    "Report",
    "ReportVote",
    "ReportTemplate", 
    "ReportStatistics",
    
    # AI analysis models
    "AIAnalysis",
    "ContentSimilarity",
    "AIModelMetrics",
    "ProcessingStatus",
    "AnalysisType",
]