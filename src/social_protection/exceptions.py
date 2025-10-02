"""
Exception hierarchy for social protection module.

This module defines a comprehensive exception hierarchy for handling errors
across all social protection components including analyzers, services,
controllers, and platform adapters.
"""

from typing import Optional, Dict, Any


# Base Exception
class SocialProtectionError(Exception):
    """Base exception for all social protection errors."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.message = message
        self.details = details or {}
        self.original_error = original_error
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        result = {
            "error_type": self.__class__.__name__,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        return result


# Analyzer Errors
class AnalyzerError(SocialProtectionError):
    """Base exception for analyzer-specific errors."""
    pass


class ContentAnalysisError(AnalyzerError):
    """Error during content risk analysis."""
    pass


class LinkAnalysisError(AnalyzerError):
    """Error during link penalty detection."""
    pass


class SpamDetectionError(AnalyzerError):
    """Error during spam pattern detection."""
    pass


class CommunityNotesError(AnalyzerError):
    """Error during community notes analysis."""
    pass


class AlgorithmHealthError(AnalyzerError):
    """Error during algorithm health analysis."""
    pass


class VisibilityAnalysisError(AlgorithmHealthError):
    """Error during visibility scoring."""
    pass


class EngagementAnalysisError(AlgorithmHealthError):
    """Error during engagement analysis."""
    pass


class PenaltyDetectionError(AlgorithmHealthError):
    """Error during penalty detection."""
    pass


class ShadowBanDetectionError(AlgorithmHealthError):
    """Error during shadow ban detection."""
    pass


# Service Errors
class ServiceError(SocialProtectionError):
    """Base exception for service layer errors."""
    pass


class ScanServiceError(ServiceError):
    """Error in social scan service."""
    pass


class ExtensionProcessingError(ServiceError):
    """Error processing extension data."""
    pass


class CrisisDetectionError(ServiceError):
    """Error during crisis detection."""
    pass


class ReputationTrackingError(ServiceError):
    """Error in reputation tracking service."""
    pass


class BrandMonitoringError(ServiceError):
    """Error in brand monitoring service."""
    pass


# Platform Adapter Errors
class PlatformAdapterError(SocialProtectionError):
    """Base exception for platform adapter errors."""
    
    def __init__(
        self,
        message: str,
        platform: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.platform = platform
        super().__init__(message, details, original_error)
    
    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        if self.platform:
            result["platform"] = self.platform
        return result


class PlatformAuthenticationError(PlatformAdapterError):
    """Platform API authentication failed."""
    pass


class PlatformAPIError(PlatformAdapterError):
    """Platform API request failed."""
    pass


class PlatformRateLimitError(PlatformAdapterError):
    """Platform API rate limit exceeded."""
    
    def __init__(
        self,
        message: str,
        platform: Optional[str] = None,
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.retry_after = retry_after
        super().__init__(message, platform, details, original_error)
    
    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        if self.retry_after:
            result["retry_after"] = self.retry_after
        return result


class PlatformConfigurationError(PlatformAdapterError):
    """Platform adapter configuration is invalid."""
    pass


class PlatformUnavailableError(PlatformAdapterError):
    """Platform is temporarily unavailable."""
    pass


# Data and Validation Errors
class DataValidationError(SocialProtectionError):
    """Data validation failed."""
    pass


class InvalidPlatformError(DataValidationError):
    """Invalid or unsupported platform specified."""
    pass


class InvalidContentError(DataValidationError):
    """Invalid content provided for analysis."""
    pass


class InvalidProfileError(DataValidationError):
    """Invalid profile identifier or data."""
    pass


# Database Errors
class DatabaseError(SocialProtectionError):
    """Database operation failed."""
    pass


class RecordNotFoundError(DatabaseError):
    """Requested record not found in database."""
    pass


class RecordAlreadyExistsError(DatabaseError):
    """Record already exists in database."""
    pass


# External Service Errors
class ExternalServiceError(SocialProtectionError):
    """External service integration error."""
    pass


class AIServiceError(ExternalServiceError):
    """AI service request failed."""
    pass


class CacheServiceError(ExternalServiceError):
    """Cache service operation failed."""
    pass


class NotificationServiceError(ExternalServiceError):
    """Notification service failed."""
    pass


# Authorization and Access Errors
class AuthorizationError(SocialProtectionError):
    """User not authorized for requested operation."""
    pass


class SubscriptionRequiredError(AuthorizationError):
    """Operation requires higher subscription tier."""
    
    def __init__(
        self,
        message: str,
        required_tier: Optional[str] = None,
        current_tier: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.required_tier = required_tier
        self.current_tier = current_tier
        super().__init__(message, details, original_error)
    
    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        if self.required_tier:
            result["required_tier"] = self.required_tier
        if self.current_tier:
            result["current_tier"] = self.current_tier
        return result


class RateLimitError(AuthorizationError):
    """Rate limit exceeded for user."""
    
    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.retry_after = retry_after
        self.limit = limit
        self.window = window
        super().__init__(message, details, original_error)
    
    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        if self.retry_after:
            result["retry_after"] = self.retry_after
        if self.limit:
            result["limit"] = self.limit
        if self.window:
            result["window"] = self.window
        return result


# Configuration Errors
class ConfigurationError(SocialProtectionError):
    """Configuration error."""
    pass


class MissingDependencyError(ConfigurationError):
    """Required dependency not available."""
    pass


# Timeout Errors
class TimeoutError(SocialProtectionError):
    """Operation timed out."""
    pass


class AnalysisTimeoutError(TimeoutError):
    """Analysis operation timed out."""
    pass


class PlatformTimeoutError(TimeoutError):
    """Platform API request timed out."""
    pass
