"""
Centralized error handling for social media bot service.

This module provides comprehensive error handling across all bot components
including command parsing, platform API interactions, BotController communication,
and response formatting with appropriate fallbacks and user guidance.
"""

import logging
import traceback
from typing import Dict, Any, Optional, List, Union
from enum import Enum
from datetime import datetime
import asyncio

from .models import (
    BotCommand, BotResponse, FormattedResponse, 
    CommandType, ResponseType, DeliveryMethod,
    PlatformType
)

logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    """Categories of bot errors for classification and handling."""
    COMMAND_PARSING = "command_parsing"
    PLATFORM_API = "platform_api"
    BOT_CONTROLLER = "bot_controller"
    RESPONSE_FORMATTING = "response_formatting"
    RATE_LIMITING = "rate_limiting"
    AUTHENTICATION = "authentication"
    VALIDATION = "validation"
    NETWORK = "network"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class ErrorSeverity(Enum):
    """Error severity levels for appropriate response handling."""
    LOW = "low"          # Minor issues, continue with fallback
    MEDIUM = "medium"    # Moderate issues, inform user but continue
    HIGH = "high"        # Serious issues, stop processing and inform user
    CRITICAL = "critical"  # Critical failures, escalate and log extensively


class BotError(Exception):
    """
    Custom exception class for bot-specific errors.
    
    Provides structured error information for consistent handling
    across all bot components.
    """
    
    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        platform: Optional[Union[str, PlatformType]] = None,
        user_id: Optional[str] = None,
        command_type: Optional[CommandType] = None,
        original_error: Optional[Exception] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize bot error with structured information.
        
        Args:
            message: Human-readable error message
            category: Error category for classification
            severity: Error severity level
            platform: Platform where error occurred
            user_id: User ID associated with the error
            command_type: Command type being processed when error occurred
            original_error: Original exception that caused this error
            context: Additional context information
        """
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.platform = platform
        self.user_id = user_id
        self.command_type = command_type
        self.original_error = original_error
        self.context = context or {}
        self.timestamp = datetime.utcnow()
        self.error_id = self._generate_error_id()
    
    def _generate_error_id(self) -> str:
        """Generate unique error ID for tracking."""
        import uuid
        return f"bot_error_{uuid.uuid4().hex[:8]}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging and analysis."""
        platform_str = self.platform.value if isinstance(self.platform, PlatformType) else self.platform
        
        return {
            "error_id": self.error_id,
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "platform": platform_str,
            "user_id": self.user_id,
            "command_type": self.command_type.value if self.command_type else None,
            "original_error": str(self.original_error) if self.original_error else None,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "traceback": traceback.format_exc() if self.original_error else None
        }

class BotErrorHandler:
    """
    Centralized error handling for all bot components.
    
    Provides consistent error handling, user-friendly messages,
    fallback mechanisms, and comprehensive logging across all
    social media bot platforms and operations.
    """
    
    def __init__(self):
        """Initialize the bot error handler."""
        self.error_counts: Dict[str, int] = {}
        self.recent_errors: List[BotError] = []
        self.max_recent_errors = 100
        
        # User-friendly error messages by category
        self.user_messages = {
            ErrorCategory.COMMAND_PARSING: {
                ErrorSeverity.LOW: "I didn't quite understand that command. Try using /help for available commands.",
                ErrorSeverity.MEDIUM: "There's an issue with your command format. Please check the syntax and try again.",
                ErrorSeverity.HIGH: "I can't process that command. Please use /help to see the correct format.",
                ErrorSeverity.CRITICAL: "Command processing is currently unavailable. Please try again later."
            },
            ErrorCategory.PLATFORM_API: {
                ErrorSeverity.LOW: "There's a minor issue with the platform connection. Trying again...",
                ErrorSeverity.MEDIUM: "I'm having trouble connecting to the platform. Please wait a moment and try again.",
                ErrorSeverity.HIGH: "Platform connection issues are preventing me from responding. Please try again in a few minutes.",
                ErrorSeverity.CRITICAL: "Platform services are currently unavailable. Please try again later."
            },
            ErrorCategory.BOT_CONTROLLER: {
                ErrorSeverity.LOW: "Analysis is taking longer than expected. Please wait...",
                ErrorSeverity.MEDIUM: "I'm having trouble processing your request. Let me try a different approach.",
                ErrorSeverity.HIGH: "Analysis services are currently experiencing issues. Please try again later.",
                ErrorSeverity.CRITICAL: "Analysis services are temporarily unavailable. Please try again later."
            },
            ErrorCategory.RESPONSE_FORMATTING: {
                ErrorSeverity.LOW: "Response formatting issue - sending simplified response.",
                ErrorSeverity.MEDIUM: "I'm having trouble formatting the response properly. Here's the basic information:",
                ErrorSeverity.HIGH: "Response formatting failed. Please try your request again.",
                ErrorSeverity.CRITICAL: "Unable to format response. Please contact support if this continues."
            },
            ErrorCategory.RATE_LIMITING: {
                ErrorSeverity.LOW: "You're sending requests quickly. Please wait a moment before trying again.",
                ErrorSeverity.MEDIUM: "Rate limit reached. Please wait 1 minute before sending another request.",
                ErrorSeverity.HIGH: "Too many requests. Please wait 5 minutes before trying again.",
                ErrorSeverity.CRITICAL: "Rate limit exceeded. Please wait 15 minutes before trying again."
            },
            ErrorCategory.AUTHENTICATION: {
                ErrorSeverity.LOW: "Authentication issue detected. Retrying...",
                ErrorSeverity.MEDIUM: "Authentication failed. Please try again.",
                ErrorSeverity.HIGH: "Authentication error. Bot services may be temporarily unavailable.",
                ErrorSeverity.CRITICAL: "Critical authentication failure. Bot services are temporarily disabled."
            },
            ErrorCategory.VALIDATION: {
                ErrorSeverity.LOW: "Input validation issue. Please check your command parameters.",
                ErrorSeverity.MEDIUM: "Invalid input detected. Please verify your command and try again.",
                ErrorSeverity.HIGH: "Input validation failed. Please use /help for correct command format.",
                ErrorSeverity.CRITICAL: "Severe validation error. Please contact support."
            },
            ErrorCategory.NETWORK: {
                ErrorSeverity.LOW: "Network connectivity issue. Retrying...",
                ErrorSeverity.MEDIUM: "Network problems detected. Please try again in a moment.",
                ErrorSeverity.HIGH: "Network connectivity issues. Please try again in a few minutes.",
                ErrorSeverity.CRITICAL: "Network services are unavailable. Please try again later."
            },
            ErrorCategory.TIMEOUT: {
                ErrorSeverity.LOW: "Request is taking longer than expected. Please wait...",
                ErrorSeverity.MEDIUM: "Request timed out. Please try again.",
                ErrorSeverity.HIGH: "Service timeout. Please try again in a few minutes.",
                ErrorSeverity.CRITICAL: "Services are experiencing high load. Please try again later."
            },
            ErrorCategory.UNKNOWN: {
                ErrorSeverity.LOW: "Minor issue encountered. Trying again...",
                ErrorSeverity.MEDIUM: "An unexpected issue occurred. Please try again.",
                ErrorSeverity.HIGH: "Unexpected error. Please try again or contact support.",
                ErrorSeverity.CRITICAL: "Critical system error. Please contact support immediately."
            }
        }
    
    async def handle_command_parsing_error(
        self,
        error: Exception,
        platform: Union[str, PlatformType],
        raw_command: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> BotResponse:
        """
        Handle command parsing errors with helpful user guidance.
        
        Args:
            error: Original parsing error
            platform: Platform where error occurred
            raw_command: Raw command text that failed to parse
            user_id: User ID who sent the command
            
        Returns:
            Error response with user guidance
        """
        try:
            # Determine error severity based on error type
            severity = self._determine_parsing_error_severity(error, raw_command)
            
            # Create structured bot error
            bot_error = BotError(
                message=f"Command parsing failed: {str(error)}",
                category=ErrorCategory.COMMAND_PARSING,
                severity=severity,
                platform=platform,
                user_id=user_id,
                original_error=error,
                context={"raw_command": raw_command}
            )
            
            # Log the error
            await self._log_error(bot_error)
            
            # Generate user-friendly response
            user_message = self._get_user_message(bot_error)
            
            # Add helpful guidance based on the parsing error
            guidance = self._generate_parsing_guidance(raw_command, platform)
            if guidance:
                user_message += f"\n\n{guidance}"
            
            return BotResponse.error_response(
                error_message=user_message,
                response_type=ResponseType.ERROR,
                data={
                    "error_id": bot_error.error_id,
                    "category": bot_error.category.value,
                    "severity": bot_error.severity.value,
                    "guidance_provided": bool(guidance)
                }
            )
            
        except Exception as e:
            logger.error(f"Error in command parsing error handler: {e}")
            return self._create_fallback_error_response("Command parsing failed")
    
    async def handle_platform_api_error(
        self,
        error: Exception,
        platform: Union[str, PlatformType],
        operation: str,
        user_id: Optional[str] = None,
        retry_count: int = 0
    ) -> BotResponse:
        """
        Handle platform API errors with appropriate fallbacks and retry logic.
        
        Args:
            error: Original API error
            platform: Platform where error occurred
            operation: API operation that failed
            user_id: User ID associated with the request
            retry_count: Number of retries attempted
            
        Returns:
            Error response with fallback options
        """
        try:
            # Determine error severity and if retry is appropriate
            severity, should_retry = self._analyze_api_error(error, retry_count)
            
            # Create structured bot error
            bot_error = BotError(
                message=f"Platform API error in {operation}: {str(error)}",
                category=ErrorCategory.PLATFORM_API,
                severity=severity,
                platform=platform,
                user_id=user_id,
                original_error=error,
                context={
                    "operation": operation,
                    "retry_count": retry_count,
                    "should_retry": should_retry
                }
            )
            
            # Log the error
            await self._log_error(bot_error)
            
            # Attempt retry if appropriate
            if should_retry and retry_count < 3:
                logger.info(f"Retrying platform API operation: {operation} (attempt {retry_count + 1})")
                # Return a response indicating retry is happening
                return BotResponse.error_response(
                    error_message="Temporary platform issue. Retrying...",
                    response_type=ResponseType.ERROR,
                    data={
                        "error_id": bot_error.error_id,
                        "retry_in_progress": True,
                        "retry_count": retry_count + 1
                    }
                )
            
            # Generate user-friendly response
            user_message = self._get_user_message(bot_error)
            
            # Add platform-specific guidance
            platform_guidance = self._generate_platform_guidance(platform, operation, error)
            if platform_guidance:
                user_message += f"\n\n{platform_guidance}"
            
            return BotResponse.error_response(
                error_message=user_message,
                response_type=ResponseType.ERROR,
                data={
                    "error_id": bot_error.error_id,
                    "category": bot_error.category.value,
                    "severity": bot_error.severity.value,
                    "operation": operation,
                    "retry_attempted": retry_count > 0
                }
            )
            
        except Exception as e:
            logger.error(f"Error in platform API error handler: {e}")
            return self._create_fallback_error_response("Platform communication failed")
    
    async def handle_bot_controller_error(
        self,
        error: Exception,
        command: BotCommand,
        operation: str
    ) -> BotResponse:
        """
        Handle BotController errors with graceful degradation.
        
        Args:
            error: Original BotController error
            command: Bot command being processed
            operation: BotController operation that failed
            
        Returns:
            Error response with graceful degradation
        """
        try:
            # Determine error severity and degradation options
            severity = self._determine_controller_error_severity(error, operation)
            
            # Create structured bot error
            bot_error = BotError(
                message=f"BotController error in {operation}: {str(error)}",
                category=ErrorCategory.BOT_CONTROLLER,
                severity=severity,
                platform=command.platform,
                user_id=command.user_id,
                command_type=command.command_type,
                original_error=error,
                context={
                    "operation": operation,
                    "command_parameters": command.parameters,
                    "command_metadata": command.metadata
                }
            )
            
            # Log the error
            await self._log_error(bot_error)
            
            # Attempt graceful degradation
            degraded_response = await self._attempt_graceful_degradation(command, bot_error)
            if degraded_response:
                return degraded_response
            
            # Generate user-friendly response
            user_message = self._get_user_message(bot_error)
            
            # Add command-specific guidance
            command_guidance = self._generate_command_guidance(command, error)
            if command_guidance:
                user_message += f"\n\n{command_guidance}"
            
            return BotResponse.error_response(
                error_message=user_message,
                response_type=ResponseType.ERROR,
                data={
                    "error_id": bot_error.error_id,
                    "category": bot_error.category.value,
                    "severity": bot_error.severity.value,
                    "operation": operation,
                    "command_type": command.command_type.value,
                    "degradation_attempted": True
                }
            )
            
        except Exception as e:
            logger.error(f"Error in BotController error handler: {e}")
            return self._create_fallback_error_response("Analysis service failed")
    
    async def handle_response_formatting_error(
        self,
        error: Exception,
        bot_response: BotResponse,
        platform: Union[str, PlatformType],
        delivery_method: DeliveryMethod
    ) -> FormattedResponse:
        """
        Handle response formatting errors with fallback formatting options.
        
        Args:
            error: Original formatting error
            bot_response: Response that failed to format
            platform: Target platform
            delivery_method: Intended delivery method
            
        Returns:
            Fallback formatted response
        """
        try:
            # Determine error severity
            severity = self._determine_formatting_error_severity(error, delivery_method)
            
            # Create structured bot error
            bot_error = BotError(
                message=f"Response formatting error: {str(error)}",
                category=ErrorCategory.RESPONSE_FORMATTING,
                severity=severity,
                platform=platform,
                original_error=error,
                context={
                    "delivery_method": delivery_method.value,
                    "response_type": bot_response.response_type.value,
                    "response_success": bot_response.success
                }
            )
            
            # Log the error
            await self._log_error(bot_error)
            
            # Create fallback formatted response
            fallback_response = self._create_fallback_formatted_response(
                bot_response, platform, bot_error
            )
            
            return fallback_response
            
        except Exception as e:
            logger.error(f"Error in response formatting error handler: {e}")
            return self._create_emergency_fallback_response(platform)   
 
    def _determine_parsing_error_severity(
        self, 
        error: Exception, 
        raw_command: Optional[str]
    ) -> ErrorSeverity:
        """Determine severity of command parsing error."""
        if not raw_command:
            return ErrorSeverity.HIGH
        
        # Check for common parsing issues
        if "validation" in str(error).lower():
            return ErrorSeverity.MEDIUM
        elif "syntax" in str(error).lower():
            return ErrorSeverity.MEDIUM
        elif "timeout" in str(error).lower():
            return ErrorSeverity.HIGH
        else:
            return ErrorSeverity.MEDIUM
    
    def _analyze_api_error(self, error: Exception, retry_count: int) -> tuple[ErrorSeverity, bool]:
        """Analyze API error to determine severity and retry appropriateness."""
        error_str = str(error).lower()
        
        # Rate limiting errors
        if "rate limit" in error_str or "429" in error_str:
            return ErrorSeverity.MEDIUM, False
        
        # Authentication errors
        elif "auth" in error_str or "401" in error_str or "403" in error_str:
            return ErrorSeverity.HIGH, False
        
        # Network/timeout errors (retryable)
        elif any(term in error_str for term in ["timeout", "connection", "network", "502", "503", "504"]):
            should_retry = retry_count < 2
            severity = ErrorSeverity.MEDIUM if should_retry else ErrorSeverity.HIGH
            return severity, should_retry
        
        # Server errors (potentially retryable)
        elif "500" in error_str:
            should_retry = retry_count < 1
            severity = ErrorSeverity.HIGH if not should_retry else ErrorSeverity.MEDIUM
            return severity, should_retry
        
        # Client errors (not retryable)
        elif "400" in error_str or "404" in error_str:
            return ErrorSeverity.MEDIUM, False
        
        # Unknown errors
        else:
            should_retry = retry_count < 1
            return ErrorSeverity.MEDIUM, should_retry
    
    def _determine_controller_error_severity(
        self, 
        error: Exception, 
        operation: str
    ) -> ErrorSeverity:
        """Determine severity of BotController error."""
        error_str = str(error).lower()
        
        if "timeout" in error_str:
            return ErrorSeverity.MEDIUM
        elif "database" in error_str or "connection" in error_str:
            return ErrorSeverity.HIGH
        elif "validation" in error_str:
            return ErrorSeverity.MEDIUM
        elif "permission" in error_str or "auth" in error_str:
            return ErrorSeverity.HIGH
        else:
            return ErrorSeverity.MEDIUM
    
    def _determine_formatting_error_severity(
        self, 
        error: Exception, 
        delivery_method: DeliveryMethod
    ) -> ErrorSeverity:
        """Determine severity of response formatting error."""
        error_str = str(error).lower()
        
        if "encoding" in error_str or "unicode" in error_str:
            return ErrorSeverity.MEDIUM
        elif "length" in error_str or "size" in error_str:
            return ErrorSeverity.LOW
        elif "json" in error_str or "serialization" in error_str:
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.MEDIUM
    
    def _get_user_message(self, bot_error: BotError) -> str:
        """Get user-friendly error message for a bot error."""
        try:
            return self.user_messages[bot_error.category][bot_error.severity]
        except KeyError:
            return self.user_messages[ErrorCategory.UNKNOWN][ErrorSeverity.MEDIUM]   
 
    def _generate_parsing_guidance(
        self, 
        raw_command: Optional[str], 
        platform: Union[str, PlatformType]
    ) -> Optional[str]:
        """Generate helpful guidance for command parsing errors."""
        if not raw_command:
            return "Use /help to see available commands and their correct format."
        
        platform_str = platform.value if isinstance(platform, PlatformType) else platform
        
        # Common command suggestions based on platform
        if platform_str == "twitter":
            return (
                "Twitter commands should mention @bot:\n"
                "• @bot analyze @username\n"
                "• @bot check_compliance \"content\"\n"
                "• @bot analyze_followers"
            )
        elif platform_str == "telegram":
            return (
                "Telegram commands start with /:\n"
                "• /analyze_account @username\n"
                "• /check_compliance content text\n"
                "• /analyze_followers"
            )
        elif platform_str == "discord":
            return (
                "Discord slash commands:\n"
                "• /analyze_account user:@username\n"
                "• /check_compliance content:\"text\"\n"
                "• /analyze_followers"
            )
        
        return "Use /help to see the correct command format for your platform."
    
    def _generate_platform_guidance(
        self, 
        platform: Union[str, PlatformType], 
        operation: str, 
        error: Exception
    ) -> Optional[str]:
        """Generate platform-specific guidance for API errors."""
        platform_str = platform.value if isinstance(platform, PlatformType) else platform
        error_str = str(error).lower()
        
        if "rate limit" in error_str:
            if platform_str == "twitter":
                return "Twitter rate limits apply. Please wait 15 minutes before trying again."
            elif platform_str == "telegram":
                return "Telegram rate limits apply. Please wait 1 minute before trying again."
            elif platform_str == "discord":
                return "Discord rate limits apply. Please wait a few seconds before trying again."
        
        return None
    
    def _generate_command_guidance(
        self, 
        command: BotCommand, 
        error: Exception
    ) -> Optional[str]:
        """Generate command-specific guidance for BotController errors."""
        if command.command_type == CommandType.ANALYZE_ACCOUNT:
            return "Try checking if the account username is correct and publicly accessible."
        elif command.command_type == CommandType.CHECK_COMPLIANCE:
            return "Try with shorter content or check if the content contains special characters."
        elif command.command_type == CommandType.ANALYZE_FOLLOWERS:
            return "Follower analysis requires account access. Make sure your account is properly connected."
        
        return None 
   
    async def _attempt_graceful_degradation(
        self, 
        command: BotCommand, 
        bot_error: BotError
    ) -> Optional[BotResponse]:
        """Attempt graceful degradation for BotController errors."""
        try:
            # For analysis commands, provide cached or simplified results
            if command.command_type == CommandType.ANALYZE_ACCOUNT:
                return BotResponse.success_response(
                    data={
                        "risk_level": "unknown",
                        "risk_score": 0,
                        "account_identifier": command.get_parameter("account_identifier", "unknown"),
                        "analysis_summary": "Analysis temporarily unavailable. Basic safety guidelines apply.",
                        "recommendations": [
                            "Verify account authenticity before engaging",
                            "Be cautious with personal information sharing",
                            "Report suspicious activity to platform moderators"
                        ],
                        "degraded_response": True,
                        "error_id": bot_error.error_id
                    },
                    response_type=ResponseType.ANALYSIS_RESULT,
                    formatting_hints={"is_degraded": True, "show_warning": True}
                )
            
            elif command.command_type == CommandType.CHECK_COMPLIANCE:
                return BotResponse.success_response(
                    data={
                        "is_compliant": True,
                        "compliance_score": 0,
                        "content_preview": command.get_parameter("content", "")[:50] + "...",
                        "violations": [],
                        "recommendations": [
                            "Review platform community guidelines",
                            "Avoid potentially harmful or offensive content",
                            "Consider content impact on your audience"
                        ],
                        "degraded_response": True,
                        "error_id": bot_error.error_id
                    },
                    response_type=ResponseType.COMPLIANCE_CHECK,
                    formatting_hints={"is_degraded": True, "show_warning": True}
                )
            
            elif command.command_type == CommandType.ANALYZE_FOLLOWERS:
                return BotResponse.success_response(
                    data={
                        "verified_followers_count": 0,
                        "high_value_count": 0,
                        "total_followers": 0,
                        "verification_rate": 0.0,
                        "networking_opportunities": [
                            "Follower analysis temporarily unavailable",
                            "Try again later for detailed insights"
                        ],
                        "degraded_response": True,
                        "error_id": bot_error.error_id
                    },
                    response_type=ResponseType.FOLLOWER_ANALYSIS,
                    formatting_hints={"is_degraded": True, "show_warning": True}
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error in graceful degradation: {e}")
            return None  
  
    def _create_fallback_formatted_response(
        self, 
        bot_response: BotResponse, 
        platform: Union[str, PlatformType],
        bot_error: BotError
    ) -> FormattedResponse:
        """Create fallback formatted response when formatting fails."""
        # Create simple text-based response
        if bot_response.success:
            text = f"✅ Operation completed successfully.\n\nError ID: {bot_error.error_id}\n\nNote: Response formatting failed, showing simplified result."
        else:
            text = f"❌ {bot_response.error_message}\n\nError ID: {bot_error.error_id}"
        
        return FormattedResponse(
            platform=platform,
            response_data={"text": text},
            delivery_method=DeliveryMethod.MESSAGE,
            formatting_applied=["fallback_text", "error_recovery"]
        )
    
    def _create_emergency_fallback_response(
        self, 
        platform: Union[str, PlatformType]
    ) -> FormattedResponse:
        """Create emergency fallback response when all formatting fails."""
        return FormattedResponse(
            platform=platform,
            response_data={
                "text": "❌ System error occurred. Please try again later or contact support."
            },
            delivery_method=DeliveryMethod.MESSAGE,
            formatting_applied=["emergency_fallback"]
        )
    
    def _create_fallback_error_response(self, message: str) -> BotResponse:
        """Create fallback error response when error handling fails."""
        return BotResponse.error_response(
            error_message=f"❌ {message}. Please try again or contact support.",
            response_type=ResponseType.ERROR,
            data={"fallback_response": True}
        )
    
    async def _log_error(self, bot_error: BotError):
        """Log bot error with appropriate level and context."""
        error_dict = bot_error.to_dict()
        
        # Log based on severity
        if bot_error.severity == ErrorSeverity.CRITICAL:
            logger.critical(f"Critical bot error: {bot_error.message}", extra=error_dict)
        elif bot_error.severity == ErrorSeverity.HIGH:
            logger.error(f"High severity bot error: {bot_error.message}", extra=error_dict)
        elif bot_error.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"Medium severity bot error: {bot_error.message}", extra=error_dict)
        else:
            logger.info(f"Low severity bot error: {bot_error.message}", extra=error_dict)
        
        # Track error for analytics
        self._track_error(bot_error)
    
    def _track_error(self, bot_error: BotError):
        """Track error for analytics and monitoring."""
        # Add to recent errors list
        self.recent_errors.append(bot_error)
        if len(self.recent_errors) > self.max_recent_errors:
            self.recent_errors.pop(0)
        
        # Update error counts
        error_key = f"{bot_error.category.value}:{bot_error.severity.value}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1  
  
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring and analysis."""
        return {
            "total_errors": len(self.recent_errors),
            "error_counts_by_category": self.error_counts,
            "recent_errors": [error.to_dict() for error in self.recent_errors[-10:]],
            "error_rate_by_severity": {
                severity.value: sum(
                    1 for error in self.recent_errors 
                    if error.severity == severity
                ) for severity in ErrorSeverity
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on error handling system."""
        try:
            recent_critical_errors = [
                error for error in self.recent_errors[-50:]
                if error.severity == ErrorSeverity.CRITICAL
            ]
            
            recent_high_errors = [
                error for error in self.recent_errors[-50:]
                if error.severity == ErrorSeverity.HIGH
            ]
            
            return {
                "status": "healthy",
                "recent_critical_errors": len(recent_critical_errors),
                "recent_high_errors": len(recent_high_errors),
                "total_tracked_errors": len(self.recent_errors),
                "error_handler_operational": True
            }
            
        except Exception as e:
            logger.error(f"Error handler health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "error_handler_operational": False
            }


# Global error handler instance
bot_error_handler = BotErrorHandler()