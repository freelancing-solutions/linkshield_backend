"""
Standardized bot command and response data models for social media bot service.

This module provides dataclasses and models for consistent communication between
social media platforms and LinkShield's social protection services through bots.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional, Union
import json

# Import existing PlatformType from social protection models
from linkshield.models.social_protection import PlatformType


class CommandType(Enum):
    """Supported bot command types."""
    ANALYZE_ACCOUNT = "analyze_account"
    CHECK_COMPLIANCE = "check_compliance"
    ANALYZE_FOLLOWERS = "analyze_followers"


class ResponseType(Enum):
    """Bot response types."""
    ANALYSIS_RESULT = "analysis_result"
    COMPLIANCE_CHECK = "compliance_check"
    FOLLOWER_ANALYSIS = "follower_analysis"
    ERROR = "error"


class DeliveryMethod(Enum):
    """Platform-specific delivery methods for responses."""
    REPLY = "reply"
    DM = "dm"
    THREAD = "thread"
    EMBED = "embed"
    INLINE_KEYBOARD = "inline_keyboard"
    MESSAGE = "message"


@dataclass
class BotCommand:
    """
    Standardized command structure across all platforms.
    
    This dataclass provides a unified interface for bot commands regardless
    of the originating platform, enabling consistent processing through
    the BotController.
    """
    command_type: CommandType
    platform: Union[PlatformType, str]  # Support both enum and string platforms
    user_id: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate command after initialization."""
        if not isinstance(self.command_type, CommandType):
            raise ValueError(f"Invalid command_type: {self.command_type}")
        # Allow both PlatformType enum and string values for flexibility
        if not (isinstance(self.platform, PlatformType) or isinstance(self.platform, str)):
            raise ValueError(f"Invalid platform: {self.platform}")
        if not self.user_id:
            raise ValueError("user_id is required")
    
    def get_parameter(self, key: str, default: Any = None) -> Any:
        """Get command parameter with optional default."""
        return self.parameters.get(key, default)
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get command metadata with optional default."""
        return self.metadata.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert command to dictionary representation."""
        platform_value = self.platform.value if isinstance(self.platform, PlatformType) else self.platform
        return {
            "command_type": self.command_type.value,
            "platform": platform_value,
            "user_id": self.user_id,
            "parameters": self.parameters,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BotCommand':
        """Create BotCommand from dictionary."""
        platform_str = data["platform"]
        # Try to convert to PlatformType enum, fallback to string
        try:
            platform = PlatformType(platform_str)
        except ValueError:
            platform = platform_str
            
        return cls(
            command_type=CommandType(data["command_type"]),
            platform=platform,
            user_id=data["user_id"],
            parameters=data.get("parameters", {}),
            metadata=data.get("metadata", {}),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()))
        )


@dataclass
class BotResponse:
    """
    Consistent response format from BotController.
    
    This dataclass provides a standardized response structure that can be
    formatted appropriately for each platform while maintaining consistency
    in the underlying data.
    """
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    response_type: ResponseType = ResponseType.ANALYSIS_RESULT
    formatting_hints: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate response after initialization."""
        if not isinstance(self.response_type, ResponseType):
            raise ValueError(f"Invalid response_type: {self.response_type}")
        if not self.success and not self.error_message:
            raise ValueError("error_message is required when success is False")
    
    def get_data(self, key: str, default: Any = None) -> Any:
        """Get response data with optional default."""
        return self.data.get(key, default)
    
    def get_formatting_hint(self, key: str, default: Any = None) -> Any:
        """Get formatting hint with optional default."""
        return self.formatting_hints.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary representation."""
        return {
            "success": self.success,
            "data": self.data,
            "error_message": self.error_message,
            "response_type": self.response_type.value,
            "formatting_hints": self.formatting_hints,
            "timestamp": self.timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BotResponse':
        """Create BotResponse from dictionary."""
        return cls(
            success=data["success"],
            data=data.get("data", {}),
            error_message=data.get("error_message"),
            response_type=ResponseType(data.get("response_type", ResponseType.ANALYSIS_RESULT.value)),
            formatting_hints=data.get("formatting_hints", {}),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat()))
        )
    
    @classmethod
    def success_response(
        cls, 
        data: Dict[str, Any], 
        response_type: ResponseType = ResponseType.ANALYSIS_RESULT,
        formatting_hints: Optional[Dict[str, Any]] = None
    ) -> 'BotResponse':
        """Create a successful response."""
        return cls(
            success=True,
            data=data,
            response_type=response_type,
            formatting_hints=formatting_hints or {}
        )
    
    @classmethod
    def error_response(
        cls, 
        error_message: str, 
        response_type: ResponseType = ResponseType.ERROR,
        data: Optional[Dict[str, Any]] = None
    ) -> 'BotResponse':
        """Create an error response."""
        return cls(
            success=False,
            error_message=error_message,
            response_type=response_type,
            data=data or {}
        )


@dataclass
class PlatformCommand:
    """
    Raw command data from platform before standardization.
    
    This dataclass captures platform-specific command data before it's
    converted to the standardized BotCommand format.
    """
    platform: Union[PlatformType, str]  # Support both enum and string platforms
    raw_data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    user_context: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate platform command after initialization."""
        if not (isinstance(self.platform, PlatformType) or isinstance(self.platform, str)):
            raise ValueError(f"Invalid platform: {self.platform}")
        if not self.raw_data:
            raise ValueError("raw_data is required")
    
    def get_raw_data(self, key: str, default: Any = None) -> Any:
        """Get raw data with optional default."""
        return self.raw_data.get(key, default)
    
    def get_user_context(self, key: str, default: Any = None) -> Any:
        """Get user context with optional default."""
        return self.user_context.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert platform command to dictionary representation."""
        platform_value = self.platform.value if isinstance(self.platform, PlatformType) else self.platform
        return {
            "platform": platform_value,
            "raw_data": self.raw_data,
            "timestamp": self.timestamp.isoformat(),
            "user_context": self.user_context
        }


@dataclass
class FormattedResponse:
    """
    Platform-specific formatted response ready for delivery.
    
    This dataclass contains the final formatted response data that's
    ready to be sent back to the specific platform.
    """
    platform: Union[PlatformType, str]  # Support both enum and string platforms
    response_data: Dict[str, Any]
    delivery_method: DeliveryMethod
    formatting_applied: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate formatted response after initialization."""
        if not (isinstance(self.platform, PlatformType) or isinstance(self.platform, str)):
            raise ValueError(f"Invalid platform: {self.platform}")
        if not isinstance(self.delivery_method, DeliveryMethod):
            raise ValueError(f"Invalid delivery_method: {self.delivery_method}")
        if not self.response_data:
            raise ValueError("response_data is required")
    
    def get_response_data(self, key: str, default: Any = None) -> Any:
        """Get response data with optional default."""
        return self.response_data.get(key, default)
    
    def add_formatting(self, formatting_type: str):
        """Add formatting type to the applied list."""
        if formatting_type not in self.formatting_applied:
            self.formatting_applied.append(formatting_type)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert formatted response to dictionary representation."""
        platform_value = self.platform.value if isinstance(self.platform, PlatformType) else self.platform
        return {
            "platform": platform_value,
            "response_data": self.response_data,
            "delivery_method": self.delivery_method.value,
            "formatting_applied": self.formatting_applied,
            "timestamp": self.timestamp.isoformat()
        }


class CommandRegistry:
    """
    Registry of supported commands across platforms.
    
    This class defines the supported command syntax and patterns for each
    platform, enabling consistent command recognition and parsing.
    """
    
    # Command patterns for each platform
    # Note: Using existing PlatformType.TWITTER for Twitter bot integration
    # For Telegram and Discord, we'll use string identifiers since they're not in the existing enum
    SUPPORTED_COMMANDS = {
        CommandType.ANALYZE_ACCOUNT: {
            PlatformType.TWITTER: [
                "@bot analyze @{username}",
                "@bot check @{username}",
                "@bot analyze_account @{username}",
                "@bot safety @{username}"
            ],
            "telegram": [
                "/analyze_account @{username}",
                "/check_account @{username}",
                "/analyze @{username}",
                "/safety @{username}"
            ],
            "discord": [
                "/analyze_account user:@{username}",
                "/check_account user:@{username}",
                "/analyze user:@{username}",
                "/safety user:@{username}"
            ]
        },
        CommandType.CHECK_COMPLIANCE: {
            PlatformType.TWITTER: [
                "@bot check_compliance \"{content}\"",
                "@bot compliance \"{content}\"",
                "@bot check \"{content}\""
            ],
            "telegram": [
                "/check_compliance {content}",
                "/compliance {content}",
                "/check {content}"
            ],
            "discord": [
                "/check_compliance content:\"{content}\"",
                "/compliance content:\"{content}\"",
                "/check content:\"{content}\""
            ]
        },
        CommandType.ANALYZE_FOLLOWERS: {
            PlatformType.TWITTER: [
                "@bot analyze_followers",
                "@bot followers",
                "@bot verified_followers"
            ],
            "telegram": [
                "/analyze_followers",
                "/followers",
                "/verified_followers"
            ],
            "discord": [
                "/analyze_followers",
                "/followers",
                "/verified_followers"
            ]
        }
    }
    
    # Platform-specific command prefixes
    COMMAND_PREFIXES = {
        PlatformType.TWITTER: ["@bot"],
        "telegram": ["/"],
        "discord": ["/"]
    }
    
    # Response formatting preferences by platform
    RESPONSE_FORMATTING = {
        PlatformType.TWITTER: {
            "max_length": 280,
            "supports_threads": True,
            "supports_embeds": False,
            "supports_markdown": False,
            "emoji_indicators": True,
            "preferred_delivery": [DeliveryMethod.REPLY, DeliveryMethod.THREAD, DeliveryMethod.DM]
        },
        "telegram": {
            "max_length": 4096,
            "supports_threads": False,
            "supports_embeds": False,
            "supports_markdown": True,
            "emoji_indicators": True,
            "preferred_delivery": [DeliveryMethod.MESSAGE, DeliveryMethod.INLINE_KEYBOARD]
        },
        "discord": {
            "max_length": 2000,
            "supports_threads": True,
            "supports_embeds": True,
            "supports_markdown": True,
            "emoji_indicators": True,
            "preferred_delivery": [DeliveryMethod.EMBED, DeliveryMethod.REPLY]
        }
    }
    
    # Visual indicators for risk levels across platforms
    RISK_INDICATORS = {
        "safe": "✅",
        "low": "🟢", 
        "medium": "⚠️",
        "high": "🚫",
        "critical": "🔴",
        "unknown": "❓"
    }
    
    @classmethod
    def get_commands_for_platform(cls, platform: Union[PlatformType, str]) -> Dict[CommandType, List[str]]:
        """Get all supported commands for a specific platform."""
        result = {}
        for command_type, platform_commands in cls.SUPPORTED_COMMANDS.items():
            if platform in platform_commands:
                result[command_type] = platform_commands[platform]
        return result
    
    @classmethod
    def get_command_patterns(cls, command_type: CommandType, platform: Union[PlatformType, str]) -> List[str]:
        """Get command patterns for a specific command type and platform."""
        return cls.SUPPORTED_COMMANDS.get(command_type, {}).get(platform, [])
    
    @classmethod
    def is_valid_command(cls, command_type: CommandType, platform: Union[PlatformType, str]) -> bool:
        """Check if a command type is supported on a platform."""
        return platform in cls.SUPPORTED_COMMANDS.get(command_type, {})
    
    @classmethod
    def get_platform_formatting(cls, platform: Union[PlatformType, str]) -> Dict[str, Any]:
        """Get formatting preferences for a platform."""
        return cls.RESPONSE_FORMATTING.get(platform, {})
    
    @classmethod
    def get_risk_indicator(cls, risk_level: str) -> str:
        """Get emoji indicator for a risk level."""
        return cls.RISK_INDICATORS.get(risk_level.lower(), cls.RISK_INDICATORS["unknown"])
    
    @classmethod
    def get_command_prefixes(cls, platform: Union[PlatformType, str]) -> List[str]:
        """Get command prefixes for a platform."""
        return cls.COMMAND_PREFIXES.get(platform, [])
    
    @classmethod
    def validate_command_syntax(cls, command_text: str, platform: Union[PlatformType, str]) -> Optional[CommandType]:
        """
        Validate command syntax and return command type if valid.
        
        Args:
            command_text: Raw command text from platform
            platform: Platform the command came from
            
        Returns:
            CommandType if valid, None otherwise
        """
        command_text = command_text.strip().lower()
        
        # Check each command type
        for command_type, platform_commands in cls.SUPPORTED_COMMANDS.items():
            if platform not in platform_commands:
                continue
                
            patterns = platform_commands[platform]
            for pattern in patterns:
                # Simple pattern matching - could be enhanced with regex
                pattern_lower = pattern.lower()
                
                # Remove parameter placeholders for basic matching
                pattern_base = pattern_lower.split(' ')[0]
                command_base = command_text.split(' ')[0]
                
                if pattern_base in command_base or command_base in pattern_base:
                    return command_type
        
        return None
    
    @classmethod
    def extract_parameters(cls, command_text: str, command_type: CommandType, platform: Union[PlatformType, str]) -> Dict[str, Any]:
        """
        Extract parameters from command text based on command type and platform.
        
        Args:
            command_text: Raw command text
            command_type: Identified command type
            platform: Platform the command came from
            
        Returns:
            Dictionary of extracted parameters
        """
        parameters = {}
        command_text = command_text.strip()
        
        if command_type == CommandType.ANALYZE_ACCOUNT:
            # Extract username/account identifier
            # This is a simplified implementation - could be enhanced with regex
            parts = command_text.split()
            for part in parts:
                if part.startswith('@') and len(part) > 1:
                    parameters['account_identifier'] = part[1:]  # Remove @ symbol
                    break
                elif 'user:' in part:
                    # Discord-style parameter
                    parameters['account_identifier'] = part.split('user:')[1].strip('@')
                    break
        
        elif command_type == CommandType.CHECK_COMPLIANCE:
            # Extract content to check
            if '"' in command_text:
                # Extract quoted content
                start_quote = command_text.find('"')
                end_quote = command_text.rfind('"')
                if start_quote != end_quote and start_quote != -1:
                    parameters['content'] = command_text[start_quote + 1:end_quote]
            elif 'content:' in command_text:
                # Discord-style parameter
                content_part = command_text.split('content:')[1]
                if content_part.startswith('"') and content_part.endswith('"'):
                    parameters['content'] = content_part[1:-1]
                else:
                    parameters['content'] = content_part.strip()
            else:
                # Telegram-style - everything after command
                parts = command_text.split(' ', 1)
                if len(parts) > 1:
                    parameters['content'] = parts[1]
        
        elif command_type == CommandType.ANALYZE_FOLLOWERS:
            # No additional parameters needed for follower analysis
            pass
        
        return parameters


# Utility functions for working with bot models

def create_account_analysis_command(
    platform: Union[PlatformType, str],
    user_id: str,
    account_identifier: str,
    metadata: Optional[Dict[str, Any]] = None
) -> BotCommand:
    """Create a standardized account analysis command."""
    return BotCommand(
        command_type=CommandType.ANALYZE_ACCOUNT,
        platform=platform,
        user_id=user_id,
        parameters={"account_identifier": account_identifier},
        metadata=metadata or {}
    )


def create_compliance_check_command(
    platform: Union[PlatformType, str],
    user_id: str,
    content: str,
    metadata: Optional[Dict[str, Any]] = None
) -> BotCommand:
    """Create a standardized compliance check command."""
    return BotCommand(
        command_type=CommandType.CHECK_COMPLIANCE,
        platform=platform,
        user_id=user_id,
        parameters={"content": content},
        metadata=metadata or {}
    )


def create_follower_analysis_command(
    platform: Union[PlatformType, str],
    user_id: str,
    account_identifier: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> BotCommand:
    """Create a standardized follower analysis command."""
    parameters = {}
    if account_identifier:
        parameters["account_identifier"] = account_identifier
    
    return BotCommand(
        command_type=CommandType.ANALYZE_FOLLOWERS,
        platform=platform,
        user_id=user_id,
        parameters=parameters,
        metadata=metadata or {}
    )


def parse_platform_command(platform_command: PlatformCommand) -> Optional[BotCommand]:
    """
    Parse a platform-specific command into a standardized BotCommand.
    
    Args:
        platform_command: Raw platform command data
        
    Returns:
        Standardized BotCommand or None if parsing fails
    """
    try:
        # Extract command text from platform-specific data
        command_text = ""
        user_id = ""
        
        platform_str = platform_command.platform.value if isinstance(platform_command.platform, PlatformType) else platform_command.platform
        
        if platform_str == "twitter":
            # Twitter-specific parsing logic
            command_text = platform_command.get_raw_data("text", "")
            user_id = platform_command.get_raw_data("user_id", "")
        elif platform_str == "telegram":
            # Telegram-specific parsing logic
            command_text = platform_command.get_raw_data("text", "")
            user_id = str(platform_command.get_raw_data("from", {}).get("id", ""))
        elif platform_str == "discord":
            # Discord-specific parsing logic
            command_text = platform_command.get_raw_data("data", {}).get("name", "")
            user_id = platform_command.get_raw_data("member", {}).get("user", {}).get("id", "")
        
        if not command_text or not user_id:
            return None
        
        # Validate and identify command type
        command_type = CommandRegistry.validate_command_syntax(command_text, platform_command.platform)
        if not command_type:
            return None
        
        # Extract parameters
        parameters = CommandRegistry.extract_parameters(command_text, command_type, platform_command.platform)
        
        # Create standardized command
        return BotCommand(
            command_type=command_type,
            platform=platform_command.platform,
            user_id=user_id,
            parameters=parameters,
            metadata={
                "original_command": command_text,
                "platform_data": platform_command.raw_data,
                "user_context": platform_command.user_context
            }
        )
    
    except Exception as e:
        # Log error and return None
        return None


def format_response_for_platform(
    bot_response: BotResponse,
    platform: Union[PlatformType, str],
    delivery_method: Optional[DeliveryMethod] = None
) -> FormattedResponse:
    """
    Format a BotResponse for a specific platform.
    
    Args:
        bot_response: Standardized bot response
        platform: Target platform
        delivery_method: Preferred delivery method (optional)
        
    Returns:
        Platform-specific formatted response
    """
    platform_formatting = CommandRegistry.get_platform_formatting(platform)
    
    # Determine delivery method if not specified
    if not delivery_method:
        preferred_methods = platform_formatting.get("preferred_delivery", [DeliveryMethod.MESSAGE])
        delivery_method = preferred_methods[0]
    
    # Format response data based on platform capabilities
    response_data = {}
    formatting_applied = []
    
    if bot_response.success:
        # Format successful response
        if bot_response.response_type == ResponseType.ANALYSIS_RESULT:
            response_data = _format_analysis_result(bot_response, platform, platform_formatting)
            formatting_applied.append("analysis_result")
        elif bot_response.response_type == ResponseType.COMPLIANCE_CHECK:
            response_data = _format_compliance_result(bot_response, platform, platform_formatting)
            formatting_applied.append("compliance_check")
        elif bot_response.response_type == ResponseType.FOLLOWER_ANALYSIS:
            response_data = _format_follower_result(bot_response, platform, platform_formatting)
            formatting_applied.append("follower_analysis")
    else:
        # Format error response
        response_data = _format_error_response(bot_response, platform, platform_formatting)
        formatting_applied.append("error_response")
    
    return FormattedResponse(
        platform=platform,
        response_data=response_data,
        delivery_method=delivery_method,
        formatting_applied=formatting_applied
    )


def _format_analysis_result(
    bot_response: BotResponse,
    platform: Union[PlatformType, str],
    platform_formatting: Dict[str, Any]
) -> Dict[str, Any]:
    """Format account analysis result for platform."""
    risk_level = bot_response.get_data("risk_level", "unknown")
    risk_indicator = CommandRegistry.get_risk_indicator(risk_level)
    
    # Basic formatting - would be enhanced based on platform capabilities
    message = f"{risk_indicator} Account Analysis Result\n"
    message += f"Risk Level: {risk_level.title()}\n"
    
    if bot_response.get_data("risk_score"):
        message += f"Risk Score: {bot_response.get_data('risk_score')}/100\n"
    
    recommendations = bot_response.get_data("recommendations", [])
    if recommendations:
        message += "\nRecommendations:\n"
        for i, rec in enumerate(recommendations[:3], 1):  # Limit to 3 recommendations
            message += f"{i}. {rec}\n"
    
    return {"text": message}


def _format_compliance_result(
    bot_response: BotResponse,
    platform: Union[PlatformType, str],
    platform_formatting: Dict[str, Any]
) -> Dict[str, Any]:
    """Format compliance check result for platform."""
    is_compliant = bot_response.get_data("is_compliant", True)
    indicator = "✅" if is_compliant else "⚠️"
    
    message = f"{indicator} Compliance Check Result\n"
    message += f"Status: {'Compliant' if is_compliant else 'Issues Found'}\n"
    
    if bot_response.get_data("compliance_score"):
        message += f"Compliance Score: {bot_response.get_data('compliance_score')}/100\n"
    
    violations = bot_response.get_data("violations", [])
    if violations:
        message += f"\nViolations Found: {len(violations)}\n"
        for violation in violations[:2]:  # Limit to 2 violations
            message += f"• {violation}\n"
    
    return {"text": message}


def _format_follower_result(
    bot_response: BotResponse,
    platform: Union[PlatformType, str],
    platform_formatting: Dict[str, Any]
) -> Dict[str, Any]:
    """Format follower analysis result for platform."""
    verified_count = bot_response.get_data("verified_followers_count", 0)
    
    message = f"👥 Follower Analysis Result\n"
    message += f"Verified Followers: {verified_count}\n"
    
    if bot_response.get_data("high_value_count"):
        message += f"High-Value Followers: {bot_response.get_data('high_value_count')}\n"
    
    networking_opportunities = bot_response.get_data("networking_opportunities", [])
    if networking_opportunities:
        message += f"\nNetworking Opportunities: {len(networking_opportunities)}\n"
    
    return {"text": message}


def _format_error_response(
    bot_response: BotResponse,
    platform: Union[PlatformType, str],
    platform_formatting: Dict[str, Any]
) -> Dict[str, Any]:
    """Format error response for platform."""
    message = f"❌ Error: {bot_response.error_message}\n"
    message += "Please try again or contact support if the issue persists."
    
    return {"text": message}