"""
Bot module for LinkShield social protection platform.

This module provides bot functionality for Twitter, Telegram, and Discord platforms,
enabling quick-access responses for URL analysis and social protection services.
"""

from .gateway import QuickAccessBotGateway
from .models import (
    BotCommand,
    BotResponse,
    PlatformCommand,
    FormattedResponse,
    CommandRegistry,
    PlatformType,
    CommandType,
    ResponseType,
    DeliveryMethod,
    create_account_analysis_command,
    create_compliance_check_command,
    create_follower_analysis_command,
    parse_platform_command,
    format_response_for_platform
)

__all__ = [
    "QuickAccessBotGateway",
    "BotCommand",
    "BotResponse", 
    "PlatformCommand",
    "FormattedResponse",
    "CommandRegistry",
    "PlatformType",
    "CommandType",
    "ResponseType",
    "DeliveryMethod",
    "create_account_analysis_command",
    "create_compliance_check_command",
    "create_follower_analysis_command",
    "parse_platform_command",
    "format_response_for_platform"
]