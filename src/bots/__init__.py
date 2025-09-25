"""
Bot module for LinkShield social protection platform.

This module provides bot functionality for Twitter, Telegram, and Discord platforms,
enabling quick-access responses for URL analysis and social protection services.
"""

from .gateway import QuickAccessBotGateway

__all__ = [
    "QuickAccessBotGateway",
]