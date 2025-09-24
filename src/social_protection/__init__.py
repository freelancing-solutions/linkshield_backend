"""
Social Protection Module for LinkShield Backend

This module provides comprehensive social media protection capabilities including:
- Multi-platform risk assessment (Twitter/X, Meta, TikTok, LinkedIn)
- Real-time content analysis and threat detection
- Browser extension integration for immediate protection
- Crisis detection and reputation monitoring
- Algorithm health tracking and penalty detection

The module follows a modular plugin architecture that integrates seamlessly
with the existing LinkShield infrastructure.
"""

from .platform_adapters.base_adapter import SocialPlatformAdapter
from .registry import PlatformRegistry
from .services.extension_data_processor import ExtensionDataProcessor
from .services.social_scan_service import SocialScanService

# Core interfaces and services
__all__ = [
    "SocialPlatformAdapter",
    "PlatformRegistry", 
    "ExtensionDataProcessor",
    "SocialScanService",
]

# Module version
__version__ = "1.0.0"

# Initialize the global platform registry
platform_registry = PlatformRegistry()