"""
Platform Adapters Module

Provides platform-specific implementations for social media protection including:
- Abstract base adapter interface
- Twitter/X protection adapter
- Meta (Facebook/Instagram) protection adapter  
- TikTok protection adapter
- LinkedIn protection adapter
"""

from .base_adapter import SocialPlatformAdapter
from .twitter_adapter import TwitterProtectionAdapter
from .meta_adapter import MetaProtectionAdapter
from .tiktok_adapter import TikTokProtectionAdapter
from .linkedin_adapter import LinkedInProtectionAdapter

__all__ = [
    "SocialPlatformAdapter",
    "TwitterProtectionAdapter",
    "MetaProtectionAdapter", 
    "TikTokProtectionAdapter",
    "LinkedInProtectionAdapter",
]