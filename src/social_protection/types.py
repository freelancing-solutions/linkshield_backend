"""
Social Protection Types

This module defines shared enums and types used across the social protection
system to avoid circular import dependencies between modules.

Contains platform types, risk levels, and other common enumerations
used by platform adapters, data models, and services.
"""

from enum import Enum


class PlatformType(Enum):
    """Supported social media platforms"""
    TWITTER = "twitter"
    META_FACEBOOK = "meta_facebook"
    META_INSTAGRAM = "meta_instagram"
    TIKTOK = "tiktok"
    LINKEDIN = "linkedin"
    TELEGRAM = "telegram"
    DISCORD = "discord"


class RiskLevel(Enum):
    """Risk assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(Enum):
    """Scan operation status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MonitoringFrequency(Enum):
    """Monitoring frequency options."""
    REAL_TIME = "real_time"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ContentType(Enum):
    """Content type enumeration for social media content."""
    POST = "post"
    COMMENT = "comment"
    STORY = "story"
    REEL = "reel"
    VIDEO = "video"
    IMAGE = "image"
    LINK = "link"
    PROFILE = "profile"


class ScanDepth(Enum):
    """Scan depth levels"""
    BASIC = "basic"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    DEEP = "deep"