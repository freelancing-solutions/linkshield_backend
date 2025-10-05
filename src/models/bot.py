"""
Database models for bot operations and user interactions.

This module defines SQLAlchemy models for tracking bot usage,
user statistics, and platform-specific user mappings.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
from typing import Optional
from src.config.database import Base
import enum


class BotPlatform(enum.Enum):
    """
    Social media platform enumeration for bot operations.
    
    Defines the supported platforms where LinkShield bots can operate
    and interact with users for social protection services.
    """
    TWITTER = "twitter"
    TELEGRAM = "telegram"
    DISCORD = "discord"


class BotUser(Base):
    """
    Model for tracking bot users across different platforms.
    
    Maps platform-specific user IDs to internal user records
    and tracks user preferences and statistics. Now linked to
    authenticated users with subscription validation.
    """
    __tablename__ = "bot_users"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Link to authenticated user (required for subscription validation)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    
    platform = Column(String(20), nullable=False, index=True)  # twitter, telegram, discord
    platform_user_id = Column(String(100), nullable=False, index=True)
    username = Column(String(100), nullable=True)
    display_name = Column(String(200), nullable=True)
    
    # User preferences
    notifications_enabled = Column(Boolean, default=True)
    deep_analysis_enabled = Column(Boolean, default=False)
    language_preference = Column(String(10), default="en")
    
    # Statistics
    total_analyses = Column(Integer, default=0)
    safe_urls_count = Column(Integer, default=0)
    risky_urls_count = Column(Integer, default=0)
    last_analysis_at = Column(DateTime, nullable=True)
    
    # Subscription validation fields
    subscription_validated_at = Column(DateTime(timezone=True), nullable=True)
    last_subscription_check = Column(DateTime(timezone=True), nullable=True)
    subscription_plan_at_link = Column(String(20), nullable=True)
    
    # Bot-specific usage tracking
    monthly_bot_requests = Column(Integer, default=0, nullable=False)
    monthly_reset_date = Column(DateTime(timezone=True), nullable=True)
    feature_access_level = Column(String(20), default="basic", nullable=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="bot_users")
    rate_limits = relationship("BotRateLimit", back_populates="user")
    sessions = relationship("BotSession", back_populates="user")
    analysis_requests = relationship("BotAnalysisRequest", back_populates="user")
    interactions = relationship("BotInteraction", back_populates="user")
    analytics_events = relationship("BotAnalyticsEvent", back_populates="user")
    
    def __repr__(self):
        return f"<BotUser(platform={self.platform}, user_id={self.platform_user_id}, username={self.username}, linked_user={self.user_id})>"
    
    def is_subscription_valid(self) -> bool:
        """
        Check if the linked user has a valid subscription for bot access.
        
        Returns:
            bool: True if user has valid subscription, False otherwise
        """
        if not self.user:
            return False
        
        # FREE plan users don't have bot access
        if self.user.subscription_plan.value == "free":
            return False
        
        # Check if subscription is active
        return self.user.is_subscription_active()
    
    def get_bot_feature_limits(self) -> dict:
        """
        Get bot-specific feature limits based on user's subscription plan.
        
        Returns:
            dict: Dictionary containing feature limits
        """
        if not self.user:
            return {"monthly_requests": 0, "deep_analysis": False, "priority_support": False}
        
        plan = self.user.subscription_plan.value
        limits = {
            "basic": {
                "monthly_requests": 100,
                "deep_analysis": False,
                "priority_support": False,
                "platforms_allowed": 1
            },
            "pro": {
                "monthly_requests": 1000,
                "deep_analysis": True,
                "priority_support": True,
                "platforms_allowed": 3
            },
            "enterprise": {
                "monthly_requests": 10000,
                "deep_analysis": True,
                "priority_support": True,
                "platforms_allowed": 10
            }
        }
        
        return limits.get(plan, {"monthly_requests": 0, "deep_analysis": False, "priority_support": False})
    
    def can_make_bot_request(self) -> bool:
        """
        Check if bot user can make another request based on subscription limits.
        
        Returns:
            bool: True if request is allowed, False otherwise
        """
        if not self.is_subscription_valid():
            return False
        
        limits = self.get_bot_feature_limits()
        
        # Reset monthly count if needed
        now = datetime.now(timezone.utc)
        if not self.monthly_reset_date or self.monthly_reset_date.month != now.month:
            self.monthly_bot_requests = 0
            self.monthly_reset_date = now
        
        return self.monthly_bot_requests < limits["monthly_requests"]
    
    def increment_bot_request_count(self) -> None:
        """
        Increment the bot request counter for usage tracking.
        """
        self.monthly_bot_requests += 1
        self.last_analysis_at = datetime.utcnow()
    
    def update_subscription_validation(self) -> None:
        """
        Update subscription validation timestamp and plan info.
        """
        now = datetime.now(timezone.utc)
        self.last_subscription_check = now
        
        if self.user and self.is_subscription_valid():
            self.subscription_validated_at = now
            self.subscription_plan_at_link = self.user.subscription_plan.value
            
            # Update feature access level based on subscription
            limits = self.get_bot_feature_limits()
            if limits["deep_analysis"]:
                self.feature_access_level = "premium"
            else:
                self.feature_access_level = "basic"


class BotAnalysisRequest(Base):
    """
    Model for tracking URL analysis requests made through bots.
    
    Records each analysis request with metadata about the request,
    results, and performance metrics.
    """
    __tablename__ = "bot_analysis_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("bot_users.id"), nullable=False, index=True)
    
    # Request details
    url = Column(Text, nullable=False)
    url_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash for deduplication
    platform = Column(String(20), nullable=False, index=True)
    request_type = Column(String(20), default="quick")  # quick, deep
    
    # Analysis results
    risk_level = Column(String(20), nullable=True)  # safe, low, medium, high, unknown
    risk_score = Column(Float, nullable=True)
    analysis_message = Column(Text, nullable=True)
    threats_detected = Column(Text, nullable=True)  # JSON string of detected threats
    
    # Performance metrics
    analysis_duration_ms = Column(Integer, nullable=True)
    cache_hit = Column(Boolean, default=False)
    error_occurred = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    
    # Metadata
    requested_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Platform-specific data
    platform_message_id = Column(String(100), nullable=True)  # Original message ID
    platform_response_id = Column(String(100), nullable=True)  # Bot response message ID
    
    # Relationships
    user = relationship("BotUser", back_populates="analysis_requests")
    
    def __repr__(self):
        return f"<BotAnalysisRequest(id={self.id}, url_hash={self.url_hash}, risk_level={self.risk_level})>"


class BotRateLimit(Base):
    """
    Model for tracking rate limiting per user and platform.
    
    Implements sliding window rate limiting to prevent abuse
    and ensure fair usage across all bot users.
    """
    __tablename__ = "bot_rate_limits"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("bot_users.id"), nullable=False, index=True)
    platform = Column(String(20), nullable=False, index=True)
    
    # Rate limiting data
    requests_count = Column(Integer, default=0)
    window_start = Column(DateTime, default=datetime.utcnow)
    window_duration_minutes = Column(Integer, default=60)  # 1 hour window
    max_requests = Column(Integer, default=50)  # Max requests per window
    
    # Status
    is_blocked = Column(Boolean, default=False)
    blocked_until = Column(DateTime, nullable=True)
    block_reason = Column(String(200), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<BotRateLimit(user_id={self.user_id}, platform={self.platform}, requests={self.requests_count}/{self.max_requests})>"


class BotSession(Base):
    """
    Model for tracking bot user sessions and interactions.
    
    Tracks user engagement patterns and session-based analytics
    for improving bot performance and user experience.
    """
    __tablename__ = "bot_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("bot_users.id"), nullable=False, index=True)
    platform = Column(String(20), nullable=False, index=True)
    
    # Session data
    session_id = Column(String(100), nullable=False, unique=True, index=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    last_activity_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    
    # Session metrics
    total_requests = Column(Integer, default=0)
    successful_analyses = Column(Integer, default=0)
    failed_analyses = Column(Integer, default=0)
    commands_used = Column(Text, nullable=True)  # JSON array of commands used
    
    # Platform-specific data
    platform_chat_id = Column(String(100), nullable=True)
    platform_channel_id = Column(String(100), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    def __repr__(self):
        return f"<BotSession(id={self.id}, user_id={self.user_id}, platform={self.platform}, active={self.is_active})>"


class BotConfiguration(Base):
    """
    Model for storing bot configuration and feature flags.
    
    Allows dynamic configuration of bot behavior without
    requiring code deployments or server restarts.
    """
    __tablename__ = "bot_configurations"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Configuration identity
    config_key = Column(String(100), nullable=False, unique=True, index=True)
    config_value = Column(Text, nullable=False)
    config_type = Column(String(20), default="string")  # string, integer, boolean, json
    
    # Metadata
    description = Column(Text, nullable=True)
    category = Column(String(50), default="general")
    is_active = Column(Boolean, default=True)
    
    # Versioning
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<BotConfiguration(key={self.config_key}, value={self.config_value}, type={self.config_type})>"


class BotInteraction(Base):
    """
    Bot interaction logging.
    
    Records all interactions between users and bots across platforms.
    """
    __tablename__ = "bot_interactions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("bot_users.id"), nullable=False)
    platform = Column(String(20), nullable=False)  # 'twitter', 'telegram', 'discord'
    interaction_type = Column(String(50), nullable=False)  # 'command', 'webhook', 'message'
    request_data = Column(Text, nullable=True)  # Original request payload as JSON
    response_data = Column(Text, nullable=True)  # Response sent back as JSON
    success = Column(Boolean, default=True)
    error_message = Column(Text)
    response_time_ms = Column(Integer)  # Response time in milliseconds
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("BotUser", back_populates="interactions")
    
    def __repr__(self):
        return f"<BotInteraction(id={self.id}, platform={self.platform}, type={self.interaction_type})>"


class BotAnalyticsEvent(Base):
    """
    Model for tracking bot analytics and usage events.
    
    Records detailed analytics for monitoring bot performance,
    user engagement, and identifying improvement opportunities.
    """
    __tablename__ = "bot_analytics_events"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("bot_users.id"), nullable=True, index=True)
    
    # Event details
    event_type = Column(String(50), nullable=False, index=True)  # command_used, analysis_completed, error_occurred, etc.
    event_category = Column(String(30), nullable=False, index=True)  # user_action, system_event, error
    platform = Column(String(20), nullable=False, index=True)
    
    # Event data
    event_data = Column(Text, nullable=True)  # JSON string with event-specific data
    user_agent = Column(String(200), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    
    # Performance metrics
    response_time_ms = Column(Integer, nullable=True)
    success = Column(Boolean, default=True)
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Metadata
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    session_id = Column(String(100), nullable=True, index=True)
    
    def __repr__(self):
        return f"<BotAnalyticsEvent(type={self.event_type}, platform={self.platform}, success={self.success})>"


# Utility functions for working with bot models

def get_or_create_bot_user(db_session, platform: str, platform_user_id: str, 
                          username: Optional[str] = None, display_name: Optional[str] = None) -> BotUser:
    """
    Get existing bot user or create a new one.
    
    Args:
        db_session: Database session
        platform: Platform name (twitter, telegram, discord)
        platform_user_id: Platform-specific user ID
        username: User's username/handle
        display_name: User's display name
        
    Returns:
        BotUser instance
    """
    user = db_session.query(BotUser).filter(
        BotUser.platform == platform,
        BotUser.platform_user_id == platform_user_id
    ).first()
    
    if not user:
        user = BotUser(
            platform=platform,
            platform_user_id=platform_user_id,
            username=username,
            display_name=display_name
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    else:
        # Update username and display name if provided
        if username and user.username != username:
            user.username = username
        if display_name and user.display_name != display_name:
            user.display_name = display_name
        
        user.updated_at = datetime.utcnow()
        db_session.commit()
    
    return user


def update_user_stats(db_session, user: BotUser, risk_level: str):
    """
    Update user statistics after an analysis.
    
    Args:
        db_session: Database session
        user: BotUser instance
        risk_level: Analysis risk level result
    """
    user.total_analyses += 1
    user.last_analysis_at = datetime.utcnow()
    
    if risk_level in ["safe", "low"]:
        user.safe_urls_count += 1
    elif risk_level in ["medium", "high"]:
        user.risky_urls_count += 1
    
    user.updated_at = datetime.utcnow()
    db_session.commit()


def check_rate_limit(db_session, user: BotUser, platform: str) -> tuple[bool, Optional[BotRateLimit]]:
    """
    Check if user has exceeded rate limits.
    
    Args:
        db_session: Database session
        user: BotUser instance
        platform: Platform name
        
    Returns:
        Tuple of (is_allowed, rate_limit_record)
    """
    from datetime import timedelta
    
    rate_limit = db_session.query(BotRateLimit).filter(
        BotRateLimit.user_id == user.id,
        BotRateLimit.platform == platform
    ).first()
    
    if not rate_limit:
        # Create new rate limit record
        rate_limit = BotRateLimit(
            user_id=user.id,
            platform=platform,
            requests_count=1
        )
        db_session.add(rate_limit)
        db_session.commit()
        return True, rate_limit
    
    # Check if window has expired
    window_end = rate_limit.window_start + timedelta(minutes=rate_limit.window_duration_minutes)
    now = datetime.utcnow()
    
    if now > window_end:
        # Reset window
        rate_limit.window_start = now
        rate_limit.requests_count = 1
        rate_limit.is_blocked = False
        rate_limit.blocked_until = None
        rate_limit.updated_at = now
        db_session.commit()
        return True, rate_limit
    
    # Check if blocked
    if rate_limit.is_blocked and rate_limit.blocked_until and now < rate_limit.blocked_until:
        return False, rate_limit
    
    # Check request count
    if rate_limit.requests_count >= rate_limit.max_requests:
        # Block user
        rate_limit.is_blocked = True
        rate_limit.blocked_until = window_end
        rate_limit.block_reason = "Rate limit exceeded"
        rate_limit.updated_at = now
        db_session.commit()
        return False, rate_limit
    
    # Increment request count
    rate_limit.requests_count += 1
    rate_limit.updated_at = now
    db_session.commit()
    
    return True, rate_limit