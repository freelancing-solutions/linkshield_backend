#!/usr/bin/env python3
"""
LinkShield Backend User Models

SQLAlchemy models for user management, authentication, and profile data.
Includes user accounts, sessions, and subscription information.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from passlib.hash import bcrypt

from src.config.database import Base
import enum

class UserRole(enum.Enum):
    """
    User role enumeration.
    """
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"


class SubscriptionPlan(enum.Enum):
    """
    Subscription plan enumeration.
    """
    FREE = "free"
    BASIC = "basic"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class UserStatus(enum.Enum):
    """
    User account status enumeration.
    """
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class User(Base):
    """
    User model for authentication and profile management.
    """
    __tablename__ = "users"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Basic user information
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=True)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    
    # Authentication
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.PENDING_VERIFICATION, nullable=False)
    
    # Subscription information
    subscription_plan = Column(Enum(SubscriptionPlan), default=SubscriptionPlan.FREE, nullable=False)
    subscription_expires_at = Column(DateTime(timezone=True), nullable=True)
    stripe_customer_id = Column(String(100), nullable=True, index=True)
    
    # Usage tracking
    daily_check_count = Column(Integer, default=0, nullable=False)
    total_check_count = Column(Integer, default=0, nullable=False)
    last_check_reset = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Profile information
    avatar_url = Column(String(500), nullable=True)
    bio = Column(Text, nullable=True)
    website = Column(String(500), nullable=True)
    location = Column(String(100), nullable=True)
    
    # Security and preferences
    two_factor_enabled = Column(Boolean, default=False, nullable=False)
    two_factor_secret = Column(String(32), nullable=True)
    email_notifications = Column(Boolean, default=True, nullable=False)
    marketing_emails = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    email_verified_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    url_checks = relationship("URLCheck", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"
    
    def set_password(self, password: str) -> None:
        """Set user password with proper hashing."""
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password: str) -> bool:
        """Check if provided password matches the stored hash."""
        return bcrypt.verify(password, self.password_hash)

    def get_full_name(self) -> str:
        """
        Get user's full name or fallback to email.
        """
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.username:
            return self.username
        else:
            return self.email.split("@")[0]
    
    def is_subscription_active(self) -> bool:
        """
        Check if user's subscription is currently active.
        """
        if self.subscription_plan == SubscriptionPlan.FREE:
            return True
        
        if not self.subscription_expires_at:
            return False
        
        return self.subscription_expires_at > datetime.now(timezone.utc)
    
    def get_daily_limit(self) -> int:
        """
        Get daily check limit based on subscription plan.
        """
        limits = {
            SubscriptionPlan.FREE: 10,
            SubscriptionPlan.BASIC: 100,
            SubscriptionPlan.PRO: 1000,
            SubscriptionPlan.ENTERPRISE: 10000,
        }
        return limits.get(self.subscription_plan, 10)
    
    def can_perform_check(self) -> bool:
        """
        Check if user can perform another URL check based on daily limits.
        """
        # Reset daily count if it's a new day
        now = datetime.now(timezone.utc)
        if self.last_check_reset.date() < now.date():
            self.daily_check_count = 0
            self.last_check_reset = now
        
        return self.daily_check_count < self.get_daily_limit()
    
    def increment_check_count(self) -> None:
        """
        Increment user's check counters.
        """
        self.daily_check_count += 1
        self.total_check_count += 1
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user to dictionary representation.
        """
        data = {
            "id": str(self.id),
            "email": self.email,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.get_full_name(),
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "role": self.role.value,
            "status": self.status.value,
            "subscription_plan": self.subscription_plan.value,
            "subscription_active": self.is_subscription_active(),
            "daily_check_count": self.daily_check_count,
            "daily_limit": self.get_daily_limit(),
            "total_check_count": self.total_check_count,
            "avatar_url": self.avatar_url,
            "bio": self.bio,
            "website": self.website,
            "location": self.location,
            "two_factor_enabled": self.two_factor_enabled,
            "email_notifications": self.email_notifications,
            "marketing_emails": self.marketing_emails,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "email_verified_at": self.email_verified_at.isoformat() if self.email_verified_at else None,
        }
        
        if include_sensitive:
            data.update({
                "stripe_customer_id": self.stripe_customer_id,
                "subscription_expires_at": self.subscription_expires_at.isoformat() if self.subscription_expires_at else None,
                "two_factor_secret": self.two_factor_secret,
            })
        
        return data


class UserSession(Base):
    """
    User session model for tracking active sessions.
    """
    __tablename__ = "user_sessions"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to user
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Session information
    session_token = Column(String(255), unique=True, index=True, nullable=False)
    refresh_token = Column(String(255), unique=True, index=True, nullable=True)
    device_info = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    
    # Session status
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_accessed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self) -> str:
        return f"<UserSession(id={self.id}, user_id={self.user_id}, active={self.is_active})>"
    
    def is_expired(self) -> bool:
        """
        Check if session is expired.
        """
        return datetime.now(timezone.utc) > self.expires_at
    
    def extend_session(self, minutes: int = 30) -> None:
        """
        Extend session expiration time.
        """
        from datetime import timedelta
        self.expires_at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        self.last_accessed_at = datetime.now(timezone.utc)


class APIKey(Base):
    """
    API key model for programmatic access.
    """
    __tablename__ = "api_keys"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to user
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # API key information
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), unique=True, index=True, nullable=False)
    key_prefix = Column(String(10), nullable=False)  # First few characters for identification
    
    # Permissions and limits
    is_active = Column(Boolean, default=True, nullable=False)
    rate_limit = Column(Integer, default=100, nullable=False)  # Requests per hour
    
    # Usage tracking
    usage_count = Column(Integer, default=0, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    def __repr__(self) -> str:
        return f"<APIKey(id={self.id}, name={self.name}, user_id={self.user_id})>"
    
    def is_expired(self) -> bool:
        """
        Check if API key is expired.
        """
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def increment_usage(self) -> None:
        """
        Increment API key usage counter.
        """
        self.usage_count += 1
        self.last_used_at = datetime.now(timezone.utc)


class PasswordResetToken(Base):
    """
    Password reset token model.
    """
    __tablename__ = "password_reset_tokens"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to user
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Token information
    token_hash = Column(String(255), unique=True, index=True, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self) -> str:
        return f"<PasswordResetToken(id={self.id}, user_id={self.user_id}, used={self.is_used})>"
    
    def is_expired(self) -> bool:
        """
        Check if token is expired.
        """
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_valid(self) -> bool:
        """
        Check if token is valid (not used and not expired).
        """
        return not self.is_used and not self.is_expired()


class EmailVerificationToken(Base):
    """
    Email verification token model.
    """
    __tablename__ = "email_verification_tokens"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to user
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Token information
    token_hash = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), nullable=False)  # Email being verified
    is_used = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    
    def __repr__(self) -> str:
        return f"<EmailVerificationToken(id={self.id}, email={self.email}, used={self.is_used})>"
    
    def is_expired(self) -> bool:
        """
        Check if token is expired.
        """
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_valid(self) -> bool:
        """
        Check if token is valid (not used and not expired).
        """
        return not self.is_used and not self.is_expired()