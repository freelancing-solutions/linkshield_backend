#!/usr/bin/env python3
"""
LinkShield Backend Admin Models

SQLAlchemy models for admin dashboard functionality including global configuration,
admin actions audit trail, system health monitoring, and admin sessions.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
    Float,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from src.config.database import Base


class ConfigCategory(enum.Enum):
    """
    Configuration category enumeration for organizing settings.
    """
    SECURITY = "security"
    RATE_LIMITING = "rate_limiting"
    AI_SERVICES = "ai_services"
    EXTERNAL_APIS = "external_apis"
    SYSTEM = "system"
    NOTIFICATIONS = "notifications"


class ActionType(enum.Enum):
    """
    Admin action type enumeration for audit logging.
    """
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    CONFIG_CHANGE = "config_change"
    USER_MANAGEMENT = "user_management"
    SYSTEM_OPERATION = "system_operation"


class HealthStatus(enum.Enum):
    """
    System health status enumeration.
    """
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class GlobalConfig(Base):
    """
    Global configuration model for system-wide settings.
    Stores key-value pairs with metadata for admin configuration management.
    """
    __tablename__ = "global_config"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Configuration details
    key = Column(String(255), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=False)
    category = Column(Enum(ConfigCategory), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Metadata
    is_active = Column(Boolean, default=True, nullable=False)
    is_sensitive = Column(Boolean, default=False, nullable=False)  # For masking sensitive values
    data_type = Column(String(50), default="string", nullable=False)  # string, integer, boolean, json
    
    # Validation
    validation_regex = Column(String(500), nullable=True)
    min_value = Column(Float, nullable=True)
    max_value = Column(Float, nullable=True)
    allowed_values = Column(JSON, nullable=True)  # List of allowed values
    
    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    # Relationships
    creator = relationship("User", foreign_keys=[created_by], backref="created_configs")
    updater = relationship("User", foreign_keys=[updated_by], backref="updated_configs")


class AdminAction(Base):
    """
    Admin action audit log model.
    Tracks all administrative actions for security and compliance.
    """
    __tablename__ = "admin_actions"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Action details
    action_type = Column(Enum(ActionType), nullable=False, index=True)
    endpoint = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)  # GET, POST, PUT, DELETE, etc.
    
    # Request information
    request_data = Column(JSON, nullable=True)  # Sanitized request payload
    query_params = Column(JSON, nullable=True)
    path_params = Column(JSON, nullable=True)
    
    # Response information
    response_status = Column(Integer, nullable=True)
    response_data = Column(JSON, nullable=True)  # Sanitized response data
    
    # User and session information
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    
    # Network information
    ip_address = Column(String(45), nullable=True, index=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    
    # Timing information
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    duration_ms = Column(Integer, nullable=True)  # Request duration in milliseconds
    
    # Additional metadata
    success = Column(Boolean, nullable=False, index=True)
    error_message = Column(Text, nullable=True)
    additional_data = Column(JSON, nullable=True)  # Any additional context
    
    # Relationships
    user = relationship("User", backref="admin_actions")


class SystemHealth(Base):
    """
    System health monitoring model.
    Stores periodic health check results and system metrics.
    """
    __tablename__ = "system_health"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Health check details
    component = Column(String(100), nullable=False, index=True)  # database, redis, external_api, etc.
    status = Column(Enum(HealthStatus), nullable=False, index=True)
    
    # Metrics
    response_time_ms = Column(Float, nullable=True)
    cpu_usage_percent = Column(Float, nullable=True)
    memory_usage_percent = Column(Float, nullable=True)
    disk_usage_percent = Column(Float, nullable=True)
    
    # Additional details
    details = Column(JSON, nullable=True)  # Component-specific health data
    error_message = Column(Text, nullable=True)
    
    # Timing
    checked_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('component', 'checked_at', name='uq_component_timestamp'),
    )


class AdminSession(Base):
    """
    Admin session tracking model.
    Enhanced session tracking specifically for administrative users.
    """
    __tablename__ = "admin_sessions"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Session details
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    
    # Session metadata
    ip_address = Column(String(45), nullable=True, index=True)
    user_agent = Column(Text, nullable=True)
    location = Column(String(255), nullable=True)  # Geolocation if available
    
    # Session state
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    last_activity = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Timing
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    terminated_at = Column(DateTime(timezone=True), nullable=True)
    
    # Security
    permissions = Column(JSON, nullable=True)  # Session-specific permissions
    mfa_verified = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    user = relationship("User", backref="admin_sessions")