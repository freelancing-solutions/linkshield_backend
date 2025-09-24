#!/usr/bin/env python3
"""
Activity log models for tracking user and project activities.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any as AnyType

from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from src.config.database import Base


class ActivityLog(Base):
    """Activity log entry for tracking user and project activities."""
    
    __tablename__ = "activity_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=True, index=True)
    resource_id = Column(String(100), nullable=True, index=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 support
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    # Relationships
    user = relationship("User", back_populates="activity_logs")
    project = relationship("Project", back_populates="activity_logs")
    
    # Indexes for common queries
    __table_args__ = (
        Index("idx_activity_user_created", "user_id", "created_at"),
        Index("idx_activity_project_created", "project_id", "created_at"),
        Index("idx_activity_action_created", "action", "created_at"),
    )
    
    def __repr__(self) -> str:
        return f"<ActivityLog(id={self.id}, user_id={self.user_id}, action={self.action}, created_at={self.created_at})>"


class ActivityLogManager:
    """Manager class for activity log operations."""
    
    # Activity types for consistent logging
    ACTIVITY_TYPES = {
        # Project activities
        "project_created": "Project created",
        "project_updated": "Project updated",
        "project_deleted": "Project deleted",
        "project_member_added": "Project member added",
        "project_member_removed": "Project member removed",
        "project_member_role_changed": "Project member role changed",
        "project_settings_updated": "Project settings updated",
        
        # Monitoring activities
        "monitoring_enabled": "Monitoring enabled",
        "monitoring_disabled": "Monitoring disabled",
        "scan_started": "Scan started",
        "scan_completed": "Scan completed",
        "scan_failed": "Scan failed",
        
        # Alert activities
        "alert_created": "Alert created",
        "alert_acknowledged": "Alert acknowledged",
        "alert_resolved": "Alert resolved",
        "alert_dismissed": "Alert dismissed",
        "alert_updated": "Alert updated",
        
        # User activities
        "user_login": "User logged in",
        "user_logout": "User logged out",
        "user_registered": "User registered",
        "user_profile_updated": "User profile updated",
        "password_changed": "Password changed",
        
        # Subscription activities
        "subscription_created": "Subscription created",
        "subscription_updated": "Subscription updated",
        "subscription_cancelled": "Subscription cancelled",
        "payment_processed": "Payment processed",
        
        # Security activities
        "security_scan_completed": "Security scan completed",
        "vulnerability_detected": "Vulnerability detected",
        "suspicious_activity_detected": "Suspicious activity detected",
        "two_factor_enabled": "Two-factor authentication enabled",
        "two_factor_disabled": "Two-factor authentication disabled",
    }
    
    @classmethod
    def get_activity_description(cls, action: str) -> str:
        """Get human-readable description for an activity type."""
        return cls.ACTIVITY_TYPES.get(action, f"Unknown activity: {action}")
    
    @classmethod
    def is_valid_action(cls, action: str) -> bool:
        """Check if an action type is valid."""
        return action in cls.ACTIVITY_TYPES