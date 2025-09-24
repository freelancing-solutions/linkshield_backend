#!/usr/bin/env python3
"""
LinkShield Backend Project Models

SQLAlchemy models for dashboard project management, monitoring configuration,
and alert systems. Includes project management, team collaboration,
monitoring settings, and alert preferences.
"""

import uuid
from datetime import datetime, timezone, timedelta
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
    Index,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.config.database import Base
import enum


class ProjectRole(enum.Enum):
    """
    Project member role enumeration for team collaboration.
    """
    OWNER = "owner"
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


class AlertType(enum.Enum):
    """
    Alert type enumeration for project monitoring.
    """
    BROKEN_LINKS = "broken_links"
    HARMFUL_CONTENT = "harmful_content"
    SCAN_FAILED = "scan_failed"
    SECURITY_THREAT = "security_threat"


class AlertChannel(enum.Enum):
    """
    Alert channel enumeration for notification delivery.
    """
    EMAIL = "email"
    DASHBOARD = "dashboard"
    WEBHOOK = "webhook"


class Project(Base):
    """
    Project model for website monitoring and dashboard functionality.
    """
    __tablename__ = "projects"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to user (project owner)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Project information
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    website_url = Column(String(500), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    
    # Project status
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    monitoring_enabled = Column(Boolean, default=True, nullable=False, index=True)
    
    # Project settings
    settings = Column(JSONB, nullable=True)  # JSON object for project-specific settings
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_scan_at = Column(DateTime(timezone=True), nullable=True, index=True)
    
    # Relationships
    owner = relationship("User", back_populates="projects")
    members = relationship("ProjectMember", back_populates="project", cascade="all, delete-orphan")
    monitoring_config = relationship("MonitoringConfig", back_populates="project", uselist=False, cascade="all, delete-orphan")
    alerts = relationship("ProjectAlert", back_populates="project", cascade="all, delete-orphan")
    alert_instances = relationship("AlertInstance", back_populates="project", cascade="all, delete-orphan")
    activity_logs = relationship("ActivityLog", back_populates="project", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<Project(id={self.id}, name={self.name}, domain={self.domain})>"
    
    def is_owner(self, user_id: uuid.UUID) -> bool:
        """
        Check if user is the project owner.
        """
        return self.user_id == user_id
    
    def get_member_count(self) -> int:
        """
        Get total number of project members including owner.
        """
        return len(self.members) + 1  # +1 for owner
    
    def get_active_members(self) -> List["ProjectMember"]:
        """
        Get all active project members.
        """
        return [member for member in self.members if member.user.is_active]
    
    def can_user_access(self, user_id: uuid.UUID) -> bool:
        """
        Check if user can access this project.
        """
        if self.is_owner(user_id):
            return True
        return any(member.user_id == user_id for member in self.members)
    
    def get_user_role(self, user_id: uuid.UUID) -> Optional[ProjectRole]:
        """
        Get user's role in the project.
        """
        if self.is_owner(user_id):
            return ProjectRole.OWNER
        for member in self.members:
            if member.user_id == user_id:
                return member.role
        return None
    
    def to_dict(self) -> dict:
        """
        Convert project to dictionary representation.
        """
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "name": self.name,
            "description": self.description,
            "website_url": self.website_url,
            "domain": self.domain,
            "is_active": self.is_active,
            "monitoring_enabled": self.monitoring_enabled,
            "settings": self.settings,
            "member_count": self.get_member_count(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_scan_at": self.last_scan_at.isoformat() if self.last_scan_at else None,
        }


class ProjectMember(Base):
    """
    Project member model for team collaboration.
    """
    __tablename__ = "project_members"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    invited_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    # Member information
    role = Column(Enum(ProjectRole), default=ProjectRole.VIEWER, nullable=False, index=True)
    
    # Invitation tracking
    invited_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    joined_at = Column(DateTime(timezone=True), nullable=True)
    invitation_token = Column(String(255), nullable=True, unique=True)
    
    # Member status
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="members")
    user = relationship("User", foreign_keys=[user_id], back_populates="project_memberships")
    invited_by_user = relationship("User", foreign_keys=[invited_by])
    
    def __repr__(self) -> str:
        return f"<ProjectMember(id={self.id}, project_id={self.project_id}, user_id={self.user_id}, role={self.role})>"
    
    def is_owner(self) -> bool:
        """
        Check if member is the project owner.
        """
        return self.role == ProjectRole.OWNER
    
    def can_edit(self) -> bool:
        """
        Check if member can edit project settings.
        """
        return self.role in [ProjectRole.OWNER, ProjectRole.ADMIN, ProjectRole.EDITOR]
    
    def can_administer(self) -> bool:
        """
        Check if member can administer project (manage members, settings).
        """
        return self.role in [ProjectRole.OWNER, ProjectRole.ADMIN]
    
    def has_joined(self) -> bool:
        """
        Check if member has accepted the invitation.
        """
        return self.joined_at is not None
    
    def accept_invitation(self) -> None:
        """
        Mark invitation as accepted.
        """
        self.joined_at = datetime.now(timezone.utc)
        self.is_active = True
    
    def to_dict(self) -> dict:
        """
        Convert project member to dictionary representation.
        """
        return {
            "id": str(self.id),
            "project_id": str(self.project_id),
            "user_id": str(self.user_id),
            "role": self.role.value,
            "invited_at": self.invited_at.isoformat() if self.invited_at else None,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
            "is_active": self.is_active,
            "can_edit": self.can_edit(),
            "can_administer": self.can_administer(),
            "has_joined": self.has_joined(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class MonitoringConfig(Base):
    """
    Monitoring configuration model for project-specific scan settings.
    """
    __tablename__ = "monitoring_configs"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to project (one-to-one relationship)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # Scan configuration
    scan_frequency_minutes = Column(Integer, default=1440, nullable=False)  # 1440 minutes = 24 hours
    scan_depth = Column(Integer, default=1, nullable=False)  # How many levels deep to crawl
    max_links_per_scan = Column(Integer, default=100, nullable=False)  # Maximum links to check per scan
    
    # Scan options
    check_broken_links = Column(Boolean, default=True, nullable=False)
    check_harmful_content = Column(Boolean, default=True, nullable=False)
    check_security_threats = Column(Boolean, default=True, nullable=False)
    check_performance = Column(Boolean, default=True, nullable=False)
    check_seo_issues = Column(Boolean, default=False, nullable=False)
    
    # Advanced settings
    exclude_patterns = Column(JSONB, nullable=True)  # JSON array of regex patterns to exclude
    include_subdomains = Column(Boolean, default=False, nullable=False)
    follow_redirects = Column(Boolean, default=True, nullable=False)
    timeout_seconds = Column(Integer, default=30, nullable=False)
    
    # Scan tracking
    last_scan_at = Column(DateTime(timezone=True), nullable=True, index=True)
    next_scan_at = Column(DateTime(timezone=True), nullable=True, index=True)
    scan_count = Column(Integer, default=0, nullable=False)
    
    # Status
    is_enabled = Column(Boolean, default=True, nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="monitoring_config")
    
    def __repr__(self) -> str:
        return f"<MonitoringConfig(id={self.id}, project_id={self.project_id}, frequency={self.scan_frequency_minutes}min)>"
    
    def get_next_scan_time(self) -> Optional[datetime]:
        """
        Calculate next scan time based on frequency and last scan.
        """
        if not self.last_scan_at or not self.is_enabled:
            return None
        return self.last_scan_at + timedelta(minutes=self.scan_frequency_minutes)
    
    def is_scan_due(self) -> bool:
        """
        Check if a scan is due based on frequency.
        """
        if not self.is_enabled:
            return False
        next_scan = self.get_next_scan_time()
        return next_scan is not None and datetime.now(timezone.utc) >= next_scan
    
    def update_next_scan_time(self) -> None:
        """
        Update next scan time based on current time and frequency.
        """
        if self.is_enabled:
            self.next_scan_at = datetime.now(timezone.utc) + timedelta(minutes=self.scan_frequency_minutes)
    
    def increment_scan_count(self) -> None:
        """
        Increment scan counter and update timestamps.
        """
        self.scan_count += 1
        self.last_scan_at = datetime.now(timezone.utc)
        self.update_next_scan_time()
    
    def to_dict(self) -> dict:
        """
        Convert monitoring config to dictionary representation.
        """
        return {
            "id": str(self.id),
            "project_id": str(self.project_id),
            "scan_frequency_minutes": self.scan_frequency_minutes,
            "scan_depth": self.scan_depth,
            "max_links_per_scan": self.max_links_per_scan,
            "check_broken_links": self.check_broken_links,
            "check_harmful_content": self.check_harmful_content,
            "check_security_threats": self.check_security_threats,
            "check_performance": self.check_performance,
            "check_seo_issues": self.check_seo_issues,
            "exclude_patterns": self.exclude_patterns,
            "include_subdomains": self.include_subdomains,
            "follow_redirects": self.follow_redirects,
            "timeout_seconds": self.timeout_seconds,
            "last_scan_at": self.last_scan_at.isoformat() if self.last_scan_at else None,
            "next_scan_at": self.next_scan_at.isoformat() if self.next_scan_at else None,
            "scan_count": self.scan_count,
            "is_enabled": self.is_enabled,
            "is_scan_due": self.is_scan_due(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ProjectAlert(Base):
    """
    Project alert model for notification preferences and tracking.
    """
    __tablename__ = "project_alerts"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Alert configuration
    alert_type = Column(Enum(AlertType), nullable=False, index=True)
    channel = Column(Enum(AlertChannel), default=AlertChannel.EMAIL, nullable=False, index=True)
    
    # Alert settings
    is_enabled = Column(Boolean, default=True, nullable=False, index=True)
    threshold_value = Column(Integer, nullable=True)  # Optional threshold for triggering alerts
    
    # Notification tracking
    last_alert_sent = Column(DateTime(timezone=True), nullable=True, index=True)
    alert_count = Column(Integer, default=0, nullable=False)
    
    # Delivery settings
    delivery_config = Column(JSONB, nullable=True)  # JSON object for channel-specific settings
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="alerts")
    user = relationship("User", back_populates="project_alerts")
    alert_instances = relationship("AlertInstance", back_populates="project_alert", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<ProjectAlert(id={self.id}, project_id={self.project_id}, type={self.alert_type}, channel={self.channel})>"
    
    def should_send_alert(self) -> bool:
        """
        Check if alert should be sent based on configuration and last sent time.
        """
        if not self.is_enabled:
            return False
        
        # Basic rate limiting: don't send more than once per hour for the same alert type
        if self.last_alert_sent:
            time_since_last = datetime.now(timezone.utc) - self.last_alert_sent
            if time_since_last < timedelta(hours=1):
                return False
        
        return True
    
    def record_alert_sent(self) -> None:
        """
        Record that an alert was sent.
        """
        self.last_alert_sent = datetime.now(timezone.utc)
        self.alert_count += 1
    
    def get_delivery_config(self) -> dict:
        """
        Parse delivery configuration as dictionary.
        """
        import json
        if self.delivery_config:
            try:
                return json.loads(self.delivery_config)
            except (json.JSONDecodeError, ValueError):
                return {}
        return {}
    
    def set_delivery_config(self, config: dict) -> None:
        """
        Set delivery configuration from dictionary.
        """
        import json
        self.delivery_config = json.dumps(config) if config else None
    
    def to_dict(self) -> dict:
        """
        Convert project alert to dictionary representation.
        """
        return {
            "id": str(self.id),
            "project_id": str(self.project_id),
            "user_id": str(self.user_id),
            "alert_type": self.alert_type.value,
            "channel": self.channel.value,
            "is_enabled": self.is_enabled,
            "threshold_value": self.threshold_value,
            "last_alert_sent": self.last_alert_sent.isoformat() if self.last_alert_sent else None,
            "alert_count": self.alert_count,
            "should_send_alert": self.should_send_alert(),
            "delivery_config": self.get_delivery_config(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Add indexes for better query performance
# ProjectMember index
Index(
    "ix_project_members_project_user",
    ProjectMember.project_id,
    ProjectMember.user_id,
    unique=True,
    postgresql_where=None,         # optional partial-index predicate
    postgresql_concurrently=False  # set True if you want CONCURRENTLY
)

# ProjectAlert index
Index(
    "ix_project_alerts_project_user_type",
    ProjectAlert.project_id,
    ProjectAlert.user_id,
    ProjectAlert.alert_type,
    unique=True,
    # postgresql_if_not_exists removed
)

# Projects index
Index(
    "ix_projects_user_domain",
    Project.user_id,
    Project.domain,
    # postgresql_if_not_exists removed
)


class AlertInstance(Base):
    """
    Individual alert instance model for tracking specific alert events.
    """
    __tablename__ = "alert_instances"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    project_alert_id = Column(UUID(as_uuid=True), ForeignKey("project_alerts.id", ondelete="CASCADE"), nullable=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    
    # Alert details
    alert_type = Column(Enum(AlertType), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="medium", index=True)  # low, medium, high, critical
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    
    # Alert context
    context_data = Column(JSONB, nullable=True)  # JSON object with alert-specific context
    affected_urls = Column(JSONB, nullable=True)  # JSON array of affected URLs
    
    # Alert status
    status = Column(String(20), nullable=False, default="active", index=True)  # active, acknowledged, resolved, dismissed
    acknowledged_at = Column(DateTime(timezone=True), nullable=True, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True, index=True)
    
    # Notification tracking
    notification_sent = Column(Boolean, default=False, nullable=False, index=True)
    notification_sent_at = Column(DateTime(timezone=True), nullable=True, index=True)
    notification_channel = Column(Enum(AlertChannel), nullable=True, index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    project = relationship("Project", back_populates="alert_instances")
    project_alert = relationship("ProjectAlert", back_populates="alert_instances")
    user = relationship("User", back_populates="alert_instances")
    
    def __repr__(self) -> str:
        return f"<AlertInstance(id={self.id}, project_id={self.project_id}, type={self.alert_type}, status={self.status})>"
    
    def acknowledge(self, user_id: UUID) -> None:
        """
        Acknowledge this alert instance.
        """
        if self.status == "active":
            self.status = "acknowledged"
            self.acknowledged_at = datetime.now(timezone.utc)
            self.user_id = user_id
    
    def resolve(self, user_id: UUID) -> None:
        """
        Resolve this alert instance.
        """
        if self.status in ["active", "acknowledged"]:
            self.status = "resolved"
            self.resolved_at = datetime.now(timezone.utc)
            self.user_id = user_id
    
    def dismiss(self, user_id: UUID) -> None:
        """
        Dismiss this alert instance.
        """
        if self.status == "active":
            self.status = "dismissed"
            self.user_id = user_id
    
    def mark_notification_sent(self, channel: AlertChannel) -> None:
        """
        Mark that notification was sent for this alert.
        """
        self.notification_sent = True
        self.notification_sent_at = datetime.now(timezone.utc)
        self.notification_channel = channel
    
    def get_context_data(self) -> dict:
        """
        Parse context data as dictionary.
        """
        import json
        if self.context_data:
            try:
                return json.loads(self.context_data)
            except (json.JSONDecodeError, ValueError):
                return {}
        return {}
    
    def set_context_data(self, context: dict) -> None:
        """
        Set context data from dictionary.
        """
        import json
        self.context_data = json.dumps(context) if context else None
    
    def get_affected_urls(self) -> list:
        """
        Parse affected URLs as list.
        """
        import json
        if self.affected_urls:
            try:
                return json.loads(self.affected_urls)
            except (json.JSONDecodeError, ValueError):
                return []
        return []
    
    def set_affected_urls(self, urls: list) -> None:
        """
        Set affected URLs from list.
        """
        import json
        self.affected_urls = json.dumps(urls) if urls else None
    
    def to_dict(self) -> dict:
        """
        Convert alert instance to dictionary representation.
        """
        return {
            "id": str(self.id),
            "project_id": str(self.project_id),
            "project_alert_id": str(self.project_alert_id) if self.project_alert_id else None,
            "user_id": str(self.user_id) if self.user_id else None,
            "alert_type": self.alert_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "context_data": self.get_context_data(),
            "affected_urls": self.get_affected_urls(),
            "status": self.status,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "notification_sent": self.notification_sent,
            "notification_sent_at": self.notification_sent_at.isoformat() if self.notification_sent_at else None,
            "notification_channel": self.notification_channel.value if self.notification_channel else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# Add indexes for better query performance
Index("ix_project_members_project_user", ProjectMember.project_id, ProjectMember.user_id, unique=True)
Index("ix_project_alerts_project_user_type", ProjectAlert.project_id, ProjectAlert.user_id, ProjectAlert.alert_type, unique=True)
Index("ix_projects_user_domain", Project.user_id, Project.domain)
Index("ix_alert_instances_project_status", AlertInstance.project_id, AlertInstance.status)
Index("ix_alert_instances_type_severity", AlertInstance.alert_type, AlertInstance.severity)
Index("ix_alert_instances_created_at", AlertInstance.created_at)