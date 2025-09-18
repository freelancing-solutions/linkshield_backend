#!/usr/bin/env python3
"""
LinkShield Backend Report Models

SQLAlchemy models for user reports, feedback, and community-driven threat intelligence.
Includes user reports, admin reviews, and report statistics.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.config.database import Base
import enum

class ReportType(enum.Enum):
    """
    Report type enumeration.
    """
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    SCAM = "scam"
    INAPPROPRIATE_CONTENT = "inappropriate_content"
    COPYRIGHT_VIOLATION = "copyright_violation"
    FALSE_POSITIVE = "false_positive"
    OTHER = "other"


class ReportStatus(enum.Enum):
    """
    Report status enumeration.
    """
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"


class ReportPriority(enum.Enum):
    """
    Report priority enumeration.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Report(Base):
    """
    User report model for community-driven threat intelligence.
    """
    __tablename__ = "reports"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    url_check_id = Column(UUID(as_uuid=True), ForeignKey("url_checks.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Report information
    report_type = Column(Enum(ReportType), nullable=False, index=True)
    status = Column(Enum(ReportStatus), default=ReportStatus.PENDING, nullable=False, index=True)
    priority = Column(Enum(ReportPriority), default=ReportPriority.MEDIUM, nullable=False, index=True)
    
    # URL information (stored separately in case url_check is deleted)
    reported_url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    
    # Report details
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)  # Screenshots, additional URLs, etc.
    
    # Reporter information
    reporter_email = Column(String(255), nullable=True)  # For anonymous reports
    reporter_ip = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(String(500), nullable=True)
    
    # Review information
    reviewed_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)
    
    # Resolution information
    resolution = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Metadata
    is_verified = Column(Boolean, default=False, nullable=False)
    confidence_score = Column(Integer, nullable=True)  # 1-10 scale
    tags = Column(JSON, nullable=True)  # Additional categorization tags
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="reports", foreign_keys=[user_id])
    reviewer = relationship("User", foreign_keys=[reviewed_by])
    url_check = relationship("URLCheck", back_populates="reports")
    votes = relationship("ReportVote", back_populates="report", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_reports_domain_created", "domain", "created_at"),
        Index("idx_reports_type_status", "report_type", "status"),
        Index("idx_reports_priority_created", "priority", "created_at"),
    )
    
    def __repr__(self) -> str:
        return f"<Report(id={self.id}, type={self.report_type}, status={self.status})>"
    
    def is_pending_review(self) -> bool:
        """
        Check if report is pending review.
        """
        return self.status in [ReportStatus.PENDING, ReportStatus.UNDER_REVIEW]
    
    def is_resolved(self) -> bool:
        """
        Check if report is resolved.
        """
        return self.status in [ReportStatus.APPROVED, ReportStatus.REJECTED, ReportStatus.RESOLVED]
    
    def get_age_days(self) -> int:
        """
        Get report age in days.
        """
        return (datetime.now(timezone.utc) - self.created_at).days
    
    def get_vote_summary(self) -> Dict[str, int]:
        """
        Get summary of votes on this report.
        """
        if not self.votes:
            return {"helpful": 0, "not_helpful": 0, "total": 0}
        
        helpful = sum(1 for vote in self.votes if vote.is_helpful)
        not_helpful = len(self.votes) - helpful
        
        return {
            "helpful": helpful,
            "not_helpful": not_helpful,
            "total": len(self.votes)
        }
    
    def calculate_priority(self) -> ReportPriority:
        """
        Calculate report priority based on type and other factors.
        """
        # Critical threats
        if self.report_type in [ReportType.PHISHING, ReportType.MALWARE]:
            return ReportPriority.CRITICAL
        
        # High priority threats
        if self.report_type in [ReportType.SCAM, ReportType.SPAM]:
            return ReportPriority.HIGH
        
        # Medium priority
        if self.report_type in [ReportType.INAPPROPRIATE_CONTENT, ReportType.COPYRIGHT_VIOLATION]:
            return ReportPriority.MEDIUM
        
        # Low priority
        return ReportPriority.LOW
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert report to dictionary representation.
        """
        data = {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "url_check_id": str(self.url_check_id) if self.url_check_id else None,
            "report_type": self.report_type.value,
            "status": self.status.value,
            "priority": self.priority.value,
            "reported_url": self.reported_url,
            "domain": self.domain,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "is_verified": self.is_verified,
            "confidence_score": self.confidence_score,
            "tags": self.tags,
            "age_days": self.get_age_days(),
            "vote_summary": self.get_vote_summary(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_sensitive:
            data.update({
                "reporter_email": self.reporter_email,
                "reporter_ip": self.reporter_ip,
                "user_agent": self.user_agent,
                "reviewed_by": str(self.reviewed_by) if self.reviewed_by else None,
                "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
                "review_notes": self.review_notes,
                "resolution": self.resolution,
                "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            })
        
        return data


class ReportVote(Base):
    """
    Report vote model for community feedback on reports.
    """
    __tablename__ = "report_votes"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    report_id = Column(UUID(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Vote information
    is_helpful = Column(Boolean, nullable=False)
    comment = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    report = relationship("Report", back_populates="votes")
    user = relationship("User")
    
    # Unique constraint to prevent duplicate votes
    __table_args__ = (
        Index("idx_report_votes_unique", "report_id", "user_id", unique=True),
    )
    
    def __repr__(self) -> str:
        return f"<ReportVote(id={self.id}, report_id={self.report_id}, helpful={self.is_helpful})>"
    
    def to_dict(self) -> dict:
        """
        Convert report vote to dictionary representation.
        """
        return {
            "id": str(self.id),
            "report_id": str(self.report_id),
            "user_id": str(self.user_id),
            "is_helpful": self.is_helpful,
            "comment": self.comment,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ReportTemplate(Base):
    """
    Report template model for standardized reporting.
    """
    __tablename__ = "report_templates"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Template information
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    report_type = Column(Enum(ReportType), nullable=False, index=True)
    
    # Template content
    title_template = Column(String(200), nullable=False)
    description_template = Column(Text, nullable=False)
    required_fields = Column(JSON, nullable=True)  # List of required evidence fields
    
    # Configuration
    is_active = Column(Boolean, default=True, nullable=False)
    priority = Column(Enum(ReportPriority), default=ReportPriority.MEDIUM, nullable=False)
    
    # Usage statistics
    usage_count = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    def __repr__(self) -> str:
        return f"<ReportTemplate(id={self.id}, name={self.name}, type={self.report_type})>"
    
    def increment_usage(self) -> None:
        """
        Increment template usage counter.
        """
        self.usage_count += 1
    
    def to_dict(self) -> dict:
        """
        Convert report template to dictionary representation.
        """
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "report_type": self.report_type.value,
            "title_template": self.title_template,
            "description_template": self.description_template,
            "required_fields": self.required_fields,
            "is_active": self.is_active,
            "priority": self.priority.value,
            "usage_count": self.usage_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ReportStatistics(Base):
    """
    Report statistics model for tracking reporting trends.
    """
    __tablename__ = "report_statistics"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Time period
    date = Column(DateTime(timezone=True), nullable=False, index=True)
    period_type = Column(String(20), nullable=False)  # daily, weekly, monthly
    
    # Statistics by report type
    phishing_count = Column(Integer, default=0, nullable=False)
    malware_count = Column(Integer, default=0, nullable=False)
    spam_count = Column(Integer, default=0, nullable=False)
    scam_count = Column(Integer, default=0, nullable=False)
    inappropriate_count = Column(Integer, default=0, nullable=False)
    copyright_count = Column(Integer, default=0, nullable=False)
    false_positive_count = Column(Integer, default=0, nullable=False)
    other_count = Column(Integer, default=0, nullable=False)
    
    # Status statistics
    pending_count = Column(Integer, default=0, nullable=False)
    under_review_count = Column(Integer, default=0, nullable=False)
    approved_count = Column(Integer, default=0, nullable=False)
    rejected_count = Column(Integer, default=0, nullable=False)
    resolved_count = Column(Integer, default=0, nullable=False)
    
    # Performance metrics
    avg_resolution_time = Column(Integer, nullable=True)  # in hours
    total_reports = Column(Integer, default=0, nullable=False)
    verified_reports = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    def __repr__(self) -> str:
        return f"<ReportStatistics(date={self.date}, period={self.period_type}, total={self.total_reports})>"
    
    def get_total_by_type(self) -> Dict[str, int]:
        """
        Get total reports by type.
        """
        return {
            "phishing": self.phishing_count,
            "malware": self.malware_count,
            "spam": self.spam_count,
            "scam": self.scam_count,
            "inappropriate_content": self.inappropriate_count,
            "copyright_violation": self.copyright_count,
            "false_positive": self.false_positive_count,
            "other": self.other_count,
        }
    
    def get_total_by_status(self) -> Dict[str, int]:
        """
        Get total reports by status.
        """
        return {
            "pending": self.pending_count,
            "under_review": self.under_review_count,
            "approved": self.approved_count,
            "rejected": self.rejected_count,
            "resolved": self.resolved_count,
        }
    
    def to_dict(self) -> dict:
        """
        Convert report statistics to dictionary representation.
        """
        return {
            "id": str(self.id),
            "date": self.date.isoformat() if self.date else None,
            "period_type": self.period_type,
            "total_reports": self.total_reports,
            "verified_reports": self.verified_reports,
            "avg_resolution_time": self.avg_resolution_time,
            "by_type": self.get_total_by_type(),
            "by_status": self.get_total_by_status(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class VoteType(enum.Enum):
    """
    Enumeration for different types of votes that can be cast on reports.
    
    This enum defines the various voting options available to users when
    evaluating the helpfulness and accuracy of reports.
    """
    HELPFUL = "helpful"
    NOT_HELPFUL = "not_helpful"
    ACCURATE = "accurate"
    INACCURATE = "inaccurate"
    SPAM = "spam"
    DUPLICATE = "duplicate"