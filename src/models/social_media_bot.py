"""
Database models for Social Media Bot Service operations.

This module defines SQLAlchemy models for tracking social media bot analysis,
account safety assessments, compliance checks, and follower analysis.
"""

import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, Float, 
    ForeignKey, JSON, Enum as SQLEnum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.sql import func

from src.config.database import Base
from src.models.social_protection import PlatformType, RiskLevel


class BotAccountAnalysis(Base):
    """
    Model for storing bot account safety analysis results.
    
    Tracks account risk assessments, bot detection, spam indicators,
    and scam detection for social media accounts.
    """
    __tablename__ = "bot_account_analyses"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to bot user
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("bot_users.id"), nullable=False, index=True)
    
    # Platform and account information
    platform: Mapped[PlatformType] = mapped_column(SQLEnum(PlatformType), nullable=False, index=True)
    account_identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    account_username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    account_display_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Risk assessment results
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_level: Mapped[RiskLevel] = mapped_column(SQLEnum(RiskLevel), nullable=False, default=RiskLevel.SAFE, index=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    
    # Bot detection
    bot_probability: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_likely_bot: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    bot_indicators: Mapped[List[str]] = mapped_column(JSON, nullable=True, default=list)
    
    # Spam detection
    spam_probability: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_likely_spam: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    spam_indicators: Mapped[List[str]] = mapped_column(JSON, nullable=True, default=list)
    
    # Scam detection
    scam_probability: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_likely_scam: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scam_indicators: Mapped[List[str]] = mapped_column(JSON, nullable=True, default=list)
    
    # Analysis metadata
    analysis_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True, default=dict)
    recommendations: Mapped[List[str]] = mapped_column(JSON, nullable=True, default=list)
    analysis_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    # Cache and expiration
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    # Relationships
    user = relationship("BotUser", back_populates="account_analyses")
    
    def __repr__(self) -> str:
        return f"<BotAccountAnalysis(id={self.id}, platform={self.platform.value}, account={self.account_identifier})>"
    
    def is_expired(self) -> bool:
        """Check if analysis result has expired."""
        return datetime.utcnow() > self.expires_at
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Get risk assessment summary."""
        return {
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "confidence_score": self.confidence_score,
            "bot_probability": self.bot_probability,
            "spam_probability": self.spam_probability,
            "scam_probability": self.scam_probability,
            "total_indicators": len(self.bot_indicators) + len(self.spam_indicators) + len(self.scam_indicators)
        }


class BotComplianceCheck(Base):
    """
    Model for storing bot compliance monitoring results.
    
    Tracks content compliance checks against platform policies,
    policy violations, and compliance recommendations.
    """
    __tablename__ = "bot_compliance_checks"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to bot user
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("bot_users.id"), nullable=False, index=True)
    
    # Platform and content information
    platform: Mapped[PlatformType] = mapped_column(SQLEnum(PlatformType), nullable=False, index=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # SHA-256 hash
    content_type: Mapped[str] = mapped_column(String(50), nullable=False, default="text")
    content_preview: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # First 500 chars
    
    # Compliance assessment results
    compliance_score: Mapped[float] = mapped_column(Float, nullable=False, default=100.0)
    severity_level: Mapped[RiskLevel] = mapped_column(SQLEnum(RiskLevel), nullable=False, default=RiskLevel.SAFE, index=True)
    
    # Policy violations
    violations_detected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    violation_types: Mapped[List[str]] = mapped_column(JSON, nullable=True, default=list)
    violation_details: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=list)
    
    # Compliance metadata
    policy_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    recommendations: Mapped[List[str]] = mapped_column(JSON, nullable=True, default=list)
    analysis_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True, default=dict)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    user = relationship("BotUser", back_populates="compliance_checks")
    
    def __repr__(self) -> str:
        return f"<BotComplianceCheck(id={self.id}, platform={self.platform.value}, violations={self.violations_detected})>"
    
    def is_compliant(self) -> bool:
        """Check if content is compliant."""
        return self.violations_detected == 0 and self.severity_level in [RiskLevel.SAFE, RiskLevel.LOW]
    
    def get_compliance_summary(self) -> Dict[str, Any]:
        """Get compliance check summary."""
        return {
            "is_compliant": self.is_compliant(),
            "compliance_score": self.compliance_score,
            "severity_level": self.severity_level.value,
            "violations_count": self.violations_detected,
            "violation_types": self.violation_types,
            "recommendations_count": len(self.recommendations)
        }


class BotFollowerAnalysis(Base):
    """
    Model for storing bot verified follower analysis results.
    
    Tracks verified follower breakdowns, high-value followers,
    and networking recommendations.
    """
    __tablename__ = "bot_follower_analyses"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to bot user
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("bot_users.id"), nullable=False, index=True)
    
    # Platform and account information
    platform: Mapped[PlatformType] = mapped_column(SQLEnum(PlatformType), nullable=False, index=True)
    account_identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    account_username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Follower analysis results
    total_verified_followers: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_followers_analyzed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verification_breakdown: Mapped[Dict[str, int]] = mapped_column(JSON, nullable=True, default=dict)
    
    # High-value followers
    high_value_followers_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_value_followers: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=list)
    
    # Networking opportunities
    networking_opportunities_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    networking_recommendations: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=list)
    
    # Analysis metadata
    analysis_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True, default=dict)
    analysis_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    # Cache and expiration
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    # Relationships
    user = relationship("BotUser", back_populates="follower_analyses")
    
    def __repr__(self) -> str:
        return f"<BotFollowerAnalysis(id={self.id}, platform={self.platform.value}, verified_followers={self.total_verified_followers})>"
    
    def is_expired(self) -> bool:
        """Check if analysis result has expired."""
        return datetime.utcnow() > self.expires_at
    
    def get_follower_summary(self) -> Dict[str, Any]:
        """Get follower analysis summary."""
        return {
            "total_verified_followers": self.total_verified_followers,
            "total_analyzed": self.total_followers_analyzed,
            "verification_breakdown": self.verification_breakdown,
            "high_value_count": self.high_value_followers_count,
            "networking_opportunities": self.networking_opportunities_count,
            "analysis_age_hours": (datetime.utcnow() - self.created_at).total_seconds() / 3600
        }


class BotAnalysisLog(Base):
    """
    Model for logging all bot analysis requests and activities.
    
    Provides audit trail and analytics for bot service usage,
    performance monitoring, and user behavior analysis.
    """
    __tablename__ = "bot_analysis_logs"
    
    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to bot user
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("bot_users.id"), nullable=False, index=True)
    
    # Analysis request details
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # account_safety, compliance_check, follower_analysis
    platform: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    target_identifier: Mapped[str] = mapped_column(String(500), nullable=False)  # Account, content hash, etc.
    
    # Analysis results
    result_summary: Mapped[str] = mapped_column(String(100), nullable=False)  # Risk level, status, etc.
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Performance metrics
    response_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cache_hit: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    # Request metadata
    request_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True, default=dict)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    user = relationship("BotUser", back_populates="analysis_logs")
    
    def __repr__(self) -> str:
        return f"<BotAnalysisLog(id={self.id}, type={self.analysis_type}, platform={self.platform})>"


# Update BotUser model to include new relationships
# This would be added to the existing BotUser model in src/models/bot.py
# For now, we'll define the relationship extensions here

def extend_bot_user_relationships():
    """
    Function to extend BotUser model with new relationships.
    This should be called after the BotUser model is defined.
    """
    from src.models.bot import BotUser
    
    # Add new relationships to BotUser
    BotUser.account_analyses = relationship("BotAccountAnalysis", back_populates="user", cascade="all, delete-orphan")
    BotUser.compliance_checks = relationship("BotComplianceCheck", back_populates="user", cascade="all, delete-orphan")
    BotUser.follower_analyses = relationship("BotFollowerAnalysis", back_populates="user", cascade="all, delete-orphan")
    BotUser.analysis_logs = relationship("BotAnalysisLog", back_populates="user", cascade="all, delete-orphan")


# Utility functions for working with social media bot models

def get_recent_account_analysis(
    db_session, 
    user_id: int, 
    platform: PlatformType, 
    account_identifier: str,
    max_age_hours: int = 1
) -> Optional[BotAccountAnalysis]:
    """
    Get recent account analysis if available and not expired.
    
    Args:
        db_session: Database session
        user_id: Bot user ID
        platform: Platform type
        account_identifier: Account to check
        max_age_hours: Maximum age in hours
        
    Returns:
        Recent analysis or None
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
    
    return db_session.query(BotAccountAnalysis).filter(
        BotAccountAnalysis.user_id == user_id,
        BotAccountAnalysis.platform == platform,
        BotAccountAnalysis.account_identifier == account_identifier,
        BotAccountAnalysis.created_at >= cutoff_time,
        BotAccountAnalysis.expires_at > datetime.utcnow()
    ).order_by(BotAccountAnalysis.created_at.desc()).first()


def get_recent_compliance_check(
    db_session,
    user_id: int,
    platform: PlatformType,
    content_hash: str,
    max_age_hours: int = 24
) -> Optional[BotComplianceCheck]:
    """
    Get recent compliance check if available.
    
    Args:
        db_session: Database session
        user_id: Bot user ID
        platform: Platform type
        content_hash: Content hash to check
        max_age_hours: Maximum age in hours
        
    Returns:
        Recent compliance check or None
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
    
    return db_session.query(BotComplianceCheck).filter(
        BotComplianceCheck.user_id == user_id,
        BotComplianceCheck.platform == platform,
        BotComplianceCheck.content_hash == content_hash,
        BotComplianceCheck.created_at >= cutoff_time
    ).order_by(BotComplianceCheck.created_at.desc()).first()


def get_recent_follower_analysis(
    db_session,
    user_id: int,
    platform: PlatformType,
    account_identifier: str,
    max_age_hours: int = 24
) -> Optional[BotFollowerAnalysis]:
    """
    Get recent follower analysis if available and not expired.
    
    Args:
        db_session: Database session
        user_id: Bot user ID
        platform: Platform type
        account_identifier: Account to check
        max_age_hours: Maximum age in hours
        
    Returns:
        Recent follower analysis or None
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
    
    return db_session.query(BotFollowerAnalysis).filter(
        BotFollowerAnalysis.user_id == user_id,
        BotFollowerAnalysis.platform == platform,
        BotFollowerAnalysis.account_identifier == account_identifier,
        BotFollowerAnalysis.created_at >= cutoff_time,
        BotFollowerAnalysis.expires_at > datetime.utcnow()
    ).order_by(BotFollowerAnalysis.created_at.desc()).first()


def cleanup_expired_analyses(db_session) -> int:
    """
    Clean up expired analysis records.
    
    Args:
        db_session: Database session
        
    Returns:
        Number of records cleaned up
    """
    now = datetime.utcnow()
    
    # Clean up expired account analyses
    expired_accounts = db_session.query(BotAccountAnalysis).filter(
        BotAccountAnalysis.expires_at <= now
    ).delete()
    
    # Clean up expired follower analyses
    expired_followers = db_session.query(BotFollowerAnalysis).filter(
        BotFollowerAnalysis.expires_at <= now
    ).delete()
    
    # Clean up old compliance checks (older than 30 days)
    old_compliance = db_session.query(BotComplianceCheck).filter(
        BotComplianceCheck.created_at <= now - timedelta(days=30)
    ).delete()
    
    # Clean up old analysis logs (older than 90 days)
    old_logs = db_session.query(BotAnalysisLog).filter(
        BotAnalysisLog.created_at <= now - timedelta(days=90)
    ).delete()
    
    db_session.commit()
    
    total_cleaned = expired_accounts + expired_followers + old_compliance + old_logs
    return total_cleaned