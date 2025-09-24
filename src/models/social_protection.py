#!/usr/bin/env python3
"""
LinkShield Backend Social Protection Models

SQLAlchemy models for social media protection, profile scanning, content risk assessment,
and crisis detection. Includes social profile scans, content risk assessments, 
algorithm health monitoring, and reputation tracking.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
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


class PlatformType(enum.Enum):
    """
    Social media platform enumeration.
    """
    TWITTER = "twitter"
    META = "meta"
    TIKTOK = "tiktok"
    LINKEDIN = "linkedin"
    INSTAGRAM = "instagram"
    FACEBOOK = "facebook"


class ScanStatus(enum.Enum):
    """
    Social protection scan status enumeration.
    """
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class RiskLevel(enum.Enum):
    """
    Risk level enumeration for social protection assessments.
    """
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ContentType(enum.Enum):
    """
    Content type enumeration for social media content.
    """
    POST = "post"
    COMMENT = "comment"
    STORY = "story"
    REEL = "reel"
    VIDEO = "video"
    IMAGE = "image"
    LINK = "link"
    PROFILE = "profile"


class AssessmentType(enum.Enum):
    """
    Assessment type enumeration for different analysis types.
    """
    PROFILE_SCAN = "profile_scan"
    CONTENT_RISK = "content_risk"
    ALGORITHM_HEALTH = "algorithm_health"
    REPUTATION_MONITOR = "reputation_monitor"
    CRISIS_DETECTION = "crisis_detection"


class SocialProfileScan(Base):
    """
    Social profile scan model for storing social media profile analysis requests and results.
    """
    __tablename__ = "social_profile_scans"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to user (nullable for anonymous scans)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Foreign key to project (for dashboard integration)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    
    # Platform and profile information
    platform = Column(Enum(PlatformType), nullable=False, index=True)
    profile_url = Column(Text, nullable=False)
    profile_username = Column(String(255), nullable=True, index=True)
    profile_handle = Column(String(255), nullable=True, index=True)
    profile_id = Column(String(255), nullable=True, index=True)
    
    # Scan configuration
    scan_type = Column(Enum(AssessmentType), default=AssessmentType.PROFILE_SCAN, nullable=False)
    include_content_analysis = Column(Boolean, default=True, nullable=False)
    include_follower_analysis = Column(Boolean, default=True, nullable=False)
    include_engagement_analysis = Column(Boolean, default=True, nullable=False)
    
    # Scan status and results
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.SAFE, nullable=False, index=True)
    overall_score = Column(Float, nullable=True)  # 0.0 to 100.0
    
    # Profile verification and authenticity
    is_verified = Column(Boolean, default=False, nullable=False)
    is_suspicious = Column(Boolean, default=False, nullable=False)
    is_fake = Column(Boolean, default=False, nullable=False)
    is_bot = Column(Boolean, default=False, nullable=False)
    
    # Profile metrics
    follower_count = Column(Integer, nullable=True)
    following_count = Column(Integer, nullable=True)
    post_count = Column(Integer, nullable=True)
    engagement_rate = Column(Float, nullable=True)  # Percentage
    
    # Profile information
    profile_name = Column(String(255), nullable=True)
    profile_bio = Column(Text, nullable=True)
    profile_location = Column(String(255), nullable=True)
    profile_website = Column(Text, nullable=True)
    profile_created_at = Column(DateTime(timezone=True), nullable=True)
    
    # Risk factors and analysis
    risk_factors = Column(JSON, nullable=True)  # List of identified risk factors
    authenticity_score = Column(Float, nullable=True)  # 0.0 to 100.0
    bot_probability = Column(Float, nullable=True)  # 0.0 to 1.0
    
    # Follower analysis
    follower_authenticity_score = Column(Float, nullable=True)  # 0.0 to 100.0
    suspicious_followers_count = Column(Integer, nullable=True)
    bot_followers_percentage = Column(Float, nullable=True)
    
    # Content analysis summary
    content_risk_score = Column(Float, nullable=True)  # 0.0 to 100.0
    spam_likelihood = Column(Float, nullable=True)  # 0.0 to 1.0
    harmful_content_detected = Column(Boolean, default=False, nullable=False)
    
    # Algorithm health indicators
    visibility_score = Column(Float, nullable=True)  # 0.0 to 100.0
    shadow_ban_probability = Column(Float, nullable=True)  # 0.0 to 1.0
    engagement_drop_detected = Column(Boolean, default=False, nullable=False)
    
    # External data sources
    external_reports = Column(JSON, nullable=True)
    third_party_scores = Column(JSON, nullable=True)
    
    # Scan metadata
    scan_duration = Column(Float, nullable=True)  # in seconds
    error_message = Column(Text, nullable=True)
    error_details = Column(JSON, nullable=True)
    
    # Request metadata
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="social_profile_scans")
    project = relationship("Project", back_populates="social_profile_scans")
    content_assessments = relationship("ContentRiskAssessment", back_populates="profile_scan", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_social_profile_scans_platform_created", "platform", "created_at"),
        Index("idx_social_profile_scans_user_created", "user_id", "created_at"),
        Index("idx_social_profile_scans_project_created", "project_id", "created_at"),
        Index("idx_social_profile_scans_risk_level_created", "risk_level", "created_at"),
        Index("idx_social_profile_scans_username_platform", "profile_username", "platform"),
    )
    
    def __repr__(self) -> str:
        return f"<SocialProfileScan(id={self.id}, platform={self.platform.value}, username={self.profile_username})>"
    
    def get_duration(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def is_completed(self) -> bool:
        """Check if scan is completed."""
        return self.status == ScanStatus.COMPLETED
    
    def is_safe(self) -> bool:
        """Check if profile is considered safe."""
        return self.risk_level in [RiskLevel.SAFE, RiskLevel.LOW]
    
    def get_risk_indicators(self) -> List[str]:
        """Get list of risk indicators."""
        indicators = []
        
        if self.is_suspicious:
            indicators.append("suspicious_profile")
        if self.is_fake:
            indicators.append("fake_profile")
        if self.is_bot:
            indicators.append("bot_account")
        if self.harmful_content_detected:
            indicators.append("harmful_content")
        if self.shadow_ban_probability and self.shadow_ban_probability > 0.7:
            indicators.append("shadow_banned")
        if self.bot_followers_percentage and self.bot_followers_percentage > 50:
            indicators.append("fake_followers")
            
        return indicators
    
    def to_dict(self, include_details: bool = True) -> dict:
        """Convert to dictionary representation."""
        base_dict = {
            "id": str(self.id),
            "platform": self.platform.value,
            "profile_url": self.profile_url,
            "profile_username": self.profile_username,
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "overall_score": self.overall_score,
            "is_verified": self.is_verified,
            "is_suspicious": self.is_suspicious,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
        
        if include_details:
            base_dict.update({
                "profile_name": self.profile_name,
                "follower_count": self.follower_count,
                "following_count": self.following_count,
                "engagement_rate": self.engagement_rate,
                "authenticity_score": self.authenticity_score,
                "risk_factors": self.risk_factors,
                "risk_indicators": self.get_risk_indicators(),
                "scan_duration": self.get_duration(),
            })
        
        return base_dict


class ContentRiskAssessment(Base):
    """
    Content risk assessment model for analyzing social media content for risks and threats.
    """
    __tablename__ = "content_risk_assessments"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to user (nullable for anonymous assessments)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Foreign key to profile scan (optional)
    profile_scan_id = Column(UUID(as_uuid=True), ForeignKey("social_profile_scans.id", ondelete="CASCADE"), nullable=True, index=True)
    
    # Foreign key to project (for dashboard integration)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    
    # Platform and content information
    platform = Column(Enum(PlatformType), nullable=False, index=True)
    content_type = Column(Enum(ContentType), nullable=False, index=True)
    content_url = Column(Text, nullable=True)
    content_id = Column(String(255), nullable=True, index=True)
    
    # Content metadata
    content_text = Column(Text, nullable=True)
    content_title = Column(String(500), nullable=True)
    content_description = Column(Text, nullable=True)
    media_urls = Column(JSON, nullable=True)  # List of media URLs
    hashtags = Column(JSON, nullable=True)  # List of hashtags
    mentions = Column(JSON, nullable=True)  # List of mentions
    
    # Assessment configuration
    assessment_type = Column(Enum(AssessmentType), default=AssessmentType.CONTENT_RISK, nullable=False)
    include_sentiment_analysis = Column(Boolean, default=True, nullable=False)
    include_spam_detection = Column(Boolean, default=True, nullable=False)
    include_link_analysis = Column(Boolean, default=True, nullable=False)
    
    # Assessment status and results
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.SAFE, nullable=False, index=True)
    risk_score = Column(Float, nullable=True)  # 0.0 to 100.0
    
    # Content risk indicators
    is_spam = Column(Boolean, default=False, nullable=False)
    is_harmful = Column(Boolean, default=False, nullable=False)
    is_misleading = Column(Boolean, default=False, nullable=False)
    is_inappropriate = Column(Boolean, default=False, nullable=False)
    contains_malicious_links = Column(Boolean, default=False, nullable=False)
    
    # Spam analysis
    spam_probability = Column(Float, nullable=True)  # 0.0 to 1.0
    spam_indicators = Column(JSON, nullable=True)  # List of spam indicators
    
    # Sentiment analysis
    sentiment_score = Column(Float, nullable=True)  # -1.0 to 1.0
    sentiment_label = Column(String(50), nullable=True)  # positive, negative, neutral
    emotion_scores = Column(JSON, nullable=True)  # Dictionary of emotion scores
    
    # Link analysis
    links_found = Column(JSON, nullable=True)  # List of links found in content
    malicious_links_count = Column(Integer, default=0, nullable=False)
    suspicious_links_count = Column(Integer, default=0, nullable=False)
    link_safety_scores = Column(JSON, nullable=True)  # Dictionary of link safety scores
    
    # Content quality metrics
    readability_score = Column(Float, nullable=True)  # 0.0 to 100.0
    authenticity_score = Column(Float, nullable=True)  # 0.0 to 100.0
    engagement_manipulation_score = Column(Float, nullable=True)  # 0.0 to 1.0
    
    # Policy violations
    policy_violations = Column(JSON, nullable=True)  # List of policy violations
    community_guidelines_score = Column(Float, nullable=True)  # 0.0 to 100.0
    
    # AI analysis results
    ai_analysis_results = Column(JSON, nullable=True)
    confidence_scores = Column(JSON, nullable=True)  # Dictionary of confidence scores
    
    # External analysis
    third_party_results = Column(JSON, nullable=True)
    moderation_flags = Column(JSON, nullable=True)
    
    # Assessment metadata
    assessment_duration = Column(Float, nullable=True)  # in seconds
    error_message = Column(Text, nullable=True)
    error_details = Column(JSON, nullable=True)
    
    # Request metadata
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="content_risk_assessments")
    profile_scan = relationship("SocialProfileScan", back_populates="content_assessments")
    project = relationship("Project", back_populates="content_risk_assessments")
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_content_risk_assessments_platform_created", "platform", "created_at"),
        Index("idx_content_risk_assessments_user_created", "user_id", "created_at"),
        Index("idx_content_risk_assessments_project_created", "project_id", "created_at"),
        Index("idx_content_risk_assessments_risk_level_created", "risk_level", "created_at"),
        Index("idx_content_risk_assessments_content_type_platform", "content_type", "platform"),
        Index("idx_content_risk_assessments_profile_scan", "profile_scan_id", "created_at"),
    )
    
    def __repr__(self) -> str:
        return f"<ContentRiskAssessment(id={self.id}, platform={self.platform.value}, content_type={self.content_type.value})>"
    
    def get_duration(self) -> Optional[float]:
        """Calculate assessment duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def is_completed(self) -> bool:
        """Check if assessment is completed."""
        return self.status == ScanStatus.COMPLETED
    
    def is_safe(self) -> bool:
        """Check if content is considered safe."""
        return self.risk_level in [RiskLevel.SAFE, RiskLevel.LOW]
    
    def get_risk_indicators(self) -> List[str]:
        """Get list of risk indicators."""
        indicators = []
        
        if self.is_spam:
            indicators.append("spam_content")
        if self.is_harmful:
            indicators.append("harmful_content")
        if self.is_misleading:
            indicators.append("misleading_information")
        if self.is_inappropriate:
            indicators.append("inappropriate_content")
        if self.contains_malicious_links:
            indicators.append("malicious_links")
        if self.sentiment_score and self.sentiment_score < -0.7:
            indicators.append("negative_sentiment")
        if self.spam_probability and self.spam_probability > 0.7:
            indicators.append("high_spam_probability")
            
        return indicators
    
    def get_safety_summary(self) -> Dict[str, Any]:
        """Get content safety summary."""
        return {
            "is_safe": self.is_safe(),
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "risk_indicators": self.get_risk_indicators(),
            "spam_probability": self.spam_probability,
            "sentiment_score": self.sentiment_score,
            "malicious_links_count": self.malicious_links_count,
            "policy_violations": self.policy_violations or [],
        }
    
    def to_dict(self, include_details: bool = True) -> dict:
        """Convert to dictionary representation."""
        base_dict = {
            "id": str(self.id),
            "platform": self.platform.value,
            "content_type": self.content_type.value,
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "is_spam": self.is_spam,
            "is_harmful": self.is_harmful,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
        
        if include_details:
            base_dict.update({
                "content_text": self.content_text,
                "sentiment_score": self.sentiment_score,
                "spam_probability": self.spam_probability,
                "malicious_links_count": self.malicious_links_count,
                "risk_indicators": self.get_risk_indicators(),
                "safety_summary": self.get_safety_summary(),
                "assessment_duration": self.get_duration(),
            })
        
        return base_dict