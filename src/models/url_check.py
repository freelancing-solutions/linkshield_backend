#!/usr/bin/env python3
"""
LinkShield Backend URL Check Models

SQLAlchemy models for URL analysis, security checks, and scan results.
Includes URL checks, scan results, and threat detection data.
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

class CheckStatus(enum.Enum):
    """
    URL check status enumeration.
    """
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ThreatLevel(enum.Enum):
    """
    Threat level enumeration.
    """
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanType(enum.Enum):
    """
    Scan type enumeration.
    """
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    CUSTOM = "custom"


class URLCheck(Base):
    """
    URL check model for storing URL analysis requests and results.
    """
    __tablename__ = "url_checks"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to user (nullable for anonymous checks)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # URL information
    original_url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    final_url = Column(Text, nullable=True)  # After redirects
    
    # Check configuration
    scan_type = Column(Enum(ScanType), default=ScanType.STANDARD, nullable=False)
    check_redirects = Column(Boolean, default=True, nullable=False)
    check_ssl = Column(Boolean, default=True, nullable=False)
    check_content = Column(Boolean, default=True, nullable=False)
    check_reputation = Column(Boolean, default=True, nullable=False)
    
    # Status and results
    status = Column(Enum(CheckStatus), default=CheckStatus.PENDING, nullable=False, index=True)
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.SAFE, nullable=False, index=True)
    safety_score = Column(Float, nullable=True)  # 0.0 to 100.0
    
    # Analysis results
    is_malicious = Column(Boolean, default=False, nullable=False)
    is_phishing = Column(Boolean, default=False, nullable=False)
    is_malware = Column(Boolean, default=False, nullable=False)
    is_spam = Column(Boolean, default=False, nullable=False)
    is_suspicious = Column(Boolean, default=False, nullable=False)
    
    # Technical details
    http_status_code = Column(Integer, nullable=True)
    response_time = Column(Float, nullable=True)  # in seconds
    redirect_count = Column(Integer, default=0, nullable=False)
    ssl_valid = Column(Boolean, nullable=True)
    ssl_expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Content analysis
    page_title = Column(String(500), nullable=True)
    page_description = Column(Text, nullable=True)
    content_type = Column(String(100), nullable=True)
    content_length = Column(Integer, nullable=True)
    
    # AI analysis results
    ai_analysis = Column(JSON, nullable=True)
    content_quality_score = Column(Float, nullable=True)  # 0.0 to 100.0
    
    # External service results
    virustotal_results = Column(JSON, nullable=True)
    google_safe_browsing_results = Column(JSON, nullable=True)
    urlvoid_results = Column(JSON, nullable=True)
    
    # Metadata
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    geolocation = Column(JSON, nullable=True)
    
    # Error information
    error_message = Column(Text, nullable=True)
    error_details = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="url_checks")
    scan_results = relationship("ScanResult", back_populates="url_check", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="url_check")
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_url_checks_domain_created", "domain", "created_at"),
        Index("idx_url_checks_user_created", "user_id", "created_at"),
        Index("idx_url_checks_threat_level_created", "threat_level", "created_at"),
    )
    
    def __repr__(self) -> str:
        return f"<URLCheck(id={self.id}, domain={self.domain}, status={self.status})>"
    
    def get_duration(self) -> Optional[float]:
        """
        Get check duration in seconds.
        """
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def is_completed(self) -> bool:
        """
        Check if URL check is completed.
        """
        return self.status in [CheckStatus.COMPLETED, CheckStatus.FAILED, CheckStatus.TIMEOUT]
    
    def is_safe(self) -> bool:
        """
        Check if URL is considered safe.
        """
        return self.threat_level == ThreatLevel.SAFE and not any([
            self.is_malicious,
            self.is_phishing,
            self.is_malware,
            self.is_spam
        ])
    
    def get_threat_indicators(self) -> List[str]:
        """
        Get list of detected threat indicators.
        """
        indicators = []
        if self.is_malicious:
            indicators.append("malicious")
        if self.is_phishing:
            indicators.append("phishing")
        if self.is_malware:
            indicators.append("malware")
        if self.is_spam:
            indicators.append("spam")
        if self.is_suspicious:
            indicators.append("suspicious")
        return indicators
    
    def update_threat_level(self) -> None:
        """
        Update threat level based on detected threats and safety score.
        """
        if self.is_malicious or self.is_phishing or self.is_malware:
            self.threat_level = ThreatLevel.CRITICAL
        elif self.is_spam or (self.safety_score and self.safety_score < 30):
            self.threat_level = ThreatLevel.HIGH
        elif self.is_suspicious or (self.safety_score and self.safety_score < 60):
            self.threat_level = ThreatLevel.MEDIUM
        elif self.safety_score and self.safety_score < 80:
            self.threat_level = ThreatLevel.LOW
        else:
            self.threat_level = ThreatLevel.SAFE
    
    def to_dict(self, include_details: bool = True) -> dict:
        """
        Convert URL check to dictionary representation.
        """
        data = {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "original_url": self.original_url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "final_url": self.final_url,
            "scan_type": self.scan_type.value,
            "status": self.status.value,
            "threat_level": self.threat_level.value,
            "safety_score": self.safety_score,
            "is_safe": self.is_safe(),
            "threat_indicators": self.get_threat_indicators(),
            "http_status_code": self.http_status_code,
            "response_time": self.response_time,
            "redirect_count": self.redirect_count,
            "ssl_valid": self.ssl_valid,
            "page_title": self.page_title,
            "content_type": self.content_type,
            "content_quality_score": self.content_quality_score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.get_duration(),
        }
        
        if include_details:
            data.update({
                "page_description": self.page_description,
                "content_length": self.content_length,
                "ssl_expires_at": self.ssl_expires_at.isoformat() if self.ssl_expires_at else None,
                "ai_analysis": self.ai_analysis,
                "virustotal_results": self.virustotal_results,
                "google_safe_browsing_results": self.google_safe_browsing_results,
                "urlvoid_results": self.urlvoid_results,
                "error_message": self.error_message,
                "geolocation": self.geolocation,
            })
        
        return data


class ScanResult(Base):
    """
    Individual scan result model for detailed analysis results.
    """
    __tablename__ = "scan_results"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign key to URL check
    url_check_id = Column(UUID(as_uuid=True), ForeignKey("url_checks.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Scan information
    scanner_name = Column(String(100), nullable=False, index=True)
    scanner_version = Column(String(50), nullable=True)
    scan_type = Column(String(50), nullable=False)
    
    # Results
    is_malicious = Column(Boolean, default=False, nullable=False)
    confidence_score = Column(Float, nullable=True)  # 0.0 to 1.0
    threat_types = Column(JSON, nullable=True)  # List of detected threat types
    
    # Raw results
    raw_result = Column(JSON, nullable=True)
    summary = Column(Text, nullable=True)
    
    # Metadata
    scan_duration = Column(Float, nullable=True)  # in seconds
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    url_check = relationship("URLCheck", back_populates="scan_results")
    
    def __repr__(self) -> str:
        return f"<ScanResult(id={self.id}, scanner={self.scanner_name}, malicious={self.is_malicious})>"
    
    def to_dict(self) -> dict:
        """
        Convert scan result to dictionary representation.
        """
        return {
            "id": str(self.id),
            "url_check_id": str(self.url_check_id),
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "scan_type": self.scan_type,
            "is_malicious": self.is_malicious,
            "confidence_score": self.confidence_score,
            "threat_types": self.threat_types,
            "summary": self.summary,
            "scan_duration": self.scan_duration,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class URLReputation(Base):
    """
    URL reputation model for caching reputation data.
    """
    __tablename__ = "url_reputations"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # URL information
    domain = Column(String(255), nullable=False, index=True)
    url_hash = Column(String(64), unique=True, index=True, nullable=False)  # SHA-256 hash
    
    # Reputation data
    reputation_score = Column(Float, nullable=False)  # 0.0 to 100.0
    threat_level = Column(Enum(ThreatLevel), nullable=False)
    
    # Aggregated results
    total_scans = Column(Integer, default=0, nullable=False)
    malicious_count = Column(Integer, default=0, nullable=False)
    clean_count = Column(Integer, default=0, nullable=False)
    
    # Source information
    sources = Column(JSON, nullable=True)  # List of sources that contributed to reputation
    last_scan_results = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    
    def __repr__(self) -> str:
        return f"<URLReputation(domain={self.domain}, score={self.reputation_score})>"
    
    def is_expired(self) -> bool:
        """
        Check if reputation data is expired.
        """
        return datetime.now(timezone.utc) > self.expires_at
    
    def get_malicious_percentage(self) -> float:
        """
        Get percentage of scans that detected malicious content.
        """
        if self.total_scans == 0:
            return 0.0
        return (self.malicious_count / self.total_scans) * 100
    
    def to_dict(self) -> dict:
        """
        Convert URL reputation to dictionary representation.
        """
        return {
            "id": str(self.id),
            "domain": self.domain,
            "reputation_score": self.reputation_score,
            "threat_level": self.threat_level.value,
            "total_scans": self.total_scans,
            "malicious_count": self.malicious_count,
            "clean_count": self.clean_count,
            "malicious_percentage": self.get_malicious_percentage(),
            "sources": self.sources,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_expired": self.is_expired(),
        }