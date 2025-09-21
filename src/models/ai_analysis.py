#!/usr/bin/env python3
"""
LinkShield Backend AI Analysis Models

SQLAlchemy models for AI-powered content analysis, quality scoring,
and intelligent insights storage.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    Index,
    Float,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.config.database import Base
import enum


class ProcessingStatus(enum.Enum):
    """
    AI analysis processing status.
    """
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CACHED = "cached"


class AnalysisType(enum.Enum):
    """
    Types of AI analysis performed.
    """
    CONTENT_SUMMARY = "content_summary"
    QUALITY_SCORING = "quality_scoring"
    TOPIC_CLASSIFICATION = "topic_classification"
    CONTENT_SIMILARITY = "content_similarity"
    LANGUAGE_DETECTION = "language_detection"
    SEO_ANALYSIS = "seo_analysis"
    SENTIMENT_ANALYSIS = "sentiment_analysis"
    THREAT_ANALYSIS = "threat_analysis"


class AIAnalysis(Base):
    """
    AI analysis model for storing comprehensive content analysis results.
    """
    __tablename__ = "ai_analyses"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    check_id = Column(UUID(as_uuid=True), ForeignKey("url_checks.id"), nullable=True, index=True)
    
    # Content identification
    url = Column(String(2048), nullable=False, index=True)
    content_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 hash
    domain = Column(String(255), nullable=False, index=True)
    
    # AI Analysis Results
    content_summary = Column(Text, nullable=True)
    content_embedding = Column(JSON, nullable=True)  # Vector embeddings for similarity
    quality_metrics = Column(JSON, nullable=True)  # Detailed quality scoring
    topic_categories = Column(JSON, nullable=True)  # Topic classification results
    keyword_density = Column(JSON, nullable=True)  # Keyword analysis
    seo_metrics = Column(JSON, nullable=True)  # SEO analysis results
    sentiment_analysis = Column(JSON, nullable=True)  # Sentiment scoring
    
    # Content metadata
    content_length = Column(Integer, nullable=True)
    language = Column(String(10), nullable=True)  # ISO language code
    reading_level = Column(String(20), nullable=True)  # Reading difficulty level
    
    # Quality scores (0-100)
    overall_quality_score = Column(Integer, nullable=True)
    readability_score = Column(Integer, nullable=True)
    trustworthiness_score = Column(Integer, nullable=True)
    professionalism_score = Column(Integer, nullable=True)
    
    # Processing metadata
    processing_status = Column(Enum(ProcessingStatus), default=ProcessingStatus.PENDING, nullable=False)
    analysis_types = Column(JSON, nullable=True)  # List of analysis types performed
    processing_time_ms = Column(Integer, nullable=True)  # Processing time in milliseconds
    model_versions = Column(JSON, nullable=True)  # AI model versions used
    
    # Error handling
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    processed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="ai_analyses")
    url_check = relationship("URLCheck", back_populates="ai_analysis")
    similarity_matches = relationship("ContentSimilarity", foreign_keys="ContentSimilarity.source_analysis_id", back_populates="source_analysis")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_ai_analysis_user_created', 'user_id', 'created_at'),
        Index('idx_ai_analysis_domain_quality', 'domain', 'overall_quality_score'),
        Index('idx_ai_analysis_status_created', 'processing_status', 'created_at'),
        Index('idx_ai_analysis_hash_status', 'content_hash', 'processing_status'),
    )
    
    def __repr__(self) -> str:
        return f"<AIAnalysis(id={self.id}, url={self.url[:50]}..., status={self.processing_status})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert AI analysis to dictionary.
        """
        return {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "check_id": str(self.check_id) if self.check_id else None,
            "url": self.url,
            "content_hash": self.content_hash,
            "domain": self.domain,
            "content_summary": self.content_summary,
            "quality_metrics": self.quality_metrics,
            "topic_categories": self.topic_categories,
            "keyword_density": self.keyword_density,
            "seo_metrics": self.seo_metrics,
            "sentiment_analysis": self.sentiment_analysis,
            "content_length": self.content_length,
            "language": self.language,
            "reading_level": self.reading_level,
            "overall_quality_score": self.overall_quality_score,
            "readability_score": self.readability_score,
            "trustworthiness_score": self.trustworthiness_score,
            "professionalism_score": self.professionalism_score,
            "processing_status": self.processing_status.value,
            "analysis_types": self.analysis_types,
            "processing_time_ms": self.processing_time_ms,
            "model_versions": self.model_versions,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
        }


class ContentSimilarity(Base):
    """
    Content similarity model for detecting duplicate or similar content.
    """
    __tablename__ = "content_similarities"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Foreign keys
    source_analysis_id = Column(UUID(as_uuid=True), ForeignKey("ai_analyses.id"), nullable=False, index=True)
    target_analysis_id = Column(UUID(as_uuid=True), ForeignKey("ai_analyses.id"), nullable=False, index=True)
    
    # Similarity metrics
    similarity_score = Column(Float, nullable=False)  # 0.0 to 1.0
    similarity_type = Column(String(50), nullable=False)  # cosine, jaccard, semantic, etc.
    
    # Similarity details
    matching_elements = Column(JSON, nullable=True)  # Specific matching content elements
    confidence_score = Column(Integer, nullable=False)  # 0-100
    
    # Metadata
    algorithm_version = Column(String(20), nullable=True)
    processing_time_ms = Column(Integer, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    source_analysis = relationship("AIAnalysis", foreign_keys=[source_analysis_id])
    target_analysis = relationship("AIAnalysis", foreign_keys=[target_analysis_id])
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_similarity_source_score', 'source_analysis_id', 'similarity_score'),
        Index('idx_similarity_target_score', 'target_analysis_id', 'similarity_score'),
        Index('idx_similarity_score_type', 'similarity_score', 'similarity_type'),
    )
    
    def __repr__(self) -> str:
        return f"<ContentSimilarity(id={self.id}, score={self.similarity_score}, type={self.similarity_type})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert content similarity to dictionary.
        """
        return {
            "id": str(self.id),
            "source_analysis_id": str(self.source_analysis_id),
            "target_analysis_id": str(self.target_analysis_id),
            "similarity_score": self.similarity_score,
            "similarity_type": self.similarity_type,
            "matching_elements": self.matching_elements,
            "confidence_score": self.confidence_score,
            "algorithm_version": self.algorithm_version,
            "processing_time_ms": self.processing_time_ms,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AIModelMetrics(Base):
    """
    AI model performance metrics and monitoring.
    """
    __tablename__ = "ai_model_metrics"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    
    # Model identification
    model_name = Column(String(100), nullable=False, index=True)
    model_version = Column(String(50), nullable=False)
    analysis_type = Column(Enum(AnalysisType), nullable=False, index=True)
    
    # Performance metrics
    total_requests = Column(Integer, default=0, nullable=False)
    successful_requests = Column(Integer, default=0, nullable=False)
    failed_requests = Column(Integer, default=0, nullable=False)
    avg_processing_time_ms = Column(Float, nullable=True)
    avg_confidence_score = Column(Float, nullable=True)
    
    # Resource usage
    total_tokens_used = Column(Integer, default=0, nullable=False)  # For LLM models
    total_cost_usd = Column(Float, default=0.0, nullable=False)
    
    # Time period
    date = Column(DateTime(timezone=True), nullable=False, index=True)
    period_type = Column(String(20), nullable=False)  # hourly, daily, weekly
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_model_metrics_name_date', 'model_name', 'date'),
        Index('idx_model_metrics_type_date', 'analysis_type', 'date'),
        Index('idx_model_metrics_period_date', 'period_type', 'date'),
    )
    
    def __repr__(self) -> str:
        return f"<AIModelMetrics(id={self.id}, model={self.model_name}, type={self.analysis_type})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert AI model metrics to dictionary.
        """
        return {
            "id": str(self.id),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "analysis_type": self.analysis_type.value,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": self.successful_requests / self.total_requests if self.total_requests > 0 else 0,
            "avg_processing_time_ms": self.avg_processing_time_ms,
            "avg_confidence_score": self.avg_confidence_score,
            "total_tokens_used": self.total_tokens_used,
            "total_cost_usd": self.total_cost_usd,
            "date": self.date.isoformat() if self.date else None,
            "period_type": self.period_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }