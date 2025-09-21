#!/usr/bin/env python3
"""
LinkShield Backend Task Models

Database models for tracking FastAPI BackgroundTasks and their execution status.
Provides comprehensive task management with status tracking, metadata, and relationships.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Text, Integer, Boolean, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

from src.config.database import Base



class TaskStatus(str, Enum):
    """Task execution status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"
    TIMEOUT = "timeout"


class TaskType(str, Enum):
    """Task type enumeration for different background operations."""
    AI_ANALYSIS = "ai_analysis"
    URL_CHECK = "url_check"
    REPORT_GENERATION = "report_generation"
    REPORT_ASSIGNMENT = "report_assignment"
    BULK_ANALYSIS = "bulk_analysis"
    DATA_EXPORT = "data_export"
    DATA_IMPORT = "data_import"
    EMAIL_NOTIFICATION = "email_notification"
    WEBHOOK_DELIVERY = "webhook_delivery"
    SYSTEM_MAINTENANCE = "system_maintenance"
    USER_CLEANUP = "user_cleanup"
    CACHE_REFRESH = "cache_refresh"
    BACKUP_OPERATION = "backup_operation"
    ADMIN_OPERATION = "admin_operation"


class TaskPriority(str, Enum):
    """Task priority levels for queue management."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class BackgroundTask(Base):
    """
    Database model for tracking FastAPI BackgroundTasks.
    
    This model provides comprehensive tracking of background task execution,
    including status, progress, results, and error handling.
    """
    
    __tablename__ = "background_tasks"
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    task_id = Column(String(255), unique=True, nullable=False, index=True, 
                     comment="Unique task identifier for external reference")
    
    # Task classification
    task_type = Column(String(50), nullable=False, index=True,
                      comment="Type of background task being executed")
    task_name = Column(String(255), nullable=False,
                      comment="Human-readable task name")
    priority = Column(String(20), nullable=False, default=TaskPriority.NORMAL,
                     comment="Task execution priority")
    
    # Status tracking
    status = Column(String(20), nullable=False, default=TaskStatus.PENDING, index=True,
                   comment="Current task execution status")
    progress_percentage = Column(Integer, default=0,
                               comment="Task completion percentage (0-100)")
    
    # Timing information
    created_at = Column(DateTime(timezone=True), nullable=False, 
                       default=lambda: datetime.now(timezone.utc), index=True)
    started_at = Column(DateTime(timezone=True), nullable=True,
                       comment="When task execution began")
    completed_at = Column(DateTime(timezone=True), nullable=True,
                         comment="When task execution finished")
    estimated_duration_seconds = Column(Integer, nullable=True,
                                      comment="Estimated task duration in seconds")
    actual_duration_seconds = Column(Integer, nullable=True,
                                   comment="Actual task execution time in seconds")
    
    # Task data and configuration
    input_data = Column(JSON, nullable=True,
                       comment="Input parameters and configuration for the task")
    result_data = Column(JSON, nullable=True,
                        comment="Task execution results and output data")
    error_details = Column(Text, nullable=True,
                          comment="Error message and stack trace if task failed")
    
    # Retry and recovery
    retry_count = Column(Integer, default=0,
                        comment="Number of retry attempts made")
    max_retries = Column(Integer, default=3,
                        comment="Maximum number of retry attempts allowed")
    retry_delay_seconds = Column(Integer, default=60,
                               comment="Delay between retry attempts in seconds")
    
    # User and context
    user_id = Column(UUID(as_uuid=True), nullable=True, index=True,
                    comment="User who initiated the task")
    session_id = Column(String(255), nullable=True,
                       comment="Session identifier for task grouping")
    correlation_id = Column(String(255), nullable=True, index=True,
                          comment="Correlation ID for request tracing")
    
    # Webhook and notification
    webhook_url = Column(String(2048), nullable=True,
                        comment="Webhook URL for task completion notification")
    webhook_secret = Column(String(255), nullable=True,
                           comment="Secret for webhook HMAC authentication")
    notification_sent = Column(Boolean, default=False,
                             comment="Whether completion notification was sent")
    
    # Metadata and tags
    task_metadata = Column(JSON, nullable=True,
                     comment="Additional task metadata and custom fields")
    tags = Column(JSON, nullable=True,
                 comment="Task tags for categorization and filtering")
    
    # System fields
    worker_id = Column(String(255), nullable=True,
                      comment="Identifier of worker/process executing the task")
    queue_name = Column(String(100), nullable=True,
                       comment="Queue or channel where task was processed")
    
    def __repr__(self):
        return f"<BackgroundTask(id={self.id}, task_id={self.task_id}, type={self.task_type}, status={self.status})>"
    
    @property
    def is_running(self) -> bool:
        """Check if task is currently running."""
        return self.status == TaskStatus.RUNNING
    
    @property
    def is_completed(self) -> bool:
        """Check if task completed successfully."""
        return self.status == TaskStatus.COMPLETED
    
    @property
    def is_failed(self) -> bool:
        """Check if task failed."""
        return self.status in (TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED)
    
    @property
    def is_finished(self) -> bool:
        """Check if task is in a terminal state."""
        return self.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED)
    
    @property
    def can_retry(self) -> bool:
        """Check if task can be retried."""
        return (
            self.is_failed and 
            self.retry_count < self.max_retries and 
            self.status != TaskStatus.CANCELLED
        )
    
    @property
    def duration_seconds(self) -> Optional[int]:
        """Calculate task duration in seconds."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        elif self.started_at and not self.completed_at:
            return int((datetime.now(timezone.utc) - self.started_at).total_seconds())
        return None
    
    def update_progress(self, percentage: int, message: Optional[str] = None):
        """
        Update task progress.
        
        Args:
            percentage: Progress percentage (0-100)
            message: Optional progress message
        """
        self.progress_percentage = max(0, min(100, percentage))
        if message and self.task_metadata:
            if 'progress_messages' not in self.task_metadata:
                self.task_metadata['progress_messages'] = []
            self.task_metadata['progress_messages'].append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'percentage': percentage,
                'message': message
            })
    
    def mark_started(self, worker_id: Optional[str] = None):
        """Mark task as started."""
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)
        if worker_id:
            self.worker_id = worker_id
    
    def mark_completed(self, result_data: Optional[Dict[str, Any]] = None):
        """Mark task as completed successfully."""
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.progress_percentage = 100
        if result_data:
            self.result_data = result_data
        if self.started_at:
            self.actual_duration_seconds = self.duration_seconds
    
    def mark_failed(self, error_message: str, error_details: Optional[str] = None):
        """Mark task as failed."""
        self.status = TaskStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.error_details = error_details or error_message
        if self.started_at:
            self.actual_duration_seconds = self.duration_seconds
    
    def mark_cancelled(self, reason: Optional[str] = None):
        """Mark task as cancelled."""
        self.status = TaskStatus.CANCELLED
        self.completed_at = datetime.now(timezone.utc)
        if reason:
            self.error_details = f"Task cancelled: {reason}"
        if self.started_at:
            self.actual_duration_seconds = self.duration_seconds
    
    def increment_retry(self):
        """Increment retry count and update status."""
        self.retry_count += 1
        if self.retry_count <= self.max_retries:
            self.status = TaskStatus.RETRYING
        else:
            self.status = TaskStatus.FAILED
            if not self.error_details:
                self.error_details = f"Task failed after {self.max_retries} retry attempts"
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert task to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields like webhook_secret
            
        Returns:
            Dict[str, Any]: Task data as dictionary
        """
        data = {
            'id': str(self.id),
            'task_id': self.task_id,
            'task_type': self.task_type,
            'task_name': self.task_name,
            'priority': self.priority,
            'status': self.status,
            'progress_percentage': self.progress_percentage,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'estimated_duration_seconds': self.estimated_duration_seconds,
            'actual_duration_seconds': self.actual_duration_seconds,
            'duration_seconds': self.duration_seconds,
            'input_data': self.input_data,
            'result_data': self.result_data,
            'error_details': self.error_details,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'user_id': str(self.user_id) if self.user_id else None,
            'session_id': self.session_id,
            'correlation_id': self.correlation_id,
            'webhook_url': self.webhook_url,
            'notification_sent': self.notification_sent,
            'metadata': self.task_metadata,
            'tags': self.tags,
            'worker_id': self.worker_id,
            'queue_name': self.queue_name,
            'is_running': self.is_running,
            'is_completed': self.is_completed,
            'is_failed': self.is_failed,
            'is_finished': self.is_finished,
            'can_retry': self.can_retry
        }
        
        if include_sensitive:
            data['webhook_secret'] = self.webhook_secret
            
        return data


class TaskLog(Base):
    """
    Model for storing detailed task execution logs.
    
    Provides audit trail and debugging information for background tasks.
    """
    
    __tablename__ = "task_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    task_id = Column(UUID(as_uuid=True), ForeignKey('background_tasks.id', ondelete='CASCADE'), 
                    nullable=False, index=True)
    
    # Log entry details
    timestamp = Column(DateTime(timezone=True), nullable=False, 
                      default=lambda: datetime.now(timezone.utc), index=True)
    level = Column(String(20), nullable=False, default='INFO',
                  comment="Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    message = Column(Text, nullable=False,
                    comment="Log message content")
    
    # Context information
    component = Column(String(100), nullable=True,
                      comment="Component or module that generated the log")
    function_name = Column(String(100), nullable=True,
                          comment="Function or method name")
    line_number = Column(Integer, nullable=True,
                        comment="Source code line number")
    
    # Additional data
    extra_data = Column(JSON, nullable=True,
                       comment="Additional structured log data")
    
    # Relationship
    task = relationship("BackgroundTask", backref="logs")
    
    def __repr__(self):
        return f"<TaskLog(id={self.id}, task_id={self.task_id}, level={self.level}, timestamp={self.timestamp})>"


class TaskDependency(Base):
    """
    Model for tracking task dependencies and execution order.
    
    Allows for complex task workflows and dependency management.
    """
    
    __tablename__ = "task_dependencies"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Task relationship
    dependent_task_id = Column(UUID(as_uuid=True), ForeignKey('background_tasks.id', ondelete='CASCADE'),
                              nullable=False, index=True,
                              comment="Task that depends on another task")
    prerequisite_task_id = Column(UUID(as_uuid=True), ForeignKey('background_tasks.id', ondelete='CASCADE'),
                                 nullable=False, index=True,
                                 comment="Task that must complete before dependent task can run")
    
    # Dependency configuration
    dependency_type = Column(String(50), nullable=False, default='completion',
                           comment="Type of dependency: completion, success, failure")
    is_blocking = Column(Boolean, default=True,
                        comment="Whether this dependency blocks execution")
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, 
                       default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime(timezone=True), nullable=True,
                        comment="When the dependency was resolved")
    
    # Relationships
    dependent_task = relationship("BackgroundTask", foreign_keys=[dependent_task_id], 
                                 backref="dependencies")
    prerequisite_task = relationship("BackgroundTask", foreign_keys=[prerequisite_task_id],
                                   backref="dependents")
    
    def __repr__(self):
        return f"<TaskDependency(dependent={self.dependent_task_id}, prerequisite={self.prerequisite_task_id})>"
    
    @property
    def is_resolved(self) -> bool:
        """Check if dependency is resolved."""
        return self.resolved_at is not None
    
    def resolve(self):
        """Mark dependency as resolved."""
        self.resolved_at = datetime.now(timezone.utc)