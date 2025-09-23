#!/usr/bin/env python3
"""
LinkShield Backend Email Models

Pydantic models for email operations, validation, and type safety.
"""

import uuid
from datetime import datetime

from typing import Dict, List, Optional, Any

from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import Column, Enum, String, DateTime, Text, Integer, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from src.config.database import Base
import enum

class EmailProvider(enum.Enum):
    """
    Enum for supported email providers.
    """
    SMTP = "smtp"
    RESEND = "resend"


class EmailType(enum.Enum):
    """
    Enum for different types of emails.
    """
    VERIFICATION = "verification"
    PASSWORD_RESET = "password_reset"
    WELCOME = "welcome"
    NOTIFICATION = "notification"
    SECURITY_ALERT = "security_alert"
    BULK = "bulk"


class EmailStatus(enum.Enum):
    """
    Enum for email delivery status.
    """
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    BOUNCED = "bounced"
    REJECTED = "rejected"


class EmailAttachment(BaseModel):
    """
    Model for email attachments.
    """
    filename: str = Field(..., description="Name of the attachment file")
    content: bytes = Field(..., description="File content as bytes")
    content_type: str = Field(default="application/octet-stream", description="MIME type of the file")
    
    @field_validator('content')
    def validate_file_size(cls, v):
        """Validate attachment file size (max 10MB)."""
        max_size = 10 * 1024 * 1024  # 10MB
        if len(v) > max_size:
            raise ValueError(f"File size exceeds maximum allowed size of {max_size} bytes")
        return v

    class Config:
        arbitrary_types_allowed = True


class EmailRequest(BaseModel):
    """
    Base model for email sending requests.
    """
    to: EmailStr = Field(..., description="Recipient email address")
    subject: str = Field(..., min_length=1, max_length=255, description="Email subject")
    html_content: Optional[str] = Field(default=None, description="HTML email content")
    text_content: Optional[str] = Field(default=None, description="Plain text email content")
    from_email: Optional[EmailStr] = Field(default=None, description="Sender email address")
    from_name: Optional[str] = Field(default=None, description="Sender name")
    reply_to: Optional[EmailStr] = Field(default=None, description="Reply-to email address")
    attachments: Optional[List[EmailAttachment]] = Field(default=[], description="Email attachments")
    template_variables: Optional[Dict[str, Any]] = Field(default={}, description="Template variables")
    email_type: EmailType = Field(default=EmailType.NOTIFICATION, description="Type of email")
    priority: int = Field(default=3, ge=1, le=5, description="Email priority (1=highest, 5=lowest)")
    
    @field_validator('attachments')
    def validate_attachments_count(cls, v):
        """Validate maximum number of attachments."""
        if v and len(v) > 10:
            raise ValueError("Maximum 10 attachments allowed per email")
        return v


class BulkEmailRequest(BaseModel):
    """
    Model for sending emails to multiple recipients.
    """
    recipients: List[EmailStr] = Field(..., min_items=1, max_items=1000, description="List of recipient email addresses")
    subject: str = Field(..., min_length=1, max_length=255, description="Email subject")
    html_content: Optional[str] = Field(None, description="HTML email content")
    text_content: Optional[str] = Field(None, description="Plain text email content")
    from_email: Optional[EmailStr] = Field(None, description="Sender email address")
    from_name: Optional[str] = Field(None, description="Sender name")
    template_variables: Optional[Dict[str, Any]] = Field(default={}, description="Global template variables")
    recipient_variables: Optional[Dict[str, Dict[str, Any]]] = Field(default={}, description="Per-recipient template variables")
    email_type: EmailType = Field(default=EmailType.BULK, description="Type of email")
    
    @field_validator('recipients')
    def validate_unique_recipients(cls, v):
        """Ensure all recipients are unique."""
        if len(v) != len(set(v)):
            raise ValueError("Duplicate recipients are not allowed")
        return v


class EmailTemplate(BaseModel):
    """
    Model for email template data.
    """
    template_type: EmailType = Field(..., description="Type of email template")
    subject_template: str = Field(..., description="Subject line template")
    html_template: Optional[str] = Field(None, description="HTML template content")
    text_template: Optional[str] = Field(None, description="Plain text template content")
    variables: Dict[str, Any] = Field(default={}, description="Template variables")
    extra_metadata: Optional[Dict[str, Any]] = Field(default={}, description="Additional template metadata")

    
    @field_validator('html_template', 'text_template')
    def validate_template_content(cls, v, field):
        """Ensure at least one template content is provided."""
        return v
    
    @field_validator('variables')
    def validate_template_variables(cls, v):
        """Validate template variables format."""
        if not isinstance(v, dict):
            raise ValueError("Template variables must be a dictionary")
        return v


class EmailLog(Base):
    """
    Database model for email logging and tracking.
    """
    __tablename__ = "email_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    recipient = Column(String(255), nullable=False, index=True)
    sender = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=False)
    email_type = Column(String(50), nullable=False, index=True)
    provider = Column(String(20), nullable=False)
    status = Column(Enum(EmailStatus), default=EmailStatus.PENDING, nullable=False, index=True)

    external_id = Column(String(255), nullable=True, index=True)  # Provider's email ID
    error_message = Column(Text, nullable=True)
    email_metadata = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Tracking
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    
    def __repr__(self):
        return f"<EmailLog(id={self.id}, recipient={self.recipient}, status={self.status})>"


class EmailLogResponse(BaseModel):
    """
    Response model for email log entries.
    """
    id: uuid.UUID
    recipient: str
    sender: Optional[str]
    subject: str
    email_type: str
    provider: str
    status: str
    external_id: Optional[str]
    error_message: Optional[str]
    email_log_metadata: Optional[Dict[str, Any]]
    created_at: datetime
    sent_at: Optional[datetime]
    delivered_at: Optional[datetime]
    failed_at: Optional[datetime]
    retry_count: int
    max_retries: int
    
    class Config:
        from_attributes = True


class EmailStats(BaseModel):
    """
    Model for email statistics and metrics.
    """
    total_sent: int = Field(default=0, description="Total emails sent")
    total_delivered: int = Field(default=0, description="Total emails delivered")
    total_failed: int = Field(default=0, description="Total emails failed")
    total_bounced: int = Field(default=0, description="Total emails bounced")
    delivery_rate: float = Field(default=0.0, description="Delivery rate percentage")
    bounce_rate: float = Field(default=0.0, description="Bounce rate percentage")
    by_type: Dict[str, int] = Field(default={}, description="Email counts by type")
    by_provider: Dict[str, int] = Field(default={}, description="Email counts by provider")
    date_range: Optional[Dict[str, datetime]] = Field(None, description="Date range for statistics")


class EmailPreferences(BaseModel):
    """
    Model for user email preferences.
    """
    user_id: uuid.UUID = Field(..., description="User ID")
    marketing_emails: bool = Field(default=True, description="Receive marketing emails")
    security_alerts: bool = Field(default=True, description="Receive security alerts")
    product_updates: bool = Field(default=True, description="Receive product updates")
    weekly_reports: bool = Field(default=True, description="Receive weekly reports")
    email_frequency: str = Field(default="immediate", description="Email frequency preference")
    unsubscribe_token: Optional[str] = Field(None, description="Unsubscribe token")
    
    class Config:
        from_attributes = True


class EmailValidationResult(BaseModel):
    """
    Model for email validation results.
    """
    email: EmailStr = Field(..., description="Email address")
    is_valid: bool = Field(..., description="Whether email is valid")
    is_deliverable: bool = Field(default=False, description="Whether email is deliverable")
    is_disposable: bool = Field(default=False, description="Whether email is from disposable provider")
    domain: str = Field(..., description="Email domain")
    validation_errors: List[str] = Field(default=[], description="List of validation errors")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Risk score (0=safe, 1=risky)")
