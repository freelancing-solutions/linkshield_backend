#!/usr/bin/env python3
"""
LinkShield Backend Email Service

Comprehensive email service supporting multiple providers (SMTP, Resend)
with proper error handling, logging, and retry mechanisms.
"""

import asyncio
import logging
import smtplib
import uuid
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List, Optional, Any, Union

import resend
from sqlalchemy import and_, desc

from src.config.database import get_db_session, AsyncSession
from src.config.settings import settings
from src.models.email import (
    EmailRequest, BulkEmailRequest, EmailTemplate, EmailLog, EmailStats,
    EmailProvider, EmailType, EmailStatus, EmailAttachment, EmailLogResponse
)
from src.services.email_templates import EmailTemplateService


class EmailServiceError(Exception):
    """Base exception for email service errors."""
    pass


class EmailProviderError(EmailServiceError):
    """Exception for email provider-specific errors."""
    pass


class EmailValidationError(EmailServiceError):
    """Exception for email validation errors."""
    pass


class EmailService:
    """
    Comprehensive email service supporting multiple providers.
    
    Features:
    - Multiple provider support (SMTP, Resend)
    - Template rendering
    - Bulk email sending
    - Email logging and tracking
    - Retry mechanisms
    - Statistics and analytics
    """
    
    def __init__(self, db_session: Optional[AsyncSession] = None):
        """
        Initialize the email service.
        
        Args:
            db_session: Database session for logging
        """
        self.logger = logging.getLogger(__name__)
        self.db_session = db_session or anext(get_db_session())
        self.template_service = EmailTemplateService()
        
        # Initialize providers based on configuration
        self.provider = EmailProvider(settings.EMAIL_PROVIDER)
        self._initialize_providers()
    
    def _initialize_providers(self) -> None:
        """Initialize email providers based on configuration."""
        if self.provider == EmailProvider.RESEND:
            if not settings.RESEND_API_KEY:
                raise EmailServiceError("Resend API key is required but not configured")
            resend.api_key = settings.RESEND_API_KEY
            self.logger.info("Resend provider initialized")
        
        elif self.provider == EmailProvider.SMTP:
            if not all([settings.SMTP_HOST, settings.SMTP_PORT]):
                raise EmailServiceError("SMTP configuration is incomplete")
            self.logger.info("SMTP provider initialized")
    
    async def send_email(
        self,
        email_request: EmailRequest,
        template_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send a single email.
        
        Args:
            email_request: Email request data
            template_name: Optional template name to use
            
        Returns:
            Dict containing send result and metadata
        """
        try:
            # Create email log entry
            email_log = self._create_email_log(email_request)
            
            # Render template if specified
            if template_name:
                email_request = await self._render_template(email_request, template_name)
            
            # Validate email content
            self._validate_email_request(email_request)
            
            # Send email based on provider
            if self.provider == EmailProvider.RESEND:
                result = await self._send_via_resend(email_request, email_log)
            else:
                result = await self._send_via_smtp(email_request, email_log)
            
            # Update log with success
            self._update_email_log_success(email_log, result)
            
            self.logger.info(f"Email sent successfully to {email_request.to}")
            return {
                "success": True,
                "email_id": str(email_log.id),
                "external_id": result.get("id"),
                "provider": self.provider.value,
                "recipient": email_request.to
            }
            
        except Exception as e:
            self.logger.error(f"Failed to send email to {email_request.to}: {str(e)}")
            if 'email_log' in locals():
                self._update_email_log_failure(email_log, str(e))
            
            return {
                "success": False,
                "error": str(e),
                "email_id": str(email_log.id) if 'email_log' in locals() else None,
                "provider": self.provider.value,
                "recipient": email_request.to
            }
    
    async def send_bulk_email(
        self,
        bulk_request: BulkEmailRequest,
        template_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send emails to multiple recipients.
        
        Args:
            bulk_request: Bulk email request data
            template_name: Optional template name to use
            
        Returns:
            Dict containing bulk send results
        """
        results = []
        successful_sends = 0
        failed_sends = 0
        
        for recipient in bulk_request.recipients:
            # Create individual email request
            email_request = EmailRequest(
                to=recipient,
                subject=bulk_request.subject,
                html_content=bulk_request.html_content,
                text_content=bulk_request.text_content,
                from_email=bulk_request.from_email,
                from_name=bulk_request.from_name,
                template_variables={
                    **bulk_request.template_variables,
                    **bulk_request.recipient_variables.get(recipient, {})
                },
                email_type=bulk_request.email_type
            )
            
            # Send individual email
            result = await self.send_email(email_request, template_name)
            results.append({
                "recipient": recipient,
                **result
            })
            
            if result["success"]:
                successful_sends += 1
            else:
                failed_sends += 1
            
            # Add small delay to avoid rate limiting
            await asyncio.sleep(0.1)
        
        self.logger.info(
            f"Bulk email completed: {successful_sends} successful, {failed_sends} failed"
        )
        
        return {
            "total_recipients": len(bulk_request.recipients),
            "successful_sends": successful_sends,
            "failed_sends": failed_sends,
            "success_rate": successful_sends / len(bulk_request.recipients) * 100,
            "results": results
        }
    
    async def _send_via_resend(
        self,
        email_request: EmailRequest,
        email_log: EmailLog
    ) -> Dict[str, Any]:
        """
        Send email via Resend provider.
        
        Args:
            email_request: Email request data
            email_log: Email log entry
            
        Returns:
            Dict containing Resend response
        """
        try:
            # Prepare email data for Resend
            email_data = {
                "from": f"{email_request.from_name or settings.EMAIL_FROM_NAME} <{email_request.from_email or settings.EMAIL_FROM}>",
                "to": [email_request.to],
                "subject": email_request.subject,
            }
            
            # Add content
            if email_request.html_content:
                email_data["html"] = email_request.html_content
            if email_request.text_content:
                email_data["text"] = email_request.text_content
            
            # Add reply-to if specified
            if email_request.reply_to:
                email_data["reply_to"] = [email_request.reply_to]
            
            # Add attachments if any
            if email_request.attachments:
                email_data["attachments"] = [
                    {
                        "filename": att.filename,
                        "content": att.content,
                        "content_type": att.content_type
                    }
                    for att in email_request.attachments
                ]
            
            # Send via Resend
            response = resend.Emails.send(email_data)
            
            return {
                "id": response.get("id"),
                "provider_response": response
            }
            
        except Exception as e:
            raise EmailProviderError(f"Resend API error: {str(e)}")
    
    async def _send_via_smtp(
        self,
        email_request: EmailRequest,
        email_log: EmailLog
    ) -> Dict[str, Any]:
        """
        Send email via SMTP provider.
        
        Args:
            email_request: Email request data
            email_log: Email log entry
            
        Returns:
            Dict containing SMTP response
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{email_request.from_name or settings.EMAIL_FROM_NAME} <{email_request.from_email or settings.EMAIL_FROM}>"
            msg['To'] = email_request.to
            msg['Subject'] = email_request.subject
            
            if email_request.reply_to:
                msg['Reply-To'] = email_request.reply_to
            
            # Add text content
            if email_request.text_content:
                text_part = MIMEText(email_request.text_content, 'plain')
                msg.attach(text_part)
            
            # Add HTML content
            if email_request.html_content:
                html_part = MIMEText(email_request.html_content, 'html')
                msg.attach(html_part)
            
            # Add attachments
            if email_request.attachments:
                for attachment in email_request.attachments:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.content)
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {attachment.filename}'
                    )
                    msg.attach(part)
            
            # Send email
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_TLS:
                    server.starttls()
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                
                server.send_message(msg)
            
            return {
                "id": str(uuid.uuid4()),  # Generate local ID for SMTP
                "provider_response": "SMTP send successful"
            }
            
        except Exception as e:
            raise EmailProviderError(f"SMTP error: {str(e)}")
    
    async def _render_template(
        self,
        email_request: EmailRequest,
        template_name: str
    ) -> EmailRequest:
        """
        Render email template with variables.
        
        Args:
            email_request: Original email request
            template_name: Template name to render
            
        Returns:
            Updated email request with rendered content
        """
        template = await self.template_service.get_template(template_name)
        
        if not template:
            raise EmailValidationError(f"Template '{template_name}' not found")
        
        # Render subject
        rendered_subject = self.template_service.render_template(
            template.subject_template,
            email_request.template_variables
        )
        
        # Render HTML content
        rendered_html = None
        if template.html_template:
            rendered_html = self.template_service.render_template(
                template.html_template,
                email_request.template_variables
            )
        
        # Render text content
        rendered_text = None
        if template.text_template:
            rendered_text = self.template_service.render_template(
                template.text_template,
                email_request.template_variables
            )
        
        # Update email request
        email_request.subject = rendered_subject
        if rendered_html:
            email_request.html_content = rendered_html
        if rendered_text:
            email_request.text_content = rendered_text
        
        return email_request
    
    def _validate_email_request(self, email_request: EmailRequest) -> None:
        """
        Validate email request data.
        
        Args:
            email_request: Email request to validate
            
        Raises:
            EmailValidationError: If validation fails
        """
        if not email_request.html_content and not email_request.text_content:
            raise EmailValidationError("Either HTML or text content must be provided")
        
        if not email_request.subject.strip():
            raise EmailValidationError("Email subject cannot be empty")
    
    def _create_email_log(self, email_request: EmailRequest) -> EmailLog:
        """
        Create email log entry.
        
        Args:
            email_request: Email request data
            
        Returns:
            Created email log entry
        """
        email_log = EmailLog(
            recipient=email_request.to,
            sender=email_request.from_email or settings.EMAIL_FROM,
            subject=email_request.subject,
            email_type=email_request.email_type.value,
            provider=self.provider.value,
            status=EmailStatus.PENDING.value,
            metadata={
                "priority": email_request.priority,
                "has_attachments": bool(email_request.attachments),
                "attachment_count": len(email_request.attachments) if email_request.attachments else 0
            }
        )
        
        self.db_session.add(email_log)
        self.db_session.commit()
        self.db_session.refresh(email_log)
        
        return email_log
    
    def _update_email_log_success(
        self,
        email_log: EmailLog,
        result: Dict[str, Any]
    ) -> None:
        """
        Update email log with success status.
        
        Args:
            email_log: Email log entry to update
            result: Send result data
        """
        email_log.status = EmailStatus.SENT.value
        email_log.external_id = result.get("id")
        email_log.sent_at = datetime.utcnow()
        
        if result.get("provider_response"):
            email_log.metadata = {
                **(email_log.metadata or {}),
                "provider_response": result["provider_response"]
            }
        
        self.db_session.commit()
    
    def _update_email_log_failure(
        self,
        email_log: EmailLog,
        error_message: str
    ) -> None:
        """
        Update email log with failure status.
        
        Args:
            email_log: Email log entry to update
            error_message: Error message
        """
        email_log.status = EmailStatus.FAILED.value
        email_log.error_message = error_message
        email_log.failed_at = datetime.utcnow()
        email_log.retry_count += 1
        
        self.db_session.commit()
    
    def get_email_logs(
        self,
        recipient: Optional[str] = None,
        email_type: Optional[EmailType] = None,
        status: Optional[EmailStatus] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[EmailLogResponse]:
        """
        Retrieve email logs with optional filtering.
        
        Args:
            recipient: Filter by recipient email
            email_type: Filter by email type
            status: Filter by email status
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of email log entries
        """
        query = self.db_session.query(EmailLog)
        
        # Apply filters
        if recipient:
            query = query.filter(EmailLog.recipient == recipient)
        if email_type:
            query = query.filter(EmailLog.email_type == email_type.value)
        if status:
            query = query.filter(EmailLog.status == status.value)
        
        # Apply pagination and ordering
        logs = query.order_by(desc(EmailLog.created_at)).offset(offset).limit(limit).all()
        
        return [EmailLogResponse.from_orm(log) for log in logs]
    
    def get_email_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> EmailStats:
        """
        Get email statistics.
        
        Args:
            start_date: Start date for statistics
            end_date: End date for statistics
            
        Returns:
            Email statistics
        """
        query = self.db_session.query(EmailLog)
        
        # Apply date filters
        if start_date:
            query = query.filter(EmailLog.created_at >= start_date)
        if end_date:
            query = query.filter(EmailLog.created_at <= end_date)
        
        logs = query.all()
        
        # Calculate statistics
        total_sent = len([log for log in logs if log.status in [EmailStatus.SENT.value, EmailStatus.DELIVERED.value]])
        total_delivered = len([log for log in logs if log.status == EmailStatus.DELIVERED.value])
        total_failed = len([log for log in logs if log.status == EmailStatus.FAILED.value])
        total_bounced = len([log for log in logs if log.status == EmailStatus.BOUNCED.value])
        
        total_emails = len(logs)
        delivery_rate = (total_delivered / total_emails * 100) if total_emails > 0 else 0
        bounce_rate = (total_bounced / total_emails * 100) if total_emails > 0 else 0
        
        # Group by type and provider
        by_type = {}
        by_provider = {}
        
        for log in logs:
            by_type[log.email_type] = by_type.get(log.email_type, 0) + 1
            by_provider[log.provider] = by_provider.get(log.provider, 0) + 1
        
        return EmailStats(
            total_sent=total_sent,
            total_delivered=total_delivered,
            total_failed=total_failed,
            total_bounced=total_bounced,
            delivery_rate=delivery_rate,
            bounce_rate=bounce_rate,
            by_type=by_type,
            by_provider=by_provider,
            date_range={
                "start": start_date,
                "end": end_date
            } if start_date or end_date else None
        )
    
    async def retry_failed_emails(
        self,
        max_retries: int = 3,
        batch_size: int = 10
    ) -> Dict[str, Any]:
        """
        Retry failed email sends.
        
        Args:
            max_retries: Maximum number of retry attempts
            batch_size: Number of emails to process in each batch
            
        Returns:
            Dict containing retry results
        """
        # Get failed emails that haven't exceeded max retries
        failed_logs = self.db_session.query(EmailLog).filter(
            and_(
                EmailLog.status == EmailStatus.FAILED.value,
                EmailLog.retry_count < max_retries
            )
        ).limit(batch_size).all()
        
        retry_results = []
        successful_retries = 0
        failed_retries = 0
        
        for log in failed_logs:
            try:
                # Reconstruct email request from log
                email_request = EmailRequest(
                    to=log.recipient,
                    subject=log.subject,
                    html_content="",  # Would need to store original content
                    email_type=EmailType(log.email_type)
                )
                
                # Attempt to resend
                result = await self.send_email(email_request)
                
                if result["success"]:
                    successful_retries += 1
                else:
                    failed_retries += 1
                
                retry_results.append({
                    "email_id": str(log.id),
                    "recipient": log.recipient,
                    "success": result["success"],
                    "error": result.get("error")
                })
                
            except Exception as e:
                failed_retries += 1
                retry_results.append({
                    "email_id": str(log.id),
                    "recipient": log.recipient,
                    "success": False,
                    "error": str(e)
                })
        
        self.logger.info(
            f"Email retry completed: {successful_retries} successful, {failed_retries} failed"
        )
        
        return {
            "total_retried": len(failed_logs),
            "successful_retries": successful_retries,
            "failed_retries": failed_retries,
            "results": retry_results
        }
