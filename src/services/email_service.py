#!/usr/bin/env python3
"""
LinkShield Backend Email Service

Pure email sending service supporting multiple providers (SMTP, Resend)
with proper error handling and retry mechanisms.
"""

import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List, Optional, Any

import resend

from src.config.settings import settings
from src.models.email import (
    EmailRequest, BulkEmailRequest, EmailProvider, EmailType, EmailAttachment
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
    Pure email sending service supporting multiple providers.
    
    Features:
    - Multiple provider support (SMTP, Resend)
    - Template rendering
    - Bulk email sending
    - Retry mechanisms
    """
    
    def __init__(self):
        """Initialize the email service."""
        self.logger = logging.getLogger(__name__)
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
            # Render template if specified
            if template_name:
                email_request = await self._render_template(email_request, template_name)
            
            # Validate email content
            self._validate_email_request(email_request)
            
            # Send email based on provider
            if self.provider == EmailProvider.RESEND:
                result = await self._send_via_resend(email_request)
            else:
                result = await self._send_via_smtp(email_request)
            
            self.logger.info(f"Email sent successfully to {email_request.to}")
            return {
                "success": True,
                "external_id": result.get("id"),
                "provider": self.provider.value,
                "recipient": email_request.to,
                "provider_response": result
            }
            
        except Exception as e:
            self.logger.error(f"Failed to send email to {email_request.to}: {str(e)}")
            
            return {
                "success": False,
                "error": str(e),
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
    
    async def _send_via_resend(self, email_request: EmailRequest) -> Dict[str, Any]:
        """
        Send email via Resend provider.
        
        Args:
            email_request: Email request data
            
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
    
    async def _send_via_smtp(self, email_request: EmailRequest) -> Dict[str, Any]:
        """
        Send email via SMTP provider.
        
        Args:
            email_request: Email request data
            
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
            
            # Connect and send
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_TLS:
                    server.starttls()
                
                if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                
                server.send_message(msg)
            
            return {
                "id": f"smtp_{email_request.to}_{int(asyncio.get_event_loop().time())}",
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
            Email request with rendered content
        """
        try:
            rendered_content = await self.template_service.render_template(
                template_name,
                email_request.template_variables or {}
            )
            
            # Update email request with rendered content
            email_request.html_content = rendered_content.get("html", email_request.html_content)
            email_request.text_content = rendered_content.get("text", email_request.text_content)
            email_request.subject = rendered_content.get("subject", email_request.subject)
            
            return email_request
            
        except Exception as e:
            raise EmailServiceError(f"Template rendering failed: {str(e)}")
    
    def _validate_email_request(self, email_request: EmailRequest) -> None:
        """
        Validate email request data.
        
        Args:
            email_request: Email request to validate
            
        Raises:
            EmailValidationError: If validation fails
        """
        if not email_request.to:
            raise EmailValidationError("Recipient email is required")
        
        if not email_request.subject:
            raise EmailValidationError("Email subject is required")
        
        if not email_request.html_content and not email_request.text_content:
            raise EmailValidationError("Email content (HTML or text) is required")
        
        # Basic email format validation
        if "@" not in email_request.to or "." not in email_request.to.split("@")[1]:
            raise EmailValidationError("Invalid recipient email format")
    
    def create_verification_email(
        self,
        recipient: str,
        first_name: str,
        verification_token: str
    ) -> EmailRequest:
        """
        Create email verification request.
        
        Args:
            recipient: Recipient email address
            first_name: User's first name
            verification_token: Email verification token
            
        Returns:
            EmailRequest for verification email
        """
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"
        
        return EmailRequest(
            to=recipient,
            subject=f"Verify your {settings.APP_NAME} account",
            email_type=EmailType.VERIFICATION,
            template_variables={
                "user_name": first_name,
                "verification_url": verification_url,
                "app_name": settings.APP_NAME,
                "current_year": 2024
            }
        )
    
    def create_password_reset_email(
        self,
        recipient: str,
        first_name: str,
        reset_token: str
    ) -> EmailRequest:
        """
        Create password reset email request.
        
        Args:
            recipient: Recipient email address
            first_name: User's first name
            reset_token: Password reset token
            
        Returns:
            EmailRequest for password reset email
        """
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        
        return EmailRequest(
            to=recipient,
            subject=f"Reset your {settings.APP_NAME} password",
            email_type=EmailType.PASSWORD_RESET,
            template_variables={
                "user_name": first_name,
                "reset_url": reset_url,
                "app_name": settings.APP_NAME,
                "current_year": 2024
            }
        )
    
    def create_security_alert_email(
        self,
        recipient: str,
        first_name: str,
        login_ip: str,
        login_time: str
    ) -> EmailRequest:
        """
        Create security alert email request.
        
        Args:
            recipient: Recipient email address
            first_name: User's first name
            login_ip: Login IP address
            login_time: Login timestamp
            
        Returns:
            EmailRequest for security alert email
        """
        return EmailRequest(
            to=recipient,
            subject=f"Security Alert - New login to your {settings.APP_NAME} account",
            email_type=EmailType.SECURITY_ALERT,
            template_variables={
                "user_name": first_name,
                "login_ip": login_ip,
                "login_time": login_time,
                "app_name": settings.APP_NAME,
                "current_year": 2024
            }
        )
