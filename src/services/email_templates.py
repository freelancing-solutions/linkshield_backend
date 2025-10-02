#!/usr/bin/env python3
"""
LinkShield Backend Email Templates Service

Comprehensive email template management with HTML and text templates
for various email types including verification, password reset, and notifications.
"""

import logging
from typing import Dict, Optional, Any
from jinja2 import Environment, BaseLoader, TemplateError

from src.models.email import EmailTemplate, EmailType
from src.config.settings import settings


class EmailTemplateService:
    """
    Service for managing and rendering email templates.
    
    Features:
    - Pre-built templates for common email types
    - Jinja2 template rendering
    - HTML and text template support
    - Template validation
    - Custom template registration
    """
    
    def __init__(self):
        """
        Initialize the email template service.
        """
        self.logger = logging.getLogger(__name__)
        self.jinja_env = Environment(loader=BaseLoader())
        self._templates = {}
        self._initialize_default_templates()
    
    def _initialize_default_templates(self) -> None:
        """
        Initialize default email templates.
        """
        # Email verification template
        self._templates[EmailType.VERIFICATION] = EmailTemplate(
            template_type=EmailType.VERIFICATION,
            subject_template="Verify your {{ app_name }} account",
            html_template=self._get_verification_html_template(),
            text_template=self._get_verification_text_template(),
            variables={
                "app_name": settings.APP_NAME,
                "app_url": settings.APP_URL,
                "support_email": settings.FROM_EMAIL
            }
        )
        
        # Password reset template
        self._templates[EmailType.PASSWORD_RESET] = EmailTemplate(
            template_type=EmailType.PASSWORD_RESET,
            subject_template="Reset your {{ app_name }} password",
            html_template=self._get_password_reset_html_template(),
            text_template=self._get_password_reset_text_template(),
            variables={
                "app_name": settings.APP_NAME,
                "app_url": settings.APP_URL,
                "support_email": settings.FROM_EMAIL
            }
        )
        
        # Welcome email template
        self._templates[EmailType.WELCOME] = EmailTemplate(
            template_type=EmailType.WELCOME,
            subject_template="Welcome to {{ app_name }}!",
            html_template=self._get_welcome_html_template(),
            text_template=self._get_welcome_text_template(),
            variables={
                "app_name": settings.APP_NAME,
                "app_url": settings.APP_URL,
                "support_email": settings.FROM_EMAIL
            }
        )
        
        # Security alert template
        self._templates[EmailType.SECURITY_ALERT] = EmailTemplate(
            template_type=EmailType.SECURITY_ALERT,
            subject_template="Security Alert - {{ app_name }}",
            html_template=self._get_security_alert_html_template(),
            text_template=self._get_security_alert_text_template(),
            variables={
                "app_name": settings.APP_NAME,
                "app_url": settings.APP_URL,
                "support_email": settings.FROM_EMAIL
            }
        )
        
        # Notification template
        self._templates[EmailType.NOTIFICATION] = EmailTemplate(
            template_type=EmailType.NOTIFICATION,
            subject_template="{{ notification_title }} - {{ app_name }}",
            html_template=self._get_notification_html_template(),
            text_template=self._get_notification_text_template(),
            variables={
                "app_name": settings.APP_NAME,
                "app_url": settings.APP_URL,
                "support_email": settings.FROM_EMAIL
            }
        )
        
        self.logger.info(f"Initialized {len(self._templates)} default email templates")
    
    async def get_template(self, template_type: EmailType) -> Optional[EmailTemplate]:
        """
        Get email template by type.
        
        Args:
            template_type: Type of email template
            
        Returns:
            Email template or None if not found
        """
        return self._templates.get(template_type)
    
    def render_template(self, template_content: str, variables: Dict[str, Any]) -> str:
        """
        Render template content with variables.
        
        Args:
            template_content: Template content string
            variables: Variables to substitute
            
        Returns:
            Rendered template content
            
        Raises:
            TemplateError: If template rendering fails
        """
        try:
            template = self.jinja_env.from_string(template_content)
            return template.render(**variables)
        except TemplateError as e:
            self.logger.error(f"Template rendering error: {str(e)}")
            raise
    
    def register_template(
        self,
        template_type: EmailType,
        template: EmailTemplate
    ) -> None:
        """
        Register a custom email template.
        
        Args:
            template_type: Type of email template
            template: Email template to register
        """
        self._templates[template_type] = template
        self.logger.info(f"Registered custom template for {template_type.value}")
    
    def _get_verification_html_template(self) -> str:
        """
        Get HTML template for email verification.
        
        Returns:
            HTML template string
        """
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Account</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #2563eb;
            margin-bottom: 10px;
        }
        .title {
            font-size: 28px;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 10px;
        }
        .subtitle {
            font-size: 16px;
            color: #6b7280;
            margin-bottom: 30px;
        }
        .button {
            display: inline-block;
            background-color: #2563eb;
            color: #ffffff;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 16px;
            margin: 20px 0;
            text-align: center;
        }
        .button:hover {
            background-color: #1d4ed8;
        }
        .alternative-link {
            background-color: #f3f4f6;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            font-size: 14px;
            color: #6b7280;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            font-size: 14px;
            color: #6b7280;
        }
        .security-note {
            background-color: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{ app_name }}</div>
            <h1 class="title">Verify Your Account</h1>
            <p class="subtitle">Hi {{ user_name }}, please verify your email address to complete your registration.</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{ verification_url }}" class="button">Verify Email Address</a>
        </div>
        
        <div class="alternative-link">
            <strong>Can't click the button?</strong><br>
            Copy and paste this link into your browser:<br>
            <a href="{{ verification_url }}">{{ verification_url }}</a>
        </div>
        
        <div class="security-note">
            <strong>Security Note:</strong> This verification link will expire in {{ expiry_hours }} hours. If you didn't create an account with {{ app_name }}, please ignore this email.
        </div>
        
        <div class="footer">
            <p>Need help? Contact us at <a href="mailto:{{ support_email }}">{{ support_email }}</a></p>
            <p>&copy; {{ current_year }} {{ app_name }}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_verification_text_template(self) -> str:
        """
        Get text template for email verification.
        
        Returns:
            Text template string
        """
        return """
Verify Your {{ app_name }} Account

Hi {{ user_name }},

Thank you for signing up with {{ app_name }}! To complete your registration, please verify your email address by clicking the link below:

{{ verification_url }}

This verification link will expire in {{ expiry_hours }} hours.

If you didn't create an account with {{ app_name }}, please ignore this email.

Need help? Contact us at {{ support_email }}

Best regards,
The {{ app_name }} Team

---
&copy; {{ current_year }} {{ app_name }}. All rights reserved.
        """
    
    def _get_password_reset_html_template(self) -> str:
        """
        Get HTML template for password reset.
        
        Returns:
            HTML template string
        """
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #dc2626;
            margin-bottom: 10px;
        }
        .title {
            font-size: 28px;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 10px;
        }
        .subtitle {
            font-size: 16px;
            color: #6b7280;
            margin-bottom: 30px;
        }
        .button {
            display: inline-block;
            background-color: #dc2626;
            color: #ffffff;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 16px;
            margin: 20px 0;
            text-align: center;
        }
        .button:hover {
            background-color: #b91c1c;
        }
        .alternative-link {
            background-color: #f3f4f6;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            font-size: 14px;
            color: #6b7280;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            font-size: 14px;
            color: #6b7280;
        }
        .security-note {
            background-color: #fef2f2;
            border-left: 4px solid #dc2626;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{ app_name }}</div>
            <h1 class="title">Reset Your Password</h1>
            <p class="subtitle">Hi {{ user_name }}, we received a request to reset your password.</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{ reset_url }}" class="button">Reset Password</a>
        </div>
        
        <div class="alternative-link">
            <strong>Can't click the button?</strong><br>
            Copy and paste this link into your browser:<br>
            <a href="{{ reset_url }}">{{ reset_url }}</a>
        </div>
        
        <div class="security-note">
            <strong>Security Note:</strong> This password reset link will expire in {{ expiry_hours }} hours. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
        </div>
        
        <div class="footer">
            <p>Need help? Contact us at <a href="mailto:{{ support_email }}">{{ support_email }}</a></p>
            <p>&copy; {{ current_year }} {{ app_name }}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_password_reset_text_template(self) -> str:
        """
        Get text template for password reset.
        
        Returns:
            Text template string
        """
        return """
Reset Your {{ app_name }} Password

Hi {{ user_name }},

We received a request to reset your password for your {{ app_name }} account. Click the link below to create a new password:

{{ reset_url }}

This password reset link will expire in {{ expiry_hours }} hours.

If you didn't request a password reset, please ignore this email and your password will remain unchanged.

Need help? Contact us at {{ support_email }}

Best regards,
The {{ app_name }} Team

---
&copy; {{ current_year }} {{ app_name }}. All rights reserved.
        """
    
    def _get_welcome_html_template(self) -> str:
        """
        Get HTML template for welcome email.
        
        Returns:
            HTML template string
        """
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to {{ app_name }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #059669;
            margin-bottom: 10px;
        }
        .title {
            font-size: 28px;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 10px;
        }
        .subtitle {
            font-size: 16px;
            color: #6b7280;
            margin-bottom: 30px;
        }
        .button {
            display: inline-block;
            background-color: #059669;
            color: #ffffff;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 16px;
            margin: 20px 0;
            text-align: center;
        }
        .button:hover {
            background-color: #047857;
        }
        .features {
            margin: 30px 0;
        }
        .feature {
            display: flex;
            align-items: center;
            margin: 15px 0;
            padding: 15px;
            background-color: #f9fafb;
            border-radius: 6px;
        }
        .feature-icon {
            width: 24px;
            height: 24px;
            background-color: #059669;
            border-radius: 50%;
            margin-right: 15px;
            flex-shrink: 0;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            font-size: 14px;
            color: #6b7280;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{ app_name }}</div>
            <h1 class="title">Welcome to {{ app_name }}!</h1>
            <p class="subtitle">Hi {{ user_name }}, thank you for joining our community. We're excited to have you on board!</p>
        </div>
        
        <div style="text-align: center;">
            <a href="{{ app_url }}/dashboard" class="button">Get Started</a>
        </div>
        
        <div class="features">
            <div class="feature">
                <div class="feature-icon"></div>
                <div>
                    <strong>URL Security Scanning</strong><br>
                    <span style="color: #6b7280;">Protect yourself from malicious links and phishing attempts</span>
                </div>
            </div>
            <div class="feature">
                <div class="feature-icon"></div>
                <div>
                    <strong>Real-time Threat Detection</strong><br>
                    <span style="color: #6b7280;">Get instant alerts about suspicious websites and content</span>
                </div>
            </div>
            <div class="feature">
                <div class="feature-icon"></div>
                <div>
                    <strong>Detailed Security Reports</strong><br>
                    <span style="color: #6b7280;">Access comprehensive analysis and recommendations</span>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Need help getting started? Contact us at <a href="mailto:{{ support_email }}">{{ support_email }}</a></p>
            <p>&copy; {{ current_year }} {{ app_name }}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_welcome_text_template(self) -> str:
        """
        Get text template for welcome email.
        
        Returns:
            Text template string
        """
        return """
Welcome to {{ app_name }}!

Hi {{ user_name }},

Thank you for joining {{ app_name }}! We're excited to have you as part of our community.

Here's what you can do with {{ app_name }}:

• URL Security Scanning - Protect yourself from malicious links and phishing attempts
• Real-time Threat Detection - Get instant alerts about suspicious websites
• Detailed Security Reports - Access comprehensive analysis and recommendations

Get started by visiting your dashboard:
{{ app_url }}/dashboard

Need help getting started? Contact us at {{ support_email }}

Welcome aboard!
The {{ app_name }} Team

---
&copy; {{ current_year }} {{ app_name }}. All rights reserved.
        """
    
    def _get_security_alert_html_template(self) -> str:
        """
        Get HTML template for security alerts.
        
        Returns:
            HTML template string
        """
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #dc2626;
            margin-bottom: 10px;
        }
        .title {
            font-size: 28px;
            font-weight: 600;
            color: #dc2626;
            margin-bottom: 10px;
        }
        .subtitle {
            font-size: 16px;
            color: #6b7280;
            margin-bottom: 30px;
        }
        .alert-box {
            background-color: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 6px;
            padding: 20px;
            margin: 20px 0;
        }
        .alert-details {
            background-color: #f9fafb;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
            font-family: monospace;
            font-size: 14px;
        }
        .button {
            display: inline-block;
            background-color: #dc2626;
            color: #ffffff;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 16px;
            margin: 20px 0;
            text-align: center;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            font-size: 14px;
            color: #6b7280;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{ app_name }}</div>
            <h1 class="title">🚨 Security Alert</h1>
            <p class="subtitle">Hi {{ user_name }}, we detected suspicious activity on your account.</p>
        </div>
        
        <div class="alert-box">
            <h3 style="color: #dc2626; margin-top: 0;">{{ alert_type }}</h3>
            <p>{{ alert_message }}</p>
        </div>
        
        <div class="alert-details">
            <strong>Details:</strong><br>
            Time: {{ alert_time }}<br>
            IP Address: {{ ip_address }}<br>
            Location: {{ location }}<br>
            Device: {{ device_info }}
        </div>
        
        <div style="text-align: center;">
            <a href="{{ security_url }}" class="button">Review Security Settings</a>
        </div>
        
        <div class="footer">
            <p><strong>If this wasn't you, please secure your account immediately.</strong></p>
            <p>Contact us at <a href="mailto:{{ support_email }}">{{ support_email }}</a></p>
            <p>&copy; {{ current_year }} {{ app_name }}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_security_alert_text_template(self) -> str:
        """
        Get text template for security alerts.
        
        Returns:
            Text template string
        """
        return """
🚨 SECURITY ALERT - {{ app_name }}

Hi {{ user_name }},

We detected suspicious activity on your {{ app_name }} account:

Alert Type: {{ alert_type }}
Message: {{ alert_message }}

Details:
- Time: {{ alert_time }}
- IP Address: {{ ip_address }}
- Location: {{ location }}
- Device: {{ device_info }}

If this wasn't you, please secure your account immediately by visiting:
{{ security_url }}

Contact us immediately if you need assistance: {{ support_email }}

Stay safe,
The {{ app_name }} Security Team

---
&copy; {{ current_year }} {{ app_name }}. All rights reserved.
        """
    
    def _get_notification_html_template(self) -> str:
        """
        Get HTML template for general notifications.
        
        Returns:
            HTML template string
        """
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ notification_title }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #6366f1;
            margin-bottom: 10px;
        }
        .title {
            font-size: 28px;
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 10px;
        }
        .content {
            margin: 30px 0;
            font-size: 16px;
            line-height: 1.6;
        }
        .button {
            display: inline-block;
            background-color: #6366f1;
            color: #ffffff;
            text-decoration: none;
            padding: 14px 28px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 16px;
            margin: 20px 0;
            text-align: center;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            font-size: 14px;
            color: #6b7280;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{ app_name }}</div>
            <h1 class="title">{{ notification_title }}</h1>
        </div>
        
        <div class="content">
            <p>Hi {{ user_name }},</p>
            <p>{{ notification_message }}</p>
            {% if action_url %}
            <div style="text-align: center;">
                <a href="{{ action_url }}" class="button">{{ action_text | default('Take Action') }}</a>
            </div>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Need help? Contact us at <a href="mailto:{{ support_email }}">{{ support_email }}</a></p>
            <p>&copy; {{ current_year }} {{ app_name }}. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_notification_text_template(self) -> str:
        """
        Get text template for general notifications.
        
        Returns:
            Text template string
        """
        return """
{{ notification_title }} - {{ app_name }}

Hi {{ user_name }},

{{ notification_message }}

{% if action_url %}
{{ action_text | default('Take Action') }}: {{ action_url }}
{% endif %}

Need help? Contact us at {{ support_email }}

Best regards,
The {{ app_name }} Team

---
&copy; {{ current_year }} {{ app_name }}. All rights reserved.
        """


# Singleton instance for dependency injection
email_template_service = EmailTemplateService()


def get_email_template_service() -> EmailTemplateService:
    """
    Dependency injection function for EmailTemplateService.
    
    Returns:
        EmailTemplateService instance
    """
    return email_template_service