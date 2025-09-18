I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

I analyzed the LinkShield backend project and found it's a well-structured FastAPI application with existing email infrastructure partially in place. The project already has SMTP email settings configured in `src/config/settings.py`, email-related models (User with email verification, password reset tokens), and imports for an `EmailService` in `src/authentication/auth_service.py` that doesn't exist yet. The project uses Pydantic settings, has a services directory structure, and includes email validation. This is perfect for implementing Resend API integration to replace the current SMTP configuration.

### Approach

I'll implement a comprehensive email service using the Resend API that integrates seamlessly with the existing codebase. The approach will:

1. **Add Resend dependency** to requirements.txt
2. **Update configuration** to include Resend API settings while maintaining backward compatibility with SMTP
3. **Create EmailService class** in the services directory with methods for all email types (verification, password reset, notifications)
4. **Implement email templates** as a separate module for maintainability
5. **Add background task support** for async email sending using Celery
6. **Update authentication service** to use the new email service
7. **Create email models** for type safety and validation

This maintains the existing architecture while providing a robust, scalable email solution.

### Reasoning

I started by exploring the project structure to understand the codebase organization. I examined the requirements.txt to see current dependencies and found FastAPI, Celery, and email-validator already installed. I then reviewed the settings configuration and discovered existing SMTP email settings. Using grep search, I found multiple references to email functionality throughout the codebase, including imports for a non-existent EmailService. I also checked the services directory structure and confirmed the need to implement the missing email service that's already being imported by the authentication service.

## Mermaid Diagram

sequenceDiagram
    participant User as User/Client
    participant Route as User Routes
    participant Controller as User Controller
    participant EmailService as Email Service
    participant Templates as Email Templates
    participant Resend as Resend API
    participant BgTask as Background Tasks

    User->>Route: POST /register
    Route->>Controller: register_user()
    Controller->>EmailService: send_verification_email()
    EmailService->>Templates: get_verification_email_template()
    Templates-->>EmailService: HTML & Text content
    EmailService->>BgTask: send_email_task.delay()
    BgTask->>Resend: Send email via API
    Resend-->>BgTask: Email sent confirmation
    BgTask-->>EmailService: Task completion
    EmailService-->>Controller: Email queued
    Controller-->>Route: User created
    Route-->>User: Registration successful

    User->>Route: POST /forgot-password
    Route->>Controller: request_password_reset()
    Controller->>EmailService: send_password_reset_email()
    EmailService->>Templates: get_password_reset_template()
    Templates-->>EmailService: HTML & Text content
    EmailService->>BgTask: send_email_task.delay()
    BgTask->>Resend: Send reset email
    Resend-->>BgTask: Email sent
    BgTask-->>EmailService: Success
    EmailService-->>Controller: Reset email sent
    Controller-->>Route: Reset initiated
    Route-->>User: Check your email

## Proposed File Changes

### requirements.txt(MODIFY)

Add the Resend Python SDK to the dependencies. Insert `resend` after the existing email-validator dependency in the Utilities section (around line 41) to keep related dependencies grouped together. This will enable the application to use Resend API for email services.

### src\config\settings.py(MODIFY)

Add Resend API configuration settings to the existing Email Settings section (after line 110). Add the following fields:

- `RESEND_API_KEY`: Optional string field for Resend API key with environment variable `LINKSHIELD_RESEND_API_KEY`
- `EMAIL_PROVIDER`: String field with default "smtp" and options ["smtp", "resend"] to allow switching between providers
- `RESEND_FROM_DOMAIN`: Optional string field for verified Resend domain

This maintains backward compatibility with existing SMTP settings while enabling Resend integration. The configuration follows the existing pattern used in `src/config/settings.py` for other API keys and settings.

### src\services\email_service.py(NEW)

References: 

- src\config\settings.py(MODIFY)
- src\services\security_service.py

Create a comprehensive EmailService class that provides email functionality using either Resend API or SMTP based on configuration. The service should include:

**Class Structure:**
- `EmailService` class with dependency injection for settings and database session
- Support for both Resend and SMTP providers based on `EMAIL_PROVIDER` setting
- Async methods for all email operations

**Core Methods:**
- `send_email()`: Generic email sending method
- `send_verification_email()`: User email verification with token
- `send_password_reset_email()`: Password reset with secure token
- `send_welcome_email()`: Welcome message for new users
- `send_notification_email()`: General notifications
- `send_security_alert()`: Security-related alerts

**Features:**
- Template-based email content using the email templates from `src/services/email_templates.py`
- Error handling and retry logic
- Logging for email operations
- Rate limiting protection
- Support for HTML and text content
- Attachment support for Resend

**Integration:**
- Use settings from `src/config/settings.py` for configuration
- Follow the same patterns as other services in the services directory like `src/services/security_service.py`
- Include proper exception handling and logging similar to existing services

### src\services\email_templates.py(NEW)

References: 

- src\services\email_service.py(NEW)

Create an email templates module that provides HTML and text templates for all email types. The module should include:

**Template Functions:**
- `get_verification_email_template()`: Email verification template with token link
- `get_password_reset_template()`: Password reset template with secure reset link
- `get_welcome_email_template()`: Welcome email for new users
- `get_security_alert_template()`: Security alert notifications
- `get_notification_template()`: General notification template

**Features:**
- HTML and plain text versions for each template
- Dynamic content injection using template variables
- Responsive HTML design
- LinkShield branding and styling
- Support for custom variables (user name, company, links, etc.)
- Template validation and error handling

**Template Structure:**
- Each template function returns a dictionary with 'html' and 'text' keys
- Templates include proper email headers and footers
- Unsubscribe links where appropriate
- Security best practices for email content

This module will be used by `src/services/email_service.py` to generate email content, keeping templates separate from business logic for better maintainability.

### src\models\email.py(NEW)

References: 

- src\models\user.py
- src\models\report.py

Create email-related Pydantic models for type safety and validation. The module should include:

**Models:**
- `EmailRequest`: Base model for email sending requests with fields for recipient, subject, content
- `EmailTemplate`: Model for email template data with template_type, variables, and metadata
- `EmailLog`: Model for email logging and tracking with status, timestamps, and error details
- `EmailAttachment`: Model for email attachments with file data, name, and content type
- `BulkEmailRequest`: Model for sending emails to multiple recipients

**Enums:**
- `EmailProvider`: Enum for email providers (SMTP, RESEND)
- `EmailType`: Enum for email types (VERIFICATION, PASSWORD_RESET, WELCOME, NOTIFICATION, SECURITY_ALERT)
- `EmailStatus`: Enum for email status (PENDING, SENT, FAILED, BOUNCED)

**Features:**
- Proper validation using Pydantic validators
- Email address validation using EmailStr
- File size limits for attachments
- Template variable validation
- Integration with existing models in the models directory

This follows the same patterns as other model files like `src/models/user.py` and `src/models/report.py` for consistency.

### src\services\background_tasks.py(NEW)

References: 

- src\config\settings.py(MODIFY)
- src\services\email_service.py(NEW)

Create a background tasks module for handling asynchronous email operations using Celery. The module should include:

**Celery Tasks:**
- `send_email_task()`: Background task for sending individual emails
- `send_bulk_emails_task()`: Background task for sending multiple emails
- `process_email_queue_task()`: Task for processing email queues
- `cleanup_email_logs_task()`: Periodic task for cleaning up old email logs

**Features:**
- Integration with existing Celery configuration from `src/config/settings.py`
- Retry logic for failed email sends
- Error handling and logging
- Task status tracking
- Rate limiting to respect email provider limits
- Dead letter queue for failed emails

**Integration:**
- Use the EmailService from `src/services/email_service.py` for actual email sending
- Follow Celery best practices for task definition
- Include proper error handling and monitoring
- Support for scheduled email sending

This module will be used by controllers and services to send emails asynchronously without blocking the main application thread.

### src\authentication\auth_service.py(MODIFY)

References: 

- src\services\email_service.py(NEW)

Update the existing import statement on line 27 to properly import the EmailService class that will now exist. The import `from src.services.email_service import EmailService` should work correctly once the new email service is implemented.

Additionally, review the EmailService usage in the `__init__` method (line 71-73) and any other methods that call email service functions to ensure they use the new EmailService API methods like `send_verification_email()` and `send_password_reset_email()`.

The existing dependency injection pattern should work seamlessly with the new EmailService implementation.

### src\controllers\user_controller.py(MODIFY)

References: 

- src\services\email_service.py(NEW)
- src\authentication\auth_service.py(MODIFY)

Update the user controller to properly integrate with the new EmailService. The controller already has email verification logic (around line 137) that needs to be connected to the new email service.

**Updates needed:**
- Import the EmailService from `src/services.email_service`
- Add EmailService to the controller's dependency injection
- Update email verification token creation to use the new `send_verification_email()` method
- Update password reset functionality to use `send_password_reset_email()` method
- Add proper error handling for email sending failures
- Ensure background task integration for async email sending

The controller should maintain its existing API interface while using the new email service backend. Follow the same dependency injection pattern used for other services in the controller.

### src\routes\user.py(MODIFY)

References: 

- src\controllers\user_controller.py(MODIFY)
- src\services\email_service.py(NEW)

Update the user routes to include proper email-related endpoints and integrate with the new email service functionality. The routes file already has email-related models and endpoints that need to be connected to the email service.

**Updates needed:**
- Add endpoint for resending verification emails
- Add endpoint for email preference management
- Update existing registration and password reset endpoints to use background email tasks
- Add proper response models for email operations
- Include rate limiting for email-related endpoints
- Add email status checking endpoints

**Integration points:**
- Use the updated UserController from `src/controllers/user_controller.py` that now includes EmailService
- Ensure proper error handling for email failures
- Add appropriate HTTP status codes for email operations
- Include email validation and sanitization

The routes should maintain backward compatibility while adding new email management capabilities.

### .env.example(MODIFY)

References: 

- src\config\settings.py(MODIFY)

Add the new Resend API configuration variables to the environment example file. Add the following variables in the Email Settings section:

```
# Email Provider Configuration
LINKSHIELD_EMAIL_PROVIDER=resend
LINKSHIELD_RESEND_API_KEY=re_your_resend_api_key_here
LINKSHIELD_RESEND_FROM_DOMAIN=yourdomain.com
```

Include comments explaining:
- How to get a Resend API key
- Domain verification requirements
- Fallback to SMTP if Resend is not configured
- Security best practices for API key management

This provides clear guidance for developers setting up the email service in their environment.