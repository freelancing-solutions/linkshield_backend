#!/usr/bin/env python3
"""
LinkShield Backend Background Tasks Service

Asynchronous task processing for email operations using Celery.
Handles email sending, retries, and bulk operations in the background.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from celery import Celery
from celery.exceptions import Retry
from sqlalchemy.orm import sessionmaker

from src.config.database import engine
from src.config.settings import settings
from src.models.email import (
    EmailRequest, BulkEmailRequest, EmailLog, EmailStatus, EmailType
)
from src.services.email_service import EmailService


# Configure Celery
celery_app = Celery(
    'linkshield_email_tasks',
    broker=getattr(settings, 'CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=getattr(settings, 'CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes
    task_soft_time_limit=240,  # 4 minutes
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_disable_rate_limits=False,
    task_default_retry_delay=60,  # 1 minute
    task_max_retries=3,
    task_routes={
        'src.services.background_tasks.send_email_task': {'queue': 'email'},
        'src.services.background_tasks.send_bulk_email_task': {'queue': 'bulk_email'},
        'src.services.background_tasks.retry_failed_emails_task': {'queue': 'email_retry'},
        'src.services.background_tasks.cleanup_old_email_logs_task': {'queue': 'maintenance'},
    }
)

# Database session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Logger
logger = logging.getLogger(__name__)


class EmailTaskError(Exception):
    """Base exception for email task errors."""
    pass


@celery_app.task(bind=True, name='send_email_task')
def send_email_task(
    self,
    email_data: Dict[str, Any],
    template_name: Optional[str] = None,
    priority: int = 3
) -> Dict[str, Any]:
    """
    Celery task for sending individual emails.
    
    Args:
        self: Celery task instance
        email_data: Email request data as dictionary
        template_name: Optional template name
        priority: Task priority (1=highest, 5=lowest)
        
    Returns:
        Dict containing send result
    """
    try:
        # Create database session
        db_session = SessionLocal()
        
        try:
            # Initialize email service
            email_service = EmailService(db_session=db_session)
            
            # Convert dict to EmailRequest
            email_request = EmailRequest(**email_data)
            
            # Send email asynchronously
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(
                    email_service.send_email(email_request, template_name)
                )
                
                logger.info(
                    f"Email task completed successfully: {email_request.to}"
                )
                
                return {
                    "task_id": self.request.id,
                    "status": "success",
                    "result": result
                }
                
            finally:
                loop.close()
                
        finally:
            db_session.close()
            
    except Exception as exc:
        logger.error(f"Email task failed: {str(exc)}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            retry_delay = min(60 * (2 ** self.request.retries), 3600)  # Max 1 hour
            
            logger.info(
                f"Retrying email task in {retry_delay} seconds "
                f"(attempt {self.request.retries + 1}/{self.max_retries + 1})"
            )
            
            raise self.retry(countdown=retry_delay, exc=exc)
        
        # Max retries exceeded
        return {
            "task_id": self.request.id,
            "status": "failed",
            "error": str(exc),
            "retries": self.request.retries
        }


@celery_app.task(bind=True, name='send_bulk_email_task')
def send_bulk_email_task(
    self,
    bulk_email_data: Dict[str, Any],
    template_name: Optional[str] = None,
    batch_size: int = 50
) -> Dict[str, Any]:
    """
    Celery task for sending bulk emails.
    
    Args:
        self: Celery task instance
        bulk_email_data: Bulk email request data as dictionary
        template_name: Optional template name
        batch_size: Number of emails to process in each batch
        
    Returns:
        Dict containing bulk send results
    """
    try:
        # Create database session
        db_session = SessionLocal()
        
        try:
            # Initialize email service
            email_service = EmailService(db_session=db_session)
            
            # Convert dict to BulkEmailRequest
            bulk_request = BulkEmailRequest(**bulk_email_data)
            
            # Process in batches to avoid overwhelming the system
            total_recipients = len(bulk_request.recipients)
            processed = 0
            successful = 0
            failed = 0
            results = []
            
            # Send emails asynchronously
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                for i in range(0, total_recipients, batch_size):
                    batch_recipients = bulk_request.recipients[i:i + batch_size]
                    
                    # Create batch request
                    batch_request = BulkEmailRequest(
                        recipients=batch_recipients,
                        subject=bulk_request.subject,
                        html_content=bulk_request.html_content,
                        text_content=bulk_request.text_content,
                        from_email=bulk_request.from_email,
                        from_name=bulk_request.from_name,
                        template_variables=bulk_request.template_variables,
                        recipient_variables=bulk_request.recipient_variables,
                        email_type=bulk_request.email_type
                    )
                    
                    # Send batch
                    batch_result = loop.run_until_complete(
                        email_service.send_bulk_email(batch_request, template_name)
                    )
                    
                    # Update counters
                    successful += batch_result["successful_sends"]
                    failed += batch_result["failed_sends"]
                    results.extend(batch_result["results"])
                    processed += len(batch_recipients)
                    
                    # Update task progress
                    progress = int((processed / total_recipients) * 100)
                    self.update_state(
                        state='PROGRESS',
                        meta={
                            'current': processed,
                            'total': total_recipients,
                            'progress': progress,
                            'successful': successful,
                            'failed': failed
                        }
                    )
                    
                    # Small delay between batches
                    # await asyncio.sleep(1)
                
                logger.info(
                    f"Bulk email task completed: {successful} successful, {failed} failed"
                )
                
                return {
                    "task_id": self.request.id,
                    "status": "success",
                    "total_recipients": total_recipients,
                    "successful_sends": successful,
                    "failed_sends": failed,
                    "success_rate": (successful / total_recipients * 100) if total_recipients > 0 else 0,
                    "results": results
                }
                
            finally:
                loop.close()
                
        finally:
            db_session.close()
            
    except Exception as exc:
        logger.error(f"Bulk email task failed: {str(exc)}")
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            retry_delay = min(300 * (2 ** self.request.retries), 3600)  # Max 1 hour
            
            logger.info(
                f"Retrying bulk email task in {retry_delay} seconds "
                f"(attempt {self.request.retries + 1}/{self.max_retries + 1})"
            )
            
            raise self.retry(countdown=retry_delay, exc=exc)
        
        # Max retries exceeded
        return {
            "task_id": self.request.id,
            "status": "failed",
            "error": str(exc),
            "retries": self.request.retries
        }


@celery_app.task(bind=True, name='send_verification_email_task')
def send_verification_email_task(
    self,
    user_email: str,
    user_name: str,
    verification_token: str,
    expiry_hours: int = 24
) -> Dict[str, Any]:
    """
    Celery task for sending email verification emails.
    
    Args:
        self: Celery task instance
        user_email: User's email address
        user_name: User's name
        verification_token: Verification token
        expiry_hours: Token expiry in hours
        
    Returns:
        Dict containing send result
    """
    try:
        # Prepare email data
        verification_url = f"{settings.APP_URL}/verify-email?token={verification_token}"
        
        email_data = {
            "to": user_email,
            "subject": f"Verify your {settings.APP_NAME} account",
            "email_type": EmailType.VERIFICATION.value,
            "template_variables": {
                "user_name": user_name,
                "verification_url": verification_url,
                "expiry_hours": expiry_hours,
                "current_year": datetime.now().year
            }
        }
        
        # Send using the main email task
        return send_email_task.apply(
            args=[email_data, EmailType.VERIFICATION.value],
            priority=1  # High priority for verification emails
        ).get()
        
    except Exception as exc:
        logger.error(f"Verification email task failed: {str(exc)}")
        raise


@celery_app.task(bind=True, name='send_password_reset_email_task')
def send_password_reset_email_task(
    self,
    user_email: str,
    user_name: str,
    reset_token: str,
    expiry_hours: int = 1
) -> Dict[str, Any]:
    """
    Celery task for sending password reset emails.
    
    Args:
        self: Celery task instance
        user_email: User's email address
        user_name: User's name
        reset_token: Password reset token
        expiry_hours: Token expiry in hours
        
    Returns:
        Dict containing send result
    """
    try:
        # Prepare email data
        reset_url = f"{settings.APP_URL}/reset-password?token={reset_token}"
        
        email_data = {
            "to": user_email,
            "subject": f"Reset your {settings.APP_NAME} password",
            "email_type": EmailType.PASSWORD_RESET.value,
            "template_variables": {
                "user_name": user_name,
                "reset_url": reset_url,
                "expiry_hours": expiry_hours,
                "current_year": datetime.now().year
            }
        }
        
        # Send using the main email task
        return send_email_task.apply(
            args=[email_data, EmailType.PASSWORD_RESET.value],
            priority=1  # High priority for password reset emails
        ).get()
        
    except Exception as exc:
        logger.error(f"Password reset email task failed: {str(exc)}")
        raise


@celery_app.task(bind=True, name='send_welcome_email_task')
def send_welcome_email_task(
    self,
    user_email: str,
    user_name: str
) -> Dict[str, Any]:
    """
    Celery task for sending welcome emails.
    
    Args:
        self: Celery task instance
        user_email: User's email address
        user_name: User's name
        
    Returns:
        Dict containing send result
    """
    try:
        # Prepare email data
        email_data = {
            "to": user_email,
            "subject": f"Welcome to {settings.APP_NAME}!",
            "email_type": EmailType.WELCOME.value,
            "template_variables": {
                "user_name": user_name,
                "current_year": datetime.now().year
            }
        }
        
        # Send using the main email task
        return send_email_task.apply(
            args=[email_data, EmailType.WELCOME.value],
            priority=3  # Normal priority for welcome emails
        ).get()
        
    except Exception as exc:
        logger.error(f"Welcome email task failed: {str(exc)}")
        raise


@celery_app.task(bind=True, name='retry_failed_emails_task')
def retry_failed_emails_task(
    self,
    max_retries: int = 3,
    batch_size: int = 10
) -> Dict[str, Any]:
    """
    Celery task for retrying failed email sends.
    
    Args:
        self: Celery task instance
        max_retries: Maximum number of retry attempts
        batch_size: Number of emails to process in each batch
        
    Returns:
        Dict containing retry results
    """
    try:
        # Create database session
        db_session = SessionLocal()
        
        try:
            # Initialize email service
            email_service = EmailService(db_session=db_session)
            
            # Retry failed emails asynchronously
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(
                    email_service.retry_failed_emails(max_retries, batch_size)
                )
                
                logger.info(
                    f"Email retry task completed: {result['successful_retries']} successful, "
                    f"{result['failed_retries']} failed"
                )
                
                return {
                    "task_id": self.request.id,
                    "status": "success",
                    "result": result
                }
                
            finally:
                loop.close()
                
        finally:
            db_session.close()
            
    except Exception as exc:
        logger.error(f"Email retry task failed: {str(exc)}")
        
        return {
            "task_id": self.request.id,
            "status": "failed",
            "error": str(exc)
        }


@celery_app.task(name='cleanup_old_email_logs_task')
def cleanup_old_email_logs_task(days_to_keep: int = 90) -> Dict[str, Any]:
    """
    Celery task for cleaning up old email logs.
    
    Args:
        days_to_keep: Number of days to keep email logs
        
    Returns:
        Dict containing cleanup results
    """
    try:
        # Create database session
        db_session = SessionLocal()
        
        try:
            # Calculate cutoff date
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            # Delete old logs
            deleted_count = db_session.query(EmailLog).filter(
                EmailLog.created_at < cutoff_date
            ).delete()
            
            db_session.commit()
            
            logger.info(f"Cleaned up {deleted_count} old email logs")
            
            return {
                "status": "success",
                "deleted_count": deleted_count,
                "cutoff_date": cutoff_date.isoformat()
            }
            
        finally:
            db_session.close()
            
    except Exception as exc:
        logger.error(f"Email log cleanup task failed: {str(exc)}")
        
        return {
            "status": "failed",
            "error": str(exc)
        }


# Periodic tasks configuration
from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    'retry-failed-emails': {
        'task': 'src.services.background_tasks.retry_failed_emails_task',
        'schedule': crontab(minute='*/30'),  # Every 30 minutes
        'args': (3, 20)  # max_retries=3, batch_size=20
    },
    'cleanup-old-email-logs': {
        'task': 'src.services.background_tasks.cleanup_old_email_logs_task',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
        'args': (90,)  # Keep logs for 90 days
    },
}


class BackgroundEmailService:
    """
    Service for managing background email tasks.
    
    Provides high-level interface for queuing email tasks.
    """
    
    def __init__(self):
        """
        Initialize the background email service.
        """
        self.logger = logging.getLogger(__name__)
    
    def queue_email(
        self,
        email_request: EmailRequest,
        template_name: Optional[str] = None,
        priority: int = 3,
        delay: Optional[int] = None
    ) -> str:
        """
        Queue an email for background sending.
        
        Args:
            email_request: Email request data
            template_name: Optional template name
            priority: Task priority (1=highest, 5=lowest)
            delay: Optional delay in seconds
            
        Returns:
            Task ID
        """
        email_data = email_request.dict()
        
        task_kwargs = {
            'args': [email_data, template_name, priority],
            'priority': priority
        }
        
        if delay:
            task_kwargs['countdown'] = delay
        
        task = send_email_task.apply_async(**task_kwargs)
        
        self.logger.info(f"Queued email task {task.id} for {email_request.to}")
        
        return task.id
    
    def queue_bulk_email(
        self,
        bulk_request: BulkEmailRequest,
        template_name: Optional[str] = None,
        batch_size: int = 50,
        delay: Optional[int] = None
    ) -> str:
        """
        Queue a bulk email for background sending.
        
        Args:
            bulk_request: Bulk email request data
            template_name: Optional template name
            batch_size: Number of emails per batch
            delay: Optional delay in seconds
            
        Returns:
            Task ID
        """
        bulk_data = bulk_request.dict()
        
        task_kwargs = {
            'args': [bulk_data, template_name, batch_size],
            'priority': 4  # Lower priority for bulk emails
        }
        
        if delay:
            task_kwargs['countdown'] = delay
        
        task = send_bulk_email_task.apply_async(**task_kwargs)
        
        self.logger.info(
            f"Queued bulk email task {task.id} for {len(bulk_request.recipients)} recipients"
        )
        
        return task.id
    
    def queue_verification_email(
        self,
        user_email: str,
        user_name: str,
        verification_token: str,
        expiry_hours: int = 24
    ) -> str:
        """
        Queue a verification email.
        
        Args:
            user_email: User's email address
            user_name: User's name
            verification_token: Verification token
            expiry_hours: Token expiry in hours
            
        Returns:
            Task ID
        """
        task = send_verification_email_task.apply_async(
            args=[user_email, user_name, verification_token, expiry_hours],
            priority=1  # High priority
        )
        
        self.logger.info(f"Queued verification email task {task.id} for {user_email}")
        
        return task.id
    
    def queue_password_reset_email(
        self,
        user_email: str,
        user_name: str,
        reset_token: str,
        expiry_hours: int = 1
    ) -> str:
        """
        Queue a password reset email.
        
        Args:
            user_email: User's email address
            user_name: User's name
            reset_token: Password reset token
            expiry_hours: Token expiry in hours
            
        Returns:
            Task ID
        """
        task = send_password_reset_email_task.apply_async(
            args=[user_email, user_name, reset_token, expiry_hours],
            priority=1  # High priority
        )
        
        self.logger.info(f"Queued password reset email task {task.id} for {user_email}")
        
        return task.id
    
    def queue_welcome_email(
        self,
        user_email: str,
        user_name: str,
        delay: int = 300  # 5 minutes delay
    ) -> str:
        """
        Queue a welcome email.
        
        Args:
            user_email: User's email address
            user_name: User's name
            delay: Delay in seconds before sending
            
        Returns:
            Task ID
        """
        task = send_welcome_email_task.apply_async(
            args=[user_email, user_name],
            countdown=delay,
            priority=3  # Normal priority
        )
        
        self.logger.info(f"Queued welcome email task {task.id} for {user_email}")
        
        return task.id
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get the status of a background task.
        
        Args:
            task_id: Task ID
            
        Returns:
            Dict containing task status and result
        """
        task = celery_app.AsyncResult(task_id)
        
        return {
            "task_id": task_id,
            "status": task.status,
            "result": task.result,
            "info": task.info
        }
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a background task.
        
        Args:
            task_id: Task ID
            
        Returns:
            True if task was cancelled successfully
        """
        try:
            celery_app.control.revoke(task_id, terminate=True)
            self.logger.info(f"Cancelled task {task_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to cancel task {task_id}: {str(e)}")
            return False


# Singleton instance for dependency injection
background_email_service = BackgroundEmailService()


def get_background_email_service() -> BackgroundEmailService:
    """
    Dependency injection function for BackgroundEmailService.
    
    Returns:
        BackgroundEmailService instance
    """
    return background_email_service