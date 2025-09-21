#!/usr/bin/env python3
"""
LinkShield Backend Background Tasks Service

Pure task queuing service for background email processing.
Database operations are handled by controllers.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable
from enum import Enum
import logging

from src.config.settings import get_settings

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task status enumeration."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


class TaskPriority(Enum):
    """Task priority enumeration."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    URGENT = 4


class BackgroundTask:
    """
    Represents a background task.
    """
    
    def __init__(
        self,
        task_id: str,
        task_type: str,
        payload: Dict[str, Any],
        priority: TaskPriority = TaskPriority.MEDIUM,
        max_retries: int = 3,
        retry_delay: int = 60
    ):
        self.task_id = task_id
        self.task_type = task_type
        self.payload = payload
        self.priority = priority
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.status = TaskStatus.PENDING
        self.created_at = datetime.now(timezone.utc)
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.retry_count = 0
        self.error_message: Optional[str] = None
        self.result: Optional[Dict[str, Any]] = None


class BackgroundEmailService:
    """
    Pure task queuing service for background email processing.
    Database operations are handled by controllers.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.task_queue: List[BackgroundTask] = []
        self.task_handlers: Dict[str, Callable] = {}
        self.is_running = False
        self._worker_task: Optional[asyncio.Task] = None
        
        # Register default email handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self) -> None:
        """Register default task handlers."""
        self.task_handlers.update({
            "send_welcome_email": self._handle_welcome_email,
            "send_password_reset_email": self._handle_password_reset_email,
            "send_security_alert_email": self._handle_security_alert_email,
            "send_analysis_report_email": self._handle_analysis_report_email,
            "send_bulk_notification": self._handle_bulk_notification
        })
    
    async def start_worker(self) -> None:
        """Start the background task worker."""
        if self.is_running:
            logger.warning("Background worker is already running")
            return
        
        self.is_running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info("Background email service worker started")
    
    async def stop_worker(self) -> None:
        """Stop the background task worker."""
        if not self.is_running:
            return
        
        self.is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Background email service worker stopped")
    
    async def _worker_loop(self) -> None:
        """Main worker loop for processing tasks."""
        while self.is_running:
            try:
                # Get next task to process
                task = self._get_next_task()
                if task:
                    await self._process_task(task)
                else:
                    # No tasks available, wait before checking again
                    await asyncio.sleep(1)
            
            except Exception as e:
                logger.error(f"Error in worker loop: {str(e)}")
                await asyncio.sleep(5)  # Wait before retrying
    
    def _get_next_task(self) -> Optional[BackgroundTask]:
        """Get the next task to process based on priority."""
        # Filter pending tasks
        pending_tasks = [
            task for task in self.task_queue 
            if task.status == TaskStatus.PENDING
        ]
        
        if not pending_tasks:
            return None
        
        # Sort by priority (highest first) and creation time
        pending_tasks.sort(
            key=lambda t: (t.priority.value, t.created_at),
            reverse=True
        )
        
        return pending_tasks[0]
    
    async def _process_task(self, task: BackgroundTask) -> None:
        """Process a single task."""
        task.status = TaskStatus.PROCESSING
        task.started_at = datetime.now(timezone.utc)
        
        try:
            # Get handler for task type
            handler = self.task_handlers.get(task.task_type)
            if not handler:
                raise ValueError(f"No handler found for task type: {task.task_type}")
            
            # Execute handler
            result = await handler(task.payload)
            
            # Mark as completed
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(timezone.utc)
            task.result = result
            
            logger.info(f"Task {task.task_id} completed successfully")
        
        except Exception as e:
            # Handle task failure
            task.error_message = str(e)
            task.retry_count += 1
            
            if task.retry_count < task.max_retries:
                task.status = TaskStatus.RETRYING
                # Schedule retry (simplified - in production use proper scheduling)
                await asyncio.sleep(task.retry_delay)
                task.status = TaskStatus.PENDING
                logger.warning(f"Task {task.task_id} failed, retrying ({task.retry_count}/{task.max_retries})")
            else:
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.now(timezone.utc)
                logger.error(f"Task {task.task_id} failed permanently: {str(e)}")
    
    def queue_task(
        self,
        task_type: str,
        payload: Dict[str, Any],
        priority: TaskPriority = TaskPriority.MEDIUM,
        max_retries: int = 3,
        retry_delay: int = 60
    ) -> str:
        """
        Queue a new background task.
        
        Args:
            task_type: Type of task to execute
            payload: Task payload data
            priority: Task priority
            max_retries: Maximum retry attempts
            retry_delay: Delay between retries in seconds
            
        Returns:
            Task ID
        """
        task_id = f"{task_type}_{datetime.now(timezone.utc).timestamp()}"
        
        task = BackgroundTask(
            task_id=task_id,
            task_type=task_type,
            payload=payload,
            priority=priority,
            max_retries=max_retries,
            retry_delay=retry_delay
        )
        
        self.task_queue.append(task)
        logger.info(f"Queued task {task_id} of type {task_type}")
        
        return task_id
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task."""
        task = next((t for t in self.task_queue if t.task_id == task_id), None)
        if not task:
            return None
        
        return {
            "task_id": task.task_id,
            "task_type": task.task_type,
            "status": task.status.value,
            "priority": task.priority.value,
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "retry_count": task.retry_count,
            "max_retries": task.max_retries,
            "error_message": task.error_message,
            "result": task.result
        }
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        total_tasks = len(self.task_queue)
        status_counts = {}
        
        for status in TaskStatus:
            status_counts[status.value] = sum(
                1 for task in self.task_queue 
                if task.status == status
            )
        
        return {
            "total_tasks": total_tasks,
            "status_counts": status_counts,
            "is_worker_running": self.is_running
        }
    
    def cleanup_completed_tasks(self, max_age_hours: int = 24) -> int:
        """
        Clean up old completed/failed tasks.
        
        Args:
            max_age_hours: Maximum age in hours for completed tasks
            
        Returns:
            Number of tasks cleaned up
        """
        cutoff_time = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)
        
        initial_count = len(self.task_queue)
        
        self.task_queue = [
            task for task in self.task_queue
            if not (
                task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED] and
                task.completed_at and
                task.completed_at.timestamp() < cutoff_time
            )
        ]
        
        cleaned_count = initial_count - len(self.task_queue)
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} old tasks")
        
        return cleaned_count
    
    # Email handler methods
    async def _handle_welcome_email(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle welcome email task."""
        user_email = payload.get("user_email")
        user_name = payload.get("user_name", "User")
        
        # Simulate email sending (in production, use actual email service)
        await asyncio.sleep(0.1)  # Simulate processing time
        
        return {
            "email_sent": True,
            "recipient": user_email,
            "template": "welcome",
            "sent_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _handle_password_reset_email(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle password reset email task."""
        user_email = payload.get("user_email")
        reset_token = payload.get("reset_token")
        
        # Simulate email sending
        await asyncio.sleep(0.1)
        
        return {
            "email_sent": True,
            "recipient": user_email,
            "template": "password_reset",
            "sent_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _handle_security_alert_email(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle security alert email task."""
        user_email = payload.get("user_email")
        alert_type = payload.get("alert_type")
        alert_details = payload.get("alert_details", {})
        
        # Simulate email sending
        await asyncio.sleep(0.1)
        
        return {
            "email_sent": True,
            "recipient": user_email,
            "template": "security_alert",
            "alert_type": alert_type,
            "sent_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _handle_analysis_report_email(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle analysis report email task."""
        user_email = payload.get("user_email")
        report_data = payload.get("report_data", {})
        
        # Simulate email sending
        await asyncio.sleep(0.2)  # Reports might take longer
        
        return {
            "email_sent": True,
            "recipient": user_email,
            "template": "analysis_report",
            "report_id": report_data.get("report_id"),
            "sent_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _handle_bulk_notification(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle bulk notification email task."""
        recipients = payload.get("recipients", [])
        message_template = payload.get("template")
        
        # Simulate bulk email sending
        await asyncio.sleep(len(recipients) * 0.05)  # Scale with recipient count
        
        return {
            "emails_sent": len(recipients),
            "template": message_template,
            "sent_at": datetime.now(timezone.utc).isoformat()
        }


# Global service instance
background_email_service = BackgroundEmailService()