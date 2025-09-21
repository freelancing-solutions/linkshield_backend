#!/usr/bin/env python3
"""
LinkShield Backend Task Tracking Service

Service for tracking and managing FastAPI BackgroundTasks in the database.
Provides comprehensive CRUD operations, status monitoring, and task lifecycle management.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Callable, Union
from uuid import uuid4, UUID

from fastapi import BackgroundTasks as FastAPIBackgroundTasks
from sqlalchemy import and_, or_, desc, asc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority, TaskLog, TaskDependency
from src.services.webhook_service import get_webhook_service, WebhookPayload, WebhookEventType
from src.database.connection import get_async_session

logger = logging.getLogger(__name__)


class TaskTrackingService:
    """
    Service for tracking and managing FastAPI BackgroundTasks.
    
    Features:
    - Task creation and lifecycle management
    - Status monitoring and progress tracking
    - Webhook notifications for task completion
    - Task dependency management
    - Retry logic and error handling
    - Comprehensive logging and audit trail
    """
    
    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.db_session = db_session
        self._webhook_service = None
    
    async def _get_session(self) -> AsyncSession:
        """Get database session."""
        if self.db_session:
            return self.db_session
        return await get_async_session()
    
    async def _get_webhook_service(self):
        """Get webhook service instance."""
        if self._webhook_service is None:
            self._webhook_service = await get_webhook_service()
        return self._webhook_service
    
    async def create_task(
        self,
        task_type: Union[TaskType, str],
        task_name: str,
        input_data: Optional[Dict[str, Any]] = None,
        user_id: Optional[UUID] = None,
        priority: Union[TaskPriority, str] = TaskPriority.NORMAL,
        estimated_duration_seconds: Optional[int] = None,
        max_retries: int = 3,
        retry_delay_seconds: int = 60,
        webhook_url: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        correlation_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> BackgroundTask:
        """
        Create a new background task record.
        
        Args:
            task_type: Type of task to create
            task_name: Human-readable task name
            input_data: Task input parameters
            user_id: User who initiated the task
            priority: Task priority level
            estimated_duration_seconds: Estimated execution time
            max_retries: Maximum retry attempts
            retry_delay_seconds: Delay between retries
            webhook_url: Webhook URL for completion notification
            webhook_secret: Secret for webhook authentication
            metadata: Additional task metadata
            tags: Task tags for categorization
            correlation_id: Correlation ID for request tracing
            session_id: Session identifier
            
        Returns:
            BackgroundTask: Created task record
        """
        session = await self._get_session()
        
        # Generate unique task ID
        task_id = str(uuid4())
        
        # Create task record
        task = BackgroundTask(
            task_id=task_id,
            task_type=str(task_type),
            task_name=task_name,
            priority=str(priority),
            status=TaskStatus.PENDING,
            input_data=input_data or {},
            user_id=user_id,
            estimated_duration_seconds=estimated_duration_seconds,
            max_retries=max_retries,
            retry_delay_seconds=retry_delay_seconds,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            metadata=metadata or {},
            tags=tags,
            correlation_id=correlation_id,
            session_id=session_id
        )
        
        session.add(task)
        await session.commit()
        await session.refresh(task)
        
        logger.info(f"Created background task {task_id} of type {task_type}")
        await self._log_task_event(task.id, "INFO", f"Task created: {task_name}")
        
        return task
    
    async def get_task(self, task_id: str) -> Optional[BackgroundTask]:
        """
        Get task by ID.
        
        Args:
            task_id: Task identifier
            
        Returns:
            BackgroundTask: Task record or None if not found
        """
        session = await self._get_session()
        
        result = await session.execute(
            session.query(BackgroundTask)
            .filter(BackgroundTask.task_id == task_id)
            .options(selectinload(BackgroundTask.logs))
        )
        
        return result.scalar_one_or_none()
    
    async def get_task_by_uuid(self, task_uuid: UUID) -> Optional[BackgroundTask]:
        """
        Get task by UUID.
        
        Args:
            task_uuid: Task UUID
            
        Returns:
            BackgroundTask: Task record or None if not found
        """
        session = await self._get_session()
        
        result = await session.execute(
            session.query(BackgroundTask)
            .filter(BackgroundTask.id == task_uuid)
            .options(selectinload(BackgroundTask.logs))
        )
        
        return result.scalar_one_or_none()
    
    async def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        progress_percentage: Optional[int] = None,
        result_data: Optional[Dict[str, Any]] = None,
        error_details: Optional[str] = None,
        worker_id: Optional[str] = None
    ) -> Optional[BackgroundTask]:
        """
        Update task status and related fields.
        
        Args:
            task_id: Task identifier
            status: New task status
            progress_percentage: Task progress (0-100)
            result_data: Task results
            error_details: Error information
            worker_id: Worker identifier
            
        Returns:
            BackgroundTask: Updated task record
        """
        session = await self._get_session()
        task = await self.get_task(task_id)
        
        if not task:
            logger.warning(f"Task {task_id} not found for status update")
            return None
        
        # Update status-specific fields
        old_status = task.status
        task.status = status
        
        if progress_percentage is not None:
            task.progress_percentage = max(0, min(100, progress_percentage))
        
        if worker_id:
            task.worker_id = worker_id
        
        # Handle status transitions
        if status == TaskStatus.RUNNING and old_status != TaskStatus.RUNNING:
            task.mark_started(worker_id)
            await self._log_task_event(task.id, "INFO", f"Task started by worker {worker_id}")
            
        elif status == TaskStatus.COMPLETED:
            task.mark_completed(result_data)
            await self._log_task_event(task.id, "INFO", "Task completed successfully")
            await self._send_completion_webhook(task)
            
        elif status == TaskStatus.FAILED:
            task.mark_failed(error_details or "Task failed", error_details)
            await self._log_task_event(task.id, "ERROR", f"Task failed: {error_details}")
            await self._send_failure_webhook(task)
            
        elif status == TaskStatus.CANCELLED:
            task.mark_cancelled(error_details)
            await self._log_task_event(task.id, "WARNING", f"Task cancelled: {error_details}")
            
        elif status == TaskStatus.RETRYING:
            task.increment_retry()
            await self._log_task_event(task.id, "WARNING", f"Task retry attempt {task.retry_count}")
        
        await session.commit()
        await session.refresh(task)
        
        logger.info(f"Updated task {task_id} status from {old_status} to {status}")
        return task
    
    async def update_task_progress(
        self,
        task_id: str,
        progress_percentage: int,
        message: Optional[str] = None
    ) -> Optional[BackgroundTask]:
        """
        Update task progress.
        
        Args:
            task_id: Task identifier
            progress_percentage: Progress percentage (0-100)
            message: Optional progress message
            
        Returns:
            BackgroundTask: Updated task record
        """
        session = await self._get_session()
        task = await self.get_task(task_id)
        
        if not task:
            return None
        
        task.update_progress(progress_percentage, message)
        await session.commit()
        await session.refresh(task)
        
        if message:
            await self._log_task_event(task.id, "INFO", f"Progress {progress_percentage}%: {message}")
        
        return task
    
    async def list_tasks(
        self,
        user_id: Optional[UUID] = None,
        task_type: Optional[str] = None,
        status: Optional[TaskStatus] = None,
        priority: Optional[TaskPriority] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at",
        order_direction: str = "desc"
    ) -> List[BackgroundTask]:
        """
        List tasks with filtering and pagination.
        
        Args:
            user_id: Filter by user ID
            task_type: Filter by task type
            status: Filter by status
            priority: Filter by priority
            limit: Maximum number of results
            offset: Number of results to skip
            order_by: Field to order by
            order_direction: Order direction (asc/desc)
            
        Returns:
            List[BackgroundTask]: List of matching tasks
        """
        session = await self._get_session()
        
        query = session.query(BackgroundTask)
        
        # Apply filters
        if user_id:
            query = query.filter(BackgroundTask.user_id == user_id)
        if task_type:
            query = query.filter(BackgroundTask.task_type == task_type)
        if status:
            query = query.filter(BackgroundTask.status == status)
        if priority:
            query = query.filter(BackgroundTask.priority == priority)
        
        # Apply ordering
        order_field = getattr(BackgroundTask, order_by, BackgroundTask.created_at)
        if order_direction.lower() == "desc":
            query = query.order_by(desc(order_field))
        else:
            query = query.order_by(asc(order_field))
        
        # Apply pagination
        query = query.offset(offset).limit(limit)
        
        result = await session.execute(query)
        return result.scalars().all()
    
    async def get_task_statistics(
        self,
        user_id: Optional[UUID] = None,
        task_type: Optional[str] = None,
        time_range_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get task statistics.
        
        Args:
            user_id: Filter by user ID
            task_type: Filter by task type
            time_range_hours: Time range for statistics
            
        Returns:
            Dict[str, Any]: Task statistics
        """
        session = await self._get_session()
        
        # Base query
        base_query = session.query(BackgroundTask)
        
        # Apply filters
        if user_id:
            base_query = base_query.filter(BackgroundTask.user_id == user_id)
        if task_type:
            base_query = base_query.filter(BackgroundTask.task_type == task_type)
        
        # Time range filter
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=time_range_hours)
        base_query = base_query.filter(BackgroundTask.created_at >= time_threshold)
        
        # Count by status
        status_counts = {}
        for status in TaskStatus:
            count_query = base_query.filter(BackgroundTask.status == status)
            result = await session.execute(count_query.with_only_columns([func.count()]))
            status_counts[status.value] = result.scalar()
        
        # Total tasks
        total_result = await session.execute(base_query.with_only_columns([func.count()]))
        total_tasks = total_result.scalar()
        
        # Average duration for completed tasks
        avg_duration_query = base_query.filter(
            and_(
                BackgroundTask.status == TaskStatus.COMPLETED,
                BackgroundTask.actual_duration_seconds.isnot(None)
            )
        ).with_only_columns([func.avg(BackgroundTask.actual_duration_seconds)])
        
        avg_duration_result = await session.execute(avg_duration_query)
        avg_duration = avg_duration_result.scalar() or 0
        
        return {
            "total_tasks": total_tasks,
            "status_counts": status_counts,
            "average_duration_seconds": round(avg_duration, 2),
            "time_range_hours": time_range_hours,
            "success_rate": round(
                (status_counts.get("completed", 0) / max(total_tasks, 1)) * 100, 2
            )
        }
    
    async def retry_task(self, task_id: str) -> Optional[BackgroundTask]:
        """
        Retry a failed task.
        
        Args:
            task_id: Task identifier
            
        Returns:
            BackgroundTask: Updated task record
        """
        task = await self.get_task(task_id)
        
        if not task:
            logger.warning(f"Task {task_id} not found for retry")
            return None
        
        if not task.can_retry:
            logger.warning(f"Task {task_id} cannot be retried")
            return None
        
        # Reset task for retry
        task.status = TaskStatus.PENDING
        task.started_at = None
        task.completed_at = None
        task.error_details = None
        task.result_data = None
        task.progress_percentage = 0
        task.worker_id = None
        
        session = await self._get_session()
        await session.commit()
        await session.refresh(task)
        
        await self._log_task_event(task.id, "INFO", f"Task queued for retry (attempt {task.retry_count + 1})")
        
        return task
    
    async def cancel_task(self, task_id: str, reason: Optional[str] = None) -> Optional[BackgroundTask]:
        """
        Cancel a task.
        
        Args:
            task_id: Task identifier
            reason: Cancellation reason
            
        Returns:
            BackgroundTask: Updated task record
        """
        return await self.update_task_status(
            task_id=task_id,
            status=TaskStatus.CANCELLED,
            error_details=reason
        )
    
    async def cleanup_old_tasks(self, days_old: int = 30) -> int:
        """
        Clean up old completed/failed tasks.
        
        Args:
            days_old: Age threshold in days
            
        Returns:
            int: Number of tasks cleaned up
        """
        session = await self._get_session()
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
        
        # Delete old completed/failed tasks
        delete_query = session.query(BackgroundTask).filter(
            and_(
                BackgroundTask.created_at < cutoff_date,
                BackgroundTask.status.in_([
                    TaskStatus.COMPLETED,
                    TaskStatus.FAILED,
                    TaskStatus.CANCELLED
                ])
            )
        )
        
        tasks_to_delete = await session.execute(delete_query)
        count = len(tasks_to_delete.scalars().all())
        
        await session.execute(delete_query.delete())
        await session.commit()
        
        logger.info(f"Cleaned up {count} old tasks older than {days_old} days")
        return count
    
    async def _log_task_event(
        self,
        task_uuid: UUID,
        level: str,
        message: str,
        component: Optional[str] = None,
        extra_data: Optional[Dict[str, Any]] = None
    ):
        """Log task event."""
        session = await self._get_session()
        
        log_entry = TaskLog(
            task_id=task_uuid,
            level=level,
            message=message,
            component=component or "TaskTrackingService",
            extra_data=extra_data
        )
        
        session.add(log_entry)
        await session.commit()
    
    async def _send_completion_webhook(self, task: BackgroundTask):
        """Send webhook notification for task completion."""
        if not task.webhook_url:
            return
        
        try:
            webhook_service = await self._get_webhook_service()
            
            payload = WebhookPayload(
                event_type=WebhookEventType.TASK_COMPLETED,
                event_id=f"task_completed_{task.task_id}",
                data={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "task_name": task.task_name,
                    "status": task.status,
                    "result": task.result_data,
                    "duration_seconds": task.duration_seconds,
                    "user_id": str(task.user_id) if task.user_id else None
                }
            )
            
            result = await webhook_service.send_webhook(
                url=task.webhook_url,
                payload=payload,
                secret=task.webhook_secret
            )
            
            if result.success:
                task.notification_sent = True
                session = await self._get_session()
                await session.commit()
                logger.info(f"Webhook sent successfully for task {task.task_id}")
            else:
                logger.error(f"Failed to send webhook for task {task.task_id}: {result.error_message}")
                
        except Exception as e:
            logger.error(f"Error sending completion webhook for task {task.task_id}: {e}")
    
    async def _send_failure_webhook(self, task: BackgroundTask):
        """Send webhook notification for task failure."""
        if not task.webhook_url:
            return
        
        try:
            webhook_service = await self._get_webhook_service()
            
            payload = WebhookPayload(
                event_type=WebhookEventType.TASK_FAILED,
                event_id=f"task_failed_{task.task_id}",
                data={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "task_name": task.task_name,
                    "status": task.status,
                    "error": task.error_details,
                    "retry_count": task.retry_count,
                    "can_retry": task.can_retry,
                    "user_id": str(task.user_id) if task.user_id else None
                }
            )
            
            result = await webhook_service.send_webhook(
                url=task.webhook_url,
                payload=payload,
                secret=task.webhook_secret
            )
            
            if result.success:
                task.notification_sent = True
                session = await self._get_session()
                await session.commit()
                logger.info(f"Failure webhook sent successfully for task {task.task_id}")
            else:
                logger.error(f"Failed to send failure webhook for task {task.task_id}: {result.error_message}")
                
        except Exception as e:
            logger.error(f"Error sending failure webhook for task {task.task_id}: {e}")


# Global task tracking service instance
_task_tracking_service: Optional[TaskTrackingService] = None


async def get_task_tracking_service(db_session: Optional[AsyncSession] = None) -> TaskTrackingService:
    """
    Get or create the global task tracking service instance.
    
    Args:
        db_session: Optional database session
        
    Returns:
        TaskTrackingService: Global task tracking service instance
    """
    global _task_tracking_service
    if _task_tracking_service is None or db_session:
        _task_tracking_service = TaskTrackingService(db_session)
    return _task_tracking_service


def create_tracked_background_task(
    background_tasks: FastAPIBackgroundTasks,
    task_tracking_service: TaskTrackingService,
    task_func: Callable,
    task_id: str,
    *args,
    **kwargs
):
    """
    Create a tracked background task that updates the database.
    
    Args:
        background_tasks: FastAPI BackgroundTasks instance
        task_tracking_service: Task tracking service
        task_func: Function to execute
        task_id: Task identifier
        *args: Function arguments
        **kwargs: Function keyword arguments
    """
    
    async def tracked_task_wrapper():
        """Wrapper that tracks task execution."""
        try:
            # Mark task as started
            await task_tracking_service.update_task_status(
                task_id=task_id,
                status=TaskStatus.RUNNING
            )
            
            # Execute the actual task
            if asyncio.iscoroutinefunction(task_func):
                result = await task_func(*args, **kwargs)
            else:
                result = task_func(*args, **kwargs)
            
            # Mark task as completed
            await task_tracking_service.update_task_status(
                task_id=task_id,
                status=TaskStatus.COMPLETED,
                result_data={"result": result} if result else None
            )
            
        except Exception as e:
            # Mark task as failed
            await task_tracking_service.update_task_status(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error_details=str(e)
            )
            logger.error(f"Background task {task_id} failed: {e}")
            raise
    
    # Add the tracked task to FastAPI BackgroundTasks
    background_tasks.add_task(tracked_task_wrapper)