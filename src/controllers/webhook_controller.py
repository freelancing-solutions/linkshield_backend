"""Webhook controller class providing webhook and task tracking functionality.

This module defines the WebhookController class that handles all webhook-related
operations including task creation, progress tracking, and completion notifications.
It serves as a base class for controllers that need webhook functionality.
"""

from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from datetime import datetime
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import get_settings
from src.services.webhook_service import get_webhook_service
from src.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority


class WebhookController(ABC):
    """Base webhook controller class with task tracking and webhook functionality.
    
    This class provides:
    - Background task creation and management
    - Task progress tracking and status updates
    - Webhook notification delivery
    - Task completion and failure handling
    - Integration with FastAPI BackgroundTasks
    """
    
    def __init__(self):
        """Initialize webhook controller with common dependencies."""
        self.settings = get_settings()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    @asynccontextmanager
    async def get_db_session(self) -> AsyncSession:
        """Abstract method for database session management.
        
        This method must be implemented by subclasses to provide
        database session context management.
        
        Yields:
            AsyncSession: Database session for operations
        """
        pass
    
    # Task Tracking Service Methods (since TaskTrackingService is missing)
    
    async def create_task(self, db: AsyncSession, task: BackgroundTask) -> None:
        """Create a new background task in the database.
        
        Args:
            db: Database session
            task: BackgroundTask instance to create
        """
        db.add(task)
        await db.flush()
    
    async def update_task_status(
        self,
        db: AsyncSession,
        task_id: str,
        status: TaskStatus,
        progress: Optional[int] = None,
        result_data: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Update task status and progress.
        
        Args:
            db: Database session
            task_id: ID of the task to update
            status: New task status
            progress: Progress percentage (0-100)
            result_data: Task result data
            error_message: Error message if task failed
        """
        task = await db.get(BackgroundTask, task_id)
        if task:
            task.status = status
            if progress is not None:
                task.progress = progress
            if result_data is not None:
                task.result_data = result_data
            if error_message is not None:
                task.error_message = error_message
            task.updated_at = datetime.utcnow()
            await db.flush()
    
    async def get_task(self, db: AsyncSession, task_id: str) -> Optional[BackgroundTask]:
        """Get a task by ID.
        
        Args:
            db: Database session
            task_id: ID of the task to retrieve
            
        Returns:
            BackgroundTask instance or None if not found
        """
        return await db.get(BackgroundTask, task_id)
    
    async def complete_task(
        self,
        db: AsyncSession,
        task_id: str,
        result_data: Dict[str, Any]
    ) -> None:
        """Mark a task as completed.
        
        Args:
            db: Database session
            task_id: ID of the task to complete
            result_data: Task result data
        """
        await self.update_task_status(
            db=db,
            task_id=task_id,
            status=TaskStatus.COMPLETED,
            progress=100,
            result_data=result_data
        )
    
    async def fail_task(
        self,
        db: AsyncSession,
        task_id: str,
        error_message: str
    ) -> None:
        """Mark a task as failed.
        
        Args:
            db: Database session
            task_id: ID of the task to fail
            error_message: Error message describing the failure
        """
        await self.update_task_status(
            db=db,
            task_id=task_id,
            status=TaskStatus.FAILED,
            error_message=error_message
        )
    
    # Webhook and Task Management Methods
    
    async def create_background_task(
        self,
        task_type: TaskType,
        task_data: Dict[str, Any],
        user_id: Optional[int] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        callback_url: Optional[str] = None,
        depends_on: Optional[List[str]] = None
    ) -> str:
        """Create a new background task for tracking.
        
        Args:
            task_type: Type of the task
            task_data: Task-specific data
            user_id: ID of the user who initiated the task
            priority: Task priority level
            callback_url: Optional webhook URL for completion notification
            depends_on: List of task IDs this task depends on
            
        Returns:
            str: Task ID
            
        Raises:
            HTTPException: If task creation fails
        """
        try:
            task_id = str(uuid.uuid4())
            
            task = BackgroundTask(
                id=task_id,
                task_type=task_type,
                status=TaskStatus.PENDING,
                priority=priority,
                user_id=user_id,
                task_data=task_data,
                callback_url=callback_url,
                depends_on=depends_on or [],
                created_at=datetime.utcnow()
            )
            
            async with self.get_db_session() as session:
                await self.create_task(db=session, task=task)
            
            self.logger.info(f"Created background task {task_id} of type {task_type.value}")
            return task_id
            
        except Exception as e:
            self.logger.error(f"Failed to create background task: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create background task"
            )
    
    async def update_task_progress(
        self,
        task_id: str,
        progress: int,
        status: Optional[TaskStatus] = None,
        result_data: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Update background task progress and status.
        
        Args:
            task_id: ID of the task to update
            progress: Progress percentage (0-100)
            status: New task status
            result_data: Task result data
            error_message: Error message if task failed
            
        Raises:
            HTTPException: If task update fails
        """
        try:
            async with self.get_db_session() as session:
                await self.update_task_status(
                    db=session,
                    task_id=task_id,
                    status=status or TaskStatus.RUNNING,
                    progress=progress,
                    result_data=result_data,
                    error_message=error_message
                )
            
            self.logger.info(f"Updated task {task_id} progress to {progress}%")
            
        except Exception as e:
            self.logger.error(f"Failed to update task progress: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update task progress"
            )
    
    async def complete_task_with_webhook(
        self,
        task_id: str,
        result_data: Dict[str, Any],
        callback_url: Optional[str] = None
    ) -> None:
        """Complete a background task and send webhook notification.
        
        Args:
            task_id: ID of the task to complete
            result_data: Task result data
            callback_url: Optional webhook URL override
            
        Raises:
            HTTPException: If task completion fails
        """
        try:
            webhook_service = get_webhook_service()
            
            async with self.get_db_session() as session:
                # Update task status to completed
                await self.update_task_status(
                    db=session,
                    task_id=task_id,
                    status=TaskStatus.COMPLETED,
                    progress=100,
                    result_data=result_data
                )
                
                # Get task details for webhook
                task = await self.get_task(db=session, task_id=task_id)
                if not task:
                    self.logger.error(f"Task {task_id} not found for webhook notification")
                    return
                
                # Send webhook notification if callback URL is provided
                webhook_url = callback_url or task.callback_url
                if webhook_url:
                    webhook_payload = {
                        "task_id": task_id,
                        "task_type": task.task_type.value,
                        "status": "completed",
                        "result": result_data,
                        "completed_at": datetime.utcnow().isoformat()
                    }
                    
                    await webhook_service.send_webhook(
                        url=webhook_url,
                        payload=webhook_payload,
                        event_type="task.completed"
                    )
            
            self.logger.info(f"Completed task {task_id} with webhook notification")
            
        except Exception as e:
            self.logger.error(f"Failed to complete task with webhook: {str(e)}")
            # Don't raise exception here to avoid breaking the main process
    
    async def fail_task_with_webhook(
        self,
        task_id: str,
        error_message: str,
        callback_url: Optional[str] = None
    ) -> None:
        """Mark a background task as failed and send webhook notification.
        
        Args:
            task_id: ID of the task to fail
            error_message: Error message describing the failure
            callback_url: Optional webhook URL override
            
        Raises:
            HTTPException: If task failure handling fails
        """
        try:
            webhook_service = get_webhook_service()
            
            async with self.get_db_session() as session:
                # Update task status to failed
                await self.update_task_status(
                    db=session,
                    task_id=task_id,
                    status=TaskStatus.FAILED,
                    error_message=error_message
                )
                
                # Get task details for webhook
                task = await self.get_task(db=session, task_id=task_id)
                if not task:
                    self.logger.error(f"Task {task_id} not found for webhook notification")
                    return
                
                # Send webhook notification if callback URL is provided
                webhook_url = callback_url or task.callback_url
                if webhook_url:
                    webhook_payload = {
                        "task_id": task_id,
                        "task_type": task.task_type.value,
                        "status": "failed",
                        "error": error_message,
                        "failed_at": datetime.utcnow().isoformat()
                    }
                    
                    await webhook_service.send_webhook(
                        url=webhook_url,
                        payload=webhook_payload,
                        event_type="task.failed"
                    )
            
            self.logger.info(f"Failed task {task_id} with webhook notification")
            
        except Exception as e:
            self.logger.error(f"Failed to handle task failure with webhook: {str(e)}")
            # Don't raise exception here to avoid breaking the main process
    
    async def add_background_task_with_tracking(
        self,
        background_tasks: BackgroundTasks,
        task_func: callable,
        task_type: TaskType,
        task_data: Dict[str, Any],
        user_id: Optional[int] = None,
        priority: TaskPriority = TaskPriority.MEDIUM,
        callback_url: Optional[str] = None,
        *args,
        **kwargs
    ) -> str:
        """Add a background task with automatic tracking and webhook support.
        
        Args:
            background_tasks: FastAPI BackgroundTasks instance
            task_func: Function to execute in background
            task_type: Type of the task
            task_data: Task-specific data
            user_id: ID of the user who initiated the task
            priority: Task priority level
            callback_url: Optional webhook URL for completion notification
            *args: Additional positional arguments for task_func
            **kwargs: Additional keyword arguments for task_func
            
        Returns:
            str: Task ID
            
        Raises:
            HTTPException: If task creation fails
        """
        try:
            # Create task record
            task_id = await self.create_background_task(
                task_type=task_type,
                task_data=task_data,
                user_id=user_id,
                priority=priority,
                callback_url=callback_url
            )
            
            # Add to FastAPI background tasks
            background_tasks.add_task(
                task_func,
                task_id,
                *args,
                **kwargs
            )
            
            self.logger.info(f"Added background task {task_id} to execution queue")
            return task_id
            
        except Exception as e:
            self.logger.error(f"Failed to add background task with tracking: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to add background task"
            )
    
    def _create_webhook_payload(
        self,
        task_id: str,
        task_type: TaskType,
        status: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Create webhook payload for task notifications.
        
        Args:
            task_id: ID of the task
            task_type: Type of the task
            status: Task status (completed, failed, etc.)
            **kwargs: Additional payload data
            
        Returns:
            Dict containing webhook payload
        """
        payload = {
            "task_id": task_id,
            "task_type": task_type.value,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
        payload.update(kwargs)
        return payload
    
    def _validate_webhook_url(self, url: str) -> bool:
        """Validate webhook URL format and security.
        
        Args:
            url: Webhook URL to validate
            
        Returns:
            bool: True if URL is valid and secure
        """
        if not url:
            return False
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return False
        
        # Security check - prefer HTTPS
        if not url.startswith('https://') and not self.settings.DEBUG:
            self.logger.warning(f"Non-HTTPS webhook URL in production: {url}")
        
        return True