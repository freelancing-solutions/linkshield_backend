"""Enhanced Webhook controller with task processing functionality."""

from typing import Dict, Any, Optional, List, Callable, Protocol
import logging
import uuid
import asyncio
from contextlib import asynccontextmanager

from fastapi import HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from linkshield.config.settings import get_settings
from linkshield.services.webhook_service import get_webhook_service
from linkshield.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority
from linkshield.utils import utc_datetime


class DatabaseSessionProvider(Protocol):
    """Protocol for database session management."""
    @asynccontextmanager
    async def get_db_session(self) -> AsyncSession:
        """Get database session."""
        ...


class WebhookController:
    """Enhanced webhook controller with complete task processing."""

    def __init__(self, session_provider: Optional[DatabaseSessionProvider] = None):
        self.settings = get_settings()
        self.webhook_service = get_webhook_service()
        self.logger = logging.getLogger(self.__class__.__name__)
        self._session_provider = session_provider

    def set_session_provider(self, provider: DatabaseSessionProvider) -> None:
        """Set the database session provider."""
        self._session_provider = provider

    @asynccontextmanager
    async def get_db_session(self) -> AsyncSession:
        """Get database session from provider."""
        if not self._session_provider:
            raise RuntimeError("Session provider not set")
        async with self._session_provider.get_db_session() as session:
            yield session

    async def _execute_task_with_tracking(
            self,
            task_id: str,
            task_func: Callable,
            *args,
            **kwargs
    ) -> None:
        """Execute task function with automatic tracking and webhook delivery."""
        try:
            await self.update_task_progress(task_id, 0, TaskStatus.RUNNING)

            if asyncio.iscoroutinefunction(task_func):
                result = await task_func(task_id, *args, **kwargs)
            else:
                result = task_func(task_id, *args, **kwargs)

            await self.complete_task_with_webhook(task_id, result or {})

        except Exception as e:
            self.logger.error(f"Task {task_id} failed: {str(e)}")
            await self.fail_task_with_webhook(task_id, str(e))

    async def create_task(self, session: AsyncSession, task: BackgroundTask) -> None:
        """Create a new background task in the database."""
        session.add(task)
        await session.flush()

    async def update_task_status(
            self,
            task_id: str,
            status: TaskStatus,
            progress: Optional[int] = None,
            result_data: Optional[Dict[str, Any]] = None,
            error_message: Optional[str] = None
    ) -> None:
        """Update task status and progress."""
        async with self.get_db_session() as session:
            task = await session.get(BackgroundTask, task_id)
            if task:
                task.status = status
                if progress is not None:
                    task.progress = progress
                if result_data is not None:
                    task.result_data = result_data
                if error_message is not None:
                    task.error_message = error_message
                task.updated_at = utc_datetime()
                await session.commit()

    async def get_task(self, task_id: str) -> Optional[BackgroundTask]:
        """Get a task by ID."""
        async with self.get_db_session() as session:
            return await session.get(BackgroundTask, task_id)

    async def create_background_task(
            self,
            task_type: TaskType,
            task_data: Dict[str, Any],
            user_id: Optional[int] = None,
            priority: TaskPriority = TaskPriority.NORMAL,
            callback_url: Optional[str] = None,
            depends_on: Optional[List[str]] = None
    ) -> str:
        """Create a new background task for tracking."""
        try:
            task_id = str(uuid.uuid4())

            if callback_url and not self._validate_webhook_url(callback_url):
                raise HTTPException(400, "Invalid webhook URL format")

            task = BackgroundTask(
                id=task_id,
                task_type=task_type,
                status=TaskStatus.PENDING,
                priority=priority,
                user_id=user_id,
                task_data=task_data,
                callback_url=callback_url,
                depends_on=depends_on or [],
                created_at=utc_datetime()
            )

            async with self.get_db_session() as session:
                await self.create_task(session, task)
                await session.commit()

            self.logger.info(f"Created task {task_id} of type {task_type.value}")
            return task_id

        except Exception as e:
            self.logger.error(f"Failed to create task: {str(e)}")
            raise HTTPException(500, "Failed to create background task")

    async def update_task_progress(
            self,
            task_id: str,
            progress: int,
            status: Optional[TaskStatus] = None,
            result_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """Update task progress with validation."""
        if not 0 <= progress <= 100:
            raise ValueError("Progress must be between 0 and 100")

        await self.update_task_status(
            task_id=task_id,
            status=status or TaskStatus.RUNNING,
            progress=progress,
            result_data=result_data
        )

        self.logger.info(f"Task {task_id} progress: {progress}%")

    async def complete_task_with_webhook(
            self,
            task_id: str,
            result_data: Dict[str, Any],
            callback_url: Optional[str] = None
    ) -> None:
        """Complete task and send webhook notification."""
        try:
            await self.update_task_status(
                task_id=task_id,
                status=TaskStatus.COMPLETED,
                progress=100,
                result_data=result_data
            )

            task = await self.get_task(task_id)
            if not task:
                self.logger.error(f"Task {task_id} not found for webhook")
                return

            webhook_url = callback_url or task.callback_url
            if webhook_url:
                payload = {
                    "task_id": task_id,
                    "task_type": task.task_type.value,
                    "status": "completed",
                    "result": result_data,
                    "completed_at": utc_datetime().isoformat()
                }

                try:
                    await self.webhook_service.send_webhook(
                        url=webhook_url,
                        payload=payload,
                        event_type="task.completed"
                    )
                    self.logger.info(f"Webhook sent for completed task {task_id}")
                except Exception as webhook_error:
                    self.logger.error(f"Webhook delivery failed: {webhook_error}")

            self.logger.info(f"Task {task_id} completed successfully")

        except Exception as e:
            self.logger.error(f"Failed to complete task {task_id}: {str(e)}")

    async def fail_task_with_webhook(
            self,
            task_id: str,
            error_message: str,
            callback_url: Optional[str] = None
    ) -> None:
        """Mark task as failed and send webhook notification."""
        try:
            await self.update_task_status(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error_message=error_message
            )

            task = await self.get_task(task_id)
            if not task:
                self.logger.error(f"Task {task_id} not found for webhook")
                return

            webhook_url = callback_url or task.callback_url
            if webhook_url:
                payload = {
                    "task_id": task_id,
                    "task_type": task.task_type.value,
                    "status": "failed",
                    "error": error_message,
                    "failed_at": utc_datetime().isoformat()
                }

                try:
                    await self.webhook_service.send_webhook(
                        url=webhook_url,
                        payload=payload,
                        event_type="task.failed"
                    )
                    self.logger.info(f"Webhook sent for failed task {task_id}")
                except Exception as webhook_error:
                    self.logger.error(f"Webhook delivery failed: {webhook_error}")

            self.logger.error(f"Task {task_id} failed: {error_message}")

        except Exception as e:
            self.logger.error(f"Failed to handle task failure {task_id}: {str(e)}")

    async def add_background_task_with_tracking(
            self,
            background_tasks: BackgroundTasks,
            task_func: Callable,
            task_type: TaskType,
            task_data: Dict[str, Any],
            user_id: Optional[int] = None,
            priority: TaskPriority = TaskPriority.NORMAL,
            callback_url: Optional[str] = None,
            *args,
            **kwargs
    ) -> str:
        """Add background task with automatic tracking and webhook support."""
        try:
            task_id = await self.create_background_task(
                task_type=task_type,
                task_data=task_data,
                user_id=user_id,
                priority=priority,
                callback_url=callback_url
            )

            background_tasks.add_task(
                self._execute_task_with_tracking,
                task_id,
                task_func,
                *args,
                **kwargs
            )

            self.logger.info(f"Added tracked task {task_id} to execution queue")
            return task_id

        except Exception as e:
            self.logger.error(f"Failed to add tracked task: {str(e)}")
            raise HTTPException(500, "Failed to add background task")

    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get current task status and progress."""
        task = await self.get_task(task_id)
        if not task:
            raise HTTPException(404, "Task not found")

        return {
            "task_id": task.id,
            "task_type": task.task_type.value,
            "status": task.status.value,
            "progress": task.progress,
            "created_at": task.created_at.isoformat(),
            "updated_at": task.updated_at.isoformat() if task.updated_at else None,
            "result_data": task.result_data,
            "error_message": task.error_message
        }

    async def cancel_task(self, task_id: str) -> None:
        """Cancel a pending or running task."""
        task = await self.get_task(task_id)
        if not task:
            raise HTTPException(404, "Task not found")

        if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            raise HTTPException(400, f"Cannot cancel task with status: {task.status.value}")

        await self.update_task_status(
            task_id=task_id,
            status=TaskStatus.CANCELLED
        )

        self.logger.info(f"Task {task_id} cancelled")

    def _validate_webhook_url(self, url: str) -> bool:
        """Validate webhook URL format and security."""
        if not url or not url.startswith(('http://', 'https://')):
            return False

        if not url.startswith('https://') and not getattr(self.settings, 'DEBUG', False):
            self.logger.warning(f"Non-HTTPS webhook URL: {url}")

        return True