# #!/usr/bin/env python3
# """
# LinkShield Backend Task Management Routes
#
# API endpoints for monitoring and managing background tasks including:
# - Task status monitoring
# - Task progress tracking
# - Task cancellation
# - Task history and logs
# - Webhook management
# """
#
# from typing import Dict, Any, Optional, List
# from datetime import datetime, timezone
#
# from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks
# from fastapi.security import HTTPBearer
# from sqlalchemy.ext.asyncio import AsyncSession
# from pydantic import BaseModel, Field
#
# from src.services.webhook_service import get_webhook_service
# from src.models.user import User
# from src.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority
# from src.controllers.base_controller import BaseController
#
#
#
#
# # Initialize router
# router = APIRouter(prefix="/api/v1/tasks", tags=["Task Management"])
# security = HTTPBearer()
#
# # Pydantic models for request/response validation
# class TaskResponse(BaseModel):
#     """Response model for task data."""
#     id: str
#     task_type: str
#     status: str
#     priority: str
#     progress: int
#     created_at: datetime
#     updated_at: Optional[datetime] = None
#     completed_at: Optional[datetime] = None
#     user_id: Optional[int] = None
#     metadata: Optional[Dict[str, Any]] = None
#     result: Optional[Dict[str, Any]] = None
#     error_message: Optional[str] = None
#
# class TaskListResponse(BaseModel):
#     """Response model for task list."""
#     tasks: List[TaskResponse]
#     total: int
#     page: int
#     limit: int
#     has_next: bool
#     has_prev: bool
#
# class TaskCancelRequest(BaseModel):
#     """Request model for task cancellation."""
#     reason: Optional[str] = Field(None, description="Reason for cancellation")
#
# class WebhookTestRequest(BaseModel):
#     """Request model for webhook testing."""
#     url: str = Field(..., description="Webhook URL to test")
#     event_type: str = Field(..., description="Event type to simulate")
#     test_data: Optional[Dict[str, Any]] = Field(None, description="Test data to send")
#
# # Task Management Controller
# class TaskController(BaseController):
#     """Controller for task management operations."""
#
#     def __init__(self):
#         super().__init__()
#
# # Initialize controller
# task_controller = TaskController()
#
# @router.get("/", response_model=TaskListResponse)
# @rate_limit(requests=100, window=60)
# async def get_tasks(
#     page: int = Query(1, ge=1, description="Page number"),
#     limit: int = Query(20, ge=1, le=100, description="Items per page"),
#     status: Optional[str] = Query(None, description="Filter by task status"),
#     task_type: Optional[str] = Query(None, description="Filter by task type"),
#     user_id: Optional[int] = Query(None, description="Filter by user ID"),
#     current_user: User = Depends(get_current_user)
# ):
#     """
#     Get paginated list of tasks with optional filters.
#
#     Returns tasks visible to the current user based on their permissions.
#     Regular users can only see their own tasks, while admins can see all tasks.
#     """
#     try:
#         task_tracking_service = get_task_tracking_service()
#
#         # Build filters based on user permissions
#         filters = {}
#         if status:
#             # Validate status
#             valid_statuses = [s.value for s in TaskStatus]
#             if status not in valid_statuses:
#                 raise HTTPException(
#                     status_code=400,
#                     detail=f"Invalid status. Must be one of: {valid_statuses}"
#                 )
#             filters['status'] = status
#
#         if task_type:
#             # Validate task type
#             valid_types = [t.value for t in TaskType]
#             if task_type not in valid_types:
#                 raise HTTPException(
#                     status_code=400,
#                     detail=f"Invalid task type. Must be one of: {valid_types}"
#                 )
#             filters['task_type'] = task_type
#
#         # Apply user-based filtering
#         if not current_user.is_admin:
#             # Regular users can only see their own tasks
#             filters['user_id'] = current_user.id
#         elif user_id:
#             # Admins can filter by specific user
#             filters['user_id'] = user_id
#
#         # Get tasks from service
#         tasks_data = await task_tracking_service.get_tasks(
#             db=db,
#             page=page,
#             limit=limit,
#             filters=filters
#         )
#
#         # Convert to response format
#         task_responses = []
#         for task in tasks_data['tasks']:
#             task_responses.append(TaskResponse(
#                 id=str(task.id),
#                 task_type=task.task_type.value,
#                 status=task.status.value,
#                 priority=task.priority.value,
#                 progress=task.progress,
#                 created_at=task.created_at,
#                 updated_at=task.updated_at,
#                 completed_at=task.completed_at,
#                 user_id=task.user_id,
#                 metadata=task.metadata,
#                 result=task.result,
#                 error_message=task.error_message
#             ))
#
#         return TaskListResponse(
#             tasks=task_responses,
#             total=tasks_data['total'],
#             page=page,
#             limit=limit,
#             has_next=tasks_data['has_next'],
#             has_prev=tasks_data['has_prev']
#         )
#
#     except HTTPException:
#         raise
#     except Exception as e:
#         task_controller.logger.error(f"Failed to get tasks: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail="Failed to retrieve tasks"
#         )
#
# @router.get("/{task_id}", response_model=TaskResponse)
# @rate_limit(requests=200, window=60)
# async def get_task(
#     task_id: str = Path(..., description="Task ID"),
#     db: AsyncSession = Depends(get_db),
#     current_user: User = Depends(get_current_user)
# ):
#     """
#     Get detailed information about a specific task.
#
#     Users can only access their own tasks unless they are admins.
#     """
#     try:
#         task_tracking_service = get_task_tracking_service()
#
#         # Get task from service
#         task = await task_tracking_service.get_task(db=db, task_id=task_id)
#
#         if not task:
#             raise HTTPException(
#                 status_code=404,
#                 detail="Task not found"
#             )
#
#         # Check permissions
#         if not current_user.is_admin and task.user_id != current_user.id:
#             raise HTTPException(
#                 status_code=403,
#                 detail="Access denied. You can only view your own tasks."
#             )
#
#         return TaskResponse(
#             id=str(task.id),
#             task_type=task.task_type.value,
#             status=task.status.value,
#             priority=task.priority.value,
#             progress=task.progress,
#             created_at=task.created_at,
#             updated_at=task.updated_at,
#             completed_at=task.completed_at,
#             user_id=task.user_id,
#             metadata=task.metadata,
#             result=task.result,
#             error_message=task.error_message
#         )
#
#     except HTTPException:
#         raise
#     except Exception as e:
#         task_controller.logger.error(f"Failed to get task {task_id}: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail="Failed to retrieve task"
#         )
#
# @router.post("/{task_id}/cancel")
# @rate_limit(requests=50, window=60)
# async def cancel_task(
#     request: TaskCancelRequest,
#     task_id: str = Path(..., description="Task ID"),
#     db: AsyncSession = Depends(get_db),
#     current_user: User = Depends(get_current_user)
# ):
#     """
#     Cancel a running or pending task.
#
#     Users can only cancel their own tasks unless they are admins.
#     """
#     try:
#         task_tracking_service = get_task_tracking_service()
#
#         # Get task from service
#         task = await task_tracking_service.get_task(db=db, task_id=task_id)
#
#         if not task:
#             raise HTTPException(
#                 status_code=404,
#                 detail="Task not found"
#             )
#
#         # Check permissions
#         if not current_user.is_admin and task.user_id != current_user.id:
#             raise HTTPException(
#                 status_code=403,
#                 detail="Access denied. You can only cancel your own tasks."
#             )
#
#         # Check if task can be cancelled
#         if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
#             raise HTTPException(
#                 status_code=400,
#                 detail=f"Cannot cancel task with status: {task.status.value}"
#             )
#
#         # Cancel the task
#         await task_tracking_service.update_task_status(
#             db=db,
#             task_id=task_id,
#             status=TaskStatus.CANCELLED,
#             error_message=f"Cancelled by user: {request.reason or 'No reason provided'}"
#         )
#
#         task_controller.logger.info(f"Task {task_id} cancelled by user {current_user.id}")
#
#         return create_response(
#             success=True,
#             message="Task cancelled successfully",
#             data={"task_id": task_id, "status": "cancelled"}
#         )
#
#     except HTTPException:
#         raise
#     except Exception as e:
#         task_controller.logger.error(f"Failed to cancel task {task_id}: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail="Failed to cancel task"
#         )
#
# @router.get("/{task_id}/logs")
# @rate_limit(requests=100, window=60)
# async def get_task_logs(
#     task_id: str = Path(..., description="Task ID"),
#     limit: int = Query(100, ge=1, le=1000, description="Number of log entries"),
#     db: AsyncSession = Depends(get_db),
#     current_user: User = Depends(get_current_user)
# ):
#     """
#     Get logs for a specific task.
#
#     Users can only access logs for their own tasks unless they are admins.
#     """
#     try:
#         task_tracking_service = get_task_tracking_service()
#
#         # Get task from service
#         task = await task_tracking_service.get_task(db=db, task_id=task_id)
#
#         if not task:
#             raise HTTPException(
#                 status_code=404,
#                 detail="Task not found"
#             )
#
#         # Check permissions
#         if not current_user.is_admin and task.user_id != current_user.id:
#             raise HTTPException(
#                 status_code=403,
#                 detail="Access denied. You can only view logs for your own tasks."
#             )
#
#         # Get task logs (placeholder implementation)
#         # In a real system, this would fetch from a logging service or database
#         logs = [
#             {
#                 "timestamp": task.created_at.isoformat(),
#                 "level": "INFO",
#                 "message": f"Task {task_id} created",
#                 "details": {"task_type": task.task_type.value}
#             },
#             {
#                 "timestamp": task.updated_at.isoformat() if task.updated_at else task.created_at.isoformat(),
#                 "level": "INFO",
#                 "message": f"Task status: {task.status.value}",
#                 "details": {"progress": task.progress}
#             }
#         ]
#
#         if task.error_message:
#             logs.append({
#                 "timestamp": task.updated_at.isoformat() if task.updated_at else task.created_at.isoformat(),
#                 "level": "ERROR",
#                 "message": task.error_message,
#                 "details": {}
#             })
#
#         return create_response(
#             success=True,
#             data={
#                 "task_id": task_id,
#                 "logs": logs[:limit],
#                 "count": len(logs)
#             }
#         )
#
#     except HTTPException:
#         raise
#     except Exception as e:
#         task_controller.logger.error(f"Failed to get logs for task {task_id}: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail="Failed to retrieve task logs"
#         )
#
# # Admin-only endpoints
# @router.get("/admin/stats")
# @rate_limit(requests=50, window=60)
# async def get_task_statistics(
#     days: int = Query(7, ge=1, le=365, description="Number of days for statistics"),
#     db: AsyncSession = Depends(get_db),
#     current_admin: User = Depends(get_current_admin_user)
# ):
#     """
#     Get task statistics for admin dashboard.
#
#     Admin-only endpoint for monitoring system task performance.
#     """
#     try:
#         task_tracking_service = get_task_tracking_service()
#
#         # Get task statistics
#         stats = await task_tracking_service.get_task_statistics(db=db, days=days)
#
#         return create_response(
#             success=True,
#             data={
#                 "period_days": days,
#                 "statistics": stats,
#                 "generated_at": datetime.now(timezone.utc).isoformat()
#             }
#         )
#
#     except Exception as e:
#         task_controller.logger.error(f"Failed to get task statistics: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail="Failed to retrieve task statistics"
#         )
#
# @router.post("/admin/cleanup")
# @rate_limit(requests=10, window=300)
# async def cleanup_old_tasks(
#     background_tasks: BackgroundTasks,
#     days: int = Query(30, ge=1, le=365, description="Delete tasks older than N days"),
#     dry_run: bool = Query(True, description="Perform dry run without actual deletion"),
#     db: AsyncSession = Depends(get_db),
#     current_admin: User = Depends(get_current_admin_user)
# ):
#     """
#     Clean up old completed/failed tasks.
#
#     Admin-only endpoint for system maintenance.
#     """
#     try:
#         task_tracking_service = get_task_tracking_service()
#
#         if dry_run:
#             # Get count of tasks that would be deleted
#             count = await task_tracking_service.count_old_tasks(db=db, days=days)
#
#             return create_response(
#                 success=True,
#                 message=f"Dry run: {count} tasks would be deleted",
#                 data={"count": count, "days": days, "dry_run": True}
#             )
#         else:
#             # Schedule cleanup as background task
#             background_tasks.add_task(
#                 task_tracking_service.cleanup_old_tasks,
#                 db=db,
#                 days=days
#             )
#
#             task_controller.logger.info(f"Task cleanup scheduled by admin {current_admin.id}")
#
#             return create_response(
#                 success=True,
#                 message="Task cleanup scheduled",
#                 data={"days": days, "scheduled": True}
#             )
#
#     except Exception as e:
#         task_controller.logger.error(f"Failed to cleanup tasks: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail="Failed to cleanup tasks"
#         )
#
# @router.post("/admin/webhook/test")
# @rate_limit(requests=20, window=60)
# async def test_webhook(
#     request: WebhookTestRequest,
#     background_tasks: BackgroundTasks,
#     current_admin: User = Depends(get_current_admin_user)
# ):
#     """
#     Test webhook endpoint connectivity.
#
#     Admin-only endpoint for testing webhook configurations.
#     """
#     try:
#         webhook_service = get_webhook_service()
#
#         # Prepare test data
#         test_data = request.test_data or {
#             "test": True,
#             "timestamp": datetime.now(timezone.utc).isoformat(),
#             "admin_id": current_admin.id
#         }
#
#         # Schedule webhook test as background task
#         background_tasks.add_task(
#             webhook_service.send_webhook,
#             url=request.url,
#             event_type=request.event_type,
#             data=test_data
#         )
#
#         task_controller.logger.info(f"Webhook test scheduled by admin {current_admin.id}")
#
#         return create_response(
#             success=True,
#             message="Webhook test scheduled",
#             data={
#                 "url": request.url,
#                 "event_type": request.event_type,
#                 "scheduled": True
#             }
#         )
#
#     except Exception as e:
#         task_controller.logger.error(f"Failed to test webhook: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail="Failed to test webhook"
#         )