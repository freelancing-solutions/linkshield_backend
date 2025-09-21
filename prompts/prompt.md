I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

Based on my exploration, I can see that:

1. **Current State**: The system already uses FastAPI BackgroundTasks effectively in URLCheckController and ReportController. The Celery implementation is only used for email operations and the user wants to stick with FastAPI BackgroundTasks.

2. **Long-running Operations Identified**: 
   - AI content analysis (AIAnalysisController) - currently synchronous
   - URL analysis and bulk operations (URLCheckController) - already uses BackgroundTasks
   - Report creation and processing (ReportController) - already uses BackgroundTasks  
   - Admin analytics operations - currently synchronous

3. **Existing Patterns**: URLCheckController already demonstrates good webhook patterns with `callback_url` parameters and `_send_webhook_notification()` methods.

4. **Missing Components**: 
   - Generic webhook service to standardize webhook delivery
   - Enhanced BaseController with BackgroundTasks and webhook helpers
   - Background task support for AI analysis and admin operations
   - Consistent webhook payload schemas across all controllers

### Approach

The implementation will leverage FastAPI BackgroundTasks throughout the system and create a unified webhook system. The approach will:

1. **Create Webhook Service**: Build a generic `WebhookService` for standardized webhook delivery
2. **Enhance BaseController**: Add BackgroundTasks and webhook helper methods
3. **Extend BackgroundTasks Usage**: Convert synchronous long-running operations to use BackgroundTasks
4. **Standardize Webhooks**: Create consistent webhook payload schemas and delivery patterns
5. **Add Task Tracking**: Implement simple task status tracking using database records
6. **Update Routes**: Add webhook support to all relevant endpoints

This approach is much simpler than Celery while still providing the async processing and webhook capabilities needed.

### Reasoning

I explored the codebase systematically to understand the current architecture. I examined the existing background task system, analyzed controllers to identify long-running operations, reviewed models to understand data structures, checked routes to see current API patterns, and examined the settings. I discovered that URLCheckController and ReportController already use FastAPI BackgroundTasks effectively, making this the natural choice to extend rather than introducing Celery complexity.

## Mermaid Diagram

sequenceDiagram
    participant Client
    participant Route
    participant Controller
    participant BackgroundTasks
    participant TaskTrackingService
    participant WebhookService
    participant WebhookTarget

    Client->>Route: POST /api/ai-analysis/analyze (with callback_url)
    Route->>Controller: analyze_content(callback_url, background_tasks)
    Controller->>TaskTrackingService: create_task_record(ai_analysis)
    TaskTrackingService->>Controller: task_id
    Controller->>BackgroundTasks: add_task(perform_analysis, task_id, callback_url)
    Controller->>Client: 202 Accepted {task_id, tracking_url}
    
    Note over BackgroundTasks: Background processing
    BackgroundTasks->>TaskTrackingService: update_task_status(running)
    BackgroundTasks->>BackgroundTasks: Perform AI analysis
    BackgroundTasks->>TaskTrackingService: mark_task_completed(results)
    BackgroundTasks->>WebhookService: send_webhook(callback_url, results)
    WebhookService->>WebhookTarget: POST webhook notification
    WebhookTarget->>WebhookService: 200 OK
    
    Note over Client: Optional status checking
    Client->>Route: GET /api/tasks/{task_id}
    Route->>TaskTrackingService: get_task_status(task_id)
    TaskTrackingService->>Client: Task status and results

## Proposed File Changes

### src\services\webhook_service.py(NEW)

Create a comprehensive webhook service that handles webhook delivery and management using aiohttp. This service will:

- Send HTTP POST requests to webhook URLs with standardized payloads
- Support webhook signatures/authentication using HMAC-SHA256
- Implement retry logic with exponential backoff for failed deliveries
- Handle webhook timeouts and error responses
- Provide methods like `send_webhook()`, `send_bulk_webhook()`, `validate_webhook_url()`
- Support different event types: task_completed, analysis_finished, report_created, etc.
- Include webhook delivery logging and error tracking
- Extract and generalize the webhook functionality currently in `URLCheckController._send_webhook_notification()`

The service will be lightweight and focused on HTTP delivery without requiring Celery infrastructure.

### src\models\task.py(NEW)

Create database models for tracking background tasks since FastAPI BackgroundTasks don't have built-in persistence. Include:

- `BackgroundTask` model: id, user_id, task_type, status, progress, result, error_message, created_at, started_at, completed_at
- `TaskStatus` enum: pending, running, completed, failed, cancelled
- `TaskType` enum: ai_analysis, url_analysis, report_processing, admin_analytics, bulk_operation
- Relationships with User model
- Indexes for performance on user_id, status, and task_type

This provides persistence and tracking for FastAPI BackgroundTasks that would otherwise be fire-and-forget.

### src\services\task_tracking_service.py(NEW)

Create a service for tracking FastAPI BackgroundTasks in the database. This service will:

- Create task records when background tasks are started
- Update task status and progress during execution
- Store task results and error messages
- Provide methods like `create_task_record()`, `update_task_status()`, `get_task_status()`, `mark_task_completed()`
- Handle task cleanup and retention policies
- Support task cancellation tracking (though FastAPI BackgroundTasks can't be truly cancelled)

This bridges the gap between FastAPI's fire-and-forget BackgroundTasks and the need for task monitoring and status tracking.

### src\controllers\base_controller.py(MODIFY)

Enhance the BaseController to include generic background task and webhook functionality. Add new methods:

- `queue_background_task(task_function, task_type, *args, callback_url=None, **kwargs)` - Generic method to queue FastAPI BackgroundTasks with tracking
- `send_webhook_notification(event_type, payload, webhook_url, secret=None)` - Generic webhook sending using WebhookService
- `get_task_status(task_id)` - Get status of tracked background task
- `create_task_record(task_type, user_id=None)` - Create database record for task tracking

Integrate with the new `WebhookService` and `TaskTrackingService`. Update the constructor to inject these services. Add a `background_tasks: BackgroundTasks` parameter to the constructor for dependency injection.

This provides a consistent interface for all controllers to use background tasks and webhooks without duplicating code, building on the existing patterns in `src/controllers/base_controller.py`.

### src\controllers\ai_analysis_controller.py(MODIFY)

Convert AI analysis operations to use FastAPI BackgroundTasks and support webhooks. Modify:

- `analyze_content()` - Add `callback_url` and `background_tasks` parameters, queue the analysis as a background task, return task_id immediately with 202 status
- `find_similar_content()` - For large similarity searches, make this async with webhook support
- `retry_analysis()` - Queue retry as background task
- Add `async_mode: bool = True` parameter to allow sync/async choice

Create new background task functions:
- `_perform_ai_analysis_task()` - Background function for AI content analysis
- `_perform_similarity_search_task()` - Background function for similarity searches

Integrate with the enhanced `BaseController` methods for task queuing and webhook notifications. The heavy AI processing will run in FastAPI BackgroundTasks instead of blocking the request.

The current implementation in `src/controllers/ai_analysis_controller.py` has good structure but runs everything synchronously.

### src\controllers\report_controller.py(MODIFY)

Enhance the report controller to use the new webhook system while keeping FastAPI BackgroundTasks. Modify:

- `create_report()` - Replace inline background tasks with the new generic webhook system
- `_analyze_reported_url()` and `_notify_moderation_team()` - Update to use the new WebhookService for notifications
- Add webhook notifications for report status changes (assigned, resolved, etc.)
- Add `callback_url` parameter to report creation for webhook notifications
- Update `assign_report()` and `resolve_report()` to send webhook notifications

Integrate with the enhanced `BaseController` methods and `WebhookService`. The current implementation already uses `BackgroundTasks` effectively, so we're mainly standardizing the webhook delivery.

The existing code in `src/controllers/report_controller.py` already has good background task patterns that we can enhance.

### src\controllers\admin_controller.py(MODIFY)

Add FastAPI BackgroundTasks support for long-running admin operations. Modify methods that could benefit from async processing:

- `get_dashboard_statistics()` - Add async mode for large datasets with webhook notifications
- `get_traffic_analytics()` - Queue as background task for complex analytics
- `get_user_analytics()` - Make async for large user bases
- Add webhook support for admin events like configuration changes
- Add `background_tasks: BackgroundTasks` parameter to relevant methods

Add `callback_url` parameters where appropriate and integrate with the enhanced `BaseController` methods. Some admin operations like simple configuration retrieval can remain synchronous, but complex analytics should be moved to background tasks.

The current implementation in `src/controllers/admin_controller.py` is mostly synchronous but could benefit from background processing for heavy operations.

### src\routes\tasks.py(NEW)

Create API routes for task monitoring and management. Include endpoints:

- `GET /api/tasks/{task_id}` - Get task status and results from database
- `GET /api/tasks` - List user's tasks with filtering (status, type, date range)
- `DELETE /api/tasks/{task_id}` - Mark task as cancelled (FastAPI BackgroundTasks can't be truly cancelled)

Include request/response models:
- `TaskStatusResponse` with fields: task_id, status, progress, result, error, created_at, completed_at
- `TaskListResponse` with pagination and filtering
- `TaskType` enum for filtering

Integrate with the `TaskTrackingService` to provide task monitoring. Since FastAPI BackgroundTasks don't have built-in status tracking, this relies on database records.

Follow the same patterns as existing route files like `src/routes/ai_analysis.py` and `src/routes/url_check.py`.

### src\routes\ai_analysis.py(MODIFY)

Update AI analysis routes to support FastAPI BackgroundTasks and webhooks. Modify existing endpoints:

- Add `callback_url: Optional[HttpUrl] = Query(None)` parameter to `/analyze` endpoint
- Add `async_mode: bool = Query(True)` to allow sync/async choice
- Add `background_tasks: BackgroundTasks` dependency injection
- Update response models to include task_id when in async mode
- Modify `/analysis/{analysis_id}/similar` to support async processing for large similarity searches

Update the response handling to return 202 Accepted with task information when operating in async mode, or 200 OK with results when operating synchronously.

The existing routes in `src/routes/ai_analysis.py` have good structure but need to be enhanced for async operations with BackgroundTasks.

### src\routes\report.py(MODIFY)

Enhance report routes to support webhook notifications with FastAPI BackgroundTasks. Modify:

- Add `callback_url: Optional[HttpUrl] = Query(None)` to the report creation endpoint
- Update request models to include webhook configuration
- Add webhook events for report status changes (assigned, resolved, etc.)
- Ensure all background operations use the new webhook system
- Add `background_tasks: BackgroundTasks` dependency where needed

Update response models to include task information when background processing is involved. The existing routes in `src/routes/report.py` already have good structure with BackgroundTasks.

### src\routes\admin.py(MODIFY)

Update admin routes to support FastAPI BackgroundTasks for heavy operations. Add:

- `callback_url` parameters for long-running analytics operations
- `background_tasks: BackgroundTasks` dependency injection
- Async mode support for dashboard statistics and analytics
- Webhook notifications for admin events (configuration changes, system alerts)

Modify endpoints that could benefit from background processing to return task IDs when operating asynchronously. Follow the same patterns established in other route files.

### app.py(MODIFY)

Update the main FastAPI application to include the new task monitoring routes. Add:

- Include the new task monitoring router: `app.include_router(tasks_router, prefix="/api", tags=["Tasks"])`
- Update any global configuration needed for the new services
- Ensure proper dependency injection setup for the new services

The existing `app.py` already has good structure with router inclusion patterns that we can follow.

### src\config\settings.py(MODIFY)

Add configuration settings for the new webhook system. Add new configuration sections:

- Webhook settings: default timeout, retry attempts, signature algorithm, max payload size
- Task tracking settings: retention period, cleanup intervals
- Webhook security settings: allowed domains, signature validation
- Background task settings: default timeouts, concurrency limits

Integrate these settings with the existing configuration structure. The current `settings.py` already has comprehensive configuration management that we can extend.

Based on the file summary, the settings file already has extensive configuration options, so we're adding to the existing structure.

### alembic\versions\003_add_task_tracking.py(NEW)

Create database migration for the new task tracking models. This migration will:

- Add the `background_tasks` table with columns: id, user_id, task_type, status, progress, result, error_message, created_at, started_at, completed_at
- Add appropriate indexes for performance on user_id, status, task_type, and created_at
- Add foreign key constraints between tasks and users
- Add enum types for TaskStatus and TaskType

Follow the same patterns as existing migrations in the `alembic/versions/` directory.

### src\controllers\depends.py(MODIFY)

Add dependency injection functions for the new services. Add:

- `get_webhook_service()` - Returns WebhookService instance
- `get_task_tracking_service()` - Returns TaskTrackingService instance
- Update existing controller dependencies to inject the new services
- Ensure proper dependency management and singleton patterns for service instances

The existing `src/controllers/depends.py` likely has patterns we can follow for dependency injection.