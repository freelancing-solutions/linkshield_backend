### Observations

The LinkShield backend has a well-architected system with comprehensive URL analysis capabilities, a robust background task system, detailed project management with monitoring configurations, and a subscription system with proper limit enforcement. The existing URLAnalysisService can handle multiple scan types including broken links, the BackgroundTask system provides comprehensive task tracking and execution, the MonitoringConfig model has all necessary settings for automated scanning, and the subscription system includes monitoring-specific limits. The alert system is already in place with AlertInstance models for tracking specific alerts.

### Approach

I'll create a comprehensive automated monitoring system that leverages the existing LinkShield infrastructure. The approach involves building a MonitoringService that orchestrates periodic website scans using the existing URLAnalysisService, implementing a background task scheduler using the robust BackgroundTask system, adding scan result comparison and change detection capabilities, storing historical monitoring data, and ensuring all operations respect subscription plan limits. The system will integrate seamlessly with the existing project management, alert system, and subscription enforcement mechanisms.

### Reasoning

I explored the LinkShield backend codebase and examined the URL analysis service, background task system, project models, and subscription system. I analyzed how the existing URLAnalysisService handles different scan types including broken links, reviewed the comprehensive BackgroundTask system for task management, studied the Project and MonitoringConfig models for project-specific settings, and understood the subscription system's limit enforcement mechanisms. I identified that all the necessary infrastructure exists and needs to be orchestrated into an automated monitoring system.

## Mermaid Diagram

sequenceDiagram
    participant Scheduler as MonitoringScheduler
    participant Service as MonitoringService
    participant URLAnalysis as URLAnalysisService
    participant Database as Database
    participant AlertSystem as AlertSystem
    participant EmailService as EmailService

    Note over Scheduler,EmailService: Automated Monitoring Flow

    Scheduler->>Database: Query projects due for scanning
    Database-->>Scheduler: List of projects with MonitoringConfig
    
    loop For each project due for scan
        Scheduler->>Service: scan_project(project_id)
        Service->>Database: Get project and monitoring config
        Service->>Service: Validate subscription limits
        
        alt Subscription allows monitoring
            Service->>URLAnalysis: analyze_url(url, scan_types, depth, max_links)
            URLAnalysis-->>Service: AnalysisResults with scan data
            
            Service->>Database: Get previous scan results
            Service->>Service: Compare current vs previous results
            Service->>Service: Detect changes and new threats
            
            Service->>Database: Store MonitoringHistory record
            
            alt Changes detected or threats found
                Service->>AlertSystem: Create AlertInstance
                Service->>EmailService: Send notification email
                AlertSystem-->>Service: Alert created
                EmailService-->>Service: Email sent
            end
            
            Service->>Database: Update MonitoringConfig (last_scan_at, next_scan_at)
            Service-->>Scheduler: Scan completed successfully
            
        else Subscription limits exceeded
            Service->>Database: Log monitoring attempt with limit violation
            Service-->>Scheduler: Scan skipped due to limits
        end
    end
    
    Note over Scheduler,EmailService: Historical Data and Trend Analysis
    
    Scheduler->>Service: process_trend_analysis()
    Service->>Database: Query MonitoringHistory for trends
    Service->>Service: Calculate trend scores and risk metrics
    Service->>Database: Update trend analysis data
    
    Scheduler->>Service: cleanup_old_monitoring_data()
    Service->>Database: Archive/delete old monitoring records
    
    Note over Scheduler,EmailService: Background Task Integration
    
    Scheduler->>Database: Create BackgroundTask for monitoring
    Database-->>Scheduler: Task created with PENDING status
    Scheduler->>Service: Execute monitoring task
    Service->>Database: Update task status to RUNNING
    Service->>Service: Perform monitoring operations
    Service->>Database: Update task status to COMPLETED

## Proposed File Changes

### src\services\monitoring_service.py(NEW)

References: 

- src\services\url_analysis_service.py
- src\models\project.py
- src\models\subscription.py
- src\models\task.py(MODIFY)

Create a comprehensive MonitoringService that orchestrates automated website monitoring:

**Core Monitoring Service:**
- Create `MonitoringService` class with dependency injection for URLAnalysisService, database session, and email service
- Implement `scan_project(project_id: UUID)` method that performs comprehensive website analysis
- Add `schedule_project_scans()` method to identify and queue projects due for scanning
- Implement `process_scan_results(project_id: UUID, scan_results: AnalysisResults)` for result processing

**Scan Execution Methods:**
- Add `_perform_project_scan(project: Project, config: MonitoringConfig)` for individual project scanning
- Implement `_validate_subscription_limits(project: Project, config: MonitoringConfig)` to enforce plan limits
- Add `_create_scan_task(project_id: UUID, scan_type: str)` to create background tasks for monitoring
- Implement `_execute_monitoring_scan(project_id: UUID, config: MonitoringConfig)` for actual scan execution

**Change Detection and Comparison:**
- Add `_compare_scan_results(previous_results: Dict, current_results: Dict)` for detecting changes
- Implement `_detect_new_threats(previous_scan: URLCheck, current_scan: URLCheck)` for threat detection
- Add `_calculate_change_score(changes: Dict)` to quantify the significance of changes
- Implement `_identify_broken_link_changes(previous_links: List, current_links: List)` for link status changes

**Historical Data Management:**
- Add `_store_monitoring_history(project_id: UUID, scan_results: AnalysisResults, changes: Dict)` for data persistence
- Implement `_get_previous_scan_results(project_id: UUID)` to retrieve last scan for comparison
- Add `_cleanup_old_monitoring_data(project_id: UUID, retention_days: int)` for data management
- Implement `_aggregate_monitoring_statistics(project_id: UUID, period: str)` for analytics

**Alert Integration:**
- Add `_trigger_alerts(project_id: UUID, alert_type: AlertType, context: Dict)` for alert generation
- Implement `_should_trigger_alert(project: Project, alert_type: AlertType, severity: str)` for alert logic
- Add `_create_alert_instance(project_id: UUID, alert_type: AlertType, details: Dict)` for alert creation
- Implement `_send_monitoring_notifications(project_id: UUID, alerts: List[AlertInstance])` for notifications

**Subscription Limit Enforcement:**
- Add `_check_monitoring_permissions(user: User, project: Project)` to validate monitoring access
- Implement `_enforce_scan_frequency_limits(config: MonitoringConfig, plan: SubscriptionPlan)` for frequency validation
- Add `_apply_scan_depth_limits(requested_depth: int, plan: SubscriptionPlan)` for depth enforcement
- Implement `_apply_link_count_limits(requested_links: int, plan: SubscriptionPlan)` for link limit enforcement

**Error Handling and Logging:**
- Add comprehensive error handling for scan failures, network issues, and subscription violations
- Implement detailed logging for monitoring activities, scan results, and alert generation
- Add retry logic for transient failures and rate limiting for external API calls
- Include monitoring metrics collection for service performance tracking

The service should integrate with the existing URLAnalysisService, BackgroundTask system, Project models, and subscription enforcement mechanisms.

### src\services\monitoring_scheduler.py(NEW)

References: 

- src\models\task.py(MODIFY)
- src\models\project.py
- src\services\monitoring_service.py(NEW)

Create a background task scheduler for automated project monitoring:

**Scheduler Service:**
- Create `MonitoringScheduler` class that manages periodic monitoring tasks
- Implement `start_scheduler()` method to initialize the monitoring scheduler
- Add `schedule_monitoring_tasks()` method to identify and queue projects due for scanning
- Implement `process_monitoring_queue()` method to execute queued monitoring tasks

**Task Management:**
- Add `create_monitoring_task(project_id: UUID, scan_type: str)` to create background tasks
- Implement `execute_monitoring_task(task_id: str, project_id: UUID)` for task execution
- Add `update_task_progress(task_id: str, progress: int, message: str)` for progress tracking
- Implement `handle_task_completion(task_id: str, results: Dict)` for task completion handling

**Scheduling Logic:**
- Add `get_projects_due_for_scan()` to identify projects that need scanning based on MonitoringConfig
- Implement `calculate_next_scan_time(config: MonitoringConfig)` for scheduling calculations
- Add `prioritize_monitoring_tasks(projects: List[Project])` for task prioritization
- Implement `handle_scheduling_conflicts(tasks: List[BackgroundTask])` for conflict resolution

**Integration with FastAPI Background Tasks:**
- Add `register_monitoring_tasks()` method to register periodic monitoring with FastAPI
- Implement `create_background_task(project_id: UUID, task_type: TaskType)` for task creation
- Add `monitor_task_execution(task: BackgroundTask)` for execution monitoring
- Implement `cleanup_completed_tasks()` for task cleanup and maintenance

**Subscription-Aware Scheduling:**
- Add `validate_monitoring_permissions(project: Project)` to check subscription status
- Implement `apply_frequency_limits(config: MonitoringConfig, plan: SubscriptionPlan)` for limit enforcement
- Add `skip_monitoring_for_expired_subscriptions()` to handle expired subscriptions
- Implement `queue_monitoring_with_limits(project: Project, config: MonitoringConfig)` for limit-aware queuing

**Error Handling and Recovery:**
- Add comprehensive error handling for scheduling failures and task execution errors
- Implement retry logic for failed monitoring tasks with exponential backoff
- Add dead letter queue handling for persistently failing tasks
- Include monitoring and alerting for scheduler health and performance

**Configuration and Settings:**
- Add configurable settings for scheduler intervals, task timeouts, and retry policies
- Implement dynamic configuration updates without scheduler restart
- Add monitoring dashboard integration for scheduler status and metrics
- Include performance tuning options for high-volume monitoring scenarios

The scheduler should integrate with the existing BackgroundTask system, MonitoringService, and subscription enforcement mechanisms.

### src\models\monitoring_history.py(NEW)

References: 

- src\models\project.py
- src\models\url_check.py
- src\models\user.py

Create a comprehensive monitoring history model for storing scan results and change tracking:

**MonitoringHistory Model:**
- Create `MonitoringHistory` table with UUID primary key and proper indexing
- Add foreign key relationships to Project, User, and URLCheck models
- Include fields for scan metadata: scan_type, scan_duration, scan_timestamp, scan_status
- Add fields for scan results: threat_level, safety_score, broken_links_count, total_links_checked

**Change Detection Fields:**
- Add `previous_scan_id` foreign key to link to previous scan for comparison
- Include `changes_detected` boolean flag and `change_summary` JSON field for change details
- Add `threat_level_changed` boolean and `new_threats_detected` JSON array for threat changes
- Include `broken_links_changed` boolean and `broken_link_changes` JSON for link status changes

**Historical Metrics:**
- Add `performance_metrics` JSON field for response times, scan duration, and resource usage
- Include `scan_coverage` JSON field for crawl depth achieved, links discovered, and pages scanned
- Add `alert_triggers` JSON array for alerts generated during this scan
- Include `subscription_limits_applied` JSON for tracking limit enforcement

**Trend Analysis Fields:**
- Add `trend_score` float field for calculated trend analysis
- Include `improvement_score` float field for tracking website improvements
- Add `risk_score` float field for calculated risk assessment
- Include `change_velocity` float field for rate of change tracking

**Relationships and Indexes:**
- Add relationship to Project, User, URLCheck, and previous MonitoringHistory record
- Create indexes on project_id, scan_timestamp, threat_level, and changes_detected
- Add composite indexes for efficient querying: (project_id, scan_timestamp), (project_id, threat_level)
- Include indexes for trend analysis: (project_id, trend_score), (project_id, risk_score)

**Utility Methods:**
- Add `calculate_change_score()` method to quantify the significance of detected changes
- Implement `get_trend_data(days: int)` method to retrieve trend information
- Add `compare_with_previous()` method to compare with the previous scan
- Implement `to_dict()` method with comprehensive data serialization

**Data Retention and Cleanup:**
- Add `created_at` and `updated_at` timestamps with proper timezone handling
- Include `retention_until` field for automated data cleanup
- Add `is_archived` boolean flag for long-term storage management
- Implement data compression for older records

The model should integrate with the existing Project, URLCheck, and User models while providing comprehensive historical tracking capabilities.

### src\models\task.py(MODIFY)

Add monitoring task types to the existing TaskType enumeration:

**Add New Task Types:**
- Add `PROJECT_MONITORING = "project_monitoring"` for automated project scans
- Add `MONITORING_SCAN = "monitoring_scan"` for individual monitoring scan execution
- Add `CHANGE_DETECTION = "change_detection"` for scan result comparison tasks
- Add `ALERT_PROCESSING = "alert_processing"` for monitoring alert generation
- Add `MONITORING_CLEANUP = "monitoring_cleanup"` for historical data cleanup
- Add `TREND_ANALYSIS = "trend_analysis"` for monitoring trend calculation

**Update Task Priority Handling:**
- Ensure monitoring tasks can use appropriate priority levels
- Add logic for prioritizing critical monitoring tasks (security threats, broken links)
- Include support for user subscription level affecting task priority

**Add Monitoring-Specific Metadata:**
- Update task metadata structure to support monitoring-specific fields
- Include project_id, scan_type, and monitoring_config_id in task metadata
- Add support for tracking subscription limits applied during task execution

**Integration with Existing Task System:**
- Ensure new task types work with existing BackgroundTask model
- Maintain compatibility with existing task execution and tracking mechanisms
- Add proper error handling and retry logic for monitoring-specific failures

The changes should be minimal and maintain backward compatibility with the existing task system.

### src\models\__init__.py(MODIFY)

Update the models initialization file to include the new monitoring history model:

**Add Import Statement:**
- Add import for monitoring history model: `from .monitoring_history import MonitoringHistory`

**Update __all__ List:**
- Add `MonitoringHistory` to the __all__ list in the appropriate section
- Group it under the existing "# Project models" comment section
- Maintain alphabetical ordering within the section

**Ensure Proper Model Registration:**
- Verify that the new model is properly discoverable by Alembic for migration generation
- Ensure the model can be imported by other parts of the application
- Maintain consistency with existing model import patterns

This ensures that the new monitoring history model is properly integrated with the existing model system.

### src\services\depends.py(MODIFY)

References: 

- src\services\monitoring_service.py(NEW)
- src\services\monitoring_scheduler.py(NEW)

Add dependency injection for the new monitoring services:

**Add MonitoringService Dependency:**
- Create `get_monitoring_service()` function following the existing dependency injection pattern
- Use dependency injection for URLAnalysisService, database session, and email service
- Return configured MonitoringService instance

**Add MonitoringScheduler Dependency:**
- Create `get_monitoring_scheduler()` function with proper dependency injection
- Inject MonitoringService, database session, and background task dependencies
- Return configured MonitoringScheduler instance

**Function Implementation:**
```python
def get_monitoring_service(
    url_analysis_service: URLAnalysisService = Depends(get_url_analysis_service),
    db: AsyncSession = Depends(get_db_session),
    email_service = Depends(get_email_service),
) -> MonitoringService:
    return MonitoringService(
        url_analysis_service=url_analysis_service,
        db=db,
        email_service=email_service,
    )

def get_monitoring_scheduler(
    monitoring_service: MonitoringService = Depends(get_monitoring_service),
    db: AsyncSession = Depends(get_db_session),
) -> MonitoringScheduler:
    return MonitoringScheduler(
        monitoring_service=monitoring_service,
        db=db,
    )
```

**Integration with Existing Dependencies:**
- Follow the exact pattern used for other service dependencies in the file
- Ensure proper dependency chain for all required services
- Maintain consistency with existing dependency injection patterns

This ensures proper dependency injection for the new monitoring services while maintaining consistency with the existing architecture.

### alembic\versions\007_add_monitoring_history_table.py(NEW)

References: 

- alembic\versions\006_add_broken_link_fields.py
- alembic\versions\004_add_dashboard_project_models.py

Create a comprehensive Alembic migration for the monitoring history table:

**Migration Header:**
- Set revision ID as '007_add_monitoring_history_table'
- Set down_revision to '006_add_broken_link_fields'
- Include proper docstring describing the monitoring history functionality

**Create MonitoringHistory Table:**
- Create `monitoring_history` table with all columns as defined in the MonitoringHistory model
- Include UUID primary key, foreign keys to projects, users, and url_checks
- Add scan metadata fields: scan_type, scan_duration, scan_timestamp, scan_status
- Include scan results fields: threat_level, safety_score, broken_links_count, total_links_checked

**Add Change Detection Fields:**
- Add previous_scan_id foreign key for linking to previous scans
- Include changes_detected boolean and change_summary JSON fields
- Add threat_level_changed boolean and new_threats_detected JSON array
- Include broken_links_changed boolean and broken_link_changes JSON field

**Add Historical Metrics Fields:**
- Add performance_metrics JSON field for scan performance data
- Include scan_coverage JSON field for crawl coverage information
- Add alert_triggers JSON array for tracking generated alerts
- Include subscription_limits_applied JSON for limit tracking

**Add Trend Analysis Fields:**
- Add trend_score, improvement_score, risk_score, and change_velocity float fields
- Include proper constraints and default values for trend fields

**Create Performance Indexes:**
- Add index on project_id for efficient project-based queries
- Create composite index on (project_id, scan_timestamp) for time-series queries
- Add index on (project_id, threat_level) for threat-based filtering
- Include indexes on trend_score and risk_score for analytics queries
- Add index on changes_detected for change-based queries

**Add Foreign Key Constraints:**
- Create foreign key constraint to projects table with CASCADE delete
- Add foreign key constraint to users table with SET NULL delete
- Include foreign key constraint to url_checks table with SET NULL delete
- Add self-referencing foreign key for previous_scan_id with SET NULL delete

**Downgrade Function:**
- Implement complete rollback that drops the monitoring_history table
- Drop all indexes in correct order
- Ensure clean rollback without data loss

**Migration Validation:**
- Include validation to ensure migration runs successfully
- Add comments explaining the purpose of each field and index
- Follow the patterns established in existing migration files

The migration should be safe to run on existing databases and provide comprehensive monitoring history tracking capabilities.

### app.py(MODIFY)

References: 

- src\services\monitoring_scheduler.py(NEW)

Integrate the monitoring scheduler with the FastAPI application startup:

**Add Monitoring Scheduler Import:**
- Import the monitoring scheduler service: `from src.services.monitoring_scheduler import MonitoringScheduler`
- Import the dependency function: `from src.services.depends import get_monitoring_scheduler`

**Update Application Lifespan:**
- Modify the `lifespan` function to initialize and start the monitoring scheduler
- Add scheduler startup after database initialization
- Include scheduler shutdown in the cleanup phase

**Lifespan Integration:**
```python
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown."""
    logger.info("Starting LinkShield Backend API...")
    await init_db()
    logger.info("Database initialized successfully")
    
    # Initialize and start monitoring scheduler
    monitoring_scheduler = get_monitoring_scheduler()
    await monitoring_scheduler.start_scheduler()
    logger.info("Monitoring scheduler started successfully")
    
    yield
    
    logger.info("Shutting down LinkShield Backend API...")
    
    # Stop monitoring scheduler
    await monitoring_scheduler.stop_scheduler()
    logger.info("Monitoring scheduler stopped")
    
    await close_db()
    logger.info("Database connections closed")
```

**Error Handling:**
- Add proper error handling for scheduler startup failures
- Include graceful degradation if monitoring scheduler fails to start
- Ensure application can still function if monitoring is unavailable
- Add logging for scheduler startup and shutdown events

**Configuration Integration:**
- Ensure monitoring scheduler respects application configuration settings
- Add environment-specific scheduler behavior (development vs production)
- Include monitoring scheduler health checks in application health endpoints

The integration should be seamless and not affect the existing application functionality while adding automated monitoring capabilities.