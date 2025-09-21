I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

SecurityService currently has extensive database operations including session validation, API key management, security reporting, and session cleanup. AIAnalysisService performs database operations for storing analysis results, finding similar content, and managing analysis history. BackgroundEmailService is imported in multiple places but the actual class definition doesn't exist, suggesting it was never implemented or was deleted during previous refactoring. The services/depends.py file shows inconsistent patterns where some services have been refactored to remove database dependencies while others still have them.

### Approach

**Refactor SecurityService, AIAnalysisService, and create BackgroundEmailService to be pure business logic services:**

Remove database session dependencies from SecurityService and AIAnalysisService constructors and convert them to pure business logic services. Create the missing BackgroundEmailService as a pure email task queuing service. Move all database operations to controllers using the existing context manager pattern. Update service interfaces to accept data as parameters and return plain Python objects. Modify dependency injection to remove database session parameters from service constructors.

### Reasoning

I examined the SecurityService and found it takes `db_session: AsyncSession` in constructor and performs extensive database operations including session validation, API key validation, security report generation, and session cleanup. I explored AIAnalysisService and found it also takes database session and performs database operations for content analysis storage and retrieval. I searched for BackgroundEmailService but found it's referenced in imports but the actual class doesn't exist - it appears to be a missing service that needs to be created. I reviewed the services/depends.py file to understand current dependency injection patterns and found inconsistencies where some services still have database dependencies.

## Mermaid Diagram

sequenceDiagram
    participant Controller as Controller (User/Admin/AI)
    participant SecurityService as SecurityService (Refactored)
    participant AIAnalysisService as AIAnalysisService (Refactored)
    participant BackgroundEmailService as BackgroundEmailService (New)
    participant Database as Database
    
    Note over SecurityService: No database dependency
    Note over AIAnalysisService: No database dependency
    Note over BackgroundEmailService: Pure task queuing service
    
    Controller->>Controller: async with self.get_db_session() as session:
    Controller->>Database: Query user sessions, API keys, etc.
    Database-->>Controller: Raw security data
    
    Controller->>SecurityService: validate_session_data(session_data, user_id)
    SecurityService->>SecurityService: Validate expiry, idle timeout, etc.
    SecurityService-->>Controller: Validation result
    
    Controller->>Database: Update session activity, security logs
    Database-->>Controller: Database operations completed
    
    Controller->>AIAnalysisService: analyze_content_data(url, content, types)
    AIAnalysisService->>AIAnalysisService: Perform AI analysis
    AIAnalysisService-->>Controller: Analysis results (Dict)
    
    Controller->>Database: Create/Update AIAnalysis records
    Controller->>Database: Store analysis results
    Database-->>Controller: Analysis stored
    
    Controller->>BackgroundEmailService: queue_email_task(email_data, priority)
    BackgroundEmailService->>BackgroundEmailService: Queue task in memory/cache
    BackgroundEmailService-->>Controller: Task ID
    
    Controller->>Database: Create EmailLog entry for task
    Database-->>Controller: EmailLog created
    
    Controller-->>Controller: Commit transaction

## Proposed File Changes

### src\services\security_service.py(MODIFY)

References: 

- src\config\settings.py

**Remove database session dependency and convert to pure security utility service:**

1. **Update constructor**:
   - Remove `db_session: AsyncSession` parameter
   - Remove `self.db` attribute
   - Keep settings, encryption, and configuration initialization
   - Remove all database session references

2. **Keep utility methods as pure functions**:
   - `hash_password()`, `verify_password()`, `validate_password_strength()` - Keep unchanged
   - `generate_secure_token()`, `create_jwt_token()`, `verify_jwt_token()` - Keep unchanged
   - `encrypt_sensitive_data()`, `decrypt_sensitive_data()` - Keep unchanged
   - `detect_suspicious_activity()`, `check_ip_reputation()` - Keep unchanged
   - `log_security_event()` - Keep as utility function

3. **Convert database-dependent methods to data processing functions**:
   - `validate_session_data(session_data: Dict, user_id: str) -> Tuple[bool, Optional[Dict]]` - validate session data without database queries
   - `validate_api_key_data(api_key_data: Dict, required_permissions: List[str]) -> Tuple[bool, Optional[Dict]]` - validate API key data
   - `process_security_report_data(sessions_data: List, url_checks_data: List, start_date: datetime, end_date: datetime) -> Dict[str, Any]` - process security data
   - `identify_expired_sessions(sessions_data: List) -> List[str]` - identify expired session IDs

4. **Remove database operations**:
   - Remove `validate_session()` method (logic moves to controllers)
   - Remove `validate_api_key()` method (logic moves to controllers)
   - Remove `generate_security_report()` method (logic moves to controllers)
   - Remove `cleanup_expired_sessions()` method (logic moves to controllers)
   - Remove all `self.db.query()`, `self.db.commit()` calls

5. **Update imports**:
   - Remove database-related imports (`AsyncSession`, `Session`, model imports)
   - Keep security and utility imports
   - Remove SQLAlchemy imports

6. **Add helper methods for data validation**:
   - `validate_session_expiry(session_data: Dict) -> bool` - check if session is expired
   - `validate_session_idle_timeout(session_data: Dict) -> bool` - check idle timeout
   - `calculate_security_metrics(data: Dict) -> Dict[str, Any]` - calculate security metrics
   - `format_security_recommendations(metrics: Dict) -> List[str]` - format recommendations

### src\services\ai_analysis_service.py(MODIFY)

References: 

- src\services\ai_service.py
- src\config\settings.py

**Remove database session dependency and convert to pure AI analysis service:**

1. **Update constructor**:
   - Remove `db_session: Optional[AsyncSession] = None` parameter
   - Remove `self.db_session` attribute
   - Keep `self.settings` and `self.ai_service` initialization
   - Remove database session references

2. **Convert database-dependent methods to pure analysis functions**:
   - `analyze_content_data(url: str, content: str, analysis_types: Optional[List[AnalysisType]] = None) -> Dict[str, Any]` - perform analysis and return results
   - `calculate_content_similarity(analysis1_data: Dict, analysis2_data: Dict) -> float` - calculate similarity without database
   - `process_analysis_results(ai_results: Dict[str, Any], processing_time: int) -> Dict[str, Any]` - format analysis results
   - `validate_analysis_input(url: str, content: str, analysis_types: List) -> None` - validate input parameters

3. **Remove database operations**:
   - Remove `analyze_content()` method (database logic moves to controller)
   - Remove `find_similar_content()` method (database logic moves to controller)
   - Remove `get_user_analysis_history()` method (moves to controller)
   - Remove `get_domain_analysis_stats()` method (moves to controller)
   - Remove `retry_failed_analysis()` method (moves to controller)
   - Remove all `self.db_session.add()`, `self.db_session.commit()` calls

4. **Keep core AI functionality**:
   - `_generate_content_hash()` - Keep as utility function
   - `initialize()` - Keep for AI model initialization
   - `_store_analysis_results()` - Convert to format results without database storage
   - `_calculate_similarity()` - Keep as pure calculation function
   - `_update_model_metrics()` - Convert to return metrics data instead of storing

5. **Update imports**:
   - Remove database-related imports (`AsyncSession`, `get_db_session`, model imports)
   - Keep AI service and analysis-related imports
   - Remove SQLAlchemy imports

6. **Add helper methods for data processing**:
   - `format_analysis_for_storage(analysis_results: Dict, metadata: Dict) -> Dict[str, Any]` - format for database storage
   - `extract_quality_metrics(ai_results: Dict) -> Dict[str, Any]` - extract quality data
   - `calculate_processing_metrics(start_time: datetime, ai_results: Dict) -> Dict[str, Any]` - calculate metrics
   - `validate_similarity_threshold(threshold: float) -> bool` - validate similarity parameters

### src\services\background_tasks.py(NEW)

References: 

- src\config\settings.py

**Create BackgroundEmailService as pure task queuing service:**

1. **Import required modules**:
   - Import typing, datetime, uuid for basic functionality
   - Import logging for task logging
   - Import enum for task status and priority
   - Import dataclasses for task data structures

2. **Define task data structures**:
   - `@dataclass EmailTaskData` - structure for email task data
   - `@dataclass BulkEmailTaskData` - structure for bulk email tasks
   - `TaskStatus` enum - PENDING, PROCESSING, COMPLETED, FAILED
   - `TaskPriority` enum - LOW, NORMAL, HIGH, URGENT

3. **Create BackgroundEmailService class**:
   - Pure task queuing service without database dependencies
   - Constructor only initializes settings and logger
   - No database session parameter

4. **Implement task queuing methods**:
   - `queue_email_task(email_data: EmailTaskData, priority: TaskPriority = TaskPriority.NORMAL) -> str` - queue single email
   - `queue_bulk_email_task(bulk_data: BulkEmailTaskData, priority: TaskPriority = TaskPriority.NORMAL) -> str` - queue bulk emails
   - `queue_verification_email_task(user_email: str, token: str, user_name: str) -> str` - queue verification email
   - `queue_password_reset_email_task(user_email: str, token: str, user_name: str) -> str` - queue password reset
   - `queue_welcome_email_task(user_email: str, user_name: str) -> str` - queue welcome email

5. **Implement task status methods**:
   - `get_task_status(task_id: str) -> Dict[str, Any]` - get task status (from in-memory or cache)
   - `cancel_task(task_id: str) -> bool` - cancel pending task
   - `retry_task(task_id: str) -> str` - retry failed task

6. **Add task validation methods**:
   - `validate_email_task_data(email_data: EmailTaskData) -> None` - validate email task data
   - `validate_bulk_email_data(bulk_data: BulkEmailTaskData) -> None` - validate bulk email data
   - `estimate_task_completion_time(task_type: str, data_size: int) -> int` - estimate completion time

7. **Implement in-memory task tracking**:
   - Use dictionaries to track task status and metadata
   - Implement simple task queue with priority handling
   - Add task cleanup for completed/failed tasks

8. **Add utility methods**:
   - `generate_task_id() -> str` - generate unique task ID
   - `format_task_response(task_id: str, status: TaskStatus) -> Dict[str, Any]` - format task response
   - `get_queue_statistics() -> Dict[str, Any]` - get queue statistics

Note: This is a simplified in-memory implementation. In production, this would integrate with Celery, RQ, or similar task queue systems.

### src\services\depends.py(MODIFY)

References: 

- src\services\background_tasks.py(NEW)
- src\services\security_service.py(MODIFY)
- src\services\ai_analysis_service.py(MODIFY)
- src\authentication\auth_service.py

**Update service dependency injection to remove database session parameters:**

1. **Update `get_security_service()` function**:
   - Remove any database session dependency if present
   - Change to: `async def get_security_service() -> SecurityService:`
   - Return `SecurityService()` without database session

2. **Add `get_background_email_service()` function**:
   - Create new dependency function: `async def get_background_email_service() -> BackgroundEmailService:`
   - Return `BackgroundEmailService()` without database session
   - Add proper imports for BackgroundEmailService

3. **Update `get_ai_analysis_service()` function**:
   - Remove `db_session: AsyncSession = Depends(get_db_session)` parameter
   - Change to: `async def get_ai_analysis_service() -> AIAnalysisService:`
   - Return `AIAnalysisService()` without database session

4. **Fix `get_auth_service()` function**:
   - The current implementation has incorrect parameters
   - Should only take `security_service: SecurityService = Depends(get_security_service)`
   - Remove email_service parameter since AuthService was refactored to not need it
   - Return `AuthService(security_service=security_service)`

5. **Update `get_rate_limits()` function**:
   - This function still uses database session for SecurityService
   - Update to use SecurityService as pure utility service
   - Move database operations to controller level
   - Change to accept user data as parameter instead of querying database

6. **Update imports**:
   - Add `from src.services.background_tasks import BackgroundEmailService`
   - Remove unused database session imports if no longer needed
   - Ensure all service imports are correct

7. **Add documentation**:
   - Add docstrings explaining that all services are now pure business logic
   - Document that database operations are handled by controllers
   - Explain the new dependency injection pattern

8. **Clean up unused functions**:
   - Remove any unused dependency functions
   - Ensure all functions follow the new pure service pattern

### src\controllers\user_controller.py(MODIFY)

References: 

- src\services\security_service.py(MODIFY)
- src\services\background_tasks.py(NEW)
- src\models\user.py

**Move database operations from SecurityService and BackgroundEmailService to UserController:**

1. **Update constructor**:
   - Ensure SecurityService and BackgroundEmailService are instantiated without database sessions
   - Services become pure business logic helpers

2. **Add session validation methods**:
   - `_validate_user_session(session, session_id: str, user_id: str) -> Tuple[bool, Optional[UserSession]]` - move from SecurityService
   - Use `async with self.get_db_session() as session:` for database operations
   - Call `self.security_service.validate_session_data()` for validation logic
   - Handle session expiry and idle timeout in controller

3. **Add API key validation methods**:
   - `_validate_user_api_key(session, api_key: str, required_permissions: List[str]) -> Tuple[bool, Optional[APIKey]]` - move from SecurityService
   - Use database context manager for API key lookup
   - Call `self.security_service.validate_api_key_data()` for validation logic
   - Handle API key updates in controller

4. **Add security reporting methods**:
   - `_generate_user_security_report(session, user_id: str, start_date: datetime, end_date: datetime) -> Dict[str, Any]`
   - Query user sessions, URL checks, and security events using database context manager
   - Call `self.security_service.process_security_report_data()` for data processing
   - Return formatted security report

5. **Add session cleanup methods**:
   - `_cleanup_expired_user_sessions(session, user_id: str) -> int` - cleanup user's expired sessions
   - Use database context manager for session queries and updates
   - Call `self.security_service.identify_expired_sessions()` for identification logic
   - Handle database updates in controller

6. **Update email task handling**:
   - Replace direct database operations with BackgroundEmailService task queuing
   - Call `self.background_email_service.queue_verification_email_task()` for verification emails
   - Call `self.background_email_service.queue_password_reset_email_task()` for password resets
   - Add EmailLog creation in controller after task queuing

7. **Add helper methods for security operations**:
   - `_log_security_event(session, event_type: str, details: Dict, user_id: str, ip_address: str)` - log security events to database
   - `_check_user_rate_limits(session, user_id: str, limit_type: str, ip_address: str) -> Tuple[bool, Dict]` - check rate limits with database
   - `_update_session_activity(session, session_id: str)` - update session last activity

8. **Update authentication methods**:
   - Ensure all authentication methods use controller-managed database operations
   - Use SecurityService only for utility functions (password hashing, JWT creation, etc.)
   - Handle user lookup, session creation, and security logging in controller

### src\controllers\ai_analysis_controller.py(MODIFY)

References: 

- src\services\ai_analysis_service.py(MODIFY)
- src\models\ai_analysis.py
- src\controllers\base_controller.py

**Move database operations from AIAnalysisService to AIAnalysisController:**

1. **Update constructor**:
   - Ensure AIAnalysisService is instantiated without database session
   - Service becomes pure AI analysis helper

2. **Refactor content analysis methods**:
   - Move database operations from AIAnalysisService to controller using `async with self.get_db_session() as session:`
   - Call `self.ai_analysis_service.analyze_content_data()` for analysis only
   - Handle AIAnalysis record creation and updates in controller
   - Create ContentSimilarity records in controller

3. **Add helper methods for database operations**:
   - `_get_existing_analysis(session, content_hash: str) -> Optional[AIAnalysis]` - moved from service
   - `_create_analysis_record(session, analysis_data: Dict) -> AIAnalysis` - create analysis record
   - `_update_analysis_results(session, analysis_id: str, results: Dict) -> AIAnalysis` - update with results
   - `_find_similar_analyses(session, analysis_id: str, threshold: float, limit: int) -> List[ContentSimilarity]` - moved from service
   - `_get_user_analysis_history(session, user_id: str, limit: int, offset: int) -> List[AIAnalysis]` - moved from service
   - `_get_domain_analysis_stats(session, domain: str) -> Dict[str, Any]` - moved from service

4. **Update analysis workflow methods**:
   - `analyze_content()` - handle database operations in controller, use service for AI analysis
   - `find_similar_content()` - move database queries to controller
   - `get_analysis_history()` - move database operations to controller
   - `get_domain_statistics()` - move database operations to controller
   - `retry_failed_analysis()` - move database operations to controller

5. **Add analysis result processing methods**:
   - `_process_ai_analysis_results(analysis_results: Dict, processing_time: int) -> Dict[str, Any]` - process results for storage
   - `_calculate_content_similarity_in_db(session, source_id: str, candidates: List[AIAnalysis]) -> List[ContentSimilarity]` - calculate and store similarities
   - `_update_model_metrics_in_db(session, metrics_data: Dict) -> None` - store model performance metrics

6. **Update error handling**:
   - Handle AI analysis errors separately from database errors
   - Ensure proper error logging for both AI analysis and database operations
   - Update analysis status appropriately for different error types

7. **Update background task methods**:
   - Ensure AI analysis background tasks work with refactored service interface
   - Handle database operations in controller, not in service
   - Maintain existing functionality while using new service interface

8. **Add content deduplication methods**:
   - `_check_content_duplication(session, content_hash: str) -> Optional[AIAnalysis]` - check for existing analysis
   - `_link_analysis_to_check(session, analysis_id: str, check_id: str, user_id: str) -> None` - link analysis to URL check

### src\controllers\admin_controller.py(MODIFY)

References: 

- src\services\security_service.py(MODIFY)
- src\models\user.py
- src\models\admin.py

**Update AdminController to work with refactored SecurityService:**

1. **Update security-related methods**:
   - Ensure SecurityService is used only for utility functions
   - Move security report generation database operations to controller
   - Use `async with self.get_db_session() as session:` for all security data queries

2. **Add security management methods**:
   - `_generate_system_security_report(session, start_date: datetime, end_date: datetime) -> Dict[str, Any]` - generate security reports
   - Query UserSession, URLCheck, and security events using database context manager
   - Call `self.security_service.process_security_report_data()` for data processing
   - Handle security metrics calculation in controller

3. **Add session management methods**:
   - `_cleanup_all_expired_sessions(session) -> int` - cleanup expired sessions system-wide
   - `_get_active_sessions_stats(session) -> Dict[str, Any]` - get session statistics
   - Use SecurityService only for session validation logic
   - Handle all database operations in controller

4. **Update user management methods**:
   - Ensure user security operations use controller-managed database operations
   - Use SecurityService for password validation and security checks
   - Handle user session invalidation in controller

5. **Add API key management methods**:
   - `_manage_system_api_keys(session, action: str, key_data: Dict) -> Dict[str, Any]` - manage API keys
   - Use SecurityService for key validation and generation
   - Handle database operations in controller

6. **Update audit logging methods**:
   - Ensure security event logging uses controller-managed database operations
   - Call `self.security_service.log_security_event()` for event formatting
   - Store security events in database using controller's context manager

7. **Add system monitoring methods**:
   - `_monitor_security_threats(session) -> Dict[str, Any]` - monitor security threats
   - `_analyze_suspicious_activity(session, time_range: timedelta) -> Dict[str, Any]` - analyze suspicious activity
   - Use SecurityService for threat detection logic
   - Handle database queries in controller

### src\routes\user.py(MODIFY)

References: 

- src\services\depends.py(MODIFY)
- src\services\background_tasks.py(NEW)
- src\controllers\user_controller.py(MODIFY)

**Update user route dependency injection to work with refactored services:**

1. **Update imports**:
   - Ensure BackgroundEmailService import points to correct location: `from src.services.background_tasks import BackgroundEmailService`
   - Update service dependency imports to use services.depends

2. **Update `get_background_email_service()` function**:
   - Ensure it returns BackgroundEmailService without database session
   - Change to use dependency from services.depends if available
   - Or keep simple instantiation: `return BackgroundEmailService()`

3. **Update `get_user_controller()` function**:
   - Remove `db: Session = Depends(get_db_session)` parameter since controllers manage their own sessions
   - Update to use refactored service dependencies:
     ```python
     async def get_user_controller(
         auth_service: AuthService = Depends(get_auth_service),
         email_service: EmailService = Depends(get_email_service),
         security_service: SecurityService = Depends(get_security_service),
         background_email_service: BackgroundEmailService = Depends(get_background_email_service)
     ) -> UserController:
     ```
   - Return controller with refactored services

4. **Update route handlers if needed**:
   - Ensure all route handlers work with the new controller structure
   - Verify that error handling works correctly
   - Test that authentication and authorization still function properly

5. **Add documentation**:
   - Add comments explaining that services are now pure business logic
   - Document that controllers handle all database operations
   - Explain the new dependency injection pattern

### src\authentication\dependencies.py(MODIFY)

References: 

- src\services\security_service.py(MODIFY)
- src\models\user.py

**Update authentication dependencies to work with refactored SecurityService:**

1. **Update `get_current_user()` function**:
   - Remove database session from SecurityService instantiation
   - Create SecurityService without database session: `SecurityService()`
   - Move user and session lookup logic to use database session directly in the dependency function
   - Use SecurityService only for JWT token verification and validation logic

2. **Add helper functions for database operations**:
   - `_get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]` - get user from database
   - `_validate_user_session_in_db(db: AsyncSession, session_id: str, user_id: str) -> Tuple[bool, Optional[UserSession]]` - validate session
   - Use SecurityService for session validation logic, database operations in dependency

3. **Update JWT token verification**:
   - Use `security_service.verify_jwt_token()` for token validation
   - Perform user and session lookups using database session directly
   - Remove database operations from SecurityService calls

4. **Update session validation**:
   - Call `security_service.validate_session_data()` for validation logic
   - Handle database operations for session updates directly in dependency
   - Ensure proper session activity tracking

5. **Update error handling**:
   - Ensure proper error handling for authentication failures
   - Maintain existing security behavior while using refactored services
   - Handle database errors separately from authentication errors

6. **Add rate limiting integration**:
   - Use SecurityService for rate limit checking logic
   - Handle rate limit data storage in dependency function
   - Ensure proper rate limit enforcement