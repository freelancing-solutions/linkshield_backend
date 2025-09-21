I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

AdminService currently takes `db_session: Session` in constructor and performs extensive database operations including queries, commits, and rollbacks. The service has methods like `get_system_statistics()`, `get_traffic_analytics()`, `get_threat_intelligence()`, etc. that all perform direct database queries. AdminController calls these service methods directly and handles error responses. The current dependency injection in `src/routes/admin.py` creates `AdminService(db)` and passes it to AdminController. This pattern needs to be completely refactored to move database operations to the controller while keeping business logic in the service.

### Approach

**Remove database session dependency and convert AdminService to pure business logic service:**

Refactor AdminService to become a pure data processing service without database dependencies. Move all database operations from AdminService to AdminController methods using the existing context manager pattern. Update service interfaces to accept data as parameters and return plain Python objects. Modify dependency injection to remove database session parameters from service constructors. Update AdminController to handle all database persistence decisions while using AdminService for data processing and business logic.

### Reasoning

I examined the AdminController and AdminService files to understand current database usage patterns. I found that AdminService takes a database session in its constructor and performs extensive database operations throughout all methods. I reviewed the admin routes file to understand how AdminService is instantiated with database sessions. I checked the admin models to understand the database structure including GlobalConfig, AdminAction, SystemHealth, and AdminSession models. I also examined the dependency injection setup to understand how services are currently instantiated.

## Mermaid Diagram

sequenceDiagram
    participant Controller as AdminController
    participant AdminService as AdminService (Refactored)
    participant Database as Database
    
    Note over AdminService: No database dependency
    
    Controller->>Controller: async with self.get_db_session() as session:
    Controller->>Database: Query User statistics
    Controller->>Database: Query URLCheck statistics  
    Controller->>Database: Query AIAnalysis statistics
    Database-->>Controller: Raw statistics data
    
    Controller->>AdminService: process_system_statistics(users_data, url_checks_data, ai_analyses_data)
    AdminService->>AdminService: Calculate metrics and format data
    AdminService-->>Controller: Processed statistics
    
    Controller->>Database: Commit transaction
    Controller-->>Controller: Return formatted response
    
    Note over Controller: All database operations in controller
    Note over AdminService: Pure data processing logic

## Proposed File Changes

### src\services\admin_service.py(MODIFY)

References: 

- src\config\settings.py

**Remove database session dependency and convert to pure business logic service:**

1. **Update constructor**:
   - Remove `db_session: Session` parameter
   - Remove `self.db` attribute
   - Keep only `self.settings = get_settings()`
   - Remove all database session references

2. **Convert database-dependent methods to pure data processing functions**:
   - `process_system_statistics(users_data: Dict, url_checks_data: Dict, ai_analyses_data: Dict) -> Dict[str, Any]` - process raw data into statistics format
   - `process_traffic_analytics(daily_traffic_data: List, top_domains_data: List, threat_types_data: List, days: int) -> Dict[str, Any]` - process traffic data
   - `process_threat_intelligence(recent_threats_data: Dict, threat_trends_data: List, threat_sources_data: List) -> Dict[str, Any]` - process threat data
   - `process_user_analytics(user_growth_data: List, subscription_data: List, top_users_data: List) -> Dict[str, Any]` - process user analytics

3. **Convert configuration methods to validation and processing functions**:
   - `process_configuration_data(configs_data: List, category: Optional[str] = None) -> List[Dict[str, Any]]` - format configuration data
   - `validate_configuration_update(key: str, value: str, config_data: Dict) -> None` - validate config changes
   - `process_configuration_update(config_data: Dict, key: str, value: str) -> Dict[str, Any]` - process config update

4. **Convert user management methods to data processing functions**:
   - `process_users_data(users_data: List, total: int, page: int, limit: int) -> Dict[str, Any]` - format user data
   - `validate_user_status_update(user_data: Dict, status: str, admin_user_id: str) -> None` - validate status change
   - `process_user_status_update(user_data: Dict, status: str) -> Dict[str, Any]` - process status update

5. **Convert system health methods to data processing functions**:
   - `process_system_health_data(health_checks_data: List, db_healthy: bool) -> Dict[str, Any]` - process health data
   - `calculate_overall_health_status(components: Dict) -> str` - determine overall status

6. **Keep utility methods as pure functions**:
   - `_get_system_uptime() -> str` - Keep as utility function
   - `_validate_config_value(config_data: Dict, value: str) -> None` - Keep validation logic
   - Move validation logic to accept config data as parameter instead of config object

7. **Remove all database operations**:
   - Remove all `self.db.query()` calls
   - Remove all `self.db.commit()` and `self.db.rollback()` calls
   - Remove all SQLAlchemy imports
   - Remove model imports that are only used for database operations

8. **Update imports**:
   - Remove database-related imports (`Session`, `SQLAlchemyError`, model imports)
   - Keep only data processing and utility imports
   - Remove `from src.config.database import check_database_health`

9. **Add helper methods for data structure validation**:
   - `validate_statistics_input(users_data: Dict, url_checks_data: Dict, ai_analyses_data: Dict) -> None`
   - `validate_analytics_input(daily_traffic_data: List, days: int) -> None`
   - `format_date_range_data(data: List, date_field: str) -> List[Dict]`

### src\controllers\admin_controller.py(MODIFY)

References: 

- src\services\admin_service.py(MODIFY)
- src\models\user.py
- src\models\url_check.py
- src\models\ai_analysis.py
- src\models\admin.py
- src\config\database.py

**Move all database operations from AdminService to AdminController:**

1. **Update constructor**:
   - Remove database session from AdminService instantiation
   - Update to: `AdminService()` without database session
   - Keep existing service dependencies

2. **Refactor `get_dashboard_statistics()` method**:
   - Add database operations using `async with self.get_db_session() as session:`
   - Query User, URLCheck, AIAnalysis models directly in controller
   - Collect raw data from database queries
   - Call `self.admin_service.process_system_statistics(users_data, url_checks_data, ai_analyses_data)`
   - Return processed results

3. **Refactor `get_traffic_analytics()` method**:
   - Move URLCheck and ScanResult queries to controller using database context manager
   - Query daily traffic, top domains, and threat distribution data
   - Call `self.admin_service.process_traffic_analytics(daily_traffic_data, top_domains_data, threat_types_data, days)`
   - Handle database operations in controller

4. **Refactor `get_threat_intelligence()` method**:
   - Move threat detection queries to controller using database context manager
   - Query recent threats, threat trends, and threat sources
   - Call `self.admin_service.process_threat_intelligence(recent_threats_data, threat_trends_data, threat_sources_data)`
   - Handle all database operations in controller

5. **Refactor `get_user_analytics()` method**:
   - Move User model queries to controller using database context manager
   - Query user growth, subscription distribution, and top users data
   - Call `self.admin_service.process_user_analytics(user_growth_data, subscription_data, top_users_data)`
   - Handle database operations in controller

6. **Refactor configuration management methods**:
   - Move GlobalConfig queries to controller in `get_configuration()` method
   - Call `self.admin_service.process_configuration_data(configs_data, category)`
   - Move configuration update logic to controller in `update_configuration()` method
   - Use `self.admin_service.validate_configuration_update()` for validation
   - Handle database commit/rollback in controller

7. **Refactor user management methods**:
   - Move User model queries to controller in `get_users()` method
   - Call `self.admin_service.process_users_data(users_data, total, page, limit)`
   - Move user status update logic to controller in `update_user_status()` method
   - Use `self.admin_service.validate_user_status_update()` for validation
   - Handle database operations in controller

8. **Refactor system health methods**:
   - Move SystemHealth queries to controller in `get_system_health()` method
   - Import and call `check_database_health()` directly in controller
   - Call `self.admin_service.process_system_health_data(health_checks_data, db_healthy)`
   - Handle database operations in controller

9. **Add helper methods for database operations**:
   - `_get_user_statistics(session) -> Dict` - get user counts and distribution
   - `_get_url_check_statistics(session) -> Dict` - get URL check metrics
   - `_get_traffic_data(session, start_date) -> Tuple` - get traffic analytics data
   - `_get_threat_data(session, start_date) -> Tuple` - get threat intelligence data
   - `_get_user_analytics_data(session, start_date) -> Tuple` - get user analytics data
   - `_get_configuration_data(session, category) -> List` - get configuration settings
   - `_update_configuration_in_db(session, config, value, user_id) -> Dict` - update configuration
   - `_get_users_from_db(session, filters, page, limit) -> Tuple` - get paginated users
   - `_update_user_status_in_db(session, user_id, status) -> Dict` - update user status
   - `_get_system_health_data(session) -> List` - get health check data

10. **Update error handling**:
    - Handle database errors separately from business logic errors
    - Ensure proper error logging for both database and service operations
    - Update exception handling to work with new service interface

11. **Add audit logging methods**:
    - `_log_config_change(session, key, old_value, new_value, user_id)` - log configuration changes
    - `_log_user_management_action(session, action, target_user_id, admin_user_id, details)` - log user management actions
    - Handle audit logging in controller using database context manager

### src\routes\admin.py(MODIFY)

References: 

- src\controllers\admin_controller.py(MODIFY)
- src\services\admin_service.py(MODIFY)
- src\services\depends.py(MODIFY)

**Update admin route dependency injection to work with refactored AdminService:**

1. **Update `get_admin_controller()` function**:
   - Remove `AdminService(db)` instantiation with database session
   - Change to: `AdminService()` without database session
   - Keep database session dependency for AdminController since it needs it for database operations
   - Update function to:
     ```python
     async def get_admin_controller(db: AsyncSession = Depends(get_db_session)) -> AdminController:
         admin_service = AdminService()
         # AdminController will use db session via inherited get_db_session() context manager
         return AdminController(
             security_service=SecurityService(),
             auth_service=AuthService(),
             email_service=EmailService(),
             admin_service=admin_service
         )
     ```

2. **Add service dependency imports**:
   - Import required services: `from src.services.security_service import SecurityService`
   - Import auth and email services: `from src.authentication.auth_service import AuthService`
   - Import email service: `from src.services.email_service import EmailService`
   - Or use dependency injection functions from services.depends

3. **Update imports**:
   - Ensure all required service imports are present
   - Remove any unused imports

4. **Add documentation**:
   - Add comments explaining that AdminService is now pure business logic
   - Document that AdminController handles all database operations
   - Explain the new dependency injection pattern

5. **Verify route functionality**:
   - Ensure all admin routes work with the new controller structure
   - Verify that error handling works correctly
   - Test that authentication and authorization still function properly

### src\services\depends.py(MODIFY)

References: 

- src\services\admin_service.py(MODIFY)

**Add AdminService dependency function without database session:**

1. **Add `get_admin_service()` function**:
   - Create new dependency function: `async def get_admin_service() -> AdminService:`
   - Return `AdminService()` without database session
   - Add proper imports for AdminService

2. **Update imports**:
   - Add `from src.services.admin_service import AdminService`
   - Ensure all imports are correct

3. **Add documentation**:
   - Add docstring explaining that AdminService is now pure business logic
   - Document that database operations are handled by controllers

4. **Keep consistent pattern**:
   - Follow the same pattern as other refactored services (EmailService, AuthService)
   - Ensure AdminService follows the pure business logic pattern

5. **Verify dependency chain**:
   - Ensure AdminService can be properly instantiated without database dependencies
   - Test that the service works correctly with the new interface

### src\controllers\depends.py(MODIFY)

References: 

- src\controllers\admin_controller.py(MODIFY)
- src\services\depends.py(MODIFY)

**Add AdminController dependency function using refactored AdminService:**

1. **Add `get_admin_controller()` function**:
   - Create new dependency function that uses refactored services
   - Import AdminService from services.depends: `from src.services.depends import get_admin_service`
   - Create function:
     ```python
     async def get_admin_controller(
         security_service: SecurityService = Depends(get_security_service),
         auth_service: AuthService = Depends(get_auth_service),
         email_service: EmailService = Depends(get_email_service),
         admin_service: AdminService = Depends(get_admin_service)
     ) -> AdminController:
         return AdminController(
             security_service=security_service,
             auth_service=auth_service,
             email_service=email_service,
             admin_service=admin_service
         )
     ```

2. **Update imports**:
   - Add `from src.controllers.admin_controller import AdminController`
   - Add `from src.services.depends import get_admin_service`
   - Ensure all required imports are present

3. **Add documentation**:
   - Add docstring explaining AdminController dependency injection
   - Document that AdminService is now pure business logic
   - Explain that database operations are handled by AdminController

4. **Verify consistency**:
   - Ensure AdminController follows the same pattern as other controllers
   - Test that all dependencies are correctly resolved
   - Verify that the controller works with refactored services