I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

The current codebase has all controller logic mixed within the route files, making them large and difficult to maintain. Each route file (`report.py`, `url_check.py`, `user.py`, `health.py`) contains extensive business logic, validation, database operations, and service integrations. The existing `src/controllers/` directory is empty, providing a clean slate for implementing a proper controller architecture. The models are well-structured with clear relationships, and there are dedicated service classes for authentication, security, and URL analysis that the controllers can leverage.

### Approach

I'll create a comprehensive controller architecture that extracts business logic from the route files into dedicated controller modules. Each controller will handle specific domain logic while keeping routes clean and focused on HTTP handling. The controllers will follow a consistent pattern with dependency injection, proper error handling, and separation of concerns. This will improve code maintainability, testability, and reusability across the application.

### Reasoning

I examined the project structure and found that the `src/controllers/` directory exists but is empty. I then read through all the route files to understand the current architecture and business logic distribution. I also reviewed the model files to understand the data structures and relationships. The analysis revealed that each route file contains substantial controller logic that should be extracted into dedicated controller classes for better organization and maintainability.

## Mermaid Diagram

sequenceDiagram
    participant Route as Route Handler
    participant Controller as Domain Controller
    participant Service as Business Service
    participant Model as Data Model
    participant DB as Database

    Route->>Controller: Delegate business logic
    Controller->>Service: Use domain services
    Service->>Model: Query/manipulate data
    Model->>DB: Database operations
    DB-->>Model: Return data
    Model-->>Service: Return results
    Service-->>Controller: Return processed data
    Controller-->>Route: Return formatted response
    Route-->>Client: HTTP response

    Note over Route: Handles HTTP concerns
    Note over Controller: Manages business logic
    Note over Service: Provides domain services
    Note over Model: Data access layer

## Proposed File Changes

### src\controllers\__init__.py(MODIFY)

Create the main controllers module initialization file that exports all controller classes for easy importing. This file will serve as the central point for accessing all controllers and will include proper imports for `ReportController`, `URLCheckController`, `UserController`, and `HealthController`.

### src\controllers\base_controller.py(NEW)

References: 

- src\config\database.py
- src\config\settings.py

Create a base controller class that provides common functionality for all controllers. This will include:

- Common dependency injection patterns for database sessions, services, and settings
- Standard error handling and logging utilities
- Common validation helpers
- Response formatting utilities
- Rate limiting and authentication helpers

This base class will be inherited by all specific controllers to ensure consistency and reduce code duplication.

### src\controllers\report_controller.py(NEW)

References: 

- src\routes\report.py(MODIFY)
- src\models\report.py
- src\models\user.py
- src\services\security_service.py

Extract all report-related business logic from `src/routes/report.py` into a dedicated ReportController class. This controller will handle:

- Report creation with validation, duplicate checking, and priority assignment
- Report listing with filtering, pagination, and access control
- Report retrieval with permission checks
- Report updates with ownership validation
- Report voting functionality
- Report assignment and resolution (admin functions)
- Report statistics and analytics
- Report template management

The controller will use dependency injection for services like SecurityService and will include proper error handling, logging, and background task coordination. All Pydantic models and dependency functions will remain in the routes file.

### src\controllers\url_check_controller.py(NEW)

References: 

- src\routes\url_check.py(MODIFY)
- src\models\url_check.py
- src\models\user.py
- src\services\url_analysis_service.py
- src\services\ai_service.py
- src\services\security_service.py

Extract all URL check-related business logic from `src/routes/url_check.py` into a dedicated URLCheckController class. This controller will handle:

- Single URL analysis with rate limiting and validation
- Bulk URL checking with quota management
- URL check result retrieval with access control
- Detailed scan results with permission validation
- URL check history with filtering and pagination
- Domain reputation lookup and caching
- URL check statistics and metrics
- Webhook notification coordination

The controller will integrate with URLAnalysisService, AIService, and SecurityService through dependency injection. It will include proper error handling for various analysis failures and rate limiting scenarios.

### src\controllers\user_controller.py(NEW)

References: 

- src\routes\user.py(MODIFY)
- src\models\user.py
- src\authentication\auth_service.py
- src\services\security_service.py

Extract all user management business logic from `src/routes/user.py` into a dedicated UserController class. This controller will handle:

- User registration with validation and email verification
- User authentication and session management
- User logout and session invalidation
- Profile management and updates
- Password change and reset functionality
- API key creation, listing, and deletion
- Session management and termination
- Email verification and resending
- User preferences and settings

The controller will work with AuthService and SecurityService for authentication operations and will coordinate background tasks for email notifications. It will include comprehensive error handling for authentication failures and rate limiting.

### src\controllers\health_controller.py(NEW)

References: 

- src\routes\health.py(MODIFY)
- src\config\database.py
- src\config\settings.py

Extract health check logic from `src/routes/health.py` into a dedicated HealthController class. This controller will handle:

- Basic health checks with API status verification
- Detailed health checks including database and external service connectivity
- Readiness probes for Kubernetes deployment
- Liveness probes for container orchestration
- Version information and build details
- Application metrics collection and reporting

The controller will include proper error handling for service unavailability and will integrate with database health check functions from `src/config/database.py`. It will provide structured health data for monitoring systems.

### src\routes\report.py(MODIFY)

References: 

- src\controllers\report_controller.py(NEW)

Refactor the report routes to use the new ReportController. This involves:

- Importing the ReportController class from `src/controllers/report_controller.py`
- Keeping all Pydantic models (request/response classes) in this file
- Keeping dependency functions for authentication and permissions
- Modifying all route handlers to delegate business logic to controller methods
- Maintaining the same API interface and response formats
- Keeping background task function definitions but moving logic to controller
- Ensuring proper error handling and HTTP status code mapping

The routes will become thin wrappers that handle HTTP-specific concerns while delegating business logic to the controller.

### src\routes\url_check.py(MODIFY)

References: 

- src\controllers\url_check_controller.py(NEW)

Refactor the URL check routes to use the new URLCheckController. This involves:

- Importing the URLCheckController class from `src/controllers/url_check_controller.py`
- Keeping all Pydantic models and validation logic in this file
- Keeping dependency functions for authentication and rate limiting
- Modifying all route handlers to delegate business logic to controller methods
- Maintaining the same API interface and response formats
- Keeping background task function definitions but moving logic to controller
- Ensuring proper error handling and HTTP status code mapping

The routes will focus on HTTP request/response handling while the controller manages the URL analysis business logic.

### src\routes\user.py(MODIFY)

References: 

- src\controllers\user_controller.py(NEW)

Refactor the user routes to use the new UserController. This involves:

- Importing the UserController class from `src/controllers/user_controller.py`
- Keeping all Pydantic models and validation logic in this file
- Keeping dependency functions for authentication and rate limiting
- Modifying all route handlers to delegate business logic to controller methods
- Maintaining the same API interface and response formats
- Keeping background task function definitions but moving logic to controller
- Ensuring proper error handling and HTTP status code mapping

The routes will handle HTTP-specific concerns while the controller manages user authentication and profile management logic.

### src\routes\health.py(MODIFY)

References: 

- src\controllers\health_controller.py(NEW)

Refactor the health routes to use the new HealthController. This involves:

- Importing the HealthController class from `src/controllers/health_controller.py`
- Keeping all Pydantic models in this file
- Modifying all route handlers to delegate business logic to controller methods
- Maintaining the same API interface and response formats
- Ensuring proper error handling and HTTP status code mapping

The routes will become simple HTTP handlers that delegate health check logic to the controller while maintaining the same monitoring and probe endpoints.