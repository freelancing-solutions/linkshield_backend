I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

I analyzed the current AI analysis route and compared it with the existing controller pattern used in other routes. The current `ai_analysis.py` route has all business logic directly in route handlers, while other routes like `user.py` and `url_check.py` follow a clean controller pattern where routes are thin and delegate to controller methods. I examined the existing `BaseController`, `URLCheckController`, and dependency injection patterns to understand the structure needed for the new AI analysis controller.

### Approach

I'll create an `AIAnalysisController` that follows the established controller pattern in this codebase. The controller will inherit from `BaseController` and contain all the business logic currently in the route handlers. I'll also create the necessary dependency injection functions and update the routes to use the controller pattern. This will make the code more maintainable, testable, and consistent with the rest of the application.

### Reasoning

I examined the current AI analysis route file and found it contains all business logic directly in route handlers. I then looked at other routes like user and URL check routes to understand the controller pattern used. I studied the base controller class and existing controllers to understand the structure, dependency injection patterns, and how routes delegate to controllers. I also examined the AI analysis service and models to understand what dependencies the new controller will need.

## Proposed File Changes

### src\controllers\ai_analysis_controller.py(NEW)

References: 

- src\controllers\base_controller.py
- src\controllers\url_check_controller.py
- src\services\ai_analysis_service.py
- src\models\ai_analysis.py

Create a new AI Analysis Controller that inherits from `BaseController` and contains all the business logic currently in the AI analysis route handlers. The controller will include methods for:

- `analyze_content()` - Handle content analysis requests with validation, rate limiting, and service delegation
- `get_analysis()` - Retrieve analysis results by ID with access control
- `find_similar_content()` - Find similar content with pagination and filtering
- `get_analysis_history()` - Get user's analysis history with pagination
- `get_domain_stats()` - Get domain analysis statistics
- `retry_analysis()` - Retry failed analyses
- `get_service_status()` - Get AI service status

The controller will handle:
- Input validation using the existing request models
- Rate limiting and user authentication
- Error handling and logging using base controller methods
- Service orchestration with `AIAnalysisService`
- Response formatting and access control
- UUID validation and database operations

The controller will be initialized with dependencies: `db_session`, `ai_analysis_service`, `security_service`, and `auth_service` following the same pattern as `URLCheckController`.

### src\controllers\depends.py(MODIFY)

References: 

- src\controllers\url_check_controller.py
- src\services\ai_analysis_service.py

Add dependency injection function for the AI Analysis Controller:

- Import the new `AIAnalysisController` class
- Import `AIAnalysisService` from services
- Add `get_ai_analysis_service()` dependency function if not already available
- Add `get_ai_analysis_controller()` function that creates and returns an `AIAnalysisController` instance with all required dependencies (db_session, ai_analysis_service, security_service, auth_service)

Follow the same pattern as the existing `get_url_check_controller()` function in this file, ensuring proper dependency injection and type hints.

### src\controllers\__init__.py(MODIFY)

References: 

- src\controllers\url_check_controller.py
- src\controllers\user_controller.py

Add the new `AIAnalysisController` to the controllers module exports:

- Import `AIAnalysisController` from `.ai_analysis_controller`
- Add it to the `__all__` list if one exists, or ensure it's available for import

This follows the same pattern as other controllers like `URLCheckController`, `UserController`, etc. that are already exported from this module.

### src\routes\ai_analysis.py(MODIFY)

References: 

- src\routes\url_check.py
- src\routes\user.py
- src\controllers\ai_analysis_controller.py(NEW)
- src\controllers\depends.py(MODIFY)

Refactor the AI analysis routes to use the controller pattern:

- Import `AIAnalysisController` and the dependency injection function from `src.controllers.depends`
- Remove the direct instantiation of `AIAnalysisService` at module level
- Update all route handlers to be thin and delegate business logic to controller methods:
  - `analyze_content()` → `controller.analyze_content()`
  - `get_analysis()` → `controller.get_analysis()`
  - `find_similar_content()` → `controller.find_similar_content()`
  - `get_analysis_history()` → `controller.get_analysis_history()`
  - `get_domain_stats()` → `controller.get_domain_stats()`
  - `retry_analysis()` → `controller.retry_analysis()`
  - `get_service_status()` → `controller.get_service_status()`

- Add `controller: AIAnalysisController = Depends(get_ai_analysis_controller)` to each route handler
- Remove all business logic, validation, database operations, and error handling from route handlers
- Keep only HTTP-specific concerns like request/response models and route decorators
- Remove direct database session and service dependencies since they'll be handled by the controller
- Update route handler signatures to pass the appropriate parameters to controller methods

The routes should become thin wrappers that delegate to the controller, similar to how `src/routes/url_check.py` and `src/routes/user.py` are structured.

### src\services\depends.py(MODIFY)

References: 

- src\services\ai_analysis_service.py
- src\controllers\depends.py(MODIFY)

Add dependency injection function for `AIAnalysisService` if it doesn't already exist:

- Add `get_ai_analysis_service()` function that returns an `AIAnalysisService` instance
- Follow the same pattern as other service dependency functions in this file
- Ensure proper type hints and async/await patterns if needed

This service dependency will be used by the AI analysis controller through the dependency injection system, maintaining consistency with how other services are provided.