I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

The LinkShield backend has a well-structured architecture with comprehensive user management, URL analysis, and admin functionality. The new project models (Project, ProjectMember, MonitoringConfig, ProjectAlert) have been implemented with proper relationships and utility methods. The existing authentication system supports role-based access control, and the admin routes demonstrate how to implement complex dashboard endpoints. The codebase uses async SQLAlchemy, follows UUID primary key patterns, and has consistent error handling and logging throughout.

### Approach

I'll create a comprehensive dashboard API system following the existing patterns in the LinkShield backend. The approach involves creating new dashboard routes that leverage the project models we've already implemented, building a dedicated DashboardController for business logic, and implementing proper authentication and authorization middleware. The dashboard will provide user-facing endpoints for project management, team collaboration, monitoring configuration, and analytics. I'll follow the established patterns from the user and admin routes, ensuring consistency in structure, error handling, and response models.

### Reasoning

I explored the repository structure and examined the existing models, routes, and controllers. I analyzed the user.py, user_controller.py, and dependencies.py files to understand the current authentication and route patterns. I also reviewed the project.py models to understand the new dashboard functionality and the admin.py routes to see how complex API endpoints are structured. I identified that the codebase follows a clean architecture with thin routes, business logic in controllers, and proper dependency injection patterns.

## Mermaid Diagram

sequenceDiagram
    participant Client
    participant DashboardRoutes
    participant DashboardController
    participant AuthDependencies
    participant ProjectModels
    participant Database

    Note over Client,Database: Dashboard Overview Flow
    Client->>DashboardRoutes: GET /api/v1/dashboard/overview
    DashboardRoutes->>AuthDependencies: get_current_user()
    AuthDependencies->>Database: Validate session & get user
    AuthDependencies-->>DashboardRoutes: User object
    DashboardRoutes->>DashboardController: get_dashboard_overview(user)
    DashboardController->>Database: Query projects, alerts, usage stats
    DashboardController-->>DashboardRoutes: Dashboard overview data
    DashboardRoutes-->>Client: DashboardOverviewResponse

    Note over Client,Database: Project Management Flow
    Client->>DashboardRoutes: POST /api/v1/dashboard/projects
    DashboardRoutes->>AuthDependencies: get_current_user()
    DashboardRoutes->>DashboardController: create_project(user, request_data)
    DashboardController->>Database: Check subscription limits
    DashboardController->>ProjectModels: Create Project & MonitoringConfig
    DashboardController->>Database: Save new project
    DashboardController-->>DashboardRoutes: Project response
    DashboardRoutes-->>Client: ProjectResponse

    Note over Client,Database: Team Management Flow
    Client->>DashboardRoutes: POST /api/v1/dashboard/projects/{id}/members
    DashboardRoutes->>AuthDependencies: get_project_owner()
    AuthDependencies->>Database: Verify project ownership
    DashboardRoutes->>DashboardController: invite_member(user, project_id, email, role)
    DashboardController->>ProjectModels: Create ProjectMember
    DashboardController->>Database: Save invitation
    DashboardController->>EmailService: Send invitation email
    DashboardController-->>DashboardRoutes: Member response
    DashboardRoutes-->>Client: MemberResponse

    Note over Client,Database: Analytics Flow
    Client->>DashboardRoutes: GET /api/v1/dashboard/analytics
    DashboardRoutes->>AuthDependencies: get_current_user()
    DashboardRoutes->>DashboardController: get_analytics(user, filters)
    DashboardController->>Database: Aggregate usage data, scan history
    DashboardController->>Database: Calculate trends and metrics
    DashboardController-->>DashboardRoutes: Analytics data
    DashboardRoutes-->>Client: AnalyticsResponse

## Proposed File Changes

### src\routes\dashboard.py(NEW)

References: 

- src\routes\user.py
- src\routes\admin.py
- src\authentication\dependencies.py(MODIFY)

Create a comprehensive dashboard routes file with the following endpoints:

**Dashboard Overview Route:**
- `GET /api/v1/dashboard/overview` - Returns user dashboard summary including project count, recent activity, subscription status, usage statistics, and alerts summary
- Include authentication via `get_current_user` dependency
- Return dashboard overview data with project statistics, monitoring status, and recent alerts

**Project Management Routes:**
- `GET /api/v1/dashboard/projects` - List user's projects with pagination, filtering, and search
- `POST /api/v1/dashboard/projects` - Create new monitoring project
- `GET /api/v1/dashboard/projects/{project_id}` - Get specific project details
- `PUT /api/v1/dashboard/projects/{project_id}` - Update project settings
- `DELETE /api/v1/dashboard/projects/{project_id}` - Delete project (soft delete)
- `POST /api/v1/dashboard/projects/{project_id}/toggle-monitoring` - Enable/disable monitoring

**Team Management Routes:**
- `GET /api/v1/dashboard/projects/{project_id}/members` - List project members
- `POST /api/v1/dashboard/projects/{project_id}/members` - Invite team member
- `PUT /api/v1/dashboard/projects/{project_id}/members/{member_id}` - Update member role
- `DELETE /api/v1/dashboard/projects/{project_id}/members/{member_id}` - Remove team member
- `POST /api/v1/dashboard/projects/{project_id}/members/{member_id}/accept` - Accept invitation

**Analytics Route:**
- `GET /api/v1/dashboard/analytics` - Get usage statistics, trends, scan history, and performance metrics
- Support date range filtering and metric type selection

**Request/Response Models:**
- Create Pydantic models for all request/response data following existing patterns
- Include proper validation, field descriptions, and examples
- Models: DashboardOverviewResponse, ProjectCreateRequest, ProjectResponse, ProjectUpdateRequest, MemberInviteRequest, MemberResponse, AnalyticsResponse

**Authentication & Authorization:**
- Use `get_current_user` for all authenticated endpoints
- Implement project ownership and member access checks
- Add proper error handling for unauthorized access

**Rate Limiting & Validation:**
- Apply appropriate rate limiting for creation and invitation endpoints
- Include comprehensive input validation and sanitization
- Follow existing error response patterns from `src/routes/user.py`

The routes should follow the thin layer pattern established in `src/routes/user.py`, delegating all business logic to the DashboardController.

### src\controllers\dashboard_controller.py(NEW)

References: 

- src\controllers\user_controller.py
- src\controllers\base_controller.py
- src\models\project.py
- src\models\subscription.py

Create a comprehensive DashboardController that handles all dashboard business logic:

**Controller Structure:**
- Inherit from BaseController following the pattern in `src/controllers/user_controller.py`
- Use dependency injection for SecurityService, AuthService, and EmailService
- Include proper error handling, logging, and rate limiting

**Dashboard Overview Methods:**
- `get_dashboard_overview(user)` - Aggregate user's project data, recent activity, subscription limits, and alert summaries
- Calculate usage statistics against subscription plan limits from `SubscriptionPlan` model
- Include recent scan results, active alerts, and system notifications

**Project Management Methods:**
- `list_projects(user, page, limit, search, status)` - Get paginated project list with filtering
- `create_project(user, request_data)` - Create new project with validation against subscription limits
- `get_project(user, project_id)` - Get project details with access control
- `update_project(user, project_id, request_data)` - Update project with permission checks
- `delete_project(user, project_id)` - Soft delete project with cleanup
- `toggle_monitoring(user, project_id, enabled)` - Enable/disable project monitoring

**Team Management Methods:**
- `list_project_members(user, project_id)` - Get project team members with roles
- `invite_member(user, project_id, email, role)` - Send team invitation with email notification
- `update_member_role(user, project_id, member_id, new_role)` - Update team member permissions
- `remove_member(user, project_id, member_id)` - Remove team member with cleanup
- `accept_invitation(user, project_id, invitation_token)` - Accept team invitation

**Analytics Methods:**
- `get_analytics(user, date_range, metrics)` - Generate usage analytics and trends
- Aggregate scan history, performance metrics, and usage patterns
- Calculate subscription usage and remaining limits

**Access Control Methods:**
- `check_project_access(user, project_id, required_role)` - Verify user can access project
- `check_subscription_limits(user, action)` - Validate against subscription plan limits
- `can_create_project(user)` - Check if user can create more projects

**Utility Methods:**
- `send_invitation_email(project, invitee_email, inviter, role)` - Send team invitation emails
- `log_project_activity(project_id, user_id, action, details)` - Log project activities
- `calculate_usage_stats(user)` - Calculate current usage against limits

**Response Models:**
- Create comprehensive Pydantic response models for all return data
- Include proper serialization of project, member, and analytics data
- Follow patterns from `src/controllers/user_controller.py` for response model structure

**Error Handling:**
- Implement proper HTTP exception handling for all scenarios
- Include specific error messages for subscription limits, access denied, and validation failures
- Use consistent error response format across all methods

The controller should integrate with the Project, ProjectMember, MonitoringConfig, and ProjectAlert models from `src/models/project.py`.

### src\controllers\depends.py(MODIFY)

References: 

- src\controllers\user_controller.py

Add dependency injection function for the DashboardController:

**Add Import:**
- Import the new DashboardController class

**Add Dependency Function:**
- Create `get_dashboard_controller()` function following the same pattern as existing controller dependencies
- Use dependency injection for SecurityService, AuthService, and EmailService
- Return configured DashboardController instance

**Function Implementation:**
```python
def get_dashboard_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service = Depends(get_email_service),
) -> DashboardController:
    return DashboardController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
    )
```

This follows the exact pattern used for other controllers in the file and ensures proper dependency injection for the dashboard functionality.

### src\authentication\dependencies.py(MODIFY)

References: 

- src\models\project.py
- src\models\user.py

Add project-specific authorization dependencies for dashboard access control:

**Add Project Access Dependencies:**
- `get_project_owner(project_id, current_user)` - Verify user owns the specified project
- `get_project_member(project_id, current_user, min_role)` - Verify user has minimum role in project
- `get_project_admin(project_id, current_user)` - Verify user has admin access to project

**Implementation Details:**
- Add async functions that check project membership and roles
- Query Project and ProjectMember models to verify access
- Raise HTTPException with 403 Forbidden for unauthorized access
- Raise HTTPException with 404 Not Found for non-existent projects
- Return the project object for successful authorization

**Helper Functions:**
- `_get_project_by_id(db, project_id)` - Database lookup for project
- `_check_project_membership(db, project_id, user_id, min_role)` - Verify membership and role
- `_get_user_project_role(db, project_id, user_id)` - Get user's role in project

**Usage Pattern:**
```python
async def get_project_owner(
    project_id: str = Path(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> Project:
    # Verify project exists and user is owner
    # Return project object or raise HTTPException
```

**Integration:**
- Import ProjectRole enum from `src/models/project.py`
- Use existing database session and user authentication patterns
- Follow error handling patterns from existing dependencies
- Add proper logging for authorization attempts

These dependencies will be used in dashboard routes to ensure users can only access projects they own or are members of, with appropriate role-based permissions.

### src\routes\__init__.py(MODIFY)

Add the new dashboard router to the routes module:

**Add Import:**
- Import the dashboard router: `from .dashboard import router as dashboard_router`

**Update Router List:**
- Add `dashboard_router` to the list of available routers
- Ensure it's properly exported for use in the main application

**Update __all__ List:**
- Include `dashboard_router` in the __all__ list if one exists
- Maintain alphabetical ordering of router imports

This ensures the dashboard routes are properly discoverable and can be included in the main FastAPI application routing.

### app.py(MODIFY)

References: 

- src\routes\user.py
- src\routes\admin.py

Register the new dashboard router with the FastAPI application:

**Add Router Import:**
- Import the dashboard router from routes: `from src.routes.dashboard import router as dashboard_router`

**Register Router:**
- Add the dashboard router to the FastAPI app using `app.include_router(dashboard_router)`
- Place it in the appropriate section with other API routers
- Ensure it's registered after authentication middleware is set up

**Router Registration:**
```python
# Add after existing router registrations
app.include_router(dashboard_router)
```

**Placement:**
- Add the router registration in the same section where other routers (user, admin, url_check) are registered
- Maintain consistent ordering and formatting with existing router registrations
- Ensure the dashboard routes are available at `/api/v1/dashboard/*`

This makes the dashboard API endpoints accessible through the main FastAPI application and ensures they're properly integrated with the existing middleware and authentication systems.