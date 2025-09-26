I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

The LinkShield backend has a sophisticated social protection system with three controllers: `SocialProtectionController` (main orchestrator), `UserController` (user-focused operations), and `ExtensionController` (browser extension integration). However, the specialized controllers are not accessible via routes, and there's no clear architectural decision on browser extension strategy. The current routes only expose basic extension data processing through the main controller, missing the rich functionality available in the specialized controllers.

### Approach

The implementation will focus on three key areas: 1) Making an architectural decision on browser extension strategy (one unified extension vs multiple specialized extensions), 2) Creating proper route integration for the existing sophisticated controllers, and 3) Documenting the complete browser extension architecture. This approach leverages existing well-built controllers rather than rebuilding functionality, ensuring the dashboard integration works seamlessly while providing a clear roadmap for browser extension development.

### Reasoning

I analyzed the current LinkShield backend structure by examining the main application file, route configurations, and the three key controllers in the social protection module. I discovered that while sophisticated controllers exist for user protection and extension handling, they're not accessible via API routes. I also reviewed the existing social protection routes and found they only expose basic functionality through the main orchestrator controller, missing the rich features available in the specialized controllers.

## Mermaid Diagram

sequenceDiagram
    participant BE as Browser Extension
    participant API as API Gateway
    participant EC as Extension Controller
    participant UC as User Controller
    participant SPC as Social Protection Controller
    participant DB as Database
    participant BG as Background Tasks

    Note over BE,BG: Browser Extension Architecture Decision Flow

    BE->>API: POST /extension/process (session_id, content_data)
    API->>EC: process_extension_data()
    EC->>EC: Track session & analyze content
    EC->>DB: Cache analysis results
    EC-->>API: Immediate response
    API-->>BE: Risk assessment + UI indicators

    BE->>API: GET /user-protection/settings
    API->>UC: get_user_protection_settings()
    UC->>DB: Retrieve user preferences
    UC-->>API: Settings with subscription features
    API-->>BE: Extension configuration

    BE->>API: POST /user-protection/platform-scan
    API->>UC: initiate_user_platform_scan()
    UC->>BG: Schedule deep analysis
    UC->>DB: Create scan record
    UC-->>API: Scan initiated
    API-->>BE: Scan ID + status

    Note over BE,BG: Three Protection Modules in One Extension
    
    BE->>API: Social Media Shield requests
    BE->>API: Web Safety Shield requests  
    BE->>API: Content Protection Shield requests
    
    Note over API,DB: All modules use same authentication & session management

## Proposed File Changes

### \docs\extension\browser-extension-architecture.md(NEW)

References: 

- src\social_protection\controllers\extension_controller.py
- src\social_protection\controllers\user_controller.py
- docs\extension\README.MD

Create comprehensive browser extension architecture documentation that addresses the core architectural decision: **One Unified Extension with Feature Modules**. Document three main protection modules: 1) **Social Media Shield** - monitors social profiles, posts, engagement patterns, and algorithm health, 2) **Web Safety Shield** - analyzes URLs, blog content, e-commerce sites for trustworthiness and safety, 3) **Content Protection Shield** - scans for malware, phishing, suspicious downloads, and privacy leaks. Include detailed API surface design showing how each module communicates with backend controllers, authentication flow using JWT tokens, request/response schemas with session tracking, rate limiting strategies, and real-time vs polling communication patterns. Provide sequence diagrams for each protection module's workflow and decision matrix comparing one extension vs multiple extensions approach with clear justification for the unified approach.

### \src\controllers\depends.py(NEW)

References: 

- src\social_protection\controllers\user_controller.py
- src\social_protection\controllers\extension_controller.py

Add dependency injection providers for the specialized controllers that are currently not accessible via routes. Create `get_user_protection_controller()` function that properly wires all required services including security service, auth service, email service, social scan service, and all the content analysis services (ContentRiskAnalyzer, LinkPenaltyDetector, SpamPatternDetector, etc.) and algorithm health services (VisibilityScorer, EngagementAnalyzer, etc.). Create `get_extension_controller()` function that wires the ExtensionController with all its dependencies including the extension data processor and various analysis services. These providers should follow the same pattern as the existing `get_social_protection_controller()` function, ensuring proper service instantiation and dependency resolution.

### \src\routes\user_protection.py(NEW)

References: 

- src\social_protection\controllers\user_controller.py
- src\routes\social_protection.py

Create comprehensive FastAPI router for user protection functionality that exposes all methods from `UserController`. Include endpoints: GET `/api/v1/user-protection/settings` for retrieving user protection settings, PUT `/api/v1/user-protection/settings` for updating settings with validation, POST `/api/v1/user-protection/platform-scan` for initiating platform scans with background task support, POST `/api/v1/user-protection/content/analyze` for content analysis with different analysis types, GET `/api/v1/user-protection/analytics` for protection analytics with filtering options, and GET `/api/v1/user-protection/algorithm-health` for premium algorithm health analysis. Create comprehensive Pydantic request/response models for each endpoint including proper validation, examples, and field descriptions. Implement proper error handling, rate limiting integration, and authentication dependencies using the existing patterns from other route files.

### \src\routes\extension.py(NEW)

References: 

- src\social_protection\controllers\extension_controller.py
- src\routes\social_protection.py

Create specialized FastAPI router for browser extension functionality that exposes the sophisticated ExtensionController methods. Include endpoints: POST `/api/v1/extension/process` for processing extension data with session tracking, POST `/api/v1/extension/analyze-realtime` for real-time content analysis with caching, GET `/api/v1/extension/settings` for retrieving extension configuration, PUT `/api/v1/extension/settings` for updating extension settings, GET `/api/v1/extension/analytics` for extension usage analytics, and POST `/api/v1/extension/sync-state` for synchronizing extension state with backend. Create Pydantic models that include extension-specific fields like `session_id`, `tab_id`, `event_type`, `analysis_mode`, `response_type` that are used by ExtensionController but not currently exposed in API schemas. Implement proper authentication for extensions, rate limiting based on subscription tiers, and support for different response types (immediate, progressive, deferred) as implemented in the ExtensionController.

### \app.py(NEW)

References: 

- src\routes\user_protection.py
- src\routes\extension.py

Add the new routers to the FastAPI application by importing the new router modules and including them in the application. Import `user_protection_router` from `src.routes.user_protection` and `extension_router` from `src.routes.extension`. Add `app.include_router(user_protection_router)` and `app.include_router(extension_router)` after the existing router inclusions, following the same pattern as other routers. This ensures the new endpoints are properly mounted and accessible through the API, making the sophisticated functionality in UserController and ExtensionController available to clients including the dashboard and browser extensions.

### \src\social_protection\controllers\social_protection_controller.py(NEW)

References: 

- src\social_protection\controllers\extension_controller.py

Refactor the `process_extension_data` method to leverage the sophisticated ExtensionController instead of directly using ExtensionDataProcessor. Add ExtensionController as a dependency in the constructor and modify the method to delegate extension data processing to ExtensionController while maintaining backward compatibility. This creates a bridge between the existing API surface and the advanced extension functionality, ensuring that calls to the current `/api/v1/social-protection/extension/process` endpoint benefit from the session tracking, caching, and advanced analysis capabilities of ExtensionController. Update the method to handle the additional parameters like session_id and response_type that ExtensionController expects, providing sensible defaults when not provided by legacy clients.

### \docs\extension\api-integration-guide.md(NEW)

References: 

- src\routes\extension.py
- src\routes\user_protection.py

Create detailed API integration guide for browser extension developers showing how to integrate with each protection module. Document authentication flow including JWT token handling and refresh strategies. Provide complete request/response examples for each endpoint including headers, payload structure, and expected responses. Include rate limiting information with specific limits for free vs premium users. Document session management including how to maintain session_id and tab_id across requests. Provide error handling guidelines with common error scenarios and recommended retry strategies. Include real-time communication patterns showing when to use polling vs WebSocket connections. Add code examples in JavaScript showing how to make API calls from browser extension context, handle CORS, and manage background script communication.

### \docs\extension\extension-development-roadmap.md(NEW)

References: 

- docs\extension\browser-extension-architecture.md

Create comprehensive development roadmap for browser extension implementation showing three phases: **Phase 1 - Core Infrastructure** (authentication, basic API integration, settings sync), **Phase 2 - Social Media Shield** (profile scanning, content analysis, real-time monitoring), **Phase 3 - Web Safety & Content Protection** (URL analysis, blog trust scoring, malware detection). For each phase, define specific milestones, required backend endpoints, frontend components, testing strategies, and success metrics. Include technical specifications for extension manifest, permissions required, content script injection strategies, and background script architecture. Document the decision rationale for unified extension approach including development efficiency, user experience benefits, and maintenance considerations. Provide timeline estimates and resource requirements for each phase.

### \tests\test_user_protection_routes.py(NEW)

References: 

- src\routes\user_protection.py
- tests\test_social_protection_controllers.py

Create comprehensive test suite for user protection routes covering all endpoints with positive and negative test cases. Test authentication requirements, rate limiting behavior, input validation, and response formats. Include tests for settings retrieval and updates with subscription-based feature restrictions, platform scan initiation with background task verification, content analysis with different analysis types, analytics retrieval with filtering options, and algorithm health analysis for premium users. Mock external dependencies and database operations following the existing test patterns in the codebase. Ensure tests cover edge cases like invalid input data, rate limit exceeded scenarios, and unauthorized access attempts.

### \tests\test_extension_routes.py(NEW)

References: 

- src\routes\extension.py
- tests\test_social_protection_controllers.py

Create comprehensive test suite for extension routes covering all extension-specific endpoints. Test session tracking functionality, real-time analysis with caching behavior, settings synchronization, state management, and analytics retrieval. Include tests for different response types (immediate, progressive, deferred), extension authentication flows, and rate limiting based on subscription tiers. Test extension-specific parameters like session_id, tab_id, event_type, and analysis_mode. Mock the ExtensionController dependencies and verify proper integration with caching mechanisms. Include performance tests for real-time analysis endpoints and concurrency tests for session management.