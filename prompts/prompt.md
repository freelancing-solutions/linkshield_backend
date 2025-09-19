I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

I have thoroughly explored the LinkShield backend codebase and discovered it's a comprehensive FastAPI-based URL security analysis platform. The system includes:

**Core Features:**
- URL security analysis with multiple threat intelligence providers (VirusTotal, Google Safe Browsing, URLVoid)
- AI-powered content analysis using OpenAI and local ML models
- User authentication with JWT tokens and API keys
- Subscription management with tiered plans (Free, Basic, Pro, Enterprise)
- Community reporting system with voting and moderation
- Real-time health monitoring and metrics
- Rate limiting and security middleware

**Architecture:**
- FastAPI with SQLAlchemy ORM and PostgreSQL database
- Redis for caching and rate limiting
- Background task processing with Celery
- Comprehensive security service with threat detection
- Modular controller-service architecture

**API Surface:**
- 5 main routers: health, url_check, user, report, ai_analysis
- 40+ endpoints covering all functionality
- Comprehensive request/response models with validation
- Proper error handling and status codes

The existing documentation in the `docs/` folder appears to be outdated and describes a Next.js application rather than the actual FastAPI backend. A complete rewrite is needed to accurately document the current system.

### Approach

I will create comprehensive API documentation that covers every aspect of the LinkShield backend system. The documentation will be structured for both developers integrating with the API and AI agents that need to understand the complete system architecture.

The approach will be:
1. **Complete API Reference** - Document all 40+ endpoints with request/response schemas, authentication requirements, and error codes
2. **Architecture Overview** - Explain the FastAPI-based system design, database models, and service integrations
3. **Authentication Guide** - Cover JWT tokens, API keys, sessions, and security features
4. **Feature Documentation** - Detail URL analysis, AI services, reporting system, and subscription management
5. **Integration Examples** - Provide practical examples for frontend developers
6. **Error Handling** - Comprehensive error taxonomy and troubleshooting guide

This will replace the outdated Next.js documentation with accurate FastAPI backend documentation.

### Reasoning

I systematically explored the LinkShield backend codebase by:

1. **Initial Assessment** - Listed the project structure and identified it as a FastAPI Python backend, not the Next.js application described in existing docs
2. **Core Analysis** - Examined the main application entry point (`app.py`), configuration (`settings.py`), and requirements to understand the tech stack
3. **Route Exploration** - Read all 5 router files to understand the complete API surface area and endpoint structure
4. **Model Investigation** - Analyzed all SQLAlchemy models to understand the data structure and relationships
5. **Service Review** - Examined key services like URL analysis, AI analysis, and security to understand business logic
6. **Controller Analysis** - Reviewed controllers to understand request handling and error patterns

This comprehensive exploration revealed the complete scope of the system and identified the gap between existing documentation and actual implementation.

## Mermaid Diagram

sequenceDiagram
    participant Dev as Frontend Developer
    participant API as LinkShield API
    participant Auth as Authentication Service
    participant Analysis as URL Analysis Service
    participant AI as AI Service
    participant DB as Database
    participant External as External APIs

    Note over Dev,External: Complete LinkShield API Documentation Flow

    Dev->>API: POST /api/v1/user/register
    API->>Auth: Validate & Create User
    Auth->>DB: Store User Data
    API-->>Dev: User Created + JWT Token

    Dev->>API: POST /api/v1/url-check/check (with JWT)
    API->>Auth: Verify Token & Check Limits
    Auth-->>API: User Validated
    API->>Analysis: Analyze URL
    Analysis->>External: Query VirusTotal, Safe Browsing
    Analysis->>AI: AI Content Analysis
    AI-->>Analysis: Quality Scores & Topics
    External-->>Analysis: Threat Intelligence
    Analysis->>DB: Store Results
    Analysis-->>API: Analysis Complete
    API-->>Dev: URL Check Results

    Dev->>API: GET /api/v1/ai-analysis/history
    API->>Auth: Verify Token
    API->>DB: Query User's AI Analyses
    DB-->>API: Analysis History
    API-->>Dev: Paginated Results

    Dev->>API: POST /api/v1/reports/
    API->>Auth: Verify Token
    API->>DB: Create Report
    API-->>Dev: Report Created

    Note over Dev,External: Documentation covers all endpoints, authentication, rate limits, and error handling

## Proposed File Changes

### docs\api\README.md(NEW)

References: 

- app.py
- src\config\settings.py
- README.md

Create the main API documentation index that provides an overview of the LinkShield Backend API. This will serve as the entry point for developers and AI agents.

Include:
- Overview of LinkShield as a URL security analysis platform
- FastAPI-based architecture summary
- Quick start guide for developers
- Authentication overview (JWT + API keys)
- Base URLs for different environments
- Link to detailed endpoint documentation
- Rate limiting and usage quota information
- Support and contact information

This replaces the outdated documentation that described a Next.js application with accurate FastAPI backend information.

### docs\api\authentication.md(NEW)

References: 

- src\services\security_service.py
- src\authentication\auth_service.py
- src\routes\user.py
- src\models\user.py

Create comprehensive authentication documentation covering all authentication methods supported by the LinkShield backend.

Document:
- JWT token authentication flow with session management
- API key authentication for programmatic access
- Session management and expiration policies
- Rate limiting per authentication method
- Security headers and CORS configuration
- Authentication error codes and troubleshooting
- Code examples for different authentication scenarios

Reference the SecurityService implementation in `src/services/security_service.py` for JWT handling, session validation, and API key verification. Include the authentication dependencies from route files.

### docs\api\endpoints\url-analysis.md(NEW)

References: 

- src\routes\url_check.py
- src\controllers\url_check_controller.py
- src\services\url_analysis_service.py
- src\models\url_check.py

Document all URL analysis endpoints from the url_check router. This is the core functionality of LinkShield.

Cover:
- POST `/api/v1/url-check/check` - Single URL analysis with all scan types
- POST `/api/v1/url-check/bulk-check` - Bulk URL analysis (authenticated users only)
- GET `/api/v1/url-check/check/{check_id}` - Retrieve analysis results
- GET `/api/v1/url-check/check/{check_id}/results` - Detailed scan results
- GET `/api/v1/url-check/history` - User's analysis history with filtering
- GET `/api/v1/url-check/reputation/{domain}` - Domain reputation data
- GET `/api/v1/url-check/stats` - User statistics

For each endpoint include: authentication requirements, request/response schemas, scan types (SECURITY, REPUTATION, CONTENT), threat levels, error codes, rate limits, and usage examples.

Reference the URLCheckController and URLAnalysisService for business logic details.

### docs\api\endpoints\user-management.md(NEW)

References: 

- src\routes\user.py
- src\controllers\user_controller.py
- src\models\user.py
- src\models\subscription.py

Document all user management endpoints from the user router covering authentication, profile management, and account features.

Cover:
- POST `/api/v1/user/register` - User registration with validation
- POST `/api/v1/user/login` - User authentication
- POST `/api/v1/user/logout` - Session termination
- GET `/api/v1/user/profile` - User profile retrieval
- PUT `/api/v1/user/profile` - Profile updates
- POST `/api/v1/user/change-password` - Password changes
- POST `/api/v1/user/request-password-reset` - Password reset flow
- POST `/api/v1/user/reset-password` - Password reset confirmation
- API key management endpoints (create, list, delete)
- Session management endpoints
- Email verification endpoints

Include subscription plan information, usage limits, and user roles. Reference the User model and UserController for complete functionality.

### docs\api\endpoints\reports.md(NEW)

References: 

- src\routes\report.py
- src\controllers\report_controller.py
- src\models\report.py

Document the community reporting system endpoints from the report router.

Cover:
- POST `/api/v1/reports/` - Create security reports
- GET `/api/v1/reports/` - List reports with filtering
- GET `/api/v1/reports/{report_id}` - Get report details
- PUT `/api/v1/reports/{report_id}` - Update reports
- POST `/api/v1/reports/{report_id}/vote` - Vote on reports
- DELETE `/api/v1/reports/{report_id}/vote` - Remove votes
- PUT `/api/v1/reports/{report_id}/assign` - Assign reports (admin)
- PUT `/api/v1/reports/{report_id}/resolve` - Resolve reports (admin)
- GET `/api/v1/reports/stats/overview` - Report statistics
- GET `/api/v1/reports/templates/` - Report templates

Include report types (PHISHING, MALWARE, SPAM, etc.), status workflow, voting system, and admin moderation features. Reference the Report model and ReportController.

### docs\api\endpoints\ai-analysis.md(NEW)

References: 

- src\routes\ai_analysis.py
- src\services\ai_service.py
- src\models\ai_analysis.py

Document the AI-powered content analysis endpoints from the ai_analysis router.

Cover:
- POST `/api/v1/ai-analysis/analyze` - Perform AI content analysis
- GET `/api/v1/ai-analysis/analysis/{analysis_id}` - Get analysis results
- GET `/api/v1/ai-analysis/analysis/{analysis_id}/similar` - Find similar content
- GET `/api/v1/ai-analysis/history` - User's analysis history
- GET `/api/v1/ai-analysis/domain/{domain}/stats` - Domain analysis statistics
- POST `/api/v1/ai-analysis/analysis/{analysis_id}/retry` - Retry failed analysis
- GET `/api/v1/ai-analysis/status` - Service status and model information

Include analysis types (content summary, quality scoring, topic classification, sentiment analysis), processing status, similarity matching, and AI model details. Reference the AIAnalysis model and AIService.

### docs\api\endpoints\health-monitoring.md(NEW)

References: 

- src\routes\health.py
- src\controllers\health_controller.py
- src\config\database.py

Document the health check and monitoring endpoints from the health router.

Cover:
- GET `/api/health` - Basic health check
- GET `/api/health/detailed` - Detailed system health
- GET `/api/health/ready` - Kubernetes readiness probe
- GET `/api/health/live` - Kubernetes liveness probe
- GET `/api/version` - Version information
- GET `/api/metrics` - Application metrics

Include system status indicators, database connectivity checks, external service availability, uptime metrics, and monitoring integration details. Reference the HealthController and health check implementations.

### docs\api\data-models.md(NEW)

References: 

- src\models\user.py
- src\models\url_check.py
- src\models\report.py
- src\models\ai_analysis.py
- src\models\subscription.py

Document all data models and schemas used throughout the API.

Cover:
- User models (User, UserSession, APIKey)
- URL analysis models (URLCheck, ScanResult, URLReputation)
- Report models (Report, ReportVote, ReportTemplate)
- AI analysis models (AIAnalysis, ContentSimilarity)
- Subscription models (SubscriptionPlan, UserSubscription, Payment)
- Enumeration types (ThreatLevel, CheckStatus, ReportType, etc.)
- Request/response schemas for all endpoints
- Validation rules and constraints
- Relationship mappings between models

Include field descriptions, data types, constraints, and example JSON representations. This serves as a complete data dictionary for the API.

### docs\api\error-handling.md(NEW)

References: 

- app.py
- src\controllers\url_check_controller.py
- src\controllers\user_controller.py
- src\services\security_service.py

Create comprehensive error handling documentation covering all error scenarios in the LinkShield API.

Document:
- Standard error response format used across all endpoints
- HTTP status codes and their meanings (400, 401, 403, 404, 429, 500)
- Specific error codes (LIMIT_EXCEEDED, AI_LIMIT_EXCEEDED, INVALID_URL, etc.)
- Rate limiting errors with retry-after headers
- Authentication and authorization errors
- Validation errors with field-specific messages
- Service unavailable errors for external dependencies
- Error handling best practices for client applications
- Troubleshooting guide for common issues

Reference the error handling patterns from controllers and the global exception handler in `app.py`.

### docs\api\rate-limiting.md(NEW)

References: 

- src\services\security_service.py
- src\models\subscription.py
- src\security\rate_limiting.py
- src\config\settings.py

Document the comprehensive rate limiting system implemented in LinkShield.

Cover:
- Global rate limiting (10 requests per minute per IP)
- User-based rate limiting by subscription tier
- API endpoint specific limits (URL checks, AI analysis)
- Rate limit headers in responses
- Rate limit exceeded error handling
- Subscription plan limits and quotas
- Usage tracking and reset cycles
- Best practices for handling rate limits in client applications

Reference the SecurityService rate limiting implementation and subscription plan limits from the models.

### docs\api\subscription-system.md(NEW)

References: 

- src\models\subscription.py
- src\models\user.py
- src\config\settings.py

Document the subscription and billing system that controls access to LinkShield features.

Cover:
- Subscription plans (Free, Basic, Pro, Enterprise) with feature comparison
- Usage limits and quotas per plan
- Billing intervals (monthly, yearly)
- Trial periods and cancellation policies
- Payment processing integration (Stripe)
- Usage tracking and billing cycles
- Plan upgrade/downgrade workflows
- Feature access control based on subscription
- Webhook notifications for billing events

Reference the subscription models, payment processing, and usage limit enforcement throughout the codebase.

### docs\api\external-integrations.md(NEW)

References: 

- src\services\url_analysis_service.py
- src\services\ai_service.py
- src\services\email_service.py
- src\config\settings.py

Document all external service integrations used by LinkShield for threat detection and analysis.

Cover:
- VirusTotal API integration for malware detection
- Google Safe Browsing API for phishing detection
- URLVoid API for reputation checking
- OpenAI API for AI-powered content analysis
- Stripe integration for payment processing
- Email service integration (SMTP/Resend)
- Redis for caching and rate limiting
- Configuration requirements and API keys
- Service availability and fallback handling
- Rate limits and quotas for external services

Reference the URLAnalysisService, AIService, and configuration settings for external API integration details.

### docs\api\security.md(NEW)

References: 

- src\services\security_service.py
- src\security\middleware.py
- src\authentication\auth_service.py
- app.py

Document the comprehensive security features implemented in LinkShield.

Cover:
- Authentication mechanisms (JWT, API keys, sessions)
- Password security policies and validation
- Session management and expiration
- Rate limiting and abuse prevention
- Input validation and sanitization
- SQL injection and XSS protection
- CORS configuration and security headers
- IP reputation checking
- Suspicious activity detection
- Security event logging and monitoring
- Data encryption for sensitive information
- Security best practices for API consumers

Reference the SecurityService implementation and security middleware for comprehensive coverage.

### docs\api\examples\integration-guide.md(NEW)

References: 

- src\routes\url_check.py
- src\routes\user.py
- src\routes\ai_analysis.py
- src\models\user.py

Create practical integration examples for frontend developers and API consumers.

Include:
- Complete authentication flow examples (registration, login, token refresh)
- URL analysis workflow with error handling
- Bulk URL checking implementation
- AI analysis integration examples
- Report creation and management
- Subscription management integration
- Rate limit handling and retry logic
- WebSocket integration for real-time updates
- TypeScript/JavaScript SDK examples
- Python client library examples
- cURL examples for testing

Provide complete, working code examples that developers can copy and adapt for their applications.

### docs\api\examples\frontend-sdk.md(NEW)

References: 

- src\routes\url_check.py
- src\routes\user.py
- src\models\user.py
- src\models\url_check.py

Create a comprehensive guide for frontend developers building Next.js applications that integrate with the LinkShield backend.

Cover:
- TypeScript interfaces for all API responses
- React hooks for API integration
- Authentication context and token management
- Error boundary implementation for API errors
- Loading states and user feedback patterns
- Real-time updates with WebSocket integration
- Form validation matching backend requirements
- Subscription management UI components
- Dashboard implementation examples
- Best practices for API integration in Next.js

This serves as the bridge between the FastAPI backend and Next.js frontend applications.

### docs\api\deployment.md(NEW)

References: 

- Dockerfile
- docker-compose.yml
- alembic.ini
- src\config\settings.py
- src\config\database.py

Document deployment and operational aspects of the LinkShield backend.

Cover:
- Environment configuration and variables
- Database setup and migrations with Alembic
- Redis configuration for caching and rate limiting
- Docker deployment with docker-compose
- Production deployment considerations
- Environment-specific settings (development, staging, production)
- Health check endpoints for monitoring
- Logging configuration and log management
- Performance monitoring and metrics
- Backup and disaster recovery procedures
- Scaling considerations and load balancing

Reference the Docker configuration, Alembic migrations, and settings management.

### docs\README.md(MODIFY)

References: 

- app.py
- src\config\settings.py
- requirements.txt
- README.md

Update the main documentation README to accurately reflect the FastAPI backend architecture instead of the outdated Next.js application description.

Replace the existing content with:
- Accurate description of LinkShield as a FastAPI-based URL security analysis backend
- Updated technology stack (FastAPI, PostgreSQL, Redis, SQLAlchemy)
- Corrected architecture overview showing the actual backend components
- Updated navigation links pointing to the new API documentation
- Removal of frontend-specific documentation references
- Addition of backend-specific sections (API endpoints, data models, external integrations)
- Updated quick start guide for backend developers
- Corrected feature descriptions matching the actual implementation

This ensures the documentation accurately represents the current FastAPI backend system.