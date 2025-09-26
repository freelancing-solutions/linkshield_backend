# Project Structure

## Root Directory Layout
```
linkshield_backend/
├── app.py                      # FastAPI application entry point
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container configuration
├── docker-compose.yml          # Multi-service orchestration
├── alembic.ini                 # Database migration configuration
├── pytest.ini                 # Test configuration
├── Makefile                    # Development automation commands
├── .env.example               # Environment variables template
└── README.md                  # Project documentation
```

## Source Code Organization (`src/`)

### Core Application Structure
- **`config/`**: Application configuration and settings management
  - `settings.py`: Pydantic-based configuration with environment variables
  - `database.py`: Database connection and session management
  
- **`models/`**: SQLAlchemy database models
  - Organized by domain: `user.py`, `url_check.py`, `subscription.py`, etc.
  - `__init__.py`: Centralized model imports
  
- **`routes/`**: FastAPI route definitions (API endpoints)
  - RESTful API structure with versioning (`/api/v1/`)
  - Separate files per domain: `user.py`, `url_check.py`, `admin.py`
  
- **`controllers/`**: Business logic layer
  - Handles complex operations between routes and services
  - Domain-specific controllers matching route structure

### Service Layer
- **`services/`**: External service integrations and core business services
  - `virustotal.py`, `google_safe_browsing.py`: Security scanning APIs
  - `openai_service.py`: AI-powered content analysis
  - `email_service.py`: Email notifications via Resend
  - `advanced_rate_limiter.py`: Custom rate limiting implementation

### Security & Middleware
- **`security/`**: Security-related functionality
  - `middleware.py`: Security headers and request validation
  - SSRF protection, input sanitization, audit logging
  
- **`middleware/`**: Custom FastAPI middleware
  - `admin_audit.py`: Admin action auditing
  - Request/response processing and logging

- **`authentication/`**: User authentication services
  - JWT token management, session handling
  - Password validation and security policies

### Specialized Features
- **`bots/`**: Social media bot integration
  - `gateway.py`: Bot management and routing
  - Platform-specific handlers for Twitter, Telegram, Discord
  
- **`social_protection/`**: Social media content analysis
  - Extension data processing and content risk assessment
  
- **`agents/`**: AI agent functionality
  - Automated analysis and decision-making components

### Utilities & Support
- **`utils/`**: Shared utility functions
  - Common helpers, validators, and data processing functions
  
- **`alembic/`**: Database migration files
  - Version-controlled schema changes

## Testing Structure (`tests/`)
```
tests/
├── test_app.py                 # Application-level tests
├── test_*_functionality.py     # Feature-specific tests
├── test_*_integration.py       # Integration tests
├── test_*_security.py          # Security-focused tests
├── test_*_performance.py       # Performance tests
└── __init__.py
```

## Documentation (`docs/`)
- **`api/`**: API documentation and specifications
- **`database/`**: Database schema and migration docs
- **`security/`**: Security implementation details
- **`features/`**: Feature-specific documentation
- **`specs/`**: Technical specifications and requirements

## Configuration & Deployment
- **`logs/`**: Application log files (created at runtime)
- **`uploads/`**: File upload storage (created at runtime)
- **`.kiro/`**: Kiro IDE configuration and steering rules
- **`.venv/` or `venv/`**: Python virtual environment
- **`.git/`**: Git version control

## Key Architectural Patterns

### Layered Architecture
1. **Routes Layer**: FastAPI endpoints handling HTTP requests/responses
2. **Controllers Layer**: Business logic orchestration
3. **Services Layer**: External integrations and core business services
4. **Models Layer**: Data persistence and database interactions

### Configuration Management
- Environment-based configuration using Pydantic Settings
- All settings prefixed with `LINKSHIELD_` for clarity
- Separate configurations for development, testing, and production

### Security-First Design
- Comprehensive security middleware stack
- SSRF protection with configurable policies
- Advanced rate limiting with multiple strategies
- Audit logging for all critical operations
- Input validation and sanitization at multiple layers

### Async-First Implementation
- FastAPI's async capabilities throughout
- Async database operations with SQLAlchemy
- Background task processing for long-running operations
- Async external API integrations

### Modular Bot Architecture
- Centralized bot gateway for managing multiple platforms
- Platform-specific handlers with common interfaces
- Webhook-based real-time integration
- Rate limiting and security controls per platform