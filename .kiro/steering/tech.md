# Technology Stack

## Core Framework & Language
- **Python 3.11+**: Primary language
- **FastAPI 0.104.1**: Modern async web framework with automatic OpenAPI documentation
- **Uvicorn**: ASGI server for production deployment
- **Pydantic**: Data validation and settings management with type hints

## Database & Storage
- **PostgreSQL 12+**: Primary database with SQLAlchemy ORM
- **Redis 6+**: Caching, session storage, and distributed rate limiting
- **Alembic**: Database migrations and schema versioning

## Authentication & Security
- **JWT**: Token-based authentication with refresh tokens
- **bcrypt**: Password hashing via passlib
- **python-jose**: JWT token handling with cryptographic support
- **Advanced Rate Limiting**: Custom implementation with Redis backend

## External Integrations
- **OpenAI GPT**: AI-powered content analysis
- **VirusTotal API**: URL threat detection
- **Google Safe Browsing API**: Malicious URL detection
- **URLVoid API**: Additional URL reputation checking
- **Resend**: Email service for notifications
- **Stripe**: Payment processing for subscriptions

## Social Media Bots
- **python-telegram-bot**: Telegram bot integration
- **discord.py**: Discord bot functionality
- **tweepy**: Twitter API integration

## Development Tools
- **pytest**: Testing framework with async support
- **black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Static type checking

## Deployment & Infrastructure
- **Docker**: Containerization with multi-stage builds
- **Docker Compose**: Local development and orchestration
- **Nginx**: Reverse proxy (optional)
- **Prometheus**: Metrics collection
- **Loguru**: Structured logging with rotation

## Common Commands

### Development Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env
# Edit .env with your configuration

# Database setup
createdb linkshield_db
alembic upgrade head

# Start Redis
redis-server

# Run development server
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest -m "unit"
pytest -m "integration"
pytest -m "security"
```

### Code Quality
```bash
# Format code
black .
isort .

# Lint code
flake8 src tests
mypy src

# Security analysis
bandit -r src
safety check
```

### Database Operations
```bash
# Create migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

### Docker Operations
```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Run tests in container
docker-compose run --rm api pytest
```

### Production Deployment
```bash
# Build production image
docker build -t linkshield-api .

# Run with Gunicorn
gunicorn app:app -w 4 -k uvicorn.workers.UvicornWorker

# Health check
curl http://localhost:8000/api/v1/health
```

## Configuration Management
- Environment variables with `LINKSHIELD_` prefix
- Pydantic Settings for type-safe configuration
- Separate configs for development, testing, and production
- Comprehensive security settings for SSRF protection, rate limiting, and audit logging