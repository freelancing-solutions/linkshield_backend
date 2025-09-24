# Social Protection Implementation Guide

## Document Information

- **Document ID**: SP-002
- **Version**: 1.0.0
- **Date**: 2024-01-15
- **Status**: Active
- **Author**: LinkShield Development Team

## 1. Introduction

This implementation guide provides developers with detailed instructions for working with the Social Protection feature in the LinkShield backend. It covers setup, development workflows, testing procedures, and deployment guidelines.

## 2. Development Environment Setup

### 2.1 Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 6+
- Node.js 18+ (for frontend integration)
- Docker and Docker Compose

### 2.2 Local Development Setup

```bash
# Clone the repository
git clone https://github.com/linkshield/backend.git
cd linkshield_backend

# Create and activate virtual environment
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your local configuration

# Run database migrations
alembic upgrade head

# Start the development server
uvicorn src.app:app --reload --host 0.0.0.0 --port 8000
```

### 2.3 Database Setup

```sql
-- Create database
CREATE DATABASE linkshield_dev;

-- Create test database
CREATE DATABASE linkshield_test;

-- Run migrations
alembic upgrade head
```

### 2.4 Configuration

Key configuration settings in `src/config/settings.py`:

```python
# Social Protection Settings
SOCIAL_SCAN_RATE_LIMIT_PER_HOUR = 50
SOCIAL_PROTECTION_API_RATE_LIMIT = 100
SOCIAL_PROTECTION_ENABLED = True

# Platform API Keys (set in environment)
TWITTER_API_KEY = os.getenv("TWITTER_API_KEY")
FACEBOOK_API_KEY = os.getenv("FACEBOOK_API_KEY")
INSTAGRAM_API_KEY = os.getenv("INSTAGRAM_API_KEY")
```

## 3. Architecture Overview

### 3.1 Module Structure

```
src/
├── social_protection/
│   ├── __init__.py
│   ├── data_models.py          # Pydantic models
│   ├── services/
│   │   ├── __init__.py
│   │   ├── social_scan_service.py
│   │   └── extension_data_processor.py
│   └── utils/
│       ├── __init__.py
│       └── risk_calculator.py
├── models/
│   └── social_protection.py    # SQLAlchemy models
├── controllers/
│   └── social_protection_controller.py
├── routes/
│   └── social_protection.py    # FastAPI routes
└── migrations/
    └── versions/
        └── 007_add_social_protection_models.py
```

### 3.2 Key Components

#### 3.2.1 Data Models (Pydantic)

Located in `src/social_protection/data_models.py`:

```python
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class PlatformType(str, Enum):
    TWITTER = "twitter"
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    LINKEDIN = "linkedin"
    TIKTOK = "tiktok"
    YOUTUBE = "youtube"
    OTHER = "other"

class ProfileScanRequest(BaseModel):
    project_id: UUID
    platform: PlatformType
    target: str
    scan_type: str = "profile_analysis"
    options: Optional[Dict[str, Any]] = None

class ProfileScanResponse(BaseModel):
    scan_id: UUID
    status: str
    estimated_completion: Optional[datetime] = None
    created_at: datetime
```

#### 3.2.2 Database Models (SQLAlchemy)

Located in `src/models/social_protection.py`:

```python
from sqlalchemy import Column, String, DateTime, Text, Float, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB, ENUM
from sqlalchemy.orm import relationship
from src.database.base import Base

class SocialProfileScan(Base):
    __tablename__ = "social_profile_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    platform = Column(ENUM(PlatformType), nullable=False)
    target_url = Column(String(2048), nullable=False)
    scan_status = Column(ENUM(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    # ... additional columns
    
    # Relationships
    user = relationship("User", back_populates="social_scans")
    project = relationship("Project", back_populates="social_scans")
```

#### 3.2.3 Services

**Social Scan Service** (`src/social_protection/services/social_scan_service.py`):

```python
class SocialScanService:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        
    async def initiate_profile_scan(
        self, 
        user_id: UUID, 
        request: ProfileScanRequest
    ) -> ProfileScanResponse:
        """Initiate a new social media profile scan."""
        # Implementation details
        pass
        
    async def get_scan_results(
        self, 
        scan_id: UUID, 
        user_id: UUID
    ) -> Optional[ScanResultResponse]:
        """Retrieve scan results by ID."""
        # Implementation details
        pass
```

**Extension Data Processor** (`src/social_protection/services/extension_data_processor.py`):

```python
class ExtensionDataProcessor:
    def __init__(self, risk_calculator: RiskCalculator):
        self.risk_calculator = risk_calculator
        
    async def process_extension_data(
        self, 
        user_id: UUID, 
        data: ExtensionDataRequest
    ) -> ExtensionDataResponse:
        """Process data from browser extension."""
        # Implementation details
        pass
```

## 4. Development Workflows

### 4.1 Adding New Platform Support

1. **Update Enums**:
```python
# In src/social_protection/data_models.py
class PlatformType(str, Enum):
    # ... existing platforms
    NEW_PLATFORM = "new_platform"
```

2. **Create Platform Adapter**:
```python
# In src/social_protection/adapters/new_platform_adapter.py
class NewPlatformAdapter(BasePlatformAdapter):
    async def scan_profile(self, target_url: str) -> Dict[str, Any]:
        # Platform-specific implementation
        pass
```

3. **Update Service**:
```python
# In src/social_protection/services/social_scan_service.py
def _get_platform_adapter(self, platform: PlatformType):
    adapters = {
        PlatformType.TWITTER: TwitterAdapter(),
        PlatformType.NEW_PLATFORM: NewPlatformAdapter(),
        # ... other adapters
    }
    return adapters.get(platform)
```

4. **Add Tests**:
```python
# In tests/test_social_protection_services.py
class TestNewPlatformIntegration:
    async def test_new_platform_scan(self):
        # Test implementation
        pass
```

### 4.2 Adding New Risk Assessment Rules

1. **Create Rule Class**:
```python
# In src/social_protection/rules/new_rule.py
class NewRiskRule(BaseRiskRule):
    def evaluate(self, content: Dict[str, Any]) -> RiskAssessment:
        # Rule implementation
        pass
```

2. **Register Rule**:
```python
# In src/social_protection/utils/risk_calculator.py
class RiskCalculator:
    def __init__(self):
        self.rules = [
            ExistingRule(),
            NewRiskRule(),
            # ... other rules
        ]
```

3. **Add Configuration**:
```python
# In src/config/settings.py
NEW_RULE_THRESHOLD = 0.7
NEW_RULE_ENABLED = True
```

### 4.3 Extending API Endpoints

1. **Add Route**:
```python
# In src/routes/social_protection.py
@router.post("/new-endpoint")
async def new_endpoint(
    request: NewRequest,
    current_user: User = Depends(get_current_user),
    controller: SocialProtectionController = Depends(get_social_protection_controller)
):
    return await controller.handle_new_request(current_user.id, request)
```

2. **Add Controller Method**:
```python
# In src/controllers/social_protection_controller.py
async def handle_new_request(
    self, 
    user_id: UUID, 
    request: NewRequest
) -> NewResponse:
    # Implementation
    pass
```

3. **Add Data Models**:
```python
# In src/social_protection/data_models.py
class NewRequest(BaseModel):
    # Request fields
    pass

class NewResponse(BaseModel):
    # Response fields
    pass
```

## 5. Testing Guidelines

### 5.1 Unit Testing

**Test Structure**:
```python
# tests/test_social_protection_services.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from src.social_protection.services.social_scan_service import SocialScanService

class TestSocialScanService:
    @pytest.fixture
    def mock_db_session(self):
        return AsyncMock()
    
    @pytest.fixture
    def service(self, mock_db_session):
        return SocialScanService(mock_db_session)
    
    async def test_initiate_profile_scan_success(self, service):
        # Test implementation
        pass
```

**Running Tests**:
```bash
# Run all social protection tests
pytest tests/test_social_protection_* -v

# Run with coverage
pytest tests/test_social_protection_* --cov=src/social_protection --cov-report=html

# Run specific test file
pytest tests/test_social_protection_services.py -v
```

### 5.2 Integration Testing

**API Testing**:
```python
# tests/test_social_protection_integration.py
from fastapi.testclient import TestClient
from src.app import app

class TestSocialProtectionIntegration:
    @pytest.fixture
    def client(self):
        return TestClient(app)
    
    def test_process_extension_data_success(self, client):
        response = client.post(
            "/api/v1/social-protection/extension/process",
            json={"project_id": str(uuid.uuid4()), "platform": "twitter", "data": {}},
            headers={"Authorization": "Bearer test_token"}
        )
        assert response.status_code == 200
```

### 5.3 Performance Testing

**Load Testing with Locust**:
```python
# tests/performance/locustfile.py
from locust import HttpUser, task, between

class SocialProtectionUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        # Login and get token
        pass
    
    @task(3)
    def process_extension_data(self):
        self.client.post(
            "/api/v1/social-protection/extension/process",
            json=self.get_test_data(),
            headers={"Authorization": f"Bearer {self.token}"}
        )
    
    @task(1)
    def initiate_scan(self):
        self.client.post(
            "/api/v1/social-protection/scans",
            json=self.get_scan_request(),
            headers={"Authorization": f"Bearer {self.token}"}
        )
```

## 6. Database Operations

### 6.1 Migrations

**Creating New Migration**:
```bash
# Generate migration
alembic revision --autogenerate -m "Add new social protection feature"

# Review generated migration file
# Edit if necessary

# Apply migration
alembic upgrade head
```

**Migration Best Practices**:
- Always review auto-generated migrations
- Test migrations on development data
- Include both upgrade and downgrade functions
- Use appropriate indexes for query performance

### 6.2 Query Optimization

**Efficient Queries**:
```python
# Good: Use joins and select specific columns
async def get_user_scans_optimized(self, user_id: UUID, limit: int = 20):
    query = (
        select(SocialProfileScan.id, SocialProfileScan.platform, SocialProfileScan.scan_status)
        .where(SocialProfileScan.user_id == user_id)
        .order_by(SocialProfileScan.created_at.desc())
        .limit(limit)
    )
    result = await self.db.execute(query)
    return result.all()

# Bad: N+1 queries
async def get_user_scans_inefficient(self, user_id: UUID):
    scans = await self.db.execute(
        select(SocialProfileScan).where(SocialProfileScan.user_id == user_id)
    )
    for scan in scans:
        # This creates N+1 queries
        user = await self.db.get(User, scan.user_id)
```

## 7. Error Handling

### 7.1 Exception Hierarchy

```python
# src/social_protection/exceptions.py
class SocialProtectionException(Exception):
    """Base exception for social protection module."""
    pass

class PlatformAPIException(SocialProtectionException):
    """Exception for platform API errors."""
    pass

class RateLimitExceededException(SocialProtectionException):
    """Exception for rate limit violations."""
    pass

class InvalidScanRequestException(SocialProtectionException):
    """Exception for invalid scan requests."""
    pass
```

### 7.2 Error Handling Patterns

```python
# In service methods
async def initiate_profile_scan(self, user_id: UUID, request: ProfileScanRequest):
    try:
        # Validate request
        if not self._validate_scan_request(request):
            raise InvalidScanRequestException("Invalid scan parameters")
        
        # Check rate limits
        if await self._check_rate_limit(user_id):
            raise RateLimitExceededException("Rate limit exceeded")
        
        # Perform scan
        result = await self._perform_scan(request)
        return result
        
    except PlatformAPIException as e:
        logger.error(f"Platform API error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in profile scan: {e}")
        raise SocialProtectionException("Internal error occurred")
```

## 8. Security Implementation

### 8.1 Authentication and Authorization

```python
# In routes
@router.post("/scans")
async def initiate_scan(
    request: ProfileScanRequest,
    current_user: User = Depends(get_current_user),  # Authentication
    controller: SocialProtectionController = Depends(get_social_protection_controller)
):
    # Authorization check
    if not await controller.can_user_access_project(current_user.id, request.project_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return await controller.initiate_scan(current_user.id, request)
```

### 8.2 Input Validation

```python
# In data models
class ProfileScanRequest(BaseModel):
    project_id: UUID = Field(..., description="Project ID")
    platform: PlatformType = Field(..., description="Social media platform")
    target: str = Field(..., min_length=1, max_length=2048, description="Target URL or username")
    
    @validator('target')
    def validate_target(cls, v):
        # Custom validation logic
        if not v or len(v.strip()) == 0:
            raise ValueError('Target cannot be empty')
        return v.strip()
```

### 8.3 Rate Limiting

```python
# In controller
async def process_extension_data(self, user_id: UUID, request: ExtensionDataRequest):
    # Check rate limit
    rate_limit_key = f"social_protection:extension:{user_id}"
    current_count = await self.redis.get(rate_limit_key)
    
    if current_count and int(current_count) >= self.rate_limit:
        raise RateLimitExceededException("Rate limit exceeded")
    
    # Increment counter
    await self.redis.incr(rate_limit_key)
    await self.redis.expire(rate_limit_key, 3600)  # 1 hour
    
    # Process request
    return await self._process_data(request)
```

## 9. Monitoring and Logging

### 9.1 Logging Configuration

```python
# src/utils/logging.py
import logging
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()
```

### 9.2 Metrics Collection

```python
# src/social_protection/metrics.py
from prometheus_client import Counter, Histogram, Gauge

# Define metrics
scan_requests_total = Counter(
    'social_protection_scan_requests_total',
    'Total number of scan requests',
    ['platform', 'status']
)

scan_duration_seconds = Histogram(
    'social_protection_scan_duration_seconds',
    'Time spent processing scans',
    ['platform']
)

active_scans = Gauge(
    'social_protection_active_scans',
    'Number of currently active scans'
)

# Usage in service
async def initiate_profile_scan(self, user_id: UUID, request: ProfileScanRequest):
    start_time = time.time()
    active_scans.inc()
    
    try:
        result = await self._perform_scan(request)
        scan_requests_total.labels(platform=request.platform, status='success').inc()
        return result
    except Exception as e:
        scan_requests_total.labels(platform=request.platform, status='error').inc()
        raise
    finally:
        active_scans.dec()
        scan_duration_seconds.labels(platform=request.platform).observe(time.time() - start_time)
```

## 10. Deployment

### 10.1 Docker Configuration

**Dockerfile**:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY alembic.ini .
COPY migrations/ ./migrations/

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
USER app

# Expose port
EXPOSE 8000

# Start application
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

**docker-compose.yml**:
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:password@db:5432/linkshield
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - ./src:/app/src
    
  db:
    image: postgres:14
    environment:
      - POSTGRES_DB=linkshield
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    
  redis:
    image: redis:6-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### 10.2 Environment Configuration

**Production Environment Variables**:
```bash
# Database
DATABASE_URL=postgresql://user:password@host:5432/linkshield_prod
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30

# Redis
REDIS_URL=redis://redis-host:6379
REDIS_POOL_SIZE=10

# Social Protection
SOCIAL_PROTECTION_ENABLED=true
SOCIAL_SCAN_RATE_LIMIT_PER_HOUR=50
SOCIAL_PROTECTION_API_RATE_LIMIT=100

# Platform APIs
TWITTER_API_KEY=your_twitter_api_key
FACEBOOK_API_KEY=your_facebook_api_key
INSTAGRAM_API_KEY=your_instagram_api_key

# Security
JWT_SECRET_KEY=your_jwt_secret
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# Monitoring
PROMETHEUS_ENABLED=true
SENTRY_DSN=your_sentry_dsn
LOG_LEVEL=INFO
```

### 10.3 Health Checks

```python
# src/routes/health.py
@router.get("/health/social-protection")
async def social_protection_health():
    """Health check for social protection services."""
    checks = {
        "database": await check_database_connection(),
        "redis": await check_redis_connection(),
        "platform_apis": await check_platform_apis(),
    }
    
    all_healthy = all(checks.values())
    status_code = 200 if all_healthy else 503
    
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if all_healthy else "unhealthy",
            "checks": checks,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
```

## 11. Troubleshooting

### 11.1 Common Issues

**Database Connection Issues**:
```bash
# Check database connectivity
psql -h localhost -U user -d linkshield -c "SELECT 1;"

# Check migration status
alembic current
alembic history
```

**Rate Limiting Issues**:
```bash
# Check Redis connectivity
redis-cli ping

# Check rate limit keys
redis-cli keys "social_protection:*"
redis-cli get "social_protection:extension:user_id"
```

**Platform API Issues**:
```python
# Test platform API connectivity
async def test_platform_apis():
    adapters = {
        'twitter': TwitterAdapter(),
        'facebook': FacebookAdapter(),
    }
    
    for platform, adapter in adapters.items():
        try:
            await adapter.test_connection()
            print(f"{platform}: OK")
        except Exception as e:
            print(f"{platform}: ERROR - {e}")
```

### 11.2 Performance Issues

**Slow Queries**:
```sql
-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
WHERE query LIKE '%social_profile_scans%' 
ORDER BY mean_time DESC;

-- Check missing indexes
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats 
WHERE tablename = 'social_profile_scans';
```

**Memory Issues**:
```python
# Monitor memory usage
import psutil
import gc

def check_memory_usage():
    process = psutil.Process()
    memory_info = process.memory_info()
    print(f"RSS: {memory_info.rss / 1024 / 1024:.2f} MB")
    print(f"VMS: {memory_info.vms / 1024 / 1024:.2f} MB")
    
    # Force garbage collection
    gc.collect()
```

## 12. Best Practices

### 12.1 Code Quality

- **Type Hints**: Use type hints for all function parameters and return values
- **Docstrings**: Document all public methods and classes
- **Error Handling**: Handle exceptions gracefully with appropriate logging
- **Testing**: Maintain high test coverage (>90%)
- **Code Review**: All changes require peer review

### 12.2 Performance

- **Database Queries**: Use efficient queries with proper indexing
- **Caching**: Cache frequently accessed data
- **Async Operations**: Use async/await for I/O operations
- **Connection Pooling**: Use connection pools for database and Redis

### 12.3 Security

- **Input Validation**: Validate all user inputs
- **Authentication**: Require authentication for all endpoints
- **Authorization**: Check user permissions for resource access
- **Logging**: Log security-relevant events
- **Secrets Management**: Use environment variables for sensitive data

## 13. Conclusion

This implementation guide provides comprehensive instructions for developing, testing, and deploying the Social Protection feature. Following these guidelines ensures consistent, secure, and maintainable code that meets the project's quality standards.

For additional support or questions, refer to the project documentation or contact the development team.