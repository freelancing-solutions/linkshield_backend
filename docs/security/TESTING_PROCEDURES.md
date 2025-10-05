# Security Testing Procedures

## Overview

This document outlines comprehensive testing procedures for the LinkShield security system, including unit tests, integration tests, security tests, performance tests, and compliance validation.

## Table of Contents

1. [Testing Framework](#testing-framework)
2. [Test Categories](#test-categories)
3. [Unit Testing](#unit-testing)
4. [Integration Testing](#integration-testing)
5. [Security Testing](#security-testing)
6. [Performance Testing](#performance-testing)
7. [End-to-End Testing](#end-to-end-testing)
8. [Test Data Management](#test-data-management)
9. [Continuous Integration](#continuous-integration)
10. [Test Reporting](#test-reporting)

## Testing Framework

### Test Infrastructure

The security testing framework is built on:

- **pytest**: Primary testing framework
- **pytest-asyncio**: Async test support
- **pytest-cov**: Coverage reporting
- **pytest-mock**: Mocking capabilities
- **pytest-benchmark**: Performance testing
- **Redis**: Test database
- **Docker**: Containerized test environment

### Test Configuration

```ini
# pytest.ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v
    --tb=short
    --strict-markers
    --disable-warnings
    --asyncio-mode=auto
    --cov=src
    --cov-report=html
    --cov-report=term-missing
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests
    security: marks tests as security tests
    performance: marks tests as performance tests
    e2e: marks tests as end-to-end tests
```

### Test Environment Setup

```bash
# Set up test environment
export TESTING=true
export REDIS_URL="redis://localhost:6379/1"
export JWT_SECRET_KEY="test-jwt-secret-key"
export CSRF_SECRET_KEY="test-csrf-secret-key"
export SESSION_SECRET_KEY="test-session-secret-key"

# Start test services
docker-compose -f docker-compose.test.yml up -d redis

# Run tests
pytest tests/security/ -v
```

## Test Categories

### Test Hierarchy

1. **Unit Tests** (Fast, Isolated)
   - Individual component testing
   - Mock external dependencies
   - High coverage, fast execution

2. **Integration Tests** (Medium Speed)
   - Component interaction testing
   - Real Redis connections
   - Cross-service communication

3. **Security Tests** (Comprehensive)
   - Vulnerability testing
   - Attack simulation
   - Security policy validation

4. **Performance Tests** (Resource Intensive)
   - Load testing
   - Stress testing
   - Benchmark validation

5. **End-to-End Tests** (Slow, Complete)
   - Full workflow testing
   - Real environment simulation
   - User journey validation

## Unit Testing

### JWT Blacklist Service Tests

#### Test Structure

```python
# tests/security/test_jwt_blacklist.py
class TestJWTBlacklistService:
    """Unit tests for JWT Blacklist Service"""
    
    async def test_token_revocation(self, jwt_blacklist_service):
        """Test token revocation functionality"""
        # Test implementation
        
    async def test_blacklist_validation(self, jwt_blacklist_service):
        """Test blacklist validation"""
        # Test implementation
        
    async def test_cleanup_expired_tokens(self, jwt_blacklist_service):
        """Test automatic cleanup"""
        # Test implementation
```

#### Key Test Cases

1. **Token Revocation**
   - Valid token revocation
   - Duplicate revocation handling
   - Invalid token handling
   - Batch revocation

2. **Blacklist Validation**
   - Blacklisted token detection
   - Non-blacklisted token validation
   - Expired token handling
   - Invalid JTI handling

3. **Cleanup Operations**
   - Expired token removal
   - Batch cleanup efficiency
   - Memory usage optimization
   - Error handling

#### Test Execution

```bash
# Run JWT blacklist unit tests
pytest tests/security/test_jwt_blacklist.py::TestJWTBlacklistService -v

# Run with coverage
pytest tests/security/test_jwt_blacklist.py --cov=src.security.jwt_blacklist

# Run specific test
pytest tests/security/test_jwt_blacklist.py::TestJWTBlacklistService::test_token_revocation -v
```

### CSRF Protection Tests

#### Test Categories

1. **Token Generation**
   - Valid token creation
   - Token uniqueness
   - Expiration handling
   - Secret key validation

2. **Token Validation**
   - Valid token acceptance
   - Invalid token rejection
   - Expired token handling
   - Tampered token detection

3. **Double-Submit Cookie**
   - Cookie-header matching
   - Missing cookie handling
   - Cookie tampering detection
   - SameSite attribute validation

#### Sample Test

```python
async def test_csrf_token_validation(self, csrf_service):
    """Test CSRF token validation"""
    # Generate token
    token = await csrf_service.generate_token(
        session_id="test_session",
        user_id="test_user"
    )
    
    # Validate token
    is_valid = await csrf_service.validate_token(
        token=token.token,
        session_id="test_session",
        user_id="test_user"
    )
    
    assert is_valid is True
    
    # Test invalid token
    is_valid = await csrf_service.validate_token(
        token="invalid_token",
        session_id="test_session",
        user_id="test_user"
    )
    
    assert is_valid is False
```

### Rate Limiting Tests

#### Algorithm Testing

1. **Token Bucket Algorithm**
   - Bucket initialization
   - Token consumption
   - Bucket refill
   - Burst handling

2. **Sliding Window Algorithm**
   - Window management
   - Request counting
   - Window sliding
   - Precision validation

3. **Fixed Window Algorithm**
   - Window boundaries
   - Request counting
   - Window reset
   - Edge case handling

#### Performance Testing

```python
@pytest.mark.benchmark
async def test_rate_limit_performance(self, rate_limiter, benchmark):
    """Benchmark rate limiting performance"""
    
    async def rate_limit_check():
        return await rate_limiter.check_rate_limit(
            key="test_key",
            limit=1000,
            window=3600,
            algorithm="sliding_window"
        )
    
    result = await benchmark(rate_limit_check)
    assert result.allowed is True
```

### Session Security Tests

#### Security Validation

1. **Session Creation**
   - Secure session generation
   - Session data validation
   - Expiration setting
   - Security attributes

2. **Session Validation**
   - Valid session acceptance
   - Invalid session rejection
   - Expired session handling
   - Security check validation

3. **Risk Analysis**
   - IP address validation
   - User agent validation
   - Behavioral analysis
   - Anomaly detection

#### Concurrent Session Testing

```python
async def test_concurrent_session_handling(self, session_manager):
    """Test concurrent session management"""
    user_id = "test_user"
    
    # Create multiple sessions
    sessions = []
    for i in range(5):
        session = await session_manager.create_session(
            user_id=user_id,
            ip_address=f"192.168.1.{i}",
            user_agent=f"TestAgent/{i}"
        )
        sessions.append(session)
    
    # Validate all sessions
    for session in sessions:
        is_valid = await session_manager.validate_session(
            session_id=session.session_id,
            ip_address=session.ip_address,
            user_agent=session.user_agent
        )
        assert is_valid is True
    
    # Test session limit enforcement
    max_sessions = 3
    active_sessions = await session_manager.get_active_sessions(user_id)
    assert len(active_sessions) <= max_sessions
```

## Integration Testing

### Cross-Component Testing

#### Security Middleware Integration

```python
class TestSecurityMiddlewareIntegration:
    """Integration tests for security middleware"""
    
    async def test_jwt_csrf_integration(self, app_client):
        """Test JWT and CSRF protection integration"""
        # Login to get JWT token
        login_response = await app_client.post("/auth/login", json={
            "username": "testuser",
            "password": "testpass"
        })
        
        jwt_token = login_response.json()["access_token"]
        csrf_token = login_response.json()["csrf_token"]
        
        # Make protected request with both tokens
        response = await app_client.post(
            "/api/protected",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-CSRF-Token": csrf_token
            },
            json={"data": "test"}
        )
        
        assert response.status_code == 200
    
    async def test_rate_limit_jwt_integration(self, app_client):
        """Test rate limiting with JWT authentication"""
        # Get JWT token
        token = await self.get_jwt_token(app_client)
        
        # Make requests up to rate limit
        for i in range(100):
            response = await app_client.get(
                "/api/data",
                headers={"Authorization": f"Bearer {token}"}
            )
            
            if i < 99:
                assert response.status_code == 200
            else:
                assert response.status_code == 429  # Rate limited
```

#### Database Integration

```python
async def test_blacklist_database_integration(self, jwt_blacklist_service, db_session):
    """Test JWT blacklist with database integration"""
    # Create user and token
    user = await create_test_user(db_session)
    token_jti = "test_jti_123"
    
    # Revoke token
    await jwt_blacklist_service.revoke_token(
        token_jti=token_jti,
        user_id=str(user.id),
        reason="user_logout"
    )
    
    # Verify blacklist entry in database
    blacklist_entry = await db_session.execute(
        select(BlacklistEntry).where(BlacklistEntry.jti == token_jti)
    )
    entry = blacklist_entry.scalar_one_or_none()
    
    assert entry is not None
    assert entry.user_id == str(user.id)
    assert entry.reason == "user_logout"
```

### Redis Integration Testing

#### Redis Connectivity

```python
async def test_redis_connectivity(self, redis_client):
    """Test Redis connectivity and operations"""
    # Test basic operations
    await redis_client.set("test_key", "test_value")
    value = await redis_client.get("test_key")
    assert value == "test_value"
    
    # Test expiration
    await redis_client.setex("expire_key", 1, "expire_value")
    await asyncio.sleep(2)
    value = await redis_client.get("expire_key")
    assert value is None
```

#### Redis Performance

```python
@pytest.mark.performance
async def test_redis_performance(self, redis_client, benchmark):
    """Test Redis operation performance"""
    
    async def redis_operations():
        # Simulate typical security operations
        await redis_client.set("perf_test", "value")
        await redis_client.get("perf_test")
        await redis_client.incr("counter")
        await redis_client.expire("perf_test", 3600)
    
    await benchmark(redis_operations)
```

## Security Testing

### Vulnerability Testing

#### JWT Security Tests

```python
class TestJWTSecurity:
    """Security tests for JWT implementation"""
    
    async def test_jwt_tampering_detection(self, jwt_service):
        """Test JWT tampering detection"""
        # Create valid token
        token = await jwt_service.create_token(user_id="test_user")
        
        # Tamper with token
        tampered_token = token[:-5] + "XXXXX"
        
        # Verify tampering is detected
        with pytest.raises(InvalidTokenError):
            await jwt_service.validate_token(tampered_token)
    
    async def test_jwt_replay_attack(self, jwt_blacklist_service):
        """Test JWT replay attack prevention"""
        token_jti = "replay_test_jti"
        
        # Revoke token (simulate logout)
        await jwt_blacklist_service.revoke_token(
            token_jti=token_jti,
            user_id="test_user",
            reason="user_logout"
        )
        
        # Attempt to use revoked token
        is_blacklisted = await jwt_blacklist_service.is_token_blacklisted(token_jti)
        assert is_blacklisted is True
    
    async def test_jwt_timing_attack_resistance(self, jwt_service):
        """Test resistance to timing attacks"""
        valid_token = await jwt_service.create_token(user_id="test_user")
        invalid_token = "invalid.token.here"
        
        # Measure validation times
        valid_times = []
        invalid_times = []
        
        for _ in range(100):
            # Time valid token validation
            start = time.time()
            try:
                await jwt_service.validate_token(valid_token)
            except:
                pass
            valid_times.append(time.time() - start)
            
            # Time invalid token validation
            start = time.time()
            try:
                await jwt_service.validate_token(invalid_token)
            except:
                pass
            invalid_times.append(time.time() - start)
        
        # Verify timing consistency (prevent timing attacks)
        valid_avg = sum(valid_times) / len(valid_times)
        invalid_avg = sum(invalid_times) / len(invalid_times)
        
        # Times should be similar (within 50% difference)
        assert abs(valid_avg - invalid_avg) / max(valid_avg, invalid_avg) < 0.5
```

#### CSRF Attack Simulation

```python
async def test_csrf_attack_prevention(self, app_client):
    """Test CSRF attack prevention"""
    # Login to get session
    login_response = await app_client.post("/auth/login", json={
        "username": "testuser",
        "password": "testpass"
    })
    
    session_cookie = login_response.cookies.get("session")
    
    # Attempt CSRF attack (request without CSRF token)
    response = await app_client.post(
        "/api/sensitive-action",
        cookies={"session": session_cookie},
        json={"action": "delete_account"}
    )
    
    # Should be rejected due to missing CSRF token
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]
```

#### Session Hijacking Tests

```python
async def test_session_hijacking_prevention(self, session_manager):
    """Test session hijacking prevention"""
    # Create session
    session = await session_manager.create_session(
        user_id="test_user",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Test Browser)"
    )
    
    # Attempt to use session from different IP
    is_valid = await session_manager.validate_session(
        session_id=session.session_id,
        ip_address="192.168.1.200",  # Different IP
        user_agent="Mozilla/5.0 (Test Browser)"
    )
    
    # Should be rejected due to IP mismatch
    assert is_valid is False
    
    # Attempt to use session with different User-Agent
    is_valid = await session_manager.validate_session(
        session_id=session.session_id,
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Different Browser)"  # Different UA
    )
    
    # Should be rejected due to User-Agent mismatch
    assert is_valid is False
```

### Penetration Testing

#### Rate Limit Bypass Attempts

```python
async def test_rate_limit_bypass_attempts(self, app_client):
    """Test various rate limit bypass techniques"""
    
    # Test 1: Different IP addresses
    for i in range(150):  # Exceed rate limit
        headers = {"X-Forwarded-For": f"192.168.1.{i % 255}"}
        response = await app_client.get("/api/data", headers=headers)
        
        if i < 100:
            assert response.status_code == 200
        else:
            # Should still be rate limited despite different IPs
            assert response.status_code == 429
    
    # Test 2: Different User-Agents
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)"
    ]
    
    for i in range(150):
        headers = {"User-Agent": user_agents[i % len(user_agents)]}
        response = await app_client.get("/api/data", headers=headers)
        
        if i < 100:
            assert response.status_code == 200
        else:
            # Should still be rate limited
            assert response.status_code == 429
```

#### SQL Injection Tests

```python
async def test_sql_injection_prevention(self, app_client):
    """Test SQL injection prevention"""
    # Common SQL injection payloads
    payloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "'; INSERT INTO users (username) VALUES ('hacker'); --"
    ]
    
    for payload in payloads:
        response = await app_client.post("/auth/login", json={
            "username": payload,
            "password": "password"
        })
        
        # Should not cause SQL injection
        assert response.status_code in [400, 401]  # Bad request or unauthorized
        assert "error" not in response.text.lower()  # No SQL errors exposed
```

## Performance Testing

### Load Testing

#### Concurrent Request Testing

```python
@pytest.mark.performance
async def test_concurrent_authentication(self, app_client):
    """Test authentication under concurrent load"""
    
    async def authenticate_user(session, user_id):
        response = await session.post("/auth/login", json={
            "username": f"user_{user_id}",
            "password": "password"
        })
        return response.status_code == 200
    
    # Create concurrent sessions
    async with aiohttp.ClientSession() as session:
        tasks = [
            authenticate_user(session, i)
            for i in range(100)  # 100 concurrent authentications
        ]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
        # Verify performance
        success_rate = sum(results) / len(results)
        total_time = end_time - start_time
        
        assert success_rate > 0.95  # 95% success rate
        assert total_time < 10.0    # Complete within 10 seconds
```

#### Memory Usage Testing

```python
@pytest.mark.performance
async def test_memory_usage_under_load(self, jwt_blacklist_service):
    """Test memory usage under high load"""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss
    
    # Generate many blacklist entries
    for i in range(10000):
        await jwt_blacklist_service.revoke_token(
            token_jti=f"test_jti_{i}",
            user_id=f"user_{i}",
            reason="load_test"
        )
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Memory increase should be reasonable (less than 100MB)
    assert memory_increase < 100 * 1024 * 1024
```

### Stress Testing

#### Redis Stress Testing

```python
@pytest.mark.performance
async def test_redis_stress(self, redis_client):
    """Stress test Redis operations"""
    
    async def redis_operations():
        tasks = []
        for i in range(1000):
            # Mix of operations
            tasks.append(redis_client.set(f"key_{i}", f"value_{i}"))
            tasks.append(redis_client.get(f"key_{i}"))
            tasks.append(redis_client.incr(f"counter_{i}"))
            tasks.append(redis_client.expire(f"key_{i}", 3600))
        
        await asyncio.gather(*tasks)
    
    start_time = time.time()
    await redis_operations()
    end_time = time.time()
    
    # Should complete within reasonable time
    assert end_time - start_time < 30.0  # 30 seconds
```

### Benchmark Testing

#### Security Operation Benchmarks

```python
@pytest.mark.benchmark
class TestSecurityBenchmarks:
    """Benchmark tests for security operations"""
    
    def test_jwt_validation_benchmark(self, benchmark, jwt_service):
        """Benchmark JWT validation performance"""
        token = jwt_service.create_token_sync(user_id="test_user")
        
        result = benchmark(jwt_service.validate_token_sync, token)
        assert result is not None
    
    def test_csrf_token_generation_benchmark(self, benchmark, csrf_service):
        """Benchmark CSRF token generation"""
        result = benchmark(
            csrf_service.generate_token_sync,
            session_id="test_session",
            user_id="test_user"
        )
        assert result is not None
    
    def test_rate_limit_check_benchmark(self, benchmark, rate_limiter):
        """Benchmark rate limit checking"""
        result = benchmark(
            rate_limiter.check_rate_limit_sync,
            key="test_key",
            limit=1000,
            window=3600
        )
        assert result.allowed is True
```

## End-to-End Testing

### User Journey Testing

#### Complete Authentication Flow

```python
@pytest.mark.e2e
async def test_complete_authentication_flow(self, app_client):
    """Test complete user authentication journey"""
    
    # 1. User registration
    register_response = await app_client.post("/auth/register", json={
        "username": "e2e_user",
        "email": "e2e@test.com",
        "password": "SecurePass123!"
    })
    assert register_response.status_code == 201
    
    # 2. User login
    login_response = await app_client.post("/auth/login", json={
        "username": "e2e_user",
        "password": "SecurePass123!"
    })
    assert login_response.status_code == 200
    
    tokens = login_response.json()
    access_token = tokens["access_token"]
    csrf_token = tokens["csrf_token"]
    
    # 3. Access protected resource
    protected_response = await app_client.get(
        "/api/profile",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-CSRF-Token": csrf_token
        }
    )
    assert protected_response.status_code == 200
    
    # 4. Perform sensitive action
    action_response = await app_client.post(
        "/api/change-password",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-CSRF-Token": csrf_token
        },
        json={
            "current_password": "SecurePass123!",
            "new_password": "NewSecurePass456!"
        }
    )
    assert action_response.status_code == 200
    
    # 5. Logout
    logout_response = await app_client.post(
        "/auth/logout",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-CSRF-Token": csrf_token
        }
    )
    assert logout_response.status_code == 200
    
    # 6. Verify token is blacklisted
    blacklisted_response = await app_client.get(
        "/api/profile",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert blacklisted_response.status_code == 401
```

#### Security Incident Response

```python
@pytest.mark.e2e
async def test_security_incident_response(self, app_client, notification_system):
    """Test security incident detection and response"""
    
    # 1. Simulate suspicious activity (multiple failed logins)
    for i in range(10):
        response = await app_client.post("/auth/login", json={
            "username": "target_user",
            "password": "wrong_password"
        })
        assert response.status_code == 401
    
    # 2. Verify account lockout
    response = await app_client.post("/auth/login", json={
        "username": "target_user",
        "password": "correct_password"
    })
    assert response.status_code == 423  # Account locked
    
    # 3. Verify security notification was sent
    notifications = await notification_system.get_recent_notifications(
        notification_type=NotificationType.SECURITY_ALERT,
        hours=1
    )
    
    security_alerts = [
        n for n in notifications
        if "failed login" in n.message.lower()
    ]
    assert len(security_alerts) > 0
    
    # 4. Admin unlocks account
    admin_token = await self.get_admin_token(app_client)
    unlock_response = await app_client.post(
        "/admin/unlock-account",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"username": "target_user"}
    )
    assert unlock_response.status_code == 200
    
    # 5. User can login again
    response = await app_client.post("/auth/login", json={
        "username": "target_user",
        "password": "correct_password"
    })
    assert response.status_code == 200
```

## Test Data Management

### Test Fixtures

#### Database Fixtures

```python
# conftest.py
@pytest.fixture
async def db_session():
    """Database session for testing"""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()

@pytest.fixture
async def test_user(db_session):
    """Create test user"""
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password="$2b$12$hashed_password"
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user
```

#### Redis Fixtures

```python
@pytest.fixture
async def redis_client():
    """Redis client for testing"""
    client = redis.Redis.from_url("redis://localhost:6379/1")
    yield client
    await client.flushdb()
    await client.close()

@pytest.fixture
async def clean_redis(redis_client):
    """Clean Redis before and after test"""
    await redis_client.flushdb()
    yield redis_client
    await redis_client.flushdb()
```

#### Security Service Fixtures

```python
@pytest.fixture
async def jwt_blacklist_service(redis_client, security_logger):
    """JWT blacklist service for testing"""
    return JWTBlacklistService(redis_client, security_logger)

@pytest.fixture
async def csrf_service():
    """CSRF protection service for testing"""
    return CSRFProtectionService(secret_key="test-csrf-secret")

@pytest.fixture
async def rate_limiter(redis_client):
    """Rate limiter for testing"""
    return RateLimitService(redis_client)

@pytest.fixture
async def session_manager(redis_client, security_logger):
    """Session manager for testing"""
    return SessionManager(redis_client, security_logger)
```

### Test Data Generation

#### User Data Factory

```python
class UserFactory:
    """Factory for creating test users"""
    
    @staticmethod
    async def create_user(
        db_session,
        username: str = None,
        email: str = None,
        password: str = "testpass123"
    ) -> User:
        """Create a test user"""
        username = username or f"user_{uuid.uuid4().hex[:8]}"
        email = email or f"{username}@test.com"
        
        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user
    
    @staticmethod
    async def create_admin_user(db_session) -> User:
        """Create an admin test user"""
        return await UserFactory.create_user(
            db_session,
            username="admin_user",
            email="admin@test.com"
        )
```

#### Token Data Factory

```python
class TokenFactory:
    """Factory for creating test tokens"""
    
    @staticmethod
    def create_jwt_token(
        user_id: str,
        expires_delta: timedelta = None
    ) -> str:
        """Create a test JWT token"""
        if expires_delta is None:
            expires_delta = timedelta(hours=1)
        
        expire = datetime.utcnow() + expires_delta
        payload = {
            "sub": user_id,
            "exp": expire,
            "jti": str(uuid.uuid4())
        }
        
        return jwt.encode(payload, "test-secret", algorithm="HS256")
    
    @staticmethod
    async def create_csrf_token(
        csrf_service,
        session_id: str = "test_session",
        user_id: str = "test_user"
    ) -> CSRFToken:
        """Create a test CSRF token"""
        return await csrf_service.generate_token(session_id, user_id)
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/security-tests.yml
name: Security Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-test.txt
    
    - name: Run security unit tests
      run: |
        pytest tests/security/ -m "unit" --cov=src --cov-report=xml
    
    - name: Run security integration tests
      run: |
        pytest tests/security/ -m "integration" --cov=src --cov-append --cov-report=xml
    
    - name: Run security tests
      run: |
        pytest tests/security/ -m "security" --cov=src --cov-append --cov-report=xml
    
    - name: Run performance tests
      run: |
        pytest tests/security/ -m "performance" --benchmark-only
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: security
        name: security-coverage
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: security-tests
        name: Security Tests
        entry: pytest tests/security/ -m "unit or integration"
        language: system
        pass_filenames: false
        always_run: true
      
      - id: security-linting
        name: Security Linting
        entry: bandit -r src/security/
        language: system
        pass_filenames: false
        always_run: true
      
      - id: dependency-check
        name: Dependency Security Check
        entry: safety check
        language: system
        pass_filenames: false
        always_run: true
```

### Test Automation

#### Makefile Targets

```makefile
# Makefile
.PHONY: test-security test-security-unit test-security-integration test-security-performance

test-security: test-security-unit test-security-integration test-security-performance

test-security-unit:
	pytest tests/security/ -m "unit" -v --cov=src.security

test-security-integration:
	pytest tests/security/ -m "integration" -v --cov=src.security --cov-append

test-security-performance:
	pytest tests/security/ -m "performance" -v --benchmark-only

test-security-e2e:
	pytest tests/security/ -m "e2e" -v --tb=short

test-security-coverage:
	pytest tests/security/ --cov=src.security --cov-report=html --cov-report=term-missing

test-security-watch:
	ptw tests/security/ -- -m "unit or integration" -v
```

## Test Reporting

### Coverage Reporting

#### HTML Coverage Report

```bash
# Generate HTML coverage report
pytest tests/security/ --cov=src.security --cov-report=html

# Open coverage report
open htmlcov/index.html
```

#### Coverage Configuration

```ini
# .coveragerc
[run]
source = src
omit = 
    */tests/*
    */venv/*
    */migrations/*
    */conftest.py

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:

[html]
directory = htmlcov
```

### Performance Reporting

#### Benchmark Reports

```bash
# Generate benchmark report
pytest tests/security/ --benchmark-only --benchmark-json=benchmark.json

# Generate HTML benchmark report
pytest-benchmark compare benchmark.json --html=benchmark.html
```

### Security Test Reports

#### Security Scan Integration

```bash
# Run security scans
bandit -r src/security/ -f json -o security-scan.json

# Run dependency vulnerability check
safety check --json --output vulnerability-report.json

# Generate combined security report
python scripts/generate_security_report.py
```

## Best Practices

### Test Organization

1. **Clear Test Structure**: Organize tests by component and functionality
2. **Descriptive Names**: Use clear, descriptive test names
3. **Test Documentation**: Document complex test scenarios
4. **Test Data Isolation**: Ensure tests don't interfere with each other
5. **Cleanup**: Proper cleanup of test data and resources

### Test Quality

1. **Comprehensive Coverage**: Aim for high test coverage
2. **Edge Case Testing**: Test boundary conditions and edge cases
3. **Error Handling**: Test error conditions and exception handling
4. **Performance Testing**: Include performance and load testing
5. **Security Testing**: Regular security vulnerability testing

### Maintenance

1. **Regular Updates**: Keep tests updated with code changes
2. **Test Review**: Regular review of test effectiveness
3. **Performance Monitoring**: Monitor test execution performance
4. **Documentation**: Keep test documentation current
5. **Automation**: Automate test execution and reporting

---

**Document Version**: 1.0  
**Last Updated**: 2024-12-19  
**Next Review**: 2025-01-19