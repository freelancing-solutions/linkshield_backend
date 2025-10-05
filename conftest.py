"""
Global pytest configuration and fixtures for LinkShield Backend tests.

This file configures pytest to properly handle imports and provides
common fixtures used across all test modules.
"""

import os
import sys
from pathlib import Path

import pytest

# Add src directory to Python path for proper imports
project_root = Path(__file__).parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Set environment variables for testing - must satisfy Settings validation
os.environ.setdefault("LINKSHIELD_ENVIRONMENT", "development")  # Must be one of: development, staging, production
os.environ.setdefault("LINKSHIELD_DEBUG", "true")
os.environ.setdefault("LINKSHIELD_DATABASE_URL", "postgresql://test:test@localhost:5432/test_db")  # Must be PostgreSQL format
os.environ.setdefault("LINKSHIELD_REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("LINKSHIELD_SECRET_KEY", "test-secret-key-for-testing-only")
os.environ.setdefault("LINKSHIELD_JWT_SECRET_KEY", "test-jwt-secret-key-for-testing-only")


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """
    Set up the test environment before running any tests.
    
    This fixture runs once per test session and ensures that
    the test environment is properly configured.
    """
    # Ensure reports directory exists
    reports_dir = project_root / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    # Ensure htmlcov directory exists for coverage reports
    htmlcov_dir = project_root / "htmlcov"
    htmlcov_dir.mkdir(exist_ok=True)
    
    yield
    
    # Cleanup after all tests
    # Remove test database if it exists
    test_db = project_root / "test.db"
    if test_db.exists():
        test_db.unlink()


@pytest.fixture
def mock_settings():
    """
    Provide mock settings for testing.
    
    Returns a Settings object configured for testing.
    """
    try:
        from linkshield.config.settings import Settings
        
        return Settings(
            ENVIRONMENT="testing",
            DEBUG=True,
            DATABASE_URL="sqlite:///test.db",
            REDIS_URL="redis://localhost:6379/1",
            SECRET_KEY="test-secret-key",
            JWT_SECRET_KEY="test-jwt-secret-key",
            CORS_ORIGINS=["http://localhost:3000"],
            ALLOWED_HOSTS=["localhost", "127.0.0.1"],
        )
    except ImportError:
        # Return a mock object if Settings can't be imported
        class MockSettings:
            ENVIRONMENT = "testing"
            DEBUG = True
            DATABASE_URL = "sqlite:///test.db"
            REDIS_URL = "redis://localhost:6379/1"
            SECRET_KEY = "test-secret-key"
            JWT_SECRET_KEY = "test-jwt-secret-key"
            CORS_ORIGINS = ["http://localhost:3000"]
            ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
        
        return MockSettings()


@pytest.fixture
def test_client():
    """
    Provide a test client for API testing.
    
    Returns a FastAPI test client configured for testing.
    """
    try:
        from fastapi.testclient import TestClient
        from linkshield.main import create_app
        from linkshield.config.settings import Settings
        
        settings = Settings(
            ENVIRONMENT="testing",
            DEBUG=True,
            DATABASE_URL="sqlite:///test.db",
        )
        
        app = create_app(settings)
        return TestClient(app)
    except ImportError:
        # Return None if dependencies can't be imported
        return None


@pytest.fixture
async def async_test_client():
    """
    Provide an async test client for API testing.
    
    Returns an async FastAPI test client configured for testing.
    """
    try:
        from httpx import AsyncClient
        from linkshield.main import create_app
        from linkshield.config.settings import Settings
        
        settings = Settings(
            ENVIRONMENT="testing",
            DEBUG=True,
            DATABASE_URL="sqlite:///test.db",
        )
        
        app = create_app(settings)
        
        async with AsyncClient(app=app, base_url="http://test") as client:
            yield client
    except ImportError:
        # Yield None if dependencies can't be imported
        yield None


# Configure pytest markers
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "api: API tests")
    config.addinivalue_line("markers", "database: Database tests")
    config.addinivalue_line("markers", "redis: Redis tests")
    config.addinivalue_line("markers", "auth: Authentication tests")
    config.addinivalue_line("markers", "middleware: Middleware tests")


# Collection hook to modify test collection
def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add markers based on test location.
    
    This automatically adds appropriate markers to tests based on
    their file path and name patterns.
    """
    for item in items:
        # Add markers based on test file path
        if "test_security" in str(item.fspath):
            item.add_marker(pytest.mark.security)
        elif "test_auth" in str(item.fspath):
            item.add_marker(pytest.mark.auth)
        elif "test_api" in str(item.fspath):
            item.add_marker(pytest.mark.api)
        elif "test_middleware" in str(item.fspath):
            item.add_marker(pytest.mark.middleware)
        elif "test_database" in str(item.fspath):
            item.add_marker(pytest.mark.database)
        elif "test_redis" in str(item.fspath):
            item.add_marker(pytest.mark.redis)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        else:
            item.add_marker(pytest.mark.unit)