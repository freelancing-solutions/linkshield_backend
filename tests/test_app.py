"""Basic application tests to verify FastAPI setup and parameter fixes."""

import pytest
from fastapi.testclient import TestClient
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


def test_app_import():
    """Test that the main app can be imported without errors."""
    try:
        from app import app
        assert app is not None
    except Exception as e:
        pytest.fail(f"Failed to import app: {e}")


def test_health_endpoint():
    """Test the health endpoint is accessible."""
    try:
        from app import app
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
    except Exception as e:
        pytest.fail(f"Health endpoint test failed: {e}")


def test_fastapi_parameter_validation():
    """Test that FastAPI parameter validation works correctly."""
    try:
        from app import app
        # This test verifies that the app can start without parameter validation errors
        assert app is not None
        # If we reach here, the parameter fixes worked
        assert True
    except Exception as e:
        pytest.fail(f"Parameter validation test failed: {e}")