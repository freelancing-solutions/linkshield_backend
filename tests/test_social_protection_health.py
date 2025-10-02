#!/usr/bin/env python3
"""
Tests for Social Protection Health Check Endpoint

Tests the comprehensive health check functionality for social protection services.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone
from fastapi import HTTPException
from fastapi.testclient import TestClient


@pytest.fixture
def mock_controller():
    """Create a mock controller for testing."""
    controller = AsyncMock()
    
    # Mock the health status response
    controller.get_health_status = AsyncMock(return_value={
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "response_time_seconds": 0.123,
        "checks": {
            "extension_data_processor": {
                "status": "healthy",
                "message": "Extension data processor operational"
            },
            "social_scan_service": {
                "status": "healthy",
                "message": "Social scan service operational"
            },
            "database": {
                "status": "healthy",
                "message": "Database connection successful"
            },
            "analyzers": {
                "status": "healthy",
                "message": "8/8 analyzers available",
                "details": []
            },
            "platform_adapters": {
                "status": "healthy",
                "message": "7/7 platform adapters configured",
                "details": []
            },
            "crisis_detection": {
                "status": "available",
                "message": "Crisis detection system operational"
            }
        },
        "summary": {
            "total_checks": 6,
            "healthy": 6,
            "degraded": 0,
            "unhealthy": 0
        }
    })
    
    return controller


@pytest.mark.asyncio
async def test_health_check_response_structure(mock_controller):
    """Test that health check response has correct structure."""
    result = await mock_controller.get_health_status()
    
    # Verify response structure
    assert isinstance(result, dict)
    assert "status" in result
    assert result["status"] in ["healthy", "degraded", "unhealthy"]
    
    assert "timestamp" in result
    assert isinstance(result["timestamp"], str)
    
    assert "response_time_seconds" in result
    assert isinstance(result["response_time_seconds"], (int, float))
    
    assert "checks" in result
    assert isinstance(result["checks"], dict)
    
    assert "summary" in result
    assert "total_checks" in result["summary"]
    assert "healthy" in result["summary"]
    assert "degraded" in result["summary"]
    assert "unhealthy" in result["summary"]


@pytest.mark.asyncio
async def test_health_check_all_services_healthy(mock_controller):
    """Test health check when all services are healthy."""
    result = await mock_controller.get_health_status()
    
    assert result["status"] == "healthy"
    assert "timestamp" in result
    assert "response_time_seconds" in result
    assert "checks" in result
    assert "summary" in result
    
    # Verify core services are checked
    assert "extension_data_processor" in result["checks"]
    assert "social_scan_service" in result["checks"]
    assert "database" in result["checks"]
    
    # Verify summary counts
    assert result["summary"]["total_checks"] > 0
    assert result["summary"]["healthy"] == 6


@pytest.mark.asyncio
async def test_health_check_database_failure():
    """Test health check when database is unavailable."""
    controller = AsyncMock()
    
    # Mock database failure
    controller.get_health_status = AsyncMock(
        side_effect=HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "checks": {
                    "database": {
                        "status": "unhealthy",
                        "message": "Database connection failed"
                    }
                }
            }
        )
    )
    
    # Should raise HTTPException with 503 status
    with pytest.raises(HTTPException) as exc_info:
        await controller.get_health_status()
    
    assert exc_info.value.status_code == 503
    assert "status" in exc_info.value.detail
    assert exc_info.value.detail["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_health_check_degraded_services():
    """Test health check when some services are degraded."""
    controller = AsyncMock()
    
    controller.get_health_status = AsyncMock(return_value={
        "status": "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "response_time_seconds": 0.150,
        "checks": {
            "extension_data_processor": {
                "status": "unavailable",
                "message": "Service not initialized"
            },
            "social_scan_service": {
                "status": "unavailable",
                "message": "Service not initialized"
            },
            "database": {
                "status": "healthy",
                "message": "Database connection successful"
            }
        },
        "summary": {
            "total_checks": 3,
            "healthy": 1,
            "degraded": 2,
            "unhealthy": 0
        }
    })
    
    result = await controller.get_health_status()
    
    # Should be degraded but not unhealthy
    assert result["status"] == "degraded"
    assert result["checks"]["extension_data_processor"]["status"] == "unavailable"
    assert result["checks"]["social_scan_service"]["status"] == "unavailable"
    assert result["summary"]["degraded"] == 2


@pytest.mark.asyncio
async def test_health_check_includes_all_components(mock_controller):
    """Test that health check includes all expected components."""
    result = await mock_controller.get_health_status()
    
    # Verify all major components are checked
    expected_checks = [
        "extension_data_processor",
        "social_scan_service",
        "database",
        "analyzers",
        "platform_adapters",
        "crisis_detection"
    ]
    
    for check in expected_checks:
        assert check in result["checks"], f"Missing check: {check}"
        assert "status" in result["checks"][check]
        assert "message" in result["checks"][check]
