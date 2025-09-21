#!/usr/bin/env python3
"""
LinkShield Backend Health Check Routes

Health check endpoints for monitoring API status, database connectivity,
and external service availability.
"""

import time
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.config.settings import get_settings
from src.controllers import HealthController
from src.controllers.depends import get_health_controller

# Get settings instance
settings = get_settings()

# Create router
router = APIRouter()


class HealthResponse(BaseModel):
    """
    Health check response model.
    """
    status: str
    timestamp: datetime
    version: str
    environment: str
    uptime: float
    checks: Dict[str, Any]


class ServiceStatus(BaseModel):
    """
    Individual service status model.
    """
    status: str
    response_time: float
    message: str = ""
    details: Dict[str, Any] = {}


# Store application start time
APP_START_TIME = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check(controller:HealthController = Depends(get_health_controller)) -> HealthResponse:
    """
    Basic health check endpoint.
    Returns overall API health status and basic information.
    
    Delegates business logic to HealthController.
    """
    return await controller.get_basic_health()


@router.get("/health/detailed", response_model=HealthResponse)
async def detailed_health_check(controller:HealthController = Depends(get_health_controller)) -> HealthResponse:
    """
    Detailed health check endpoint.
    Checks database connectivity and external service availability.
    
    Delegates business logic to HealthController.
    """
    return await controller.get_detailed_health()


@router.get("/health/ready")
async def readiness_check(controller:HealthController = Depends(get_health_controller)) -> Dict[str, Any]:
    """
    Readiness check endpoint.
    
    Kubernetes readiness probe endpoint.
    Returns 200 if the service is ready to accept traffic.

    """
    return await controller.check_readiness()


@router.get("/health/live")
async def liveness_check(controller:HealthController = Depends(get_health_controller)) -> Dict[str, Any]:
    """
    Liveness check endpoint.
    
    Delegates business logic to HealthController.
    Kubernetes liveness probe endpoint.
    Returns 200 if the service is alive (basic functionality works).

    """
    return await controller.check_liveness()


@router.get("/version")
async def version_info(controller:HealthController = Depends(get_health_controller)) -> Dict[str, Any]:
    """
    Version information endpoint.
    Get API version and build information.
    
    Delegates business logic to HealthController.
    """
    return await controller.get_version_info()


@router.get("/metrics")
async def metrics(controller:HealthController = Depends(get_health_controller)) -> Dict[str, Any]:
    """
    Metrics endpoint.
    Basic metrics endpoint for monitoring.
    Returns simple application metrics.
    
    Delegates business logic to HealthController.
    """
    return await controller.get_metrics()
