#!/usr/bin/env python3
"""
LinkShield Backend Health Check Routes

Health check endpoints for monitoring API status, database connectivity,
and external service availability.
"""
from fastapi import APIRouter, Depends

from linkshield.controllers.health_controller import (
    HealthController,
    HealthResponse,
    ReadinessResponse,
    LivenessResponse,
    VersionInfoResponse,
    MetricsResponse,
)
from linkshield.controllers.depends import get_health_controller


# Create router
router = APIRouter(prefix="/api/v1", tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check(controller: HealthController = Depends(get_health_controller)) -> HealthResponse:
    """
    Basic health check endpoint.
    Returns overall API health status and basic information.
    """
    return await controller.get_basic_health()


@router.get("/health/detailed", response_model=HealthResponse)
async def detailed_health_check(controller: HealthController = Depends(get_health_controller)) -> HealthResponse:
    """
    Detailed health check endpoint.
    Checks database connectivity and external service availability.
    Delegates business logic to HealthController.
    """
    return await controller.get_detailed_health()


@router.get("/health/ready", response_model=ReadinessResponse)
async def readiness_check(controller: HealthController = Depends(get_health_controller)) -> ReadinessResponse:
    """
    Readiness check endpoint.
    Kubernetes readiness probe endpoint.
    Returns 200 if the service is ready to accept traffic.
    """
    return await controller.check_readiness()


@router.get("/health/live", response_model=LivenessResponse)
async def liveness_check(controller: HealthController = Depends(get_health_controller)) -> LivenessResponse:
    """
    Liveness check endpoint.
    Kubernetes liveness probe endpoint.
    Returns 200 if the service is alive (basic functionality works).
    """
    return await controller.check_liveness()


@router.get("/version", response_model=VersionInfoResponse)
async def version_info(controller: HealthController = Depends(get_health_controller)) -> VersionInfoResponse:
    """
    Version information endpoint.
    Get API version and build information.
    """
    return await controller.get_version_info()


@router.get("/metrics", response_model=MetricsResponse)
async def metrics(controller: HealthController = Depends(get_health_controller)) -> MetricsResponse:
    """
    Metrics endpoint.
    Basic metrics endpoint for monitoring.
    Returns simple application metrics.
    """
    return await controller.get_metrics()
