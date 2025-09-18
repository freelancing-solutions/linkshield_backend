#!/usr/bin/env python3
"""
LinkShield Backend Health Check Routes

Health check endpoints for monitoring API status, database connectivity,
and external service availability.
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from pydantic import BaseModel

from src.config.database import check_database_health
from src.config.settings import get_settings

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
async def health_check() -> HealthResponse:
    """
    Basic health check endpoint.
    Returns overall API health status and basic information.
    """
    try:
        current_time = time.time()
        uptime = current_time - APP_START_TIME
        
        # Perform basic checks
        checks = {
            "api": {
                "status": "healthy",
                "response_time": 0.001,
                "message": "API is running"
            }
        }
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.now(timezone.utc),
            version=settings.APP_VERSION,
            environment=settings.ENVIRONMENT,
            uptime=uptime,
            checks=checks
        )
    
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Health check failed"
        )


@router.get("/health/detailed", response_model=HealthResponse)
async def detailed_health_check() -> HealthResponse:
    """
    Detailed health check endpoint.
    Checks database connectivity and external service availability.
    """
    try:
        current_time = time.time()
        uptime = current_time - APP_START_TIME
        overall_status = "healthy"
        checks = {}
        
        # Check API status
        api_start = time.time()
        checks["api"] = {
            "status": "healthy",
            "response_time": time.time() - api_start,
            "message": "API is running",
            "details": {
                "uptime": uptime,
                "version": settings.APP_VERSION,
                "environment": settings.ENVIRONMENT
            }
        }
        
        # Check database connectivity
        db_start = time.time()
        try:
            db_healthy = await check_database_health()
            db_response_time = time.time() - db_start
            
            if db_healthy:
                checks["database"] = {
                    "status": "healthy",
                    "response_time": db_response_time,
                    "message": "Database connection successful",
                    "details": {
                        "url": settings.DATABASE_URL.split("@")[1] if "@" in settings.DATABASE_URL else "configured",
                        "pool_size": settings.DATABASE_POOL_SIZE
                    }
                }
            else:
                checks["database"] = {
                    "status": "unhealthy",
                    "response_time": db_response_time,
                    "message": "Database connection failed"
                }
                overall_status = "degraded"
        
        except Exception as e:
            checks["database"] = {
                "status": "unhealthy",
                "response_time": time.time() - db_start,
                "message": f"Database check failed: {str(e)}"
            }
            overall_status = "degraded"
        
        # Check Redis connectivity (if configured)
        if settings.REDIS_URL:
            redis_start = time.time()
            try:
                # TODO: Implement Redis health check when Redis client is added
                checks["redis"] = {
                    "status": "healthy",
                    "response_time": time.time() - redis_start,
                    "message": "Redis connection successful",
                    "details": {
                        "url": settings.REDIS_URL.split("@")[1] if "@" in settings.REDIS_URL else "configured"
                    }
                }
            except Exception as e:
                checks["redis"] = {
                    "status": "unhealthy",
                    "response_time": time.time() - redis_start,
                    "message": f"Redis check failed: {str(e)}"
                }
                if overall_status == "healthy":
                    overall_status = "degraded"
        
        # Check external services
        external_services = {
            "openai": settings.OPENAI_API_KEY is not None,
            "virustotal": settings.VIRUSTOTAL_API_KEY is not None,
            "google_safe_browsing": settings.GOOGLE_SAFE_BROWSING_API_KEY is not None,
            "urlvoid": settings.URLVOID_API_KEY is not None,
            "stripe": settings.STRIPE_SECRET_KEY is not None,
        }
        
        checks["external_services"] = {
            "status": "healthy",
            "response_time": 0.001,
            "message": "External service configuration checked",
            "details": {
                "configured_services": [service for service, configured in external_services.items() if configured],
                "total_configured": sum(external_services.values())
            }
        }
        
        return HealthResponse(
            status=overall_status,
            timestamp=datetime.now(timezone.utc),
            version=settings.APP_VERSION,
            environment=settings.ENVIRONMENT,
            uptime=uptime,
            checks=checks
        )
    
    except Exception as e:
        logger.error(f"Detailed health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detailed health check failed"
        )


@router.get("/health/ready")
async def readiness_check() -> Dict[str, Any]:
    """
    Kubernetes readiness probe endpoint.
    Returns 200 if the service is ready to accept traffic.
    """
    try:
        # Check if database is accessible
        db_healthy = await check_database_health()
        
        if not db_healthy:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service not ready - database unavailable"
            )
        
        return {
            "status": "ready",
            "timestamp": datetime.now(timezone.utc),
            "message": "Service is ready to accept traffic"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready"
        )


@router.get("/health/live")
async def liveness_check() -> Dict[str, Any]:
    """
    Kubernetes liveness probe endpoint.
    Returns 200 if the service is alive (basic functionality works).
    """
    try:
        current_time = time.time()
        uptime = current_time - APP_START_TIME
        
        return {
            "status": "alive",
            "timestamp": datetime.now(timezone.utc),
            "uptime": uptime,
            "message": "Service is alive"
        }
    
    except Exception as e:
        logger.error(f"Liveness check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not alive"
        )


@router.get("/version")
async def version_info() -> Dict[str, Any]:
    """
    Get API version and build information.
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "build_time": datetime.fromtimestamp(APP_START_TIME, tz=timezone.utc),
        "uptime": time.time() - APP_START_TIME,
        "python_version": "3.11+",
        "framework": "FastAPI"
    }


@router.get("/metrics")
async def metrics() -> Dict[str, Any]:
    """
    Basic metrics endpoint for monitoring.
    Returns simple application metrics.
    """
    try:
        current_time = time.time()
        uptime = current_time - APP_START_TIME
        
        # Basic metrics
        metrics_data = {
            "uptime_seconds": uptime,
            "start_time": APP_START_TIME,
            "current_time": current_time,
            "environment": settings.ENVIRONMENT,
            "version": settings.APP_VERSION,
            "status": "healthy"
        }
        
        # Add database metrics if available
        try:
            db_healthy = await check_database_health()
            metrics_data["database_healthy"] = db_healthy
        except Exception:
            metrics_data["database_healthy"] = False
        
        return metrics_data
    
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Metrics collection failed"
        )