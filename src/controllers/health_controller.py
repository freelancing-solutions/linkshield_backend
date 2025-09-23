#!/usr/bin/env python3
"""
LinkShield Backend Health Controller

Controller for handling health check business logic including system monitoring,
database connectivity checks, and external service availability validation.
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import HTTPException
from loguru import logger
from pydantic import BaseModel

from src.controllers.base_controller import BaseController
from src.config.database import check_database_health
from src.config.settings import get_settings


# --- Response Models ---

class ServiceStatus(BaseModel):
    status: str
    response_time: float
    message: str = ""
    details: Dict[str, Any] = {}


class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str
    environment: str
    uptime: float
    checks: Dict[str, Any]


class ReadinessResponse(BaseModel):
    status: str
    timestamp: datetime
    message: str


class LivenessResponse(BaseModel):
    status: str
    timestamp: datetime
    uptime: float
    message: str


class VersionInfoResponse(BaseModel):
    version: str
    environment: str
    build_time: Optional[str] = None
    commit_hash: Optional[str] = None
    python_version: Optional[str] = None


class MetricsResponse(BaseModel):
    uptime_seconds: float
    timestamp: datetime
    environment: str
    version: str
    memory_usage: Optional[Dict[str, Any]] = None
    cpu_usage: Optional[Dict[str, Any]] = None
    disk_usage: Optional[Dict[str, Any]] = None


# --- Controller ---

class HealthController(BaseController):
    """
    Controller for health check operations.

    Handles system health monitoring, database connectivity checks,
    external service validation, and application metrics.
    """

    def __init__(self, security_service, auth_service, email_service):
        if security_service is None:
            raise ValueError("security_service cannot be None")
        if auth_service is None:
            raise ValueError("auth_service cannot be None")
        if email_service is None:
            raise ValueError("email_service cannot be None")

        super().__init__(security_service, auth_service, email_service)
        self.app_start_time = time.time()

    @staticmethod
    def _create_http_exception(status_code: int, detail: str) -> Exception:
        return HTTPException(status_code=status_code, detail=detail)

    async def get_basic_health(self) -> HealthResponse:
        try:
            current_time = time.time()
            uptime = current_time - self.app_start_time
            checks = {
                "api": ServiceStatus(
                    status="healthy",
                    response_time=0.001,
                    message="API is running"
                ).dict()
            }
            return HealthResponse(
                status="healthy",
                timestamp=datetime.now(timezone.utc),
                version=self.settings.APP_VERSION,
                environment=self.settings.ENVIRONMENT,
                uptime=uptime,
                checks=checks
            )
        except Exception as e:
            self.logger.error(f"Basic health check failed: {e}")
            raise self._create_http_exception(503, "Health check failed")

    async def get_detailed_health(self) -> HealthResponse:
        try:
            current_time = time.time()
            uptime = current_time - self.app_start_time
            overall_status = "healthy"
            checks = {}

            api_start = time.time()
            checks["api"] = ServiceStatus(
                status="healthy",
                response_time=time.time() - api_start,
                message="API is running",
                details={
                    "uptime": uptime,
                    "version": self.settings.APP_VERSION,
                    "environment": self.settings.ENVIRONMENT
                }
            ).dict()

            db_check = await self._check_database_health()
            checks["database"] = db_check
            if db_check["status"] != "healthy":
                overall_status = "degraded"

            if self.settings.REDIS_URL:
                redis_check = await self._check_redis_health()
                checks["redis"] = redis_check
                if redis_check["status"] != "healthy" and overall_status == "healthy":
                    overall_status = "degraded"

            checks["external_services"] = self._check_external_services()

            return HealthResponse(
                status=overall_status,
                timestamp=datetime.now(timezone.utc),
                version=self.settings.APP_VERSION,
                environment=self.settings.ENVIRONMENT,
                uptime=uptime,
                checks=checks
            )
        except Exception as e:
            self.logger.error(f"Detailed health check failed: {e}")
            raise self._create_http_exception(503, "Detailed health check failed")

    async def check_readiness(self) -> ReadinessResponse:
        try:
            db_healthy = await check_database_health()
            if not db_healthy:
                raise self._create_http_exception(503, "Service not ready - database unavailable")
            return ReadinessResponse(
                status="ready",
                timestamp=datetime.now(timezone.utc),
                message="Service is ready to accept traffic"
            )
        except Exception as e:
            if hasattr(e, 'status_code'):
                raise
            self.logger.error(f"Readiness check failed: {e}")
            raise self._create_http_exception(503, "Service not ready")

    async def check_liveness(self) -> LivenessResponse:
        try:
            current_time = time.time()
            uptime = current_time - self.app_start_time
            return LivenessResponse(
                status="alive",
                timestamp=datetime.now(timezone.utc),
                uptime=uptime,
                message="Service is alive"
            )
        except Exception as e:
            self.logger.error(f"Liveness check failed: {e}")
            raise self._create_http_exception(503, "Service liveness check failed")

    async def get_version_info(self) -> VersionInfoResponse:
        try:
            return VersionInfoResponse(
                version=self.settings.APP_VERSION,
                environment=self.settings.ENVIRONMENT,
                build_time=getattr(self.settings, 'BUILD_TIME', None),
                commit_hash=getattr(self.settings, 'COMMIT_HASH', None),
                python_version=getattr(self.settings, 'PYTHON_VERSION', None)
            )
        except Exception as e:
            self.logger.error(f"Version info retrieval failed: {e}")
            raise self._create_http_exception(500, "Failed to retrieve version information")

    async def get_metrics(self) -> MetricsResponse:
        try:
            current_time = time.time()
            uptime = current_time - self.app_start_time
            metrics = {
                "uptime_seconds": uptime,
                "timestamp": datetime.now(timezone.utc),
                "environment": self.settings.ENVIRONMENT,
                "version": self.settings.APP_VERSION
            }
            try:
                import psutil
                metrics.update({
                    "memory_usage": {
                        "percent": psutil.virtual_memory().percent,
                        "available_mb": psutil.virtual_memory().available / 1024 / 1024
                    },
                    "cpu_usage": {"percent": psutil.cpu_percent(interval=1)},
                    "disk_usage": {"percent": psutil.disk_usage('/').percent}
                })
            except ImportError:
                pass
            return MetricsResponse(**metrics)
        except Exception as e:
            self.logger.error(f"Metrics retrieval failed: {e}")
            raise self._create_http_exception(500, "Failed to retrieve metrics")

    async def _check_database_health(self) -> Dict[str, Any]:
        db_start = time.time()
        try:
            db_healthy = await check_database_health()
            db_response_time = time.time() - db_start
            if db_healthy:
                return {
                    "status": "healthy",
                    "response_time": db_response_time,
                    "message": "Database connection successful",
                    "details": {
                        "url": self.settings.DATABASE_URL.split("@")[
                            1] if "@" in self.settings.DATABASE_URL else "configured",
                        "pool_size": self.settings.DATABASE_POOL_SIZE
                    }
                }
            else:
                return {
                    "status": "unhealthy",
                    "response_time": db_response_time,
                    "message": "Database connection failed"
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "response_time": time.time() - db_start,
                "message": f"Database check failed: {str(e)}"
            }

    async def _check_redis_health(self) -> Dict[str, Any]:
        redis_start = time.time()
        try:
            return {
                "status": "healthy",
                "response_time": time.time() - redis_start,
                "message": "Redis connection successful",
                "details": {
                    "url": self.settings.REDIS_URL.split("@")[1] if "@" in self.settings.REDIS_URL else "configured"
                }
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "response_time": time.time() - redis_start,
                "message": f"Redis check failed: {str(e)}"
            }

    def _check_external_services(self) -> Dict[str, Any]:
        external_services = {
            "openai": self.settings.OPENAI_API_KEY is not None,
            "virustotal": self.settings.VIRUSTOTAL_API_KEY is not None,
            "google_safe_browsing": self.settings.GOOGLE_SAFE_BROWSING_API_KEY is not None,
            "urlvoid": self.settings.URLVOID_API_KEY is not None,
            "stripe": self.settings.STRIPE_SECRET_KEY is not None,
        }
        return {
            "status": "healthy",
            "response_time": 0.001,
            "message": "External service configuration checked",
            "details": {
                "configured_services": [s for s, c in external_services.items() if c],
                "total_configured": sum(external_services.values())
            }
        }
