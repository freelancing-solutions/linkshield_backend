"""
System Monitoring Routes

API endpoints for system health monitoring and metrics.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from datetime import datetime

from src.authentication.auth_service import get_current_user
from src.models.user import User, UserRole
from src.social_protection.monitoring import get_system_monitor

router = APIRouter(prefix="/api/v1/monitoring", tags=["Monitoring"])


@router.get("/health")
async def system_health():
    """
    Get overall system health status
    
    Public endpoint for basic health checks.
    """
    monitor = get_system_monitor()
    health_status = await monitor.get_system_status()
    
    return {
        "status": health_status.get("overall_status", "unknown"),
        "timestamp": health_status.get("timestamp"),
        "services": {
            name: {"healthy": service["healthy"], "status": service["status"]}
            for name, service in health_status.get("services", {}).items()
        }
    }


@router.get("/health/detailed")
async def detailed_health(
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed system health information
    
    Requires authentication. Provides comprehensive health data.
    """
    # Only admins can see detailed health
    if current_user.role != UserRole.ADMIN:
        return {
            "error": "Insufficient permissions",
            "message": "Admin access required for detailed health information"
        }
    
    monitor = get_system_monitor()
    return await monitor.get_system_status()


@router.get("/metrics")
async def get_metrics(
    metric_name: Optional[str] = Query(None, description="Specific metric to retrieve"),
    window_minutes: int = Query(60, ge=1, le=1440, description="Time window in minutes"),
    current_user: User = Depends(get_current_user)
):
    """
    Get system metrics
    
    Requires authentication. Returns metrics for monitoring and analysis.
    """
    # Only admins can see metrics
    if current_user.role != UserRole.ADMIN:
        return {
            "error": "Insufficient permissions",
            "message": "Admin access required for metrics"
        }
    
    monitor = get_system_monitor()
    
    if metric_name:
        # Get specific metric stats
        stats = monitor.get_metric_stats(metric_name, window_minutes)
        return {
            "metric": metric_name,
            "window_minutes": window_minutes,
            "stats": stats
        }
    else:
        # Get all current metrics
        metrics = monitor.metrics_collector.get_all_metrics()
        return {
            "metrics": metrics,
            "timestamp": datetime.utcnow().isoformat()
        }


@router.get("/services")
async def service_status(
    current_user: User = Depends(get_current_user)
):
    """
    Get status of all monitored services
    
    Requires authentication.
    """
    # Only admins can see service status
    if current_user.role != UserRole.ADMIN:
        return {
            "error": "Insufficient permissions",
            "message": "Admin access required for service status"
        }
    
    monitor = get_system_monitor()
    health_status = await monitor.get_system_status()
    
    return {
        "services": health_status.get("services", {}),
        "overall_status": health_status.get("overall_status"),
        "timestamp": health_status.get("timestamp")
    }


@router.post("/check")
async def trigger_health_check(
    current_user: User = Depends(get_current_user)
):
    """
    Manually trigger a health check
    
    Requires admin authentication.
    """
    # Only admins can trigger checks
    if current_user.role != UserRole.ADMIN:
        return {
            "error": "Insufficient permissions",
            "message": "Admin access required to trigger health checks"
        }
    
    monitor = get_system_monitor()
    result = await monitor.perform_health_check()
    
    return {
        "success": True,
        "message": "Health check completed",
        "result": result
    }
