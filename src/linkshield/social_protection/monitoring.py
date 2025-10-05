"""
System Health Monitoring for Social Protection

This module provides comprehensive system health monitoring including:
- Service health checks
- Metrics collection and analysis
- Log monitoring
- Alert generation
- Performance tracking
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from enum import Enum

from linkshield.utils import utc_datetime
from linkshield.social_protection.logging_utils import get_logger

logger = get_logger("SystemHealthMonitor")


class HealthStatus(Enum):
    """System health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    WARNING = "warning"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"


class ServiceHealthCheck:
    """Health check for individual services"""
    
    def __init__(self, service_name: str, check_interval: int = 60):
        self.service_name = service_name
        self.check_interval = check_interval
        self.last_check = None
        self.status = HealthStatus.HEALTHY
        self.error_count = 0
        self.consecutive_failures = 0
        
    async def check(self) -> Dict[str, Any]:
        """Perform health check"""
        self.last_check = utc_datetime()
        
        try:
            # Implement service-specific health check
            result = await self._perform_check()
            
            if result["healthy"]:
                self.consecutive_failures = 0
                self.status = HealthStatus.HEALTHY
            else:
                self.consecutive_failures += 1
                self._update_status()
            
            return {
                "service": self.service_name,
                "status": self.status.value,
                "healthy": result["healthy"],
                "details": result.get("details", {}),
                "last_check": self.last_check.isoformat(),
                "consecutive_failures": self.consecutive_failures
            }
            
        except Exception as e:
            self.error_count += 1
            self.consecutive_failures += 1
            self._update_status()
            
            logger.error(
                f"Health check failed for {self.service_name}",
                extra={"error": str(e), "consecutive_failures": self.consecutive_failures}
            )
            
            return {
                "service": self.service_name,
                "status": self.status.value,
                "healthy": False,
                "error": str(e),
                "last_check": self.last_check.isoformat(),
                "consecutive_failures": self.consecutive_failures
            }
    
    async def _perform_check(self) -> Dict[str, Any]:
        """Override in subclasses for specific checks"""
        return {"healthy": True}
    
    def _update_status(self):
        """Update status based on consecutive failures"""
        if self.consecutive_failures >= 5:
            self.status = HealthStatus.CRITICAL
        elif self.consecutive_failures >= 3:
            self.status = HealthStatus.UNHEALTHY
        elif self.consecutive_failures >= 2:
            self.status = HealthStatus.WARNING
        else:
            self.status = HealthStatus.DEGRADED


class DatabaseHealthCheck(ServiceHealthCheck):
    """Database connection health check"""
    
    def __init__(self, db_session_factory):
        super().__init__("database", check_interval=30)
        self.db_session_factory = db_session_factory
    
    async def _perform_check(self) -> Dict[str, Any]:
        """Check database connectivity"""
        try:
            async with self.db_session_factory() as session:
                # Simple query to verify connection
                result = await session.execute("SELECT 1")
                return {
                    "healthy": True,
                    "details": {"connection": "active"}
                }
        except Exception as e:
            return {
                "healthy": False,
                "details": {"error": str(e)}
            }


class RedisHealthCheck(ServiceHealthCheck):
    """Redis connection health check"""
    
    def __init__(self, redis_client):
        super().__init__("redis", check_interval=30)
        self.redis_client = redis_client
    
    async def _perform_check(self) -> Dict[str, Any]:
        """Check Redis connectivity"""
        try:
            if self.redis_client:
                await self.redis_client.ping()
                return {
                    "healthy": True,
                    "details": {"connection": "active"}
                }
            else:
                return {
                    "healthy": False,
                    "details": {"error": "Redis client not configured"}
                }
        except Exception as e:
            return {
                "healthy": False,
                "details": {"error": str(e)}
            }


class AIServiceHealthCheck(ServiceHealthCheck):
    """AI service health check"""
    
    def __init__(self, ai_service):
        super().__init__("ai_service", check_interval=60)
        self.ai_service = ai_service
    
    async def _perform_check(self) -> Dict[str, Any]:
        """Check AI service availability"""
        try:
            # Simple test query
            test_result = await self.ai_service.analyze_text(
                "test", analysis_type="health_check"
            )
            return {
                "healthy": True,
                "details": {"response_time": test_result.get("processing_time", 0)}
            }
        except Exception as e:
            return {
                "healthy": False,
                "details": {"error": str(e)}
            }


class MetricsCollector:
    """Collect and analyze system metrics"""
    
    def __init__(self):
        self.metrics = {}
        self.metric_history = {}
        
    def record_metric(self, metric_name: str, value: float, tags: Optional[Dict] = None):
        """Record a metric value"""
        timestamp = utc_datetime()
        
        if metric_name not in self.metric_history:
            self.metric_history[metric_name] = []
        
        self.metric_history[metric_name].append({
            "value": value,
            "timestamp": timestamp,
            "tags": tags or {}
        })
        
        # Keep only last 1000 entries per metric
        if len(self.metric_history[metric_name]) > 1000:
            self.metric_history[metric_name] = self.metric_history[metric_name][-1000:]
        
        self.metrics[metric_name] = value
    
    def get_metric_stats(self, metric_name: str, window_minutes: int = 60) -> Dict[str, Any]:
        """Get statistics for a metric over a time window"""
        if metric_name not in self.metric_history:
            return {}
        
        cutoff_time = utc_datetime() - timedelta(minutes=window_minutes)
        recent_values = [
            entry["value"] for entry in self.metric_history[metric_name]
            if entry["timestamp"] >= cutoff_time
        ]
        
        if not recent_values:
            return {}
        
        return {
            "count": len(recent_values),
            "min": min(recent_values),
            "max": max(recent_values),
            "avg": sum(recent_values) / len(recent_values),
            "latest": recent_values[-1]
        }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all current metrics"""
        return self.metrics.copy()


class SystemHealthMonitor:
    """Comprehensive system health monitoring"""
    
    def __init__(
        self,
        db_session_factory=None,
        redis_client=None,
        ai_service=None,
        check_interval: int = 60
    ):
        self.check_interval = check_interval
        self.health_checks: List[ServiceHealthCheck] = []
        self.metrics_collector = MetricsCollector()
        self.monitoring_active = False
        self.last_full_check = None
        
        # Register health checks
        if db_session_factory:
            self.health_checks.append(DatabaseHealthCheck(db_session_factory))
        
        if redis_client:
            self.health_checks.append(RedisHealthCheck(redis_client))
        
        if ai_service:
            self.health_checks.append(AIServiceHealthCheck(ai_service))
    
    async def start_monitoring(self):
        """Start continuous health monitoring"""
        self.monitoring_active = True
        logger.info("System health monitoring started")
        
        while self.monitoring_active:
            try:
                await self.perform_health_check()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                await asyncio.sleep(self.check_interval)
    
    def stop_monitoring(self):
        """Stop health monitoring"""
        self.monitoring_active = False
        logger.info("System health monitoring stopped")
    
    async def perform_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        self.last_full_check = utc_datetime()
        
        # Run all health checks concurrently
        check_results = await asyncio.gather(
            *[check.check() for check in self.health_checks],
            return_exceptions=True
        )
        
        # Process results
        service_statuses = {}
        overall_status = HealthStatus.HEALTHY
        
        for result in check_results:
            if isinstance(result, Exception):
                logger.error(f"Health check exception: {str(result)}")
                overall_status = HealthStatus.UNHEALTHY
                continue
            
            service_name = result["service"]
            service_statuses[service_name] = result
            
            # Update overall status
            service_status = HealthStatus(result["status"])
            if service_status == HealthStatus.CRITICAL:
                overall_status = HealthStatus.CRITICAL
            elif service_status == HealthStatus.UNHEALTHY and overall_status != HealthStatus.CRITICAL:
                overall_status = HealthStatus.UNHEALTHY
            elif service_status == HealthStatus.WARNING and overall_status == HealthStatus.HEALTHY:
                overall_status = HealthStatus.WARNING
        
        # Collect metrics
        metrics = self.metrics_collector.get_all_metrics()
        
        health_report = {
            "overall_status": overall_status.value,
            "timestamp": self.last_full_check.isoformat(),
            "services": service_statuses,
            "metrics": metrics,
            "check_interval": self.check_interval
        }
        
        # Log health status
        logger.info(
            f"Health check completed: {overall_status.value}",
            extra={
                "overall_status": overall_status.value,
                "service_count": len(service_statuses),
                "healthy_services": sum(1 for s in service_statuses.values() if s["healthy"])
            }
        )
        
        # Generate alerts if needed
        if overall_status in [HealthStatus.UNHEALTHY, HealthStatus.CRITICAL]:
            await self._generate_alert(health_report)
        
        return health_report
    
    async def _generate_alert(self, health_report: Dict[str, Any]):
        """Generate alert for unhealthy system"""
        logger.warning(
            "System health alert generated",
            extra={
                "status": health_report["overall_status"],
                "unhealthy_services": [
                    name for name, status in health_report["services"].items()
                    if not status["healthy"]
                ]
            }
        )
        
        # In production, send alerts via email, Slack, PagerDuty, etc.
        # For now, just log the alert
    
    def record_metric(self, metric_name: str, value: float, tags: Optional[Dict] = None):
        """Record a metric"""
        self.metrics_collector.record_metric(metric_name, value, tags)
    
    def get_metric_stats(self, metric_name: str, window_minutes: int = 60) -> Dict[str, Any]:
        """Get metric statistics"""
        return self.metrics_collector.get_metric_stats(metric_name, window_minutes)
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        if not self.last_full_check:
            return {
                "status": "unknown",
                "message": "No health checks performed yet"
            }
        
        # Perform fresh health check
        return await self.perform_health_check()


# Global monitor instance
_monitor_instance: Optional[SystemHealthMonitor] = None


def get_system_monitor() -> SystemHealthMonitor:
    """Get global system monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = SystemHealthMonitor()
    return _monitor_instance


def initialize_monitoring(
    db_session_factory=None,
    redis_client=None,
    ai_service=None,
    check_interval: int = 60
):
    """Initialize system monitoring"""
    global _monitor_instance
    _monitor_instance = SystemHealthMonitor(
        db_session_factory=db_session_factory,
        redis_client=redis_client,
        ai_service=ai_service,
        check_interval=check_interval
    )
    return _monitor_instance
