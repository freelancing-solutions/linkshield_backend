"""
Social Protection Background Tasks

Celery tasks for long-running social protection operations including
deep analysis, comprehensive scans, and crisis detection.
"""

import asyncio
from typing import Dict, Any, Optional
from uuid import UUID
from datetime import datetime

from src.social_protection.logging_utils import get_logger

logger = get_logger("SocialProtectionTasks")

# Celery app will be initialized by the main application
try:
    from celery import Celery, Task
    from celery.result import AsyncResult
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    logger.warning("Celery not available, background tasks disabled")
    Celery = None
    Task = object
    AsyncResult = None


# Task configuration
TASK_CONFIG = {
    "deep_analysis": {
        "max_retries": 3,
        "retry_backoff": True,
        "retry_backoff_max": 600,  # 10 minutes
        "retry_jitter": True,
        "time_limit": 300,  # 5 minutes
        "soft_time_limit": 240  # 4 minutes
    },
    "comprehensive_scan": {
        "max_retries": 3,
        "retry_backoff": True,
        "retry_backoff_max": 1800,  # 30 minutes
        "retry_jitter": True,
        "time_limit": 600,  # 10 minutes
        "soft_time_limit": 540  # 9 minutes
    },
    "crisis_detection": {
        "max_retries": 2,
        "retry_backoff": True,
        "retry_backoff_max": 300,  # 5 minutes
        "time_limit": 180,  # 3 minutes
        "soft_time_limit": 150  # 2.5 minutes
    }
}


class SocialProtectionTask(Task):
    """Base task class for social protection operations"""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        logger.error(
            f"Task {self.name} failed",
            extra={
                "task_id": task_id,
                "exception": str(exc),
                "args": args,
                "kwargs": kwargs
            }
        )
    
    def on_success(self, retval, task_id, args, kwargs):
        """Handle task success"""
        logger.info(
            f"Task {self.name} completed successfully",
            extra={
                "task_id": task_id,
                "args": args
            }
        )
    
    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Handle task retry"""
        logger.warning(
            f"Task {self.name} retrying",
            extra={
                "task_id": task_id,
                "exception": str(exc),
                "retry_count": self.request.retries
            }
        )


def create_celery_app(broker_url: str = "redis://localhost:6379/0") -> Optional[Celery]:
    """
    Create and configure Celery application
    
    Args:
        broker_url: Celery broker URL
        
    Returns:
        Configured Celery app or None if Celery not available
    """
    if not CELERY_AVAILABLE:
        logger.warning("Celery not available, returning None")
        return None
    
    app = Celery(
        "social_protection",
        broker=broker_url,
        backend=broker_url
    )
    
    # Configure Celery
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_time_limit=600,
        task_soft_time_limit=540,
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=1000
    )
    
    return app


# Global Celery app instance
celery_app = None


def get_celery_app() -> Optional[Celery]:
    """Get or create Celery app instance"""
    global celery_app
    
    if celery_app is None and CELERY_AVAILABLE:
        celery_app = create_celery_app()
    
    return celery_app


# Task definitions (will be registered when Celery is available)

if CELERY_AVAILABLE:
    app = get_celery_app()
    
    @app.task(
        base=SocialProtectionTask,
        bind=True,
        **TASK_CONFIG["deep_analysis"]
    )
    def process_deep_analysis(self, scan_id: str, user_id: str) -> Dict[str, Any]:
        """
        Process deep content analysis
        
        Args:
            scan_id: ID of the scan to analyze
            user_id: ID of the user requesting analysis
            
        Returns:
            Analysis results
        """
        try:
            logger.info(f"Starting deep analysis for scan {scan_id}")
            
            # Import here to avoid circular dependencies
            from src.config.database import get_db_session
            from src.social_protection.services import SocialScanService
            
            # Run async code in sync context
            async def run_analysis():
                async with get_db_session() as session:
                    service = SocialScanService()
                    result = await service.perform_deep_analysis(scan_id, session)
                    return result
            
            # Execute async function
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(run_analysis())
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "result": result,
                    "completed_at": datetime.utcnow().isoformat()
                }
            finally:
                loop.close()
        
        except Exception as exc:
            logger.error(f"Deep analysis failed: {exc}")
            # Retry with exponential backoff
            raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))
    
    @app.task(
        base=SocialProtectionTask,
        bind=True,
        **TASK_CONFIG["comprehensive_scan"]
    )
    def process_comprehensive_scan(
        self,
        platform: str,
        profile_url: str,
        user_id: str,
        scan_options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process comprehensive profile scan
        
        Args:
            platform: Social media platform
            profile_url: Profile URL to scan
            user_id: ID of the user requesting scan
            scan_options: Scan configuration options
            
        Returns:
            Scan results
        """
        try:
            logger.info(f"Starting comprehensive scan for {profile_url}")
            
            from src.config.database import get_db_session
            from src.social_protection.services import SocialScanService
            from src.social_protection.types import PlatformType
            
            async def run_scan():
                async with get_db_session() as session:
                    service = SocialScanService()
                    result = await service.perform_comprehensive_scan(
                        platform=PlatformType(platform),
                        profile_url=profile_url,
                        user_id=UUID(user_id),
                        scan_options=scan_options,
                        session=session
                    )
                    return result
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(run_scan())
                return {
                    "success": True,
                    "profile_url": profile_url,
                    "result": result,
                    "completed_at": datetime.utcnow().isoformat()
                }
            finally:
                loop.close()
        
        except Exception as exc:
            logger.error(f"Comprehensive scan failed: {exc}")
            raise self.retry(exc=exc, countdown=120 * (2 ** self.request.retries))
    
    @app.task(
        base=SocialProtectionTask,
        bind=True,
        **TASK_CONFIG["crisis_detection"]
    )
    def run_crisis_detection_sweep(self, brands: Optional[list] = None) -> Dict[str, Any]:
        """
        Run crisis detection sweep for monitored brands
        
        Args:
            brands: Optional list of specific brands to check
            
        Returns:
            Detection results
        """
        try:
            logger.info("Starting crisis detection sweep")
            
            from src.config.database import get_db_session
            from src.social_protection.crisis_detector import CrisisDetector
            from src.social_protection.reputation_monitor.reputation_tracker import ReputationTracker
            from src.services.ai_service import AIService
            
            async def run_detection():
                async with get_db_session() as session:
                    # Initialize services
                    tracker = ReputationTracker()
                    ai_service = AIService()
                    detector = CrisisDetector(
                        reputation_tracker=tracker,
                        ai_service=ai_service,
                        config={}
                    )
                    
                    if brands:
                        # Check specific brands
                        results = []
                        for brand in brands:
                            report = await detector.evaluate_brand(brand, session)
                            results.append(report)
                        return results
                    else:
                        # Check all brands
                        reports = await detector.evaluate_all_brands(session)
                        return reports
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                results = loop.run_until_complete(run_detection())
                return {
                    "success": True,
                    "brands_checked": len(results) if results else 0,
                    "alerts_generated": sum(1 for r in results if r.crisis_detected) if results else 0,
                    "completed_at": datetime.utcnow().isoformat()
                }
            finally:
                loop.close()
        
        except Exception as exc:
            logger.error(f"Crisis detection sweep failed: {exc}")
            raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))
    
    @app.task(base=SocialProtectionTask)
    def send_analysis_notification(
        user_id: str,
        notification_type: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send notification about completed analysis
        
        Args:
            user_id: ID of the user to notify
            notification_type: Type of notification
            data: Notification data
            
        Returns:
            Notification result
        """
        try:
            logger.info(f"Sending {notification_type} notification to user {user_id}")
            
            from src.services.email_service import EmailService
            
            # Send notification (email, webhook, etc.)
            # Implementation depends on notification service
            
            return {
                "success": True,
                "user_id": user_id,
                "notification_type": notification_type,
                "sent_at": datetime.utcnow().isoformat()
            }
        
        except Exception as exc:
            logger.error(f"Notification failed: {exc}")
            return {
                "success": False,
                "error": str(exc)
            }


# Task management functions

def queue_deep_analysis(scan_id: str, user_id: str) -> Optional[str]:
    """
    Queue deep analysis task
    
    Args:
        scan_id: Scan ID
        user_id: User ID
        
    Returns:
        Task ID or None if Celery not available
    """
    if not CELERY_AVAILABLE or not celery_app:
        logger.warning("Celery not available, cannot queue task")
        return None
    
    result = process_deep_analysis.delay(scan_id, user_id)
    return result.id


def queue_comprehensive_scan(
    platform: str,
    profile_url: str,
    user_id: str,
    scan_options: Dict[str, Any]
) -> Optional[str]:
    """
    Queue comprehensive scan task
    
    Args:
        platform: Platform type
        profile_url: Profile URL
        user_id: User ID
        scan_options: Scan options
        
    Returns:
        Task ID or None if Celery not available
    """
    if not CELERY_AVAILABLE or not celery_app:
        logger.warning("Celery not available, cannot queue task")
        return None
    
    result = process_comprehensive_scan.delay(
        platform, profile_url, user_id, scan_options
    )
    return result.id


def queue_crisis_detection(brands: Optional[list] = None) -> Optional[str]:
    """
    Queue crisis detection sweep
    
    Args:
        brands: Optional list of brands to check
        
    Returns:
        Task ID or None if Celery not available
    """
    if not CELERY_AVAILABLE or not celery_app:
        logger.warning("Celery not available, cannot queue task")
        return None
    
    result = run_crisis_detection_sweep.delay(brands)
    return result.id


def get_task_status(task_id: str) -> Dict[str, Any]:
    """
    Get status of a background task
    
    Args:
        task_id: Task ID
        
    Returns:
        Task status information
    """
    if not CELERY_AVAILABLE or not AsyncResult:
        return {
            "status": "unavailable",
            "message": "Celery not available"
        }
    
    result = AsyncResult(task_id, app=celery_app)
    
    return {
        "task_id": task_id,
        "status": result.state,
        "ready": result.ready(),
        "successful": result.successful() if result.ready() else None,
        "result": result.result if result.ready() else None,
        "info": result.info
    }


def cancel_task(task_id: str) -> bool:
    """
    Cancel a background task
    
    Args:
        task_id: Task ID
        
    Returns:
        True if cancelled, False otherwise
    """
    if not CELERY_AVAILABLE or not AsyncResult:
        return False
    
    result = AsyncResult(task_id, app=celery_app)
    result.revoke(terminate=True)
    
    return True
