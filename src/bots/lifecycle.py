"""
Bot Lifecycle Management System.

This module provides centralized bot initialization, startup, shutdown,
and health monitoring for all social media bot platforms.
"""

import logging
import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
import signal
import sys

from ..config.settings import settings
from .registration import bot_registration_manager, bot_configuration_manager
from .gateway import bot_gateway
from .error_handler import bot_error_handler

logger = logging.getLogger(__name__)


class BotStatus(Enum):
    """Bot status enumeration."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class BotLifecycleManager:
    """
    Manages the complete lifecycle of all bot platforms.
    
    Handles initialization, startup, shutdown, health monitoring,
    and graceful error recovery for all social media bots.
    """
    
    def __init__(self):
        """Initialize the bot lifecycle manager."""
        self.status = BotStatus.STOPPED
        self.platform_statuses: Dict[str, BotStatus] = {}
        self.startup_time: Optional[datetime] = None
        self.shutdown_callbacks: List[Callable] = []
        self.health_check_task: Optional[asyncio.Task] = None
        self.is_shutting_down = False
        
        # Health monitoring
        self.last_health_check: Optional[datetime] = None
        self.health_check_interval = timedelta(seconds=settings.HEALTH_CHECK_INTERVAL)
        self.platform_health: Dict[str, Dict[str, Any]] = {}
        
        # Error tracking
        self.error_counts: Dict[str, int] = {}
        self.last_errors: Dict[str, datetime] = {}
        
        # Performance metrics
        self.metrics: Dict[str, Any] = {
            "total_commands_processed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "average_response_time": 0.0,
            "uptime_seconds": 0
        }
    
    async def initialize(self):
        """Initialize all bot components."""
        if self.status != BotStatus.STOPPED:
            logger.warning(f"Bot lifecycle manager already initialized (status: {self.status})")
            return
        
        try:
            self.status = BotStatus.STARTING
            logger.info("Initializing bot lifecycle manager...")
            
            # Initialize configuration manager
            await bot_configuration_manager.initialize()
            logger.info("Bot configuration manager initialized")
            
            # Initialize registration manager
            await bot_registration_manager.initialize()
            logger.info("Bot registration manager initialized")
            
            # Initialize bot gateway
            await bot_gateway.initialize()
            logger.info("Bot gateway initialized")
            
            # Initialize error handler
            await bot_error_handler.initialize()
            logger.info("Bot error handler initialized")
            
            # Get enabled platforms
            enabled_platforms = await bot_configuration_manager.get_enabled_platforms()
            logger.info(f"Enabled platforms: {enabled_platforms}")
            
            # Initialize platform statuses
            for platform in enabled_platforms:
                self.platform_statuses[platform] = BotStatus.STOPPED
                self.platform_health[platform] = {
                    "status": "unknown",
                    "last_check": None,
                    "response_time": None,
                    "error_count": 0
                }
            
            self.status = BotStatus.RUNNING
            self.startup_time = datetime.utcnow()
            
            logger.info("Bot lifecycle manager initialized successfully")
            
        except Exception as e:
            self.status = BotStatus.ERROR
            logger.error(f"Failed to initialize bot lifecycle manager: {e}")
            raise
    
    async def start_all_bots(self):
        """Start all enabled bot platforms."""
        if self.status != BotStatus.RUNNING:
            await self.initialize()
        
        try:
            logger.info("Starting all bot platforms...")
            
            # Register commands and set up webhooks
            registration_results = await bot_registration_manager.register_all_commands()
            
            # Update platform statuses based on registration results
            for platform, success in registration_results.items():
                if success:
                    self.platform_statuses[platform] = BotStatus.RUNNING
                    logger.info(f"Platform {platform} started successfully")
                else:
                    self.platform_statuses[platform] = BotStatus.ERROR
                    logger.error(f"Platform {platform} failed to start")
            
            # Start health monitoring
            await self._start_health_monitoring()
            
            # Set up signal handlers for graceful shutdown
            self._setup_signal_handlers()
            
            logger.info("All bot platforms startup completed")
            
        except Exception as e:
            logger.error(f"Failed to start bot platforms: {e}")
            await self.shutdown()
            raise
    
    async def stop_platform(self, platform: str):
        """
        Stop a specific platform.
        
        Args:
            platform: Platform name to stop
        """
        try:
            if platform not in self.platform_statuses:
                logger.warning(f"Platform {platform} not found")
                return
            
            logger.info(f"Stopping platform: {platform}")
            self.platform_statuses[platform] = BotStatus.STOPPING
            
            # Clean up platform commands/webhooks
            success = await bot_registration_manager.cleanup_commands(platform)
            
            if success:
                self.platform_statuses[platform] = BotStatus.STOPPED
                logger.info(f"Platform {platform} stopped successfully")
            else:
                self.platform_statuses[platform] = BotStatus.ERROR
                logger.error(f"Failed to stop platform {platform}")
            
        except Exception as e:
            self.platform_statuses[platform] = BotStatus.ERROR
            logger.error(f"Error stopping platform {platform}: {e}")
    
    async def restart_platform(self, platform: str):
        """
        Restart a specific platform.
        
        Args:
            platform: Platform name to restart
        """
        try:
            logger.info(f"Restarting platform: {platform}")
            
            # Stop the platform
            await self.stop_platform(platform)
            
            # Wait a moment
            await asyncio.sleep(2)
            
            # Start the platform
            if platform == "discord":
                success = await bot_registration_manager.register_discord_commands()
            elif platform == "telegram":
                success = await bot_registration_manager.setup_telegram_webhook()
            elif platform == "twitter":
                success = await bot_registration_manager.setup_twitter_webhook()
            else:
                success = False
            
            if success:
                self.platform_statuses[platform] = BotStatus.RUNNING
                logger.info(f"Platform {platform} restarted successfully")
            else:
                self.platform_statuses[platform] = BotStatus.ERROR
                logger.error(f"Failed to restart platform {platform}")
            
        except Exception as e:
            self.platform_statuses[platform] = BotStatus.ERROR
            logger.error(f"Error restarting platform {platform}: {e}")
    
    async def shutdown(self):
        """Shutdown all bot platforms gracefully."""
        if self.is_shutting_down:
            logger.info("Shutdown already in progress")
            return
        
        try:
            self.is_shutting_down = True
            self.status = BotStatus.STOPPING
            logger.info("Shutting down bot lifecycle manager...")
            
            # Stop health monitoring
            if self.health_check_task:
                self.health_check_task.cancel()
                try:
                    await self.health_check_task
                except asyncio.CancelledError:
                    pass
            
            # Stop all platforms
            for platform in list(self.platform_statuses.keys()):
                await self.stop_platform(platform)
            
            # Execute shutdown callbacks
            for callback in self.shutdown_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback()
                    else:
                        callback()
                except Exception as e:
                    logger.error(f"Error in shutdown callback: {e}")
            
            # Shutdown components
            await bot_gateway.shutdown()
            await bot_registration_manager.shutdown()
            await bot_error_handler.shutdown()
            
            self.status = BotStatus.STOPPED
            logger.info("Bot lifecycle manager shutdown completed")
            
        except Exception as e:
            self.status = BotStatus.ERROR
            logger.error(f"Error during shutdown: {e}")
    
    def add_shutdown_callback(self, callback: Callable):
        """
        Add a callback to be executed during shutdown.
        
        Args:
            callback: Function to call during shutdown
        """
        self.shutdown_callbacks.append(callback)
    
    async def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive status information.
        
        Returns:
            Status information dictionary
        """
        uptime_seconds = 0
        if self.startup_time:
            uptime_seconds = (datetime.utcnow() - self.startup_time).total_seconds()
        
        return {
            "overall_status": self.status.value,
            "startup_time": self.startup_time.isoformat() if self.startup_time else None,
            "uptime_seconds": uptime_seconds,
            "platform_statuses": {k: v.value for k, v in self.platform_statuses.items()},
            "platform_health": self.platform_health,
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None,
            "metrics": self.metrics,
            "error_counts": self.error_counts
        }
    
    async def get_health_status(self) -> Dict[str, Any]:
        """
        Get health status for monitoring systems.
        
        Returns:
            Health status dictionary
        """
        overall_healthy = (
            self.status == BotStatus.RUNNING and
            all(status in [BotStatus.RUNNING, BotStatus.STOPPED] for status in self.platform_statuses.values())
        )
        
        return {
            "healthy": overall_healthy,
            "status": self.status.value,
            "platforms": {
                platform: {
                    "status": status.value,
                    "healthy": status in [BotStatus.RUNNING, BotStatus.STOPPED],
                    "health_data": self.platform_health.get(platform, {})
                }
                for platform, status in self.platform_statuses.items()
            },
            "uptime_seconds": self.metrics["uptime_seconds"],
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None
        }
    
    def update_metrics(self, command_success: bool, response_time: float):
        """
        Update performance metrics.
        
        Args:
            command_success: Whether the command was successful
            response_time: Command response time in seconds
        """
        self.metrics["total_commands_processed"] += 1
        
        if command_success:
            self.metrics["successful_commands"] += 1
        else:
            self.metrics["failed_commands"] += 1
        
        # Update average response time
        total_commands = self.metrics["total_commands_processed"]
        current_avg = self.metrics["average_response_time"]
        self.metrics["average_response_time"] = (
            (current_avg * (total_commands - 1) + response_time) / total_commands
        )
        
        # Update uptime
        if self.startup_time:
            self.metrics["uptime_seconds"] = (datetime.utcnow() - self.startup_time).total_seconds()
    
    def record_platform_error(self, platform: str):
        """
        Record an error for a platform.
        
        Args:
            platform: Platform name
        """
        self.error_counts[platform] = self.error_counts.get(platform, 0) + 1
        self.last_errors[platform] = datetime.utcnow()
        
        # Update platform health
        if platform in self.platform_health:
            self.platform_health[platform]["error_count"] += 1
    
    # Private helper methods
    
    async def _start_health_monitoring(self):
        """Start the health monitoring task."""
        if self.health_check_task:
            return
        
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info("Health monitoring started")
    
    async def _health_check_loop(self):
        """Health check loop."""
        while not self.is_shutting_down:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.health_check_interval.total_seconds())
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _perform_health_checks(self):
        """Perform health checks on all platforms."""
        self.last_health_check = datetime.utcnow()
        
        for platform in self.platform_statuses:
            try:
                start_time = datetime.utcnow()
                
                # Get bot info as a health check
                bot_info = await bot_registration_manager.get_bot_info(platform)
                
                response_time = (datetime.utcnow() - start_time).total_seconds()
                
                # Update health status
                self.platform_health[platform].update({
                    "status": "healthy" if bot_info else "unhealthy",
                    "last_check": self.last_health_check.isoformat(),
                    "response_time": response_time,
                    "bot_info": bot_info is not None
                })
                
                # Check if platform needs restart
                if not bot_info and self.platform_statuses[platform] == BotStatus.RUNNING:
                    logger.warning(f"Platform {platform} health check failed, considering restart")
                    self.record_platform_error(platform)
                    
                    # Auto-restart if error count is high
                    if self.error_counts.get(platform, 0) >= 3:
                        logger.info(f"Auto-restarting platform {platform} due to repeated failures")
                        await self.restart_platform(platform)
                        self.error_counts[platform] = 0  # Reset error count after restart
                
            except Exception as e:
                logger.error(f"Health check failed for platform {platform}: {e}")
                self.record_platform_error(platform)
                
                self.platform_health[platform].update({
                    "status": "error",
                    "last_check": self.last_health_check.isoformat(),
                    "error": str(e)
                })
    
    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            asyncio.create_task(self.shutdown())
        
        # Set up signal handlers (Unix systems)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, signal_handler)


# Global lifecycle manager instance
bot_lifecycle_manager = BotLifecycleManager()


# Convenience functions for external use

async def start_bots():
    """Start all bot platforms."""
    await bot_lifecycle_manager.start_all_bots()


async def stop_bots():
    """Stop all bot platforms."""
    await bot_lifecycle_manager.shutdown()


async def restart_bot_platform(platform: str):
    """Restart a specific bot platform."""
    await bot_lifecycle_manager.restart_platform(platform)


async def get_bot_status():
    """Get bot status information."""
    return await bot_lifecycle_manager.get_status()


async def get_bot_health():
    """Get bot health information."""
    return await bot_lifecycle_manager.get_health_status()