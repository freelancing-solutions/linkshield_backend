#!/usr/bin/env python3
"""
LinkShield Backend Admin Controller

Controller for handling admin dashboard business logic including statistics,
configuration management, user administration, and system monitoring.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

from fastapi import HTTPException, BackgroundTasks
from loguru import logger

from linkshield.controllers.base_controller import BaseController
from linkshield.services.admin_service import AdminService, AdminServiceError, ConfigurationError
from linkshield.services.security_service import SecurityService
from linkshield.authentication.auth_service import AuthService
from linkshield.services.email_service import EmailService
from linkshield.models.user import User, UserRole, UserSession
from linkshield.models.url_check import URLCheck, ScanResult, ThreatLevel
from linkshield.models.ai_analysis import AIAnalysis, AnalysisType, ProcessingStatus
from linkshield.models.admin import AdminAction, AdminSession, ActionType
from linkshield.models.task import BackgroundTask, TaskStatus, TaskType, TaskPriority
from linkshield.models  import GlobalConfig
from linkshield.utils import utc_datetime


class AdminController(BaseController):
    """
    Controller for admin dashboard operations.
    
    Handles system statistics, GlobalConfig management, user administration,
    and system health monitoring for administrative users.
    """
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        admin_service: AdminService
    ):
        """
        Initialize the admin controller.
        
        Args:
            security_service: Security service for validation
            auth_service: Authentication service
            email_service: Email service for notifications
            admin_service: Admin service instance
        """
        super().__init__(security_service, auth_service, email_service)
        self.admin_service = admin_service
    
    # Dashboard Statistics Methods
    def _create_http_exception(self, status_code: int, detail: str):
        """

        :return:
        """
        # TODO - Log the Error
        return HTTPException(status_code=status_code, detail=detail)
    
    async def get_dashboard_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive dashboard statistics.
        
        Returns:
            Dict containing dashboard statistics
        """
        try:
            self.logger.info("Fetching dashboard statistics")
            
            # Get database session and fetch raw data
            async with self.get_db_session() as db:
                # Query user statistics
                total_users = await db.query(User).count()
                active_users = await db.query(User).filter(User.is_active == True).count()
                verified_users = await db.query(User).filter(User.is_verified == True).count()
                
                # Query role distribution
                role_stats = await db.query(
                    UserRole.name, 
                    db.func.count(User.id).label('count')
                ).join(User).group_by(UserRole.name).all()
                
                # Query subscription statistics
                subscription_stats = await db.query(
                    User.subscription_plan,
                    db.func.count(User.id).label('count')
                ).group_by(User.subscription_plan).all()
                
                # Query URL check statistics
                total_checks = await db.query(URLCheck).count()
                checks_today = await db.query(URLCheck).filter(
                    URLCheck.created_at >= datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                ).count()
                threats_detected = await db.query(URLCheck).filter(URLCheck.threat_level != ThreatLevel.SAFE).count()
                
                # Query AI analysis statistics
                total_analyses = await db.query(AIAnalysis).count()
                analyses_today = await db.query(AIAnalysis).filter(
                    AIAnalysis.created_at >= datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                ).count()
                
                # Query recent activity (last 24 hours)
                recent_activity = await db.query(URLCheck).filter(
                    URLCheck.created_at >= datetime.now(timezone.utc) - timedelta(hours=24)
                ).order_by(URLCheck.created_at.desc()).limit(10).all()
                
                # Prepare data for AdminService processing
                users_data = {
                    'total': total_users,
                    'active': active_users,
                    'verified': verified_users,
                    'role_distribution': {role.name: role.count for role in role_stats},
                    'subscription_distribution': {sub.subscription_plan: sub.count for sub in subscription_stats}
                }
                
                url_checks_data = {
                    'total': total_checks,
                    'today': checks_today,
                    'threats_detected': threats_detected
                }
                
                ai_analyses_data = {
                    'total': total_analyses,
                    'today': analyses_today,
                    'recent_activity': [
                        {
                            'id': str(activity.id),
                            'url': activity.url,
                            'threat_level': activity.threat_level.value,
                            'created_at': activity.created_at.isoformat()
                        } for activity in recent_activity
                    ]
                }
            
            # Process data using AdminService
            statistics = self.admin_service.process_system_statistics(
                users_data, url_checks_data, ai_analyses_data
            )
            
            self.logger.info("Dashboard statistics retrieved successfully")
            return {
                "success": True,
                "data": statistics,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get dashboard statistics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve dashboard statistics: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error getting dashboard statistics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    # Async Background Task Methods
    
    async def _export_users_async(
        self,
        task_id: str,
        page: int,
        limit: int,
        filters: Dict[str, Any],
        callback_url: Optional[str] = None
    ) -> None:
        """
        Export users data asynchronously in the background.
        
        Args:
            task_id: ID of the background task
            page: Page number for pagination
            limit: Items per page
            filters: User filters to apply
            callback_url: Optional webhook URL for completion notification
        """

        try:
            # Get database session using context manager
            async with self.get_db_session() as db:
                # Update task status to running
                await self.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.RUNNING,
                    progress=10
                )
                
                self.logger.info(f"Starting async user export (task: {task_id})")
                
                # Fetch all user data (potentially large dataset)
                users_data = await self.admin_service.get_users(page, limit, filters)
                
                # Update progress
                await self.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.RUNNING,
                    progress=50
                )
                
                # Process and format data for export
                export_data = {
                    "users": users_data.get('users', []),
                    "total": users_data.get('total', 0),
                    "page": page,
                    "limit": limit,
                    "filters": filters,
                    "exported_at": datetime.now(timezone.utc).isoformat()
                }
                
                # Update progress
                await self.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.RUNNING,
                    progress=90
                )
                
                # Complete task
                await self.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.COMPLETED,
                    progress=100,
                    result=export_data
                )
                
                # Send webhook notification if callback URL provided
                if callback_url:
                    await self.webhook_service.send_webhook(
                        url=callback_url,
                        event_type="ADMIN_USER_EXPORT_COMPLETED",
                        data={
                            "task_id": task_id,
                            "status": "completed",
                            "total_users": export_data["total"],
                            "export_data": export_data
                        }
                    )

                self.logger.info(f"User export completed successfully (task: {task_id})")

        except Exception as e:
            self.logger.error(f"User export failed (task: {task_id}): {str(e)}")

            # Update task status to failed
            try:
                async with self.get_db_session() as db:
                    await self.update_task_status(
                        db=db,
                        task_id=task_id,
                        status=TaskStatus.FAILED,
                        error_message=str(e)
                    )

                    # Send failure webhook notification
                    if callback_url:
                        await self.webhook_service.send_webhook(
                            url=callback_url,
                            event_type="ADMIN_USER_EXPORT_FAILED",
                            data={
                                "task_id": task_id,
                                "status": "failed",
                                "error": str(e)
                            }
                        )
            except Exception as webhook_error:
                self.logger.error(f"Failed to send failure notification (task: {task_id}): {webhook_error}")

    async def _export_logs_async(
        self,
        task_id: str,
        level: str,
        limit: int,
        callback_url: Optional[str] = None
    ) -> None:
        """
        Export system logs asynchronously in the background.

        Args:
            task_id: ID of the background task
            level: Log level filter
            limit: Number of log entries to export
            callback_url: Optional webhook URL for completion notification
        """
        try:
            # Get database session using context manager
            async with self.get_db_session() as db:
                # Update task status to running
                await self.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.RUNNING,
                    progress=10
                )

                self.logger.info(f"Starting async log export (task: {task_id})")

                # Simulate log processing (in real implementation, read from log files/service)
                # This would involve reading from actual log files or a logging service
                logs = []
                for i in range(min(limit, 1000)):  # Simulate processing logs
                    logs.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "level": level,
                        "message": f"Log entry {i+1}",
                        "module": "system",
                        "request_id": str(uuid.uuid4())
                    })

                    # Update progress periodically
                    if i % 100 == 0:
                        progress = min(10 + (i / limit) * 80, 90)
                        await self.update_task_status(
                            db=db,
                            task_id=task_id,
                            status=TaskStatus.RUNNING,
                            progress=int(progress)
                        )

                # Prepare export data
                export_data = {
                    "logs": logs,
                    "level": level,
                    "count": len(logs),
                    "exported_at": datetime.now(timezone.utc).isoformat()
                }

                # Complete task
                await self.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.COMPLETED,
                    progress=100,
                    result=export_data
                )

                # Send webhook notification if callback URL provided
                if callback_url:
                    await self.webhook_service.send_webhook(
                        url=callback_url,
                        event_type="ADMIN_LOG_EXPORT_COMPLETED",
                        data={
                            "task_id": task_id,
                            "status": "completed",
                            "log_count": len(logs),
                            "export_data": export_data
                        }
                    )

                self.logger.info(f"Log export completed successfully (task: {task_id})")

        except Exception as e:
            self.logger.error(f"Log export failed (task: {task_id}): {str(e)}")

            # Update task status to failed
            try:
                async with self.get_db_session() as db:
                    await self.update_task_status(
                        db=db,
                        task_id=task_id,
                        status=TaskStatus.FAILED,
                        error_message=str(e)
                    )

                    # Send failure webhook notification
                    if callback_url:
                        await self.webhook_service.send_webhook(
                            url=callback_url,
                            event_type="ADMIN_LOG_EXPORT_FAILED",
                            data={
                                "task_id": task_id,
                                "status": "failed",
                                "error": str(e)
                            }
                        )
            except Exception as webhook_error:
                self.logger.error(f"Failed to send failure notification (task: {task_id}): {webhook_error}")
    
    async def get_traffic_analytics(self, days: int = 30) -> Dict[str, Any]:
        """
        Get traffic analytics for the specified period.
        
        Args:
            days: Number of days to analyze (default: 30)
            
        Returns:
            Dict containing traffic analytics
        """
        try:
            # Validate days parameter
            if days < 1 or days > 365:
                raise HTTPException(
                    status_code=400,
                    detail="Days parameter must be between 1 and 365"
                )
            
            self.logger.info(f"Fetching traffic analytics for {days} days")
            
            # Get database session and fetch raw data
            async with self.get_db_session() as db:
                # Calculate date range
                end_date = datetime.now(timezone.utc)
                start_date = end_date - timedelta(days=days)
                
                # Query daily traffic data
                daily_traffic = await db.query(
                    db.func.date(URLCheck.created_at).label('date'),
                    db.func.count(URLCheck.id).label('count'),
                    db.func.count(db.case([(URLCheck.threat_level != ThreatLevel.SAFE, 1)])).label('threats')
                ).filter(
                    URLCheck.created_at >= start_date,
                    URLCheck.created_at <= end_date
                ).group_by(db.func.date(URLCheck.created_at)).order_by('date').all()
                
                # Query top domains
                top_domains = await db.query(
                    URLCheck.domain,
                    db.func.count(URLCheck.id).label('count')
                ).filter(
                    URLCheck.created_at >= start_date,
                    URLCheck.created_at <= end_date
                ).group_by(URLCheck.domain).order_by(db.func.count(URLCheck.id).desc()).limit(10).all()
                
                # Query threat distribution
                threat_distribution = await db.query(
                    URLCheck.threat_level,
                    db.func.count(URLCheck.id).label('count')
                ).filter(
                    URLCheck.created_at >= start_date,
                    URLCheck.created_at <= end_date
                ).group_by(URLCheck.threat_level).all()
                
                # Prepare data for AdminService processing
                daily_traffic_data = [
                    {
                        'date': traffic.date.isoformat(),
                        'count': traffic.count,
                        'threats': traffic.threats
                    } for traffic in daily_traffic
                ]
                
                top_domains_data = [
                    {
                        'domain': domain.domain,
                        'count': domain.count
                    } for domain in top_domains
                ]
                
                threat_types_data = [
                    {
                        'threat_level': threat.threat_level.value,
                        'count': threat.count
                    } for threat in threat_distribution
                ]
            
            # Process data using AdminService
            analytics = self.admin_service.process_traffic_analytics(
                daily_traffic_data, top_domains_data, threat_types_data, days
            )
            
            self.logger.info("Traffic analytics retrieved successfully")
            return {
                "success": True,
                "data": analytics,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get traffic analytics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve traffic analytics: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting traffic analytics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def get_threat_intelligence(self) -> Dict[str, Any]:
        """
        Get threat intelligence summary.
        
        Returns:
            Dict containing threat intelligence data
        """
        try:
            self.logger.info("Fetching threat intelligence")
            
            # Get database session and fetch raw data
            async with self.get_db_session() as db:
                # Query recent threats (last 7 days)
                recent_date = datetime.now(timezone.utc) - timedelta(days=7)
                recent_threats = await db.query(URLCheck).filter(
                    URLCheck.threat_level != ThreatLevel.SAFE,
                    URLCheck.created_at >= recent_date
                ).order_by(URLCheck.created_at.desc()).limit(50).all()
                
                # Query threat trends (daily counts for last 30 days)
                trend_date = datetime.now(timezone.utc) - timedelta(days=30)
                threat_trends = await db.query(
                    db.func.date(URLCheck.created_at).label('date'),
                    URLCheck.threat_level,
                    db.func.count(URLCheck.id).label('count')
                ).filter(
                    URLCheck.threat_level != ThreatLevel.SAFE,
                    URLCheck.created_at >= trend_date
                ).group_by(
                    db.func.date(URLCheck.created_at),
                    URLCheck.threat_level
                ).order_by('date').all()
                
                # Query top threat sources (domains with most threats)
                threat_sources = await db.query(
                    URLCheck.domain,
                    URLCheck.threat_level,
                    db.func.count(URLCheck.id).label('count')
                ).filter(
                    URLCheck.threat_level != ThreatLevel.SAFE,
                    URLCheck.created_at >= trend_date
                ).group_by(URLCheck.domain, URLCheck.threat_level).order_by(
                    db.func.count(URLCheck.id).desc()
                ).limit(20).all()
                
                # Prepare data for AdminService processing
                recent_threats_data = [
                    {
                        'id': str(threat.id),
                        'url': threat.url,
                        'domain': threat.domain,
                        'threat_level': threat.threat_level.value,
                        'created_at': threat.created_at.isoformat(),
                        'threat_details': threat.threat_details
                    } for threat in recent_threats
                ]
                
                threat_trends_data = [
                    {
                        'date': trend.date.isoformat(),
                        'threat_level': trend.threat_level.value,
                        'count': trend.count
                    } for trend in threat_trends
                ]
                
                threat_sources_data = [
                    {
                        'domain': source.domain,
                        'threat_level': source.threat_level.value,
                        'count': source.count
                    } for source in threat_sources
                ]
            
            # Process data using AdminService
            intelligence = self.admin_service.process_threat_intelligence(
                recent_threats_data, threat_trends_data, threat_sources_data
            )
            
            self.logger.info("Threat intelligence retrieved successfully")
            return {
                "success": True,
                "data": intelligence,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get threat intelligence: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve threat intelligence: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error getting threat intelligence: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def get_user_analytics(self) -> Dict[str, Any]:
        """
        Get user analytics and behavior insights.
        
        Returns:
            Dict containing user analytics
        """
        try:
            self.logger.info("Fetching user analytics")
            
            # Get database session and fetch raw data
            async with self.get_db_session() as db:
                # Query user growth (daily registrations for last 30 days)
                growth_date = datetime.now(timezone.utc) - timedelta(days=30)
                user_growth = await db.query(
                    db.func.date(User.created_at).label('date'),
                    db.func.count(User.id).label('count')
                ).filter(
                    User.created_at >= growth_date
                ).group_by(db.func.date(User.created_at)).order_by('date').all()
                
                # Query active users by subscription tier
                active_users_by_subscription = await db.query(
                    User.subscription_plan,
                    db.func.count(User.id).label('count')
                ).filter(
                    User.is_active == True,
                    User.last_login_at >= datetime.now(timezone.utc) - timedelta(days=30)
                ).group_by(User.subscription_plan).all()
                
                # Query top users by activity (most URL checks in last 30 days)
                top_users = await db.query(
                    User.id,
                    User.email,
                    User.subscription_plan,
                    db.func.count(URLCheck.id).label('check_count')
                ).join(URLCheck).filter(
                    URLCheck.created_at >= datetime.now(timezone.utc) - timedelta(days=30)
                ).group_by(User.id, User.email, User.subscription_plan).order_by(
                    db.func.count(URLCheck.id).desc()
                ).limit(10).all()
                
                # Query user engagement metrics
                engagement_metrics = await db.query(
                    db.func.count(db.distinct(User.id)).label('total_active_users'),
                    db.func.avg(db.func.count(URLCheck.id)).label('avg_checks_per_user')
                ).join(URLCheck).filter(
                    URLCheck.created_at >= datetime.now(timezone.utc) - timedelta(days=30)
                ).first()
                
                # Prepare data for AdminService processing
                user_growth_data = [
                    {
                        'date': growth.date.isoformat(),
                        'count': growth.count
                    } for growth in user_growth
                ]
                
                subscription_data = [
                    {
                        'subscription_plan': sub.subscription_plan,
                        'count': sub.count
                    } for sub in active_users_by_subscription
                ]
                
                top_users_data = [
                    {
                        'user_id': str(user.id),
                        'email': user.email,
                        'subscription_plan': user.subscription_plan,
                        'check_count': user.check_count
                    } for user in top_users
                ]
                
                engagement_data = {
                    'total_active_users': engagement_metrics.total_active_users or 0,
                    'avg_checks_per_user': float(engagement_metrics.avg_checks_per_user or 0)
                }
            
            # Process data using AdminService
            analytics = self.admin_service.process_user_analytics(
                user_growth_data, subscription_data, top_users_data, engagement_data
            )
            
            self.logger.info("User analytics retrieved successfully")
            return {
                "success": True,
                "data": analytics,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get user analytics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve user analytics: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error getting user analytics: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    # GlobalConfig Management Methods
    
    async def get_configuration(self, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Get system GlobalConfig settings.
        
        Args:
            category: Optional category filter
            
        Returns:
            Dict containing GlobalConfig settings
        """
        try:
            self.logger.info(f"Fetching GlobalConfig (category: {category})")
            
            # Validate category if provided
            if category:
                valid_categories = ["security", "rate_limiting", "ai_services", "external_apis", "system", "notifications"]
                if category not in valid_categories:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid category. Must be one of: {valid_categories}"
                    )
            
            # Fetch GlobalConfig data from database
            async with self.get_db_session() as db:
                query = db.query(GlobalConfig)
                if category:
                    query = query.filter(GlobalConfig.category == category)
                
                config_records = await query.filter(GlobalConfig.is_active == True).all()
                
                # Prepare GlobalConfig data
                configuration_data = {}
                for config in config_records:
                    if config.category not in configuration_data:
                        configuration_data[config.category] = {}
                    configuration_data[config.category][config.key] = {
                        'value': config.value,
                        'description': config.description,
                        'updated_at': config.updated_at.isoformat() if config.updated_at else None,
                        'updated_by': config.updated_by
                    }
            
            # Process configuration using AdminService
            configuration = self.admin_service.process_configuration(configuration_data, category)
            
            self.logger.info("GlobalConfig retrieved successfully")
            return {
                "success": True,
                "data": {
                    "category": category,
                    "settings": configuration
                },
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get configuration: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve configuration: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting configuration: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def update_configuration(self, key: str, value: str, current_user: User) -> Dict[str, Any]:
        """
        Update a configuration setting.
        
        Args:
            key: GlobalConfig key
            value: New value
            current_user: Current admin user
            
        Returns:
            Dict containing updated configuration
        """
        try:
            self.logger.info(f"Updating configuration key: {key}")
            
            # Validate inputs
            if not key or not key.strip():
                raise HTTPException(
                    status_code=400,
                    detail="GlobalConfig key cannot be empty"
                )
            
            if value is None:
                raise HTTPException(
                    status_code=400,
                    detail="GlobalConfig value cannot be null"
                )
            
            # Update configuration in database
            async with self.get_db_session() as db:
                # Find existing configuration
                config = await db.query(GlobalConfig).filter(
                    GlobalConfig.key == key.strip()
                ).first()
                
                if not config:
                    raise HTTPException(
                        status_code=404,
                        detail=f"GlobalConfig key '{key}' not found"
                    )
                
                # Update configuration
                old_value = config.value
                config.value = value
                config.updated_at = datetime.now(timezone.utc)
                config.updated_by = current_user.id
                
                # Commit handled by context manager
                await db.refresh(config)
                
                # Log admin action
                admin_action = AdminAction(
                    user_id=current_user.id,
                    action_type="configuration_update",
                    resource_type="configuration",
                    resource_id=str(config.id),
                    details={
                        "key": key.strip(),
                        "old_value": old_value,
                        "new_value": value
                    },
                    ip_address=None,  # This would be set by middleware
                    user_agent=None   # This would be set by middleware
                )
                db.add(admin_action)
                # Commit handled by context manager
                
                # Prepare updated configuration data
                updated_config_data = {
                    'id': str(config.id),
                    'key': config.key,
                    'value': config.value,
                    'category': config.category,
                    'description': config.description,
                    'updated_at': config.updated_at.isoformat(),
                    'updated_by': config.updated_by
                }
            
            # Process updated configuration using AdminService
            updated_config = self.admin_service.process_configuration_update(updated_config_data)
            
            self.logger.info(f"GlobalConfig key '{key}' updated successfully")
            return {
                "success": True,
                "data": updated_config,
                "message": f"GlobalConfig '{key}' updated successfully",
                "timestamp": datetime.now(timezone.utc)
            }
        
        except ConfigurationError as e:
            self.logger.warning(f"GlobalConfig validation error: {e}")
            raise self._create_http_exception(
                status_code=400,
                detail=str(e)
            )
        except AdminServiceError as e:
            self.logger.error(f"Failed to update configuration: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to update configuration: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error updating configuration: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    # User Management Methods
    
    async def get_users(self, page: int = 1, limit: int = 50, 
                       role: Optional[str] = None, status: Optional[str] = None,
                       subscription: Optional[str] = None, is_active: Optional[bool] = None,
                       search: Optional[str] = None, background_tasks: Optional[BackgroundTasks] = None,
                       callback_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Get paginated list of users with optional filters.
        
        Args:
            page: Page number (default: 1)
            limit: Items per page (default: 50)
            role: Filter by user role
            status: Filter by user status
            subscription: Filter by subscription plan
            is_active: Filter by active status
            search: Search term for email, username, or name
            background_tasks: FastAPI background tasks for async processing
            callback_url: Optional webhook URL for completion notification
            
        Returns:
            Dict containing paginated user data
        """
        try:
            # Validate pagination parameters
            if page < 1:
                raise HTTPException(status_code=400, detail="Page must be >= 1")
            if limit < 1 or limit > 100:
                raise HTTPException(status_code=400, detail="Limit must be between 1 and 100")
            
            # Validate filter parameters
            if role and role not in ["admin", "super_admin", "user", "moderator"]:
                raise HTTPException(status_code=400, detail="Invalid role filter")
            if status and status not in ["active", "inactive", "suspended", "pending_verification"]:
                raise HTTPException(status_code=400, detail="Invalid status filter")
            if subscription and subscription not in ["free", "basic", "pro", "enterprise"]:
                raise HTTPException(status_code=400, detail="Invalid subscription filter")
            
            self.logger.info(f"Fetching users (page: {page}, limit: {limit})")
            
            # Fetch users data from database
            async with self.get_db_session() as db:
                # Build query with filters
                query = db.query(User)
                
                if role:
                    query = query.join(UserRole).filter(UserRole.role_name == role)
                if status:
                    query = query.filter(User.status == status)
                if subscription:
                    query = query.filter(User.subscription_plan == subscription)
                if is_active is not None:
                    query = query.filter(User.is_active == is_active)
                if search:
                    search_term = f"%{search.strip()}%"
                    query = query.filter(
                        db.or_(
                            User.email.ilike(search_term),
                            User.username.ilike(search_term),
                            User.first_name.ilike(search_term),
                            User.last_name.ilike(search_term)
                        )
                    )
                
                # Get total count
                total_count = await query.count()
                
                # Apply pagination
                offset = (page - 1) * limit
                users = await query.offset(offset).limit(limit).all()
                
                # Prepare users data
                users_data = []
                for user in users:
                    user_data = {
                        'id': str(user.id),
                        'email': user.email,
                        'username': user.username,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'subscription_plan': user.subscription_plan,
                        'status': user.status,
                        'is_active': user.is_active,
                        'created_at': user.created_at.isoformat() if user.created_at else None,
                        'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
                        'email_verified': user.email_verified
                    }
                    users_data.append(user_data)
                
                # Prepare pagination metadata
                pagination_data = {
                    'users': users_data,
                    'total': total_count,
                    'page': page,
                    'limit': limit,
                    'total_pages': (total_count + limit - 1) // limit,
                    'has_next': page * limit < total_count,
                    'has_prev': page > 1
                }
            
            # Build filters for processing
            filters = {}
            if role:
                filters['role'] = role
            if status:
                filters['status'] = status
            if subscription:
                filters['subscription'] = subscription
            if is_active is not None:
                filters['is_active'] = is_active
            if search:
                filters['search'] = search.strip()
            
            # Process users data using AdminService
            processed_users_data = self.admin_service.process_users_data(pagination_data, filters)
            
            # Check if this should be processed asynchronously for large datasets
            should_process_async = (
                background_tasks is not None and 
                (total_count > 1000 or callback_url is not None)
            )
            
            if should_process_async:
                # Create background task for async processing
                async with self.get_db_session() as db:
                    task = await self.create_task(
                        db=db,
                        task_type=TaskType.DATA_EXPORT,
                        priority=TaskPriority.NORMAL,
                        user_id=None,  # Admin operation
                        metadata={
                            "page": page,
                            "limit": limit,
                            "filters": filters,
                            "total_users": total_count,
                            "callback_url": callback_url
                        }
                    )
                    
                    # Add background task for async processing
                    background_tasks.add_task(
                        self._export_users_async,
                        task_id=str(task.id),
                        page=page,
                        limit=limit,
                        filters=filters,
                        callback_url=callback_url
                    )
                
                self.logger.info(f"Large user dataset queued for async processing (task: {task.id})")
                return {
                    "success": True,
                    "task_id": str(task.id),
                    "status": "processing",
                    "message": "User data export queued for processing",
                    "timestamp": datetime.now(timezone.utc)
                }

            self.logger.info("Users retrieved successfully")
            return {
                "success": True,
                "data": processed_users_data,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get users: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve users: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting users: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def update_user_status(self, user_id: str, status: str, current_user: User) -> Dict[str, Any]:
        """
        Update user status (activate, deactivate, suspend).
        
        Args:
            user_id: User ID to update
            status: New status
            current_user: Current admin user
            
        Returns:
            Dict containing updated user data
        """
        try:
            # Validate user_id
            try:
                user_uuid = uuid.UUID(user_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid user ID format")
            
            # Validate status
            valid_statuses = ["active", "inactive", "suspended", "pending_verification"]
            if status not in valid_statuses:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status. Must be one of: {valid_statuses}"
                )
            
            # Prevent self-modification
            if user_uuid == current_user.id:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot modify your own user status"
                )
            
            self.logger.info(f"Updating user {user_id} status to {status}")
            
            # Update user status in database
            async with self.get_db_session() as db:
                # Find the user
                user = await db.query(User).filter(User.id == user_uuid).first()
                if not user:
                    raise HTTPException(
                        status_code=404,
                        detail="User not found"
                    )
                
                # Store old status for logging
                old_status = user.status
                
                # Update user status
                user.status = status
                user.is_active = status == "active"
                user.updated_at = utc_datetime()
                
                # Commit handled by context manager
                await db.refresh(user)
                
                # Log admin action
                #TODO-  Revise Admin Action not Accurate Arguments do not match
                admin_action = AdminAction(
                    user_id=current_user.id,
                    action_type=ActionType.UPDATE.value,
                    resource_type="user",
                    resource_id=str(user.id),
                    details={
                        "user_email": user.email,
                        "old_status": old_status,
                        "new_status": status
                    },
                    ip_address=None,  # This would be set by middleware
                    user_agent=None   # This would be set by middleware
                )
                db.add(admin_action)
                # Commit handled by context manager
                
                # Prepare updated user data
                updated_user_data = {
                    'id': str(user.id),
                    'email': user.email,
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'subscription_plan': user.subscription_plan,
                    'status': user.status,
                    'is_active': user.is_active,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'updated_at': user.updated_at.isoformat() if user.updated_at else None,
                    'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
                    'email_verified': user.email_verified
                }
            
            # Process updated user using AdminService
            updated_user = self.admin_service.process_user_status_update(updated_user_data, old_status, status)
            
            self.logger.info(f"User {user_id} status updated successfully")
            return {
                "success": True,
                "data": updated_user,
                "message": f"User status updated to {status}",
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to update user status: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to update user status: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error updating user status: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    # System Management Methods
    
    async def get_system_health(self) -> Dict[str, Any]:
        """
        Get current system health status.
        
        Returns:
            Dict containing system health data
        """
        try:
            self.logger.info("Fetching system health")
            
            # Gather system health data from database and system
            async with self.get_db_session() as db:
                # Database health check
                try:
                    await db.execute("SELECT 1")
                    db_status = "healthy"
                    db_response_time = 0.001  # This would be measured in real implementation
                except Exception as e:
                    db_status = "unhealthy"
                    db_response_time = None
                    self.logger.error(f"Database health check failed: {e}")
                
                # Get recent system metrics
                recent_time = datetime.now(timezone.utc) - timedelta(minutes=5)
                
                # Check recent user activity
                recent_users = await db.query(User).filter(
                    User.last_login_at >= recent_time
                ).count()
                
                # Check recent URL checks
                recent_url_checks = await db.query(URLCheck).filter(
                    URLCheck.created_at >= recent_time
                ).count()
                
                # Check recent AI analyses
                recent_ai_analyses = await db.query(AIAnalysis).filter(
                    AIAnalysis.created_at >= recent_time
                ).count()
                
                # Check background task status
                pending_tasks = await db.query(BackgroundTask).filter(
                    BackgroundTask.status == "pending"
                ).count()
                
                running_tasks = await db.query(BackgroundTask).filter(
                    BackgroundTask.status == "running"
                ).count()
                
                failed_tasks = await db.query(BackgroundTask).filter(
                    BackgroundTask.status == "failed",
                    BackgroundTask.updated_at >= datetime.now(timezone.utc) - timedelta(hours=1)
                ).count()
                
                # Prepare health data
                health_data = {
                    'database': {
                        'status': db_status,
                        'response_time_ms': db_response_time * 1000 if db_response_time else None
                    },
                    'activity': {
                        'recent_users': recent_users,
                        'recent_url_checks': recent_url_checks,
                        'recent_ai_analyses': recent_ai_analyses
                    },
                    'background_tasks': {
                        'pending': pending_tasks,
                        'running': running_tasks,
                        'failed_last_hour': failed_tasks
                    },
                    'system': {
                        'uptime': None,  # This would be calculated from system start time
                        'memory_usage': None,  # This would be gathered from system metrics
                        'cpu_usage': None  # This would be gathered from system metrics
                    }
                }
            
            # Process health data using AdminService
            processed_health_data = self.admin_service.process_system_health(health_data)
            
            self.logger.info("System health retrieved successfully")
            return {
                "success": True,
                "data": processed_health_data,
                "timestamp": datetime.now(timezone.utc)
            }
        
        except AdminServiceError as e:
            self.logger.error(f"Failed to get system health: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail=f"Failed to retrieve system health: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error getting system health: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )
    
    async def get_system_logs(self, level: str = "INFO", limit: int = 100,
                             background_tasks: Optional[BackgroundTasks] = None,
                             callback_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Get recent system logs.
        
        Args:
            level: Log level filter (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            limit: Number of log entries to return
            background_tasks: FastAPI background tasks for async processing
            callback_url: Optional webhook URL for completion notification
            
        Returns:
            Dict containing system logs
        """
        try:
            # Validate parameters
            valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            if level.upper() not in valid_levels:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid log level. Must be one of: {valid_levels}"
                )
            
            if limit < 1 or limit > 1000:
                raise HTTPException(
                    status_code=400,
                    detail="Limit must be between 1 and 1000"
                )
            
            self.logger.info(f"Fetching system logs (level: {level}, limit: {limit})")
            
            # Check if this should be processed asynchronously for large log requests
            should_process_async = (
                background_tasks is not None and 
                (limit > 500 or callback_url is not None)
            )
            
            if should_process_async:
                # Create background task for async log processing
                async with self.get_db_session() as db:
                    task = await self.create_task(
                        db=db,
                        task_type=TaskType.DATA_EXPORT.value,
                        priority=TaskPriority.LOW,
                        user_id=None,  # Admin operation
                        metadata={
                            "level": level.upper(),
                            "limit": limit,
                            "callback_url": callback_url
                        }
                    )
                
                # Add background task for async processing
                background_tasks.add_task(
                    self._export_logs_async,
                    task_id=str(task.id),
                    level=level.upper(),
                    limit=limit,
                    callback_url=callback_url
                )
                
                self.logger.info(f"Large log export queued for async processing (task: {task.id})")
                return {
                    "success": True,
                    "task_id": str(task.id),
                    "status": "processing",
                    "message": "System logs export queued for processing",
                    "timestamp": datetime.now(timezone.utc)
                }
            
            # This is a placeholder implementation
            # In a real system, you would read from log files or a logging service
            logs = [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": "INFO",
                    "message": "System logs endpoint accessed",
                    "module": "admin_controller"
                }
            ]
            
            return {
                "success": True,
                "data": {
                    "logs": logs,
                    "level": level.upper(),
                    "count": len(logs)
                },
                "timestamp": datetime.now(timezone.utc)
            }
        
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting system logs: {e}")
            raise self._create_http_exception(
                status_code=500,
                detail="Internal server error"
            )