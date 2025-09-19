#!/usr/bin/env python3
"""
LinkShield Backend Admin Service

Comprehensive admin service for dashboard statistics, configuration management,
user administration, and system monitoring.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc, asc, text
from sqlalchemy.exc import SQLAlchemyError

from src.config.settings import get_settings
from src.models.user import User, UserRole, UserStatus, SubscriptionPlan
from src.models.url_check import URLCheck, ScanResult
from src.models.ai_analysis import AIAnalysis
from src.models.admin import GlobalConfig, AdminAction, SystemHealth, AdminSession, ConfigCategory, HealthStatus
from src.config.database import check_database_health


class AdminServiceError(Exception):
    """Base admin service error."""
    pass


class ConfigurationError(AdminServiceError):
    """Configuration management error."""
    pass


class AdminService:
    """
    Admin service for dashboard operations and system management.
    """
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.settings = get_settings()
    
    # Statistics and Analytics Methods
    
    async def get_system_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive system statistics for the admin dashboard.
        
        Returns:
            Dict containing system metrics and statistics
        """
        try:
            # User statistics
            total_users = self.db.query(User).count()
            active_users = self.db.query(User).filter(User.is_active == True).count()
            verified_users = self.db.query(User).filter(User.is_verified == True).count()
            
            # User role distribution
            role_stats = self.db.query(
                User.role, func.count(User.id)
            ).group_by(User.role).all()
            
            # Subscription statistics
            subscription_stats = self.db.query(
                User.subscription_plan, func.count(User.id)
            ).group_by(User.subscription_plan).all()
            
            # URL check statistics
            total_checks = self.db.query(URLCheck).count()
            checks_today = self.db.query(URLCheck).filter(
                URLCheck.created_at >= datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            ).count()
            
            # Threat detection statistics
            threats_detected = self.db.query(URLCheck).filter(
                URLCheck.is_safe == False
            ).count()
            
            # AI analysis statistics
            ai_analyses = self.db.query(AIAnalysis).count()
            
            # Recent activity (last 7 days)
            week_ago = datetime.now(timezone.utc) - timedelta(days=7)
            recent_checks = self.db.query(
                func.date(URLCheck.created_at).label('date'),
                func.count(URLCheck.id).label('count')
            ).filter(
                URLCheck.created_at >= week_ago
            ).group_by(func.date(URLCheck.created_at)).all()
            
            return {
                "users": {
                    "total": total_users,
                    "active": active_users,
                    "verified": verified_users,
                    "verification_rate": (verified_users / total_users * 100) if total_users > 0 else 0,
                    "role_distribution": {role.value: count for role, count in role_stats},
                    "subscription_distribution": {plan.value: count for plan, count in subscription_stats}
                },
                "url_checks": {
                    "total": total_checks,
                    "today": checks_today,
                    "threats_detected": threats_detected,
                    "threat_rate": (threats_detected / total_checks * 100) if total_checks > 0 else 0,
                    "recent_activity": [
                        {"date": str(date), "count": count} for date, count in recent_checks
                    ]
                },
                "ai_analysis": {
                    "total_analyses": ai_analyses
                },
                "system": {
                    "uptime": self._get_system_uptime(),
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }
            }
        except SQLAlchemyError as e:
            raise AdminServiceError(f"Failed to get system statistics: {str(e)}")
    
    async def get_traffic_analytics(self, days: int = 30) -> Dict[str, Any]:
        """
        Get traffic analytics for the specified period.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Dict containing traffic analytics
        """
        try:
            start_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            # Daily traffic
            daily_traffic = self.db.query(
                func.date(URLCheck.created_at).label('date'),
                func.count(URLCheck.id).label('checks'),
                func.count(func.distinct(URLCheck.user_id)).label('unique_users')
            ).filter(
                URLCheck.created_at >= start_date
            ).group_by(func.date(URLCheck.created_at)).order_by('date').all()
            
            # Top domains
            top_domains = self.db.query(
                URLCheck.domain,
                func.count(URLCheck.id).label('count')
            ).filter(
                URLCheck.created_at >= start_date
            ).group_by(URLCheck.domain).order_by(desc('count')).limit(10).all()
            
            # Threat distribution
            threat_types = self.db.query(
                ScanResult.threat_type,
                func.count(ScanResult.id).label('count')
            ).join(URLCheck).filter(
                URLCheck.created_at >= start_date,
                ScanResult.threat_type.isnot(None)
            ).group_by(ScanResult.threat_type).all()
            
            return {
                "period_days": days,
                "daily_traffic": [
                    {
                        "date": str(date),
                        "checks": checks,
                        "unique_users": unique_users
                    }
                    for date, checks, unique_users in daily_traffic
                ],
                "top_domains": [
                    {"domain": domain, "count": count}
                    for domain, count in top_domains
                ],
                "threat_distribution": [
                    {"type": threat_type, "count": count}
                    for threat_type, count in threat_types
                ]
            }
        except SQLAlchemyError as e:
            raise AdminServiceError(f"Failed to get traffic analytics: {str(e)}")
    
    async def get_threat_intelligence(self) -> Dict[str, Any]:
        """
        Get threat intelligence summary.
        
        Returns:
            Dict containing threat intelligence data
        """
        try:
            # Recent threats (last 24 hours)
            day_ago = datetime.now(timezone.utc) - timedelta(days=1)
            recent_threats = self.db.query(URLCheck).filter(
                URLCheck.created_at >= day_ago,
                URLCheck.is_safe == False
            ).count()
            
            # Threat trends (last 7 days)
            week_ago = datetime.now(timezone.utc) - timedelta(days=7)
            threat_trends = self.db.query(
                func.date(URLCheck.created_at).label('date'),
                func.count(URLCheck.id).label('threats')
            ).filter(
                URLCheck.created_at >= week_ago,
                URLCheck.is_safe == False
            ).group_by(func.date(URLCheck.created_at)).all()
            
            # Top threat sources
            threat_sources = self.db.query(
                URLCheck.domain,
                func.count(URLCheck.id).label('count')
            ).filter(
                URLCheck.created_at >= week_ago,
                URLCheck.is_safe == False
            ).group_by(URLCheck.domain).order_by(desc('count')).limit(10).all()
            
            return {
                "recent_threats_24h": recent_threats,
                "threat_trends": [
                    {"date": str(date), "count": threats}
                    for date, threats in threat_trends
                ],
                "top_threat_sources": [
                    {"domain": domain, "count": count}
                    for domain, count in threat_sources
                ]
            }
        except SQLAlchemyError as e:
            raise AdminServiceError(f"Failed to get threat intelligence: {str(e)}")
    
    async def get_user_analytics(self) -> Dict[str, Any]:
        """
        Get user analytics and behavior insights.
        
        Returns:
            Dict containing user analytics
        """
        try:
            # User growth (last 30 days)
            month_ago = datetime.now(timezone.utc) - timedelta(days=30)
            user_growth = self.db.query(
                func.date(User.created_at).label('date'),
                func.count(User.id).label('new_users')
            ).filter(
                User.created_at >= month_ago
            ).group_by(func.date(User.created_at)).all()
            
            # Active users by subscription
            active_by_subscription = self.db.query(
                User.subscription_plan,
                func.count(User.id).label('count')
            ).filter(
                User.is_active == True
            ).group_by(User.subscription_plan).all()
            
            # Top users by activity
            top_users = self.db.query(
                User.email,
                User.total_check_count,
                User.subscription_plan
            ).filter(
                User.is_active == True
            ).order_by(desc(User.total_check_count)).limit(10).all()
            
            return {
                "user_growth": [
                    {"date": str(date), "new_users": new_users}
                    for date, new_users in user_growth
                ],
                "active_by_subscription": [
                    {"plan": plan.value, "count": count}
                    for plan, count in active_by_subscription
                ],
                "top_users": [
                    {
                        "email": email,
                        "total_checks": total_checks,
                        "subscription": plan.value
                    }
                    for email, total_checks, plan in top_users
                ]
            }
        except SQLAlchemyError as e:
            raise AdminServiceError(f"Failed to get user analytics: {str(e)}")
    
    # Configuration Management Methods
    
    async def get_configuration(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get system configuration settings.
        
        Args:
            category: Optional category filter
            
        Returns:
            List of configuration settings
        """
        try:
            query = self.db.query(GlobalConfig).filter(GlobalConfig.is_active == True)
            
            if category:
                query = query.filter(GlobalConfig.category == ConfigCategory(category))
            
            configs = query.order_by(GlobalConfig.category, GlobalConfig.key).all()
            
            return [
                {
                    "id": str(config.id),
                    "key": config.key,
                    "value": config.value if not config.is_sensitive else "***",
                    "category": config.category.value,
                    "description": config.description,
                    "data_type": config.data_type,
                    "is_sensitive": config.is_sensitive,
                    "updated_at": config.updated_at.isoformat()
                }
                for config in configs
            ]
        except SQLAlchemyError as e:
            raise AdminServiceError(f"Failed to get configuration: {str(e)}")
    
    async def update_configuration(self, key: str, value: str, user_id: uuid.UUID) -> Dict[str, Any]:
        """
        Update a configuration setting.
        
        Args:
            key: Configuration key
            value: New value
            user_id: ID of the user making the change
            
        Returns:
            Updated configuration data
        """
        try:
            config = self.db.query(GlobalConfig).filter(GlobalConfig.key == key).first()
            if not config:
                raise ConfigurationError(f"Configuration key '{key}' not found")
            
            # Validate value based on data type and constraints
            self._validate_config_value(config, value)
            
            # Update configuration
            old_value = config.value
            config.value = value
            config.updated_by = user_id
            config.updated_at = datetime.now(timezone.utc)
            
            self.db.commit()
            
            # Log the configuration change
            await self._log_config_change(key, old_value, value, user_id)
            
            return {
                "id": str(config.id),
                "key": config.key,
                "value": config.value if not config.is_sensitive else "***",
                "category": config.category.value,
                "updated_at": config.updated_at.isoformat()
            }
        except SQLAlchemyError as e:
            self.db.rollback()
            raise AdminServiceError(f"Failed to update configuration: {str(e)}")
    
    # User Management Methods
    
    async def get_users(self, page: int = 1, limit: int = 50, filters: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Get paginated list of users with optional filters.
        
        Args:
            page: Page number
            limit: Items per page
            filters: Optional filters (role, status, subscription, etc.)
            
        Returns:
            Paginated user data
        """
        try:
            query = self.db.query(User)
            
            # Apply filters
            if filters:
                if filters.get('role'):
                    query = query.filter(User.role == UserRole(filters['role']))
                if filters.get('status'):
                    query = query.filter(User.status == UserStatus(filters['status']))
                if filters.get('subscription'):
                    query = query.filter(User.subscription_plan == SubscriptionPlan(filters['subscription']))
                if filters.get('is_active') is not None:
                    query = query.filter(User.is_active == filters['is_active'])
                if filters.get('search'):
                    search_term = f"%{filters['search']}%"
                    query = query.filter(
                        or_(
                            User.email.ilike(search_term),
                            User.username.ilike(search_term),
                            User.first_name.ilike(search_term),
                            User.last_name.ilike(search_term)
                        )
                    )
            
            # Get total count
            total = query.count()
            
            # Apply pagination
            offset = (page - 1) * limit
            users = query.offset(offset).limit(limit).all()
            
            return {
                "users": [
                    {
                        "id": str(user.id),
                        "email": user.email,
                        "username": user.username,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "role": user.role.value,
                        "status": user.status.value,
                        "subscription_plan": user.subscription_plan.value,
                        "is_active": user.is_active,
                        "is_verified": user.is_verified,
                        "total_check_count": user.total_check_count,
                        "created_at": user.created_at.isoformat(),
                        "last_login": user.last_login.isoformat() if user.last_login else None
                    }
                    for user in users
                ],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": (total + limit - 1) // limit
                }
            }
        except SQLAlchemyError as e:
            raise AdminServiceError(f"Failed to get users: {str(e)}")
    
    async def update_user_status(self, user_id: uuid.UUID, status: str, admin_user_id: uuid.UUID) -> Dict[str, Any]:
        """
        Update user status (activate, deactivate, suspend).
        
        Args:
            user_id: User ID to update
            status: New status
            admin_user_id: ID of admin making the change
            
        Returns:
            Updated user data
        """
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                raise AdminServiceError(f"User with ID {user_id} not found")
            
            old_status = user.status.value
            user.status = UserStatus(status)
            user.is_active = status == "active"
            
            self.db.commit()
            
            # Log the user management action
            await self._log_user_management_action(
                "status_update", user_id, admin_user_id,
                {"old_status": old_status, "new_status": status}
            )
            
            return {
                "id": str(user.id),
                "email": user.email,
                "status": user.status.value,
                "is_active": user.is_active
            }
        except SQLAlchemyError as e:
            self.db.rollback()
            raise AdminServiceError(f"Failed to update user status: {str(e)}")
    
    # System Health Methods
    
    async def get_system_health(self) -> Dict[str, Any]:
        """
        Get current system health status.
        
        Returns:
            System health data
        """
        try:
            # Check database health
            db_healthy = await check_database_health()
            
            # Get latest health checks
            latest_checks = self.db.query(SystemHealth).filter(
                SystemHealth.checked_at >= datetime.now(timezone.utc) - timedelta(minutes=5)
            ).all()
            
            # Aggregate health status
            components = {}
            for check in latest_checks:
                components[check.component] = {
                    "status": check.status.value,
                    "response_time_ms": check.response_time_ms,
                    "details": check.details,
                    "checked_at": check.checked_at.isoformat()
                }
            
            # Add database status
            components["database"] = {
                "status": "healthy" if db_healthy else "critical",
                "checked_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Determine overall status
            statuses = [comp["status"] for comp in components.values()]
            if "critical" in statuses:
                overall_status = "critical"
            elif "warning" in statuses:
                overall_status = "warning"
            else:
                overall_status = "healthy"
            
            return {
                "overall_status": overall_status,
                "components": components,
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
        except SQLAlchemyError as e:
            raise AdminServiceError(f"Failed to get system health: {str(e)}")
    
    # Helper Methods
    
    def _get_system_uptime(self) -> str:
        """Get system uptime (placeholder implementation)."""
        # This would typically read from system metrics
        return "99.9%"
    
    def _validate_config_value(self, config: GlobalConfig, value: str) -> None:
        """
        Validate configuration value against constraints.
        
        Args:
            config: Configuration object
            value: Value to validate
            
        Raises:
            ConfigurationError: If validation fails
        """
        # Type validation
        if config.data_type == "integer":
            try:
                int_value = int(value)
                if config.min_value is not None and int_value < config.min_value:
                    raise ConfigurationError(f"Value must be >= {config.min_value}")
                if config.max_value is not None and int_value > config.max_value:
                    raise ConfigurationError(f"Value must be <= {config.max_value}")
            except ValueError:
                raise ConfigurationError("Value must be an integer")
        
        elif config.data_type == "boolean":
            if value.lower() not in ["true", "false", "1", "0"]:
                raise ConfigurationError("Value must be a boolean (true/false)")
        
        elif config.data_type == "json":
            try:
                json.loads(value)
            except json.JSONDecodeError:
                raise ConfigurationError("Value must be valid JSON")
        
        # Allowed values validation
        if config.allowed_values and value not in config.allowed_values:
            raise ConfigurationError(f"Value must be one of: {config.allowed_values}")
        
        # Regex validation
        if config.validation_regex:
            import re
            if not re.match(config.validation_regex, value):
                raise ConfigurationError("Value does not match required pattern")
    
    async def _log_config_change(self, key: str, old_value: str, new_value: str, user_id: uuid.UUID) -> None:
        """Log configuration change for audit trail."""
        # This would be implemented with the audit middleware
        pass
    
    async def _log_user_management_action(self, action: str, target_user_id: uuid.UUID, 
                                        admin_user_id: uuid.UUID, details: Dict) -> None:
        """Log user management action for audit trail."""
        # This would be implemented with the audit middleware
        pass