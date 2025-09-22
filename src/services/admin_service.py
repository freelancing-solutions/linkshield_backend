#!/usr/bin/env python3
"""
LinkShield Backend Admin Service

Pure business logic service for admin operations including data processing,
validation, and formatting. No database dependencies.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict

from src.config.settings import get_settings


class AdminServiceError(Exception):
    """Base admin service error."""
    pass


class ConfigurationError(AdminServiceError):
    """Configuration management error."""
    pass


class AdminService:
    """
    Pure business logic admin service for data processing and validation.
    All database operations are handled by AdminController.
    """
    
    def __init__(self):
        self.settings = get_settings()
    
    # Data Processing Methods
    
    def process_system_statistics(
        self, 
        users_data: Dict, 
        url_checks_data: Dict, 
        ai_analyses_data: Dict
    ) -> Dict[str, Any]:
        """
        Process raw system statistics data into formatted response.
        
        Args:
            users_data: Raw user statistics from database
            url_checks_data: Raw URL check statistics from database
            ai_analyses_data: Raw AI analysis statistics from database
            
        Returns:
            Dict containing processed system metrics and statistics
        """
        try:
            # Validate input data
            self.validate_statistics_input(users_data, url_checks_data, ai_analyses_data)
            
            # Process user statistics
            total_users = users_data.get('total', 0)
            active_users = users_data.get('active', 0)
            verified_users = users_data.get('verified', 0)
            
            verification_rate = (verified_users / total_users * 100) if total_users > 0 else 0
            
            # Process URL check statistics
            total_checks = url_checks_data.get('total', 0)
            checks_today = url_checks_data.get('today', 0)
            threats_detected = url_checks_data.get('threats_detected', 0)
            
            threat_rate = (threats_detected / total_checks * 100) if total_checks > 0 else 0
            
            return {
                "users": {
                    "total": total_users,
                    "active": active_users,
                    "verified": verified_users,
                    "verification_rate": round(verification_rate, 2),
                    "role_distribution": users_data.get('role_distribution', {}),
                    "subscription_distribution": users_data.get('subscription_distribution', {})
                },
                "url_checks": {
                    "total": total_checks,
                    "today": checks_today,
                    "threats_detected": threats_detected,
                    "threat_rate": round(threat_rate, 2),
                    "recent_activity": url_checks_data.get('recent_activity', [])
                },
                "ai_analysis": {
                    "total_analyses": ai_analyses_data.get('total_analyses', 0)
                },
                "system": {
                    "uptime": self._get_system_uptime(),
                    "last_updated": datetime.now(timezone.utc).isoformat()
                }
            }
        except Exception as e:
            raise AdminServiceError(f"Failed to process system statistics: {str(e)}")

    def process_traffic_analytics(
        self, 
        daily_traffic_data: List, 
        top_domains_data: List, 
        threat_types_data: List, 
        days: int
    ) -> Dict[str, Any]:
        """
        Process raw traffic analytics data into formatted response.
        
        Args:
            daily_traffic_data: Raw daily traffic data from database
            top_domains_data: Raw top domains data from database
            threat_types_data: Raw threat types data from database
            days: Number of days analyzed
            
        Returns:
            Dict containing processed traffic analytics
        """
        try:
            # Validate input data
            self.validate_analytics_input(daily_traffic_data, days)
            
            # Format daily traffic data
            formatted_daily_traffic = self.format_date_range_data(daily_traffic_data, 'date')
            
            # Calculate totals
            total_checks = sum(item.get('checks', 0) for item in formatted_daily_traffic)
            total_unique_users = len(set(item.get('unique_users', 0) for item in formatted_daily_traffic))
            
            # Process top domains
            formatted_domains = [
                {
                    "domain": domain_data.get('domain', 'Unknown'),
                    "count": domain_data.get('count', 0),
                    "percentage": round((domain_data.get('count', 0) / total_checks * 100), 2) if total_checks > 0 else 0
                }
                for domain_data in top_domains_data[:10]  # Top 10 domains
            ]
            
            # Process threat distribution
            total_threats = sum(threat.get('count', 0) for threat in threat_types_data)
            formatted_threats = [
                {
                    "type": threat.get('type', 'Unknown'),
                    "count": threat.get('count', 0),
                    "percentage": round((threat.get('count', 0) / total_threats * 100), 2) if total_threats > 0 else 0
                }
                for threat in threat_types_data
            ]
            
            return {
                "period": {
                    "days": days,
                    "start_date": (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),
                    "end_date": datetime.now(timezone.utc).isoformat()
                },
                "summary": {
                    "total_checks": total_checks,
                    "unique_users": total_unique_users,
                    "avg_checks_per_day": round(total_checks / days, 2) if days > 0 else 0
                },
                "daily_traffic": formatted_daily_traffic,
                "top_domains": formatted_domains,
                "threat_distribution": formatted_threats
            }
        except Exception as e:
            raise AdminServiceError(f"Failed to process traffic analytics: {str(e)}")
    
        except SQLAlchemyError as e:
            raise AdminServiceError(f"Failed to get traffic analytics: {str(e)}")
    
    def process_threat_intelligence(self, recent_threats_count: int, 
                                  threat_trends_data: List[Dict], 
                                  threat_sources_data: List[Dict]) -> Dict[str, Any]:
        """
        Process threat intelligence data into formatted response.
        
        Args:
            recent_threats_count: Count of recent threats in last 24h
            threat_trends_data: List of threat trend data with date and count
            threat_sources_data: List of threat source data with domain and count
            
        Returns:
            Dict containing formatted threat intelligence data
        """
        try:
            # Validate input data
            if not isinstance(recent_threats_count, int) or recent_threats_count < 0:
                recent_threats_count = 0
            
            if not isinstance(threat_trends_data, list):
                threat_trends_data = []
            
            if not isinstance(threat_sources_data, list):
                threat_sources_data = []
            
            # Format threat trends
            formatted_trends = []
            for trend in threat_trends_data:
                if isinstance(trend, dict) and 'date' in trend and 'count' in trend:
                    formatted_trends.append({
                        "date": str(trend['date']),
                        "count": int(trend['count']) if trend['count'] is not None else 0
                    })
            
            # Format threat sources (limit to top 10)
            formatted_sources = []
            for source in threat_sources_data[:10]:
                if isinstance(source, dict) and 'domain' in source and 'count' in source:
                    formatted_sources.append({
                        "domain": str(source['domain']),
                        "count": int(source['count']) if source['count'] is not None else 0
                    })
            
            return {
                "recent_threats_24h": recent_threats_count,
                "threat_trends": formatted_trends,
                "top_threat_sources": formatted_sources
            }
        except Exception as e:
            raise AdminServiceError(f"Failed to process threat intelligence: {str(e)}")
    
    def process_user_analytics(self, user_growth_data: List[Dict], 
                             subscription_data: List[Dict], 
                             top_users_data: List[Dict]) -> Dict[str, Any]:
        """
        Process user analytics data into formatted response.
        
        Args:
            user_growth_data: List of user growth data with date and new_users count
            subscription_data: List of subscription data with plan and count
            top_users_data: List of top user data with email, total_checks, and subscription
            
        Returns:
            Dict containing formatted user analytics data
        """
        try:
            # Validate and format user growth data
            formatted_growth = []
            if isinstance(user_growth_data, list):
                for growth in user_growth_data:
                    if isinstance(growth, dict) and 'date' in growth and 'new_users' in growth:
                        formatted_growth.append({
                            "date": str(growth['date']),
                            "new_users": int(growth['new_users']) if growth['new_users'] is not None else 0
                        })
            
            # Validate and format subscription data
            formatted_subscriptions = []
            if isinstance(subscription_data, list):
                for sub in subscription_data:
                    if isinstance(sub, dict) and 'plan' in sub and 'count' in sub:
                        plan_value = sub['plan']
                        # Handle enum values
                        if hasattr(plan_value, 'value'):
                            plan_value = plan_value.value
                        formatted_subscriptions.append({
                            "plan": str(plan_value),
                            "count": int(sub['count']) if sub['count'] is not None else 0
                        })
            
            # Validate and format top users data (limit to top 10)
            formatted_users = []
            if isinstance(top_users_data, list):
                for user in top_users_data[:10]:
                    if isinstance(user, dict) and all(k in user for k in ['email', 'total_checks', 'subscription']):
                        subscription_value = user['subscription']
                        # Handle enum values
                        if hasattr(subscription_value, 'value'):
                            subscription_value = subscription_value.value
                        formatted_users.append({
                            "email": str(user['email']),
                            "total_checks": int(user['total_checks']) if user['total_checks'] is not None else 0,
                            "subscription": str(subscription_value)
                        })
            
            return {
                "user_growth": formatted_growth,
                "active_by_subscription": formatted_subscriptions,
                "top_users": formatted_users
            }
        except Exception as e:
            raise AdminServiceError(f"Failed to process user analytics: {str(e)}")
    
    # Configuration Processing Methods
    
    def process_configuration(self, config_data: List[Dict]) -> List[Dict[str, Any]]:
        """
        Process configuration data into formatted response.
        
        Args:
            config_data: List of configuration data from database
            
        Returns:
            List of formatted configuration settings
        """
        try:
            formatted_configs = []
            
            if isinstance(config_data, list):
                for config in config_data:
                    if isinstance(config, dict) and all(k in config for k in ['id', 'key', 'value', 'category']):
                        # Handle sensitive values
                        display_value = config['value']
                        if config.get('is_sensitive', False):
                            display_value = "***"
                        
                        # Handle enum values
                        category_value = config['category']
                        if hasattr(category_value, 'value'):
                            category_value = category_value.value
                        
                        formatted_configs.append({
                            "id": str(config['id']),
                            "key": str(config['key']),
                            "value": display_value,
                            "category": str(category_value),
                            "description": str(config.get('description', '')),
                            "data_type": str(config.get('data_type', 'string')),
                            "is_sensitive": bool(config.get('is_sensitive', False)),
                            "updated_at": config.get('updated_at', '')
                        })
            
            return formatted_configs
        except Exception as e:
            raise AdminServiceError(f"Failed to process configuration: {str(e)}")
    
    def validate_configuration_update(self, config_data: Dict, new_value: str) -> Dict[str, Any]:
        """
        Validate and format configuration update data.
        
        Args:
            config_data: Configuration metadata from database
            new_value: New value to validate
            
        Returns:
            Dict containing validation result and formatted data
        """
        try:
            if not isinstance(config_data, dict):
                raise AdminServiceError("Invalid configuration data")
            
            # Validate value based on data type and constraints
            data_type = config_data.get('data_type', 'string')
            
            # Type validation
            if data_type == "integer":
                try:
                    int_value = int(new_value)
                    min_value = config_data.get('min_value')
                    max_value = config_data.get('max_value')
                    
                    if min_value is not None and int_value < min_value:
                        raise AdminServiceError(f"Value must be >= {min_value}")
                    if max_value is not None and int_value > max_value:
                        raise AdminServiceError(f"Value must be <= {max_value}")
                except ValueError:
                    raise AdminServiceError("Value must be an integer")
            
            elif data_type == "boolean":
                if new_value.lower() not in ["true", "false", "1", "0"]:
                    raise AdminServiceError("Value must be a boolean (true/false)")
            
            elif data_type == "json":
                try:
                    import json
                    json.loads(new_value)
                except json.JSONDecodeError:
                    raise AdminServiceError("Value must be valid JSON")
            
            # Allowed values validation
            allowed_values = config_data.get('allowed_values')
            if allowed_values and new_value not in allowed_values:
                raise AdminServiceError(f"Value must be one of: {allowed_values}")
            
            # Regex validation
            validation_regex = config_data.get('validation_regex')
            if validation_regex:
                import re
                if not re.match(validation_regex, new_value):
                    raise AdminServiceError("Value does not match required pattern")
            
            return {
                "valid": True,
                "validated_value": new_value,
                "data_type": data_type
            }
        except Exception as e:
            raise AdminServiceError(f"Configuration validation failed: {str(e)}")
    
    # User Management Processing Methods
    
    def process_users_data(self, users_data: List[Dict], total_count: int, 
                          page: int, limit: int) -> Dict[str, Any]:
        """
        Process users list data into formatted paginated response.
        
        Args:
            users_data: List of user data from database
            total_count: Total number of users matching filters
            page: Current page number
            limit: Items per page
            
        Returns:
            Dict containing formatted paginated user data
        """
        try:
            formatted_users = []
            
            if isinstance(users_data, list):
                for user in users_data:
                    if isinstance(user, dict):
                        # Handle enum values
                        role_value = user.get('role')
                        if hasattr(role_value, 'value'):
                            role_value = role_value.value
                        
                        status_value = user.get('status')
                        if hasattr(status_value, 'value'):
                            status_value = status_value.value
                        
                        subscription_value = user.get('subscription_plan')
                        if hasattr(subscription_value, 'value'):
                            subscription_value = subscription_value.value
                        
                        # Format last login
                        last_login = user.get('last_login')
                        if last_login and hasattr(last_login, 'isoformat'):
                            last_login = last_login.isoformat()
                        elif last_login:
                            last_login = str(last_login)
                        
                        # Format created_at
                        created_at = user.get('created_at')
                        if created_at and hasattr(created_at, 'isoformat'):
                            created_at = created_at.isoformat()
                        elif created_at:
                            created_at = str(created_at)
                        
                        formatted_users.append({
                            "id": str(user.get('id', '')),
                            "email": str(user.get('email', '')),
                            "username": str(user.get('username', '')),
                            "first_name": str(user.get('first_name', '')),
                            "last_name": str(user.get('last_name', '')),
                            "role": str(role_value) if role_value else '',
                            "status": str(status_value) if status_value else '',
                            "subscription_plan": str(subscription_value) if subscription_value else '',
                            "is_active": bool(user.get('is_active', False)),
                            "is_verified": bool(user.get('is_verified', False)),
                            "total_check_count": int(user.get('total_check_count', 0)),
                            "created_at": created_at,
                            "last_login": last_login
                        })
            
            # Calculate pagination info
            total_pages = (total_count + limit - 1) // limit if limit > 0 else 1
            
            return {
                "users": formatted_users,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "pages": total_pages
                }
            }
        except Exception as e:
            raise AdminServiceError(f"Failed to process users list: {str(e)}")
    
    def process_user_status_update(self, user_data: Dict) -> Dict[str, Any]:
        """
        Format user status update response.
        
        Args:
            user_data: Updated user data from database
            
        Returns:
            Dict containing formatted user status data
        """
        try:
            if not isinstance(user_data, dict):
                raise AdminServiceError("Invalid user data")
            
            # Handle enum values
            status_value = user_data.get('status')
            if hasattr(status_value, 'value'):
                status_value = status_value.value
            
            return {
                "id": str(user_data.get('id', '')),
                "email": str(user_data.get('email', '')),
                "status": str(status_value) if status_value else '',
                "is_active": bool(user_data.get('is_active', False))
            }
        except Exception as e:
            raise AdminServiceError(f"Failed to format user status update: {str(e)}")
    
    def process_configuration_update(self, config_data: Dict, updated_at: str) -> Dict[str, Any]:
        """
        Format configuration update response.
        
        Args:
            config_data: Configuration data
            updated_at: Update timestamp
            
        Returns:
            Formatted configuration update response
        """
        try:
            # Handle sensitive values
            display_value = config_data.get('value', '')
            if config_data.get('is_sensitive', False):
                display_value = "***"
            
            # Handle enum values
            category_value = config_data.get('category', '')
            if hasattr(category_value, 'value'):
                category_value = category_value.value
            
            return {
                "id": str(config_data.get('id', '')),
                "key": str(config_data.get('key', '')),
                "value": display_value,
                "category": str(category_value),
                "updated_at": updated_at
            }
        except Exception as e:
            raise AdminServiceError(f"Failed to format config update response: {str(e)}")
    
    # System Health Processing Methods
    
    def process_system_health(self, health_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process system health data into formatted response.
        
        Args:
            health_data: Health data prepared by AdminController
            
        Returns:
            Dict containing formatted system health data
        """
        try:
            from datetime import datetime, timezone
            
            # Process the health data components
            components = {}
            
            # Add database component
            if 'database' in health_data:
                db_data = health_data['database']
                components["database"] = {
                    "status": db_data.get('status', 'unknown'),
                    "response_time_ms": db_data.get('response_time_ms'),
                    "checked_at": datetime.now(timezone.utc).isoformat()
                }
            
            # Add activity metrics as components
            if 'activity' in health_data:
                activity = health_data['activity']
                components["user_activity"] = {
                    "status": "healthy" if activity.get('recent_users', 0) > 0 else "warning",
                    "recent_users": activity.get('recent_users', 0),
                    "recent_url_checks": activity.get('recent_url_checks', 0),
                    "recent_ai_analyses": activity.get('recent_ai_analyses', 0),
                    "checked_at": datetime.now(timezone.utc).isoformat()
                }
            
            # Add background tasks component
            if 'background_tasks' in health_data:
                tasks = health_data['background_tasks']
                failed_count = tasks.get('failed_last_hour', 0)
                running_count = tasks.get('running', 0)
                
                task_status = "healthy"
                if failed_count > 10:
                    task_status = "critical"
                elif failed_count > 5 or running_count > 20:
                    task_status = "warning"
                
                components["background_tasks"] = {
                    "status": task_status,
                    "pending": tasks.get('pending', 0),
                    "running": running_count,
                    "failed_last_hour": failed_count,
                    "checked_at": datetime.now(timezone.utc).isoformat()
                }
            
            # Add system metrics component
            if 'system' in health_data:
                system = health_data['system']
                components["system_metrics"] = {
                    "status": "healthy",  # Would be determined from actual metrics
                    "uptime": system.get('uptime'),
                    "memory_usage": system.get('memory_usage'),
                    "cpu_usage": system.get('cpu_usage'),
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
        except Exception as e:
            raise AdminServiceError(f"Failed to process system health: {str(e)}")
    
    # Helper Methods
    
    def _get_system_uptime(self) -> str:
        """
        Get system uptime placeholder.
        
        Returns:
            System uptime as string
        """
        # This would typically read from system metrics
        # For now, return a placeholder value
        return "99.9%"
    
    def format_date_range_data(self, data: List, date_field: str) -> List[Dict]:
        """
        Format date range data for analytics.
        
        Args:
            data: List of data items with date fields
            date_field: Name of the date field to format
            
        Returns:
            List of formatted data items
        """
        formatted_data = []
        for item in data:
            if isinstance(item, dict):
                formatted_item = dict(item)
                if date_field in formatted_item:
                    date_value = formatted_item[date_field]
                    if hasattr(date_value, 'isoformat'):
                        formatted_item[date_field] = date_value.isoformat()
                    else:
                        formatted_item[date_field] = str(date_value)
                formatted_data.append(formatted_item)
        return formatted_data
    
    def validate_statistics_input(self, users_data: Dict, url_checks_data: Dict, ai_analyses_data: Dict):
        """
        Validate input data for system statistics processing.
        
        Args:
            users_data: User statistics data
            url_checks_data: URL check statistics data
            ai_analyses_data: AI analysis statistics data
            
        Raises:
            AdminServiceError: If validation fails
        """
        if not isinstance(users_data, dict):
            raise AdminServiceError("Invalid users data format")
        if not isinstance(url_checks_data, dict):
            raise AdminServiceError("Invalid URL checks data format")
        if not isinstance(ai_analyses_data, dict):
            raise AdminServiceError("Invalid AI analyses data format")
    
    def validate_analytics_input(self, daily_traffic_data: List, days: int):
        """
        Validate input data for analytics processing.
        
        Args:
            daily_traffic_data: Daily traffic data
            days: Number of days
            
        Raises:
            AdminServiceError: If validation fails
        """
        if not isinstance(daily_traffic_data, list):
            raise AdminServiceError("Invalid daily traffic data format")
        if not isinstance(days, int) or days <= 0:
            raise AdminServiceError("Invalid days parameter")
    
    def format_config_update_response(self, config_data: Dict, updated_at: str) -> Dict[str, Any]:
        """
        Format configuration update response.
        
        Args:
            config_data: Configuration data
            updated_at: Update timestamp
            
        Returns:
            Formatted configuration update response
        """
        try:
            # Handle sensitive values
            display_value = config_data.get('value', '')
            if config_data.get('is_sensitive', False):
                display_value = "***"
            
            # Handle enum values
            category_value = config_data.get('category', '')
            if hasattr(category_value, 'value'):
                category_value = category_value.value
            
            return {
                "id": str(config_data.get('id', '')),
                "key": str(config_data.get('key', '')),
                "value": display_value,
                "category": str(category_value),
                "updated_at": updated_at
            }
        except Exception as e:
            raise AdminServiceError(f"Failed to format config update response: {str(e)}")
    
    def validate_user_filters(self, filters: Optional[Dict]) -> Dict[str, Any]:
        """
        Validate and normalize user filters.
        
        Args:
            filters: Optional filters dictionary
            
        Returns:
            Validated and normalized filters
        """
        if not filters or not isinstance(filters, dict):
            return {}
        
        validated_filters = {}
        
        # Validate role filter
        if 'role' in filters and filters['role']:
            validated_filters['role'] = str(filters['role'])
        
        # Validate status filter
        if 'status' in filters and filters['status']:
            validated_filters['status'] = str(filters['status'])
        
        # Validate subscription filter
        if 'subscription' in filters and filters['subscription']:
            validated_filters['subscription'] = str(filters['subscription'])
        
        # Validate is_active filter
        if 'is_active' in filters and filters['is_active'] is not None:
            validated_filters['is_active'] = bool(filters['is_active'])
        
        # Validate search filter
        if 'search' in filters and filters['search']:
            validated_filters['search'] = str(filters['search']).strip()
        
        return validated_filters