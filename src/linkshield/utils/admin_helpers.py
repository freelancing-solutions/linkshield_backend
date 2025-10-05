#!/usr/bin/env python3
"""
LinkShield Backend Admin Helper Utilities

Utility functions and helpers for admin dashboard operations including
data formatting, validation, export operations, and system monitoring.
"""

import csv
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from io import StringIO
import re

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from linkshield.config.settings import get_settings
from linkshield.models.user import User, UserRole
from linkshield.models.admin import AdminAction, ActionType, GlobalConfig, SystemHealth, HealthStatus


settings = get_settings()


class AdminDataFormatter:
    """Helper class for formatting admin dashboard data."""
    
    @staticmethod
    def format_user_data(user: User) -> Dict[str, Any]:
        """
        Format user data for admin display.
        
        Args:
            user: User model instance
            
        Returns:
            Dict: Formatted user data
        """
        return {
            "id": str(user.id),
            "email": user.email,
            "full_name": getattr(user, 'full_name', None),
            "role": user.role.value if user.role else None,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            "last_login": getattr(user, 'last_login', None),
            "login_count": getattr(user, 'login_count', 0),
            "subscription_plan": getattr(user, 'subscription_plan', 'free'),
            "api_calls_today": getattr(user, 'api_calls_today', 0),
            "api_calls_total": getattr(user, 'api_calls_total', 0)
        }
    
    @staticmethod
    def format_admin_action(action: AdminAction) -> Dict[str, Any]:
        """
        Format admin action for display.
        
        Args:
            action: AdminAction model instance
            
        Returns:
            Dict: Formatted action data
        """
        return {
            "id": str(action.id),
            "user_id": str(action.user_id),
            "action_type": action.action_type.value,
            "resource_type": action.resource_type,
            "resource_id": action.resource_id,
            "success": action.success,
            "ip_address": action.ip_address,
            "user_agent": action.user_agent,
            "created_at": action.created_at.isoformat() if action.created_at else None,
            "details": action.details if isinstance(action.details, dict) else {}
        }
    
    @staticmethod
    def format_system_health(health: SystemHealth) -> Dict[str, Any]:
        """
        Format system health data for display.
        
        Args:
            health: SystemHealth model instance
            
        Returns:
            Dict: Formatted health data
        """
        return {
            "id": str(health.id),
            "component": health.component,
            "status": health.status.value,
            "response_time": health.response_time,
            "error_message": health.error_message,
            "checked_at": health.checked_at.isoformat() if health.checked_at else None,
            "metadata": health.metadata if isinstance(health.metadata, dict) else {}
        }
    
    @staticmethod
    def format_config_item(config: GlobalConfig) -> Dict[str, Any]:
        """
        Format configuration item for display.
        
        Args:
            config: GlobalConfig model instance
            
        Returns:
            Dict: Formatted config data
        """
        return {
            "id": str(config.id),
            "category": config.category.value,
            "key": config.key,
            "value": config.value,
            "description": config.description,
            "is_sensitive": config.is_sensitive,
            "created_at": config.created_at.isoformat() if config.created_at else None,
            "updated_at": config.updated_at.isoformat() if config.updated_at else None
        }


class AdminValidator:
    """Helper class for validating admin operations."""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format.
        
        Args:
            email: Email address to validate
            
        Returns:
            bool: True if valid email format
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_user_role(role: str) -> bool:
        """
        Validate user role.
        
        Args:
            role: Role string to validate
            
        Returns:
            bool: True if valid role
        """
        try:
            UserRole(role)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_config_key(key: str) -> bool:
        """
        Validate configuration key format.
        
        Args:
            key: Configuration key to validate
            
        Returns:
            bool: True if valid key format
        """
        # Allow alphanumeric, underscore, dot, and hyphen
        pattern = r'^[a-zA-Z0-9._-]+$'
        return bool(re.match(pattern, key)) and len(key) <= 100
    
    @staticmethod
    def validate_json_value(value: str) -> Tuple[bool, Optional[Any]]:
        """
        Validate and parse JSON value.
        
        Args:
            value: JSON string to validate
            
        Returns:
            Tuple: (is_valid, parsed_value)
        """
        try:
            parsed = json.loads(value)
            return True, parsed
        except (json.JSONDecodeError, TypeError):
            return False, None
    
    @staticmethod
    def validate_pagination_params(page: int, size: int) -> Tuple[int, int]:
        """
        Validate and normalize pagination parameters.
        
        Args:
            page: Page number
            size: Page size
            
        Returns:
            Tuple: (normalized_page, normalized_size)
        """
        # Ensure page is at least 1
        page = max(1, page)
        
        # Limit page size to reasonable bounds
        size = max(1, min(size, settings.ADMIN_MAX_EXPORT_RECORDS // 10))
        
        return page, size


class AdminExporter:
    """Helper class for exporting admin data."""
    
    @staticmethod
    def export_to_csv(data: List[Dict[str, Any]], filename: str = None) -> str:
        """
        Export data to CSV format.
        
        Args:
            data: List of dictionaries to export
            filename: Optional filename for the export
            
        Returns:
            str: CSV content as string
        """
        if not data:
            return ""
        
        output = StringIO()
        
        # Get all unique keys from all dictionaries
        fieldnames = set()
        for item in data:
            fieldnames.update(item.keys())
        
        fieldnames = sorted(list(fieldnames))
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for item in data:
            # Convert complex objects to strings
            row = {}
            for key, value in item.items():
                if isinstance(value, (dict, list)):
                    row[key] = json.dumps(value)
                elif isinstance(value, datetime):
                    row[key] = value.isoformat()
                else:
                    row[key] = str(value) if value is not None else ""
            writer.writerow(row)
        
        return output.getvalue()
    
    @staticmethod
    def export_to_json(data: List[Dict[str, Any]], pretty: bool = True) -> str:
        """
        Export data to JSON format.
        
        Args:
            data: List of dictionaries to export
            pretty: Whether to format JSON with indentation
            
        Returns:
            str: JSON content as string
        """
        if pretty:
            return json.dumps(data, indent=2, default=str)
        else:
            return json.dumps(data, default=str)


class AdminSystemMonitor:
    """Helper class for system monitoring operations."""
    
    @staticmethod
    async def get_database_stats(db: AsyncSession) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Args:
            db: Database session
            
        Returns:
            Dict: Database statistics
        """
        try:
            # Get table sizes
            result = await db.execute(text("""
                SELECT 
                    schemaname,
                    tablename,
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
                FROM pg_tables 
                WHERE schemaname = 'public'
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
                LIMIT 10
            """))
            
            tables = []
            for row in result:
                tables.append({
                    "schema": row.schemaname,
                    "table": row.tablename,
                    "size": row.size,
                    "size_bytes": row.size_bytes
                })
            
            # Get connection stats
            conn_result = await db.execute(text("""
                SELECT 
                    count(*) as total_connections,
                    count(*) FILTER (WHERE state = 'active') as active_connections,
                    count(*) FILTER (WHERE state = 'idle') as idle_connections
                FROM pg_stat_activity
            """))
            
            conn_row = conn_result.first()
            connections = {
                "total": conn_row.total_connections,
                "active": conn_row.active_connections,
                "idle": conn_row.idle_connections
            }
            
            return {
                "tables": tables,
                "connections": connections,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    @staticmethod
    def calculate_system_health_score(health_records: List[SystemHealth]) -> Dict[str, Any]:
        """
        Calculate overall system health score.
        
        Args:
            health_records: List of system health records
            
        Returns:
            Dict: Health score and breakdown
        """
        if not health_records:
            return {
                "overall_score": 0.0,
                "status": "unknown",
                "component_scores": {},
                "issues": ["No health data available"]
            }
        
        component_scores = {}
        issues = []
        
        for record in health_records:
            component = record.component
            
            # Calculate component score based on status
            if record.status == HealthStatus.HEALTHY:
                score = 1.0
            elif record.status == HealthStatus.WARNING:
                score = 0.7
            elif record.status == HealthStatus.CRITICAL:
                score = 0.3
            else:  # UNKNOWN
                score = 0.5
            
            # Adjust score based on response time if available
            if record.response_time:
                if record.response_time > 5000:  # > 5 seconds
                    score *= 0.8
                elif record.response_time > 2000:  # > 2 seconds
                    score *= 0.9
            
            component_scores[component] = score
            
            # Collect issues
            if record.status in [HealthStatus.WARNING, HealthStatus.CRITICAL]:
                issues.append(f"{component}: {record.error_message or 'Status ' + record.status.value}")
        
        # Calculate overall score
        overall_score = sum(component_scores.values()) / len(component_scores)
        
        # Determine overall status
        if overall_score >= 0.9:
            status = "healthy"
        elif overall_score >= 0.7:
            status = "warning"
        else:
            status = "critical"
        
        return {
            "overall_score": round(overall_score, 2),
            "status": status,
            "component_scores": component_scores,
            "issues": issues,
            "total_components": len(component_scores),
            "healthy_components": sum(1 for score in component_scores.values() if score >= 0.9),
            "warning_components": sum(1 for score in component_scores.values() if 0.7 <= score < 0.9),
            "critical_components": sum(1 for score in component_scores.values() if score < 0.7)
        }


class AdminDateTimeHelper:
    """Helper class for date/time operations in admin context."""
    
    @staticmethod
    def get_date_range_filter(period: str) -> Tuple[datetime, datetime]:
        """
        Get date range for filtering based on period.
        
        Args:
            period: Period string ('today', 'week', 'month', 'quarter', 'year')
            
        Returns:
            Tuple: (start_date, end_date)
        """
        now = datetime.now(timezone.utc)
        
        if period == "today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end = now
        elif period == "week":
            start = now - timedelta(days=7)
            end = now
        elif period == "month":
            start = now - timedelta(days=30)
            end = now
        elif period == "quarter":
            start = now - timedelta(days=90)
            end = now
        elif period == "year":
            start = now - timedelta(days=365)
            end = now
        else:
            # Default to last 7 days
            start = now - timedelta(days=7)
            end = now
        
        return start, end
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """
        Format duration in human-readable format.
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            str: Formatted duration
        """
        if seconds < 1:
            return f"{int(seconds * 1000)}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            remaining_seconds = int(seconds % 60)
            return f"{minutes}m {remaining_seconds}s"
        else:
            hours = int(seconds // 3600)
            remaining_minutes = int((seconds % 3600) // 60)
            return f"{hours}h {remaining_minutes}m"


class AdminSecurityHelper:
    """Helper class for admin security operations."""
    
    @staticmethod
    def sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize data for logging by removing sensitive information.
        
        Args:
            data: Data dictionary to sanitize
            
        Returns:
            Dict: Sanitized data
        """
        sensitive_keys = {
            'password', 'token', 'secret', 'key', 'credentials',
            'authorization', 'cookie', 'session', 'api_key'
        }
        
        def sanitize_value(key: str, value: Any) -> Any:
            if isinstance(key, str) and any(sensitive in key.lower() for sensitive in sensitive_keys):
                return "<redacted>"
            elif isinstance(value, dict):
                return {k: sanitize_value(k, v) for k, v in value.items()}
            elif isinstance(value, list):
                return [sanitize_value("", item) for item in value]
            else:
                return value
        
        return {k: sanitize_value(k, v) for k, v in data.items()}
    
    @staticmethod
    def generate_audit_id() -> str:
        """
        Generate unique audit ID.
        
        Returns:
            str: Unique audit identifier
        """
        return str(uuid.uuid4())
    
    @staticmethod
    def mask_sensitive_config_value(key: str, value: str) -> str:
        """
        Mask sensitive configuration values for display.
        
        Args:
            key: Configuration key
            value: Configuration value
            
        Returns:
            str: Masked value if sensitive, original value otherwise
        """
        sensitive_patterns = [
            'password', 'secret', 'key', 'token', 'credential',
            'api_key', 'private', 'auth', 'jwt'
        ]
        
        if any(pattern in key.lower() for pattern in sensitive_patterns):
            if len(value) <= 4:
                return "*" * len(value)
            else:
                return value[:2] + "*" * (len(value) - 4) + value[-2:]
        
        return value


# Convenience functions for common operations
def format_bytes(bytes_value: int) -> str:
    """
    Format bytes in human-readable format.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        str: Formatted bytes string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def truncate_string(text: str, max_length: int = 100) -> str:
    """
    Truncate string to maximum length with ellipsis.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        
    Returns:
        str: Truncated text
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Safely divide two numbers, returning default if denominator is zero.
    
    Args:
        numerator: Numerator
        denominator: Denominator
        default: Default value if division by zero
        
    Returns:
        float: Division result or default
    """
    if denominator == 0:
        return default
    return numerator / denominator