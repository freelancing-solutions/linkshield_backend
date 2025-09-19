# Admin Helper Utilities Documentation

## Overview

The LinkShield admin helper utilities provide a comprehensive set of tools for common administrative operations. These utilities are designed to simplify complex admin tasks, ensure consistency across the application, and provide reusable components for admin functionality.

**Module Location**: `app/admin/utils/`  
**Version**: 2.1.0  
**Last Updated**: January 2024  
**Dependencies**: FastAPI, SQLAlchemy, Pydantic, Redis, Celery

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Admin Utilities Architecture                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐            │
│  │ AdminValidator  │    │AdminDataFormatter│   │AdminPermission  │            │
│  │                 │    │                 │    │Checker          │            │
│  │ • validate_user │    │ • format_user   │    │ • check_perm    │            │
│  │ • validate_role │    │ • format_audit  │    │ • has_access    │            │
│  │ • validate_perm │    │ • sanitize_data │    │ • validate_role │            │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘            │
│           │                       │                       │                    │
│           │                       │                       │                    │
│           ▼                       ▼                       ▼                    │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐            │
│  │AdminSession     │    │AdminAuditLogger │    │AdminNotification│            │
│  │Manager          │    │                 │    │Sender           │            │
│  │                 │    │ • log_action    │    │ • send_alert    │            │
│  │ • create_session│    │ • log_security  │    │ • send_report   │            │
│  │ • validate_token│    │ • log_error     │    │ • queue_notify  │            │
│  │ • cleanup_old   │    │ • search_logs   │    │ • format_msg    │            │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘            │
│           │                       │                       │                    │
│           │                       │                       │                    │
│           └───────────────────────┼───────────────────────┘                    │
│                                   │                                            │
│                                   ▼                                            │
│                         ┌─────────────────┐                                   │
│                         │AdminReport      │                                   │
│                         │Generator        │                                   │
│                         │                 │                                   │
│                         │ • generate_user │                                   │
│                         │ • generate_audit│                                   │
│                         │ • export_data   │                                   │
│                         │ • schedule_rpt  │                                   │
│                         └─────────────────┘                                   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Utility Classes

### 1. AdminDataFormatter

Handles data formatting, sanitization, and transformation for admin operations.

#### Class Definition

```python
# app/admin/utils/formatters.py

from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timezone
from decimal import Decimal
import json
import re
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

class AdminDataFormatter:
    """
    Comprehensive data formatting utility for admin operations.
    
    Provides methods for formatting user data, audit logs, system metrics,
    and other admin-related information with consistent output formats.
    """
    
    def __init__(self, timezone_offset: str = "UTC"):
        """
        Initialize the formatter with timezone settings.
        
        Args:
            timezone_offset: Default timezone for date formatting
        """
        self.timezone_offset = timezone_offset
        self.sensitive_fields = {
            'password', 'password_hash', 'secret', 'token', 'key',
            'private_key', 'api_key', 'session_token', 'refresh_token'
        }
    
    def format_user_data(self, user_data: Dict[str, Any], 
                        include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Format user data for admin display with optional sensitive data inclusion.
        
        Args:
            user_data: Raw user data from database
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            Formatted user data dictionary
            
        Example:
            >>> formatter = AdminDataFormatter()
            >>> raw_user = {
            ...     'id': 'uuid-123',
            ...     'email': 'user@example.com',
            ...     'password_hash': 'hashed_password',
            ...     'created_at': datetime.now(),
            ...     'last_login': datetime.now(),
            ...     'is_active': True
            ... }
            >>> formatted = formatter.format_user_data(raw_user)
            >>> print(formatted)
            {
                'id': 'uuid-123',
                'email': 'user@example.com',
                'created_at': '2024-01-15T10:30:00Z',
                'last_login': '2024-01-15T09:15:00Z',
                'status': 'Active',
                'account_age_days': 45
            }
        """
        if not user_data:
            return {}
        
        formatted = {}
        
        # Basic user information
        formatted['id'] = user_data.get('id')
        formatted['email'] = user_data.get('email')
        formatted['display_name'] = self._format_display_name(user_data)
        
        # Format timestamps
        if user_data.get('created_at'):
            formatted['created_at'] = self._format_datetime(user_data['created_at'])
            formatted['account_age_days'] = self._calculate_days_since(user_data['created_at'])
        
        if user_data.get('last_login'):
            formatted['last_login'] = self._format_datetime(user_data['last_login'])
            formatted['last_login_ago'] = self._format_time_ago(user_data['last_login'])
        
        # Format status information
        formatted['status'] = self._format_user_status(user_data)
        formatted['role'] = user_data.get('role_name', 'Unknown')
        
        # Security information
        formatted['two_factor_enabled'] = user_data.get('two_factor_enabled', False)
        formatted['login_attempts'] = user_data.get('login_attempts', 0)
        
        if user_data.get('locked_until'):
            formatted['locked_until'] = self._format_datetime(user_data['locked_until'])
            formatted['is_locked'] = datetime.now(timezone.utc) < user_data['locked_until']
        else:
            formatted['is_locked'] = False
        
        # Include sensitive data if requested
        if include_sensitive:
            for field in self.sensitive_fields:
                if field in user_data:
                    formatted[field] = user_data[field]
        
        # Additional metadata
        formatted['profile_completeness'] = self._calculate_profile_completeness(user_data)
        
        return formatted
    
    def format_audit_log(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format audit log entry for admin display.
        
        Args:
            audit_data: Raw audit log data from database
            
        Returns:
            Formatted audit log dictionary
            
        Example:
            >>> audit_entry = {
            ...     'id': 'audit-123',
            ...     'timestamp': datetime.now(),
            ...     'admin_email': 'admin@example.com',
            ...     'action_type': 'user_update',
            ...     'resource_id': 'user-456',
            ...     'ip_address': '192.168.1.100',
            ...     'is_successful': True,
            ...     'processing_time_ms': 150
            ... }
            >>> formatted = formatter.format_audit_log(audit_entry)
        """
        if not audit_data:
            return {}
        
        formatted = {
            'id': audit_data.get('id'),
            'timestamp': self._format_datetime(audit_data.get('timestamp')),
            'time_ago': self._format_time_ago(audit_data.get('timestamp')),
            'admin_email': audit_data.get('admin_email'),
            'action': self._format_action_description(audit_data),
            'resource': self._format_resource_info(audit_data),
            'status': 'Success' if audit_data.get('is_successful') else 'Failed',
            'ip_address': str(audit_data.get('ip_address', '')),
            'user_agent': self._format_user_agent(audit_data.get('user_agent')),
            'processing_time': f"{audit_data.get('processing_time_ms', 0)}ms",
            'risk_level': audit_data.get('risk_level', 'low').title()
        }
        
        # Add error information if action failed
        if not audit_data.get('is_successful'):
            formatted['error_code'] = audit_data.get('error_code')
            formatted['error_message'] = audit_data.get('error_message')
        
        # Add security flags if present
        if audit_data.get('is_suspicious'):
            formatted['security_flags'] = ['Suspicious Activity']
        
        return formatted
    
    def format_system_metrics(self, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format system metrics for admin dashboard display.
        
        Args:
            metrics_data: Raw system metrics data
            
        Returns:
            Formatted metrics dictionary
        """
        formatted = {}
        
        # Format memory usage
        if 'memory' in metrics_data:
            memory = metrics_data['memory']
            formatted['memory'] = {
                'used': self._format_bytes(memory.get('used', 0)),
                'total': self._format_bytes(memory.get('total', 0)),
                'percentage': f"{memory.get('percentage', 0):.1f}%"
            }
        
        # Format CPU usage
        if 'cpu' in metrics_data:
            formatted['cpu'] = {
                'percentage': f"{metrics_data['cpu'].get('percentage', 0):.1f}%",
                'load_average': metrics_data['cpu'].get('load_average', [])
            }
        
        # Format disk usage
        if 'disk' in metrics_data:
            disk = metrics_data['disk']
            formatted['disk'] = {
                'used': self._format_bytes(disk.get('used', 0)),
                'total': self._format_bytes(disk.get('total', 0)),
                'percentage': f"{disk.get('percentage', 0):.1f}%"
            }
        
        # Format database metrics
        if 'database' in metrics_data:
            db = metrics_data['database']
            formatted['database'] = {
                'connections': db.get('connections', 0),
                'queries_per_second': f"{db.get('queries_per_second', 0):.2f}",
                'avg_query_time': f"{db.get('avg_query_time_ms', 0):.2f}ms"
            }
        
        return formatted
    
    def sanitize_sensitive_data(self, data: Dict[str, Any], 
                              mask_char: str = "*") -> Dict[str, Any]:
        """
        Sanitize sensitive data by masking or removing sensitive fields.
        
        Args:
            data: Data dictionary to sanitize
            mask_char: Character to use for masking
            
        Returns:
            Sanitized data dictionary
        """
        sanitized = data.copy()
        
        for key, value in data.items():
            if self._is_sensitive_field(key):
                if isinstance(value, str) and len(value) > 4:
                    # Mask all but last 4 characters
                    sanitized[key] = mask_char * (len(value) - 4) + value[-4:]
                else:
                    sanitized[key] = mask_char * 8
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_sensitive_data(value, mask_char)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_sensitive_data(item, mask_char) 
                    if isinstance(item, dict) else item 
                    for item in value
                ]
        
        return sanitized
    
    def format_export_data(self, data: List[Dict[str, Any]], 
                          export_format: str = "csv") -> Union[str, bytes]:
        """
        Format data for export in various formats.
        
        Args:
            data: List of data dictionaries to export
            export_format: Export format ('csv', 'json', 'xlsx')
            
        Returns:
            Formatted export data
        """
        if export_format.lower() == "csv":
            return self._format_csv_export(data)
        elif export_format.lower() == "json":
            return self._format_json_export(data)
        elif export_format.lower() == "xlsx":
            return self._format_xlsx_export(data)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
    
    # Private helper methods
    def _format_datetime(self, dt: datetime) -> str:
        """Format datetime to ISO string with timezone."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    
    def _format_time_ago(self, dt: datetime) -> str:
        """Format datetime as 'time ago' string."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        diff = now - dt
        
        if diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hours ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minutes ago"
        else:
            return "Just now"
    
    def _calculate_days_since(self, dt: datetime) -> int:
        """Calculate days since given datetime."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        return (now - dt).days
    
    def _format_display_name(self, user_data: Dict[str, Any]) -> str:
        """Format user display name from available data."""
        if user_data.get('display_name'):
            return user_data['display_name']
        
        first_name = user_data.get('first_name', '')
        last_name = user_data.get('last_name', '')
        
        if first_name and last_name:
            return f"{first_name} {last_name}"
        elif first_name:
            return first_name
        else:
            return user_data.get('email', 'Unknown User')
    
    def _format_user_status(self, user_data: Dict[str, Any]) -> str:
        """Format user status based on various flags."""
        if not user_data.get('is_active', True):
            return "Inactive"
        elif user_data.get('is_locked', False):
            return "Locked"
        elif not user_data.get('is_verified', True):
            return "Unverified"
        else:
            return "Active"
    
    def _calculate_profile_completeness(self, user_data: Dict[str, Any]) -> int:
        """Calculate profile completeness percentage."""
        required_fields = ['email', 'first_name', 'last_name']
        optional_fields = ['display_name', 'timezone', 'language']
        
        completed = 0
        total = len(required_fields) + len(optional_fields)
        
        for field in required_fields:
            if user_data.get(field):
                completed += 1
        
        for field in optional_fields:
            if user_data.get(field):
                completed += 1
        
        return int((completed / total) * 100)
    
    def _format_action_description(self, audit_data: Dict[str, Any]) -> str:
        """Format action description from audit data."""
        action_type = audit_data.get('action_type', 'unknown')
        resource_type = audit_data.get('resource_type', 'resource')
        
        action_map = {
            'create': f'Created {resource_type}',
            'read': f'Viewed {resource_type}',
            'update': f'Updated {resource_type}',
            'delete': f'Deleted {resource_type}',
            'login': 'Logged in',
            'logout': 'Logged out',
            'password_change': 'Changed password',
            'password_reset': 'Reset password'
        }
        
        return action_map.get(action_type, f'{action_type.title()} {resource_type}')
    
    def _format_resource_info(self, audit_data: Dict[str, Any]) -> str:
        """Format resource information from audit data."""
        resource_type = audit_data.get('resource_type', '')
        resource_id = audit_data.get('resource_id', '')
        
        if resource_type and resource_id:
            return f"{resource_type.title()}: {resource_id}"
        elif resource_type:
            return resource_type.title()
        else:
            return "System"
    
    def _format_user_agent(self, user_agent: str) -> str:
        """Format user agent string for display."""
        if not user_agent:
            return "Unknown"
        
        # Extract browser and OS information
        browser_patterns = {
            'Chrome': r'Chrome/[\d.]+',
            'Firefox': r'Firefox/[\d.]+',
            'Safari': r'Safari/[\d.]+',
            'Edge': r'Edge/[\d.]+'
        }
        
        for browser, pattern in browser_patterns.items():
            if re.search(pattern, user_agent):
                return browser
        
        return "Other"
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if field name indicates sensitive data."""
        field_lower = field_name.lower()
        return any(sensitive in field_lower for sensitive in self.sensitive_fields)
    
    def _format_csv_export(self, data: List[Dict[str, Any]]) -> str:
        """Format data as CSV string."""
        import csv
        import io
        
        if not data:
            return ""
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        
        return output.getvalue()
    
    def _format_json_export(self, data: List[Dict[str, Any]]) -> str:
        """Format data as JSON string."""
        return json.dumps(data, indent=2, default=str)
    
    def _format_xlsx_export(self, data: List[Dict[str, Any]]) -> bytes:
        """Format data as Excel file bytes."""
        import pandas as pd
        import io
        
        df = pd.DataFrame(data)
        output = io.BytesIO()
        df.to_excel(output, index=False, engine='openpyxl')
        output.seek(0)
        
        return output.getvalue()
```

#### Usage Examples

```python
# Example 1: Format user data for admin dashboard
from app.admin.utils.formatters import AdminDataFormatter

formatter = AdminDataFormatter(timezone_offset="America/New_York")

# Raw user data from database
raw_user = {
    'id': 'user-123-456',
    'email': 'john.doe@example.com',
    'first_name': 'John',
    'last_name': 'Doe',
    'password_hash': 'bcrypt$2b$12$...',
    'created_at': datetime(2023, 12, 1, 10, 30, 0),
    'last_login': datetime(2024, 1, 15, 9, 15, 0),
    'is_active': True,
    'is_verified': True,
    'two_factor_enabled': True,
    'login_attempts': 0,
    'role_name': 'Administrator'
}

# Format for admin display (excludes sensitive data)
formatted_user = formatter.format_user_data(raw_user)
print(json.dumps(formatted_user, indent=2))

# Example 2: Format audit logs for security review
audit_logs = [
    {
        'id': 'audit-001',
        'timestamp': datetime.now(),
        'admin_email': 'admin@example.com',
        'action_type': 'user_update',
        'resource_type': 'user',
        'resource_id': 'user-123',
        'ip_address': '192.168.1.100',
        'is_successful': True,
        'processing_time_ms': 150,
        'risk_level': 'low'
    }
]

formatted_logs = [formatter.format_audit_log(log) for log in audit_logs]

# Example 3: Export user data as CSV
users_data = [formatted_user]  # List of formatted user data
csv_export = formatter.format_export_data(users_data, "csv")
print(csv_export)

# Example 4: Sanitize sensitive data for logging
sensitive_data = {
    'user_id': 'user-123',
    'email': 'user@example.com',
    'password_hash': 'very_secret_hash_value',
    'api_key': 'sk-1234567890abcdef',
    'profile': {
        'name': 'John Doe',
        'secret_question': 'What is your pet name?'
    }
}

sanitized = formatter.sanitize_sensitive_data(sensitive_data)
print(json.dumps(sanitized, indent=2))
# Output:
# {
#   "user_id": "user-123",
#   "email": "user@example.com",
#   "password_hash": "****alue",
#   "api_key": "****cdef",
#   "profile": {
#     "name": "John Doe",
#     "secret_question": "What is your pet name?"
#   }
# }
```

### 2. AdminValidator

Provides comprehensive validation for admin operations and data integrity.

#### Class Definition

```python
# app/admin/utils/validators.py

from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timezone
import re
import ipaddress
from email_validator import validate_email, EmailNotValidError
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

class ValidationError(Exception):
    """Custom exception for validation errors."""
    
    def __init__(self, message: str, field: str = None, code: str = None):
        self.message = message
        self.field = field
        self.code = code
        super().__init__(message)

class AdminValidator:
    """
    Comprehensive validation utility for admin operations.
    
    Provides validation methods for user data, permissions, system settings,
    and other admin-related operations with detailed error reporting.
    """
    
    def __init__(self, db_session: Session):
        """
        Initialize validator with database session.
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session
        self.password_requirements = {
            'min_length': 12,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True,
            'forbidden_patterns': ['password', '123456', 'qwerty']
        }
    
    def validate_user_creation(self, user_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate user creation data comprehensively.
        
        Args:
            user_data: Dictionary containing user creation data
            
        Returns:
            Tuple of (is_valid, list_of_errors)
            
        Example:
            >>> validator = AdminValidator(db_session)
            >>> user_data = {
            ...     'email': 'newuser@example.com',
            ...     'password': 'SecurePass123!',
            ...     'first_name': 'John',
            ...     'last_name': 'Doe',
            ...     'role_id': 'role-uuid-123'
            ... }
            >>> is_valid, errors = validator.validate_user_creation(user_data)
            >>> if not is_valid:
            ...     print("Validation errors:", errors)
        """
        errors = []
        
        # Validate required fields
        required_fields = ['email', 'password', 'role_id']
        for field in required_fields:
            if not user_data.get(field):
                errors.append(f"{field} is required")
        
        # Validate email
        if user_data.get('email'):
            email_valid, email_error = self.validate_email_address(user_data['email'])
            if not email_valid:
                errors.append(email_error)
            else:
                # Check email uniqueness
                if self._email_exists(user_data['email']):
                    errors.append("Email address already exists")
        
        # Validate password
        if user_data.get('password'):
            password_valid, password_errors = self.validate_password(user_data['password'])
            if not password_valid:
                errors.extend(password_errors)
        
        # Validate role
        if user_data.get('role_id'):
            role_valid, role_error = self.validate_role_assignment(user_data['role_id'])
            if not role_valid:
                errors.append(role_error)
        
        # Validate names
        if user_data.get('first_name'):
            name_valid, name_error = self.validate_name(user_data['first_name'], 'first_name')
            if not name_valid:
                errors.append(name_error)
        
        if user_data.get('last_name'):
            name_valid, name_error = self.validate_name(user_data['last_name'], 'last_name')
            if not name_valid:
                errors.append(name_error)
        
        return len(errors) == 0, errors
    
    def validate_email_address(self, email: str) -> Tuple[bool, str]:
        """
        Validate email address format and deliverability.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Basic format validation
            validated_email = validate_email(email)
            email = validated_email.email
            
            # Additional custom validations
            if len(email) > 255:
                return False, "Email address is too long (max 255 characters)"
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'\.{2,}',  # Multiple consecutive dots
                r'^\.|\.$',  # Starting or ending with dot
                r'[+]{2,}',  # Multiple plus signs
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, email):
                    return False, "Email address contains invalid patterns"
            
            return True, ""
            
        except EmailNotValidError as e:
            return False, f"Invalid email format: {str(e)}"
    
    def validate_password(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against security requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check minimum length
        if len(password) < self.password_requirements['min_length']:
            errors.append(f"Password must be at least {self.password_requirements['min_length']} characters long")
        
        # Check maximum length (prevent DoS)
        if len(password) > 128:
            errors.append("Password is too long (max 128 characters)")
        
        # Check character requirements
        if self.password_requirements['require_uppercase'] and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.password_requirements['require_lowercase'] and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.password_requirements['require_numbers'] and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if self.password_requirements['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Check forbidden patterns
        password_lower = password.lower()
        for pattern in self.password_requirements['forbidden_patterns']:
            if pattern in password_lower:
                errors.append(f"Password cannot contain common patterns like '{pattern}'")
        
        # Check for repeated characters
        if re.search(r'(.)\1{3,}', password):
            errors.append("Password cannot contain more than 3 consecutive identical characters")
        
        return len(errors) == 0, errors
    
    def validate_role_assignment(self, role_id: str, 
                               assigner_role_level: int = None) -> Tuple[bool, str]:
        """
        Validate role assignment permissions and hierarchy.
        
        Args:
            role_id: Role ID to assign
            assigner_role_level: Role level of the admin making the assignment
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if role exists and is active
        role = self.db.query(AdminRole).filter(
            AdminRole.id == role_id,
            AdminRole.is_active == True
        ).first()
        
        if not role:
            return False, "Role not found or inactive"
        
        # Check role hierarchy if assigner level is provided
        if assigner_role_level is not None:
            if role.role_level >= assigner_role_level:
                return False, "Cannot assign role with equal or higher privileges"
        
        # Check if role is system role (special handling)
        if role.is_system_role and assigner_role_level is not None and assigner_role_level < 10:
            return False, "Only super administrators can assign system roles"
        
        return True, ""
    
    def validate_permission_update(self, permissions: List[str], 
                                 role_level: int) -> Tuple[bool, List[str]]:
        """
        Validate permission updates against role capabilities.
        
        Args:
            permissions: List of permissions to validate
            role_level: Role level requesting the permissions
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Define permission hierarchy
        permission_levels = {
            '*': 10,  # Super admin only
            'system:*': 9,
            'users:delete': 8,
            'roles:*': 8,
            'users:create': 6,
            'users:update': 5,
            'users:read': 3,
            'monitoring:read': 2,
            'reports:read': 1
        }
        
        for permission in permissions:
            # Check if permission exists
            if not self._permission_exists(permission):
                errors.append(f"Unknown permission: {permission}")
                continue
            
            # Check permission level requirements
            required_level = self._get_permission_level(permission, permission_levels)
            if role_level < required_level:
                errors.append(f"Insufficient role level for permission: {permission}")
        
        return len(errors) == 0, errors
    
    def validate_ip_address(self, ip_address: str) -> Tuple[bool, str]:
        """
        Validate IP address format and check against restrictions.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check for private/local addresses in production
            if ip.is_private and not self._allow_private_ips():
                return False, "Private IP addresses are not allowed"
            
            if ip.is_loopback and not self._allow_loopback_ips():
                return False, "Loopback IP addresses are not allowed"
            
            # Check against IP blacklist
            if self._is_ip_blacklisted(str(ip)):
                return False, "IP address is blacklisted"
            
            return True, ""
            
        except ValueError:
            return False, "Invalid IP address format"
    
    def validate_session_data(self, session_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate session creation/update data.
        
        Args:
            session_data: Session data to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate required fields
        required_fields = ['admin_id', 'ip_address', 'user_agent']
        for field in required_fields:
            if not session_data.get(field):
                errors.append(f"{field} is required")
        
        # Validate IP address
        if session_data.get('ip_address'):
            ip_valid, ip_error = self.validate_ip_address(session_data['ip_address'])
            if not ip_valid:
                errors.append(ip_error)
        
        # Validate user agent
        if session_data.get('user_agent'):
            if len(session_data['user_agent']) > 1000:
                errors.append("User agent string is too long")
        
        # Validate session duration
        if session_data.get('expires_at'):
            expires_at = session_data['expires_at']
            if isinstance(expires_at, str):
                try:
                    expires_at = datetime.fromisoformat(expires_at)
                except ValueError:
                    errors.append("Invalid expiration date format")
                    return len(errors) == 0, errors
            
            if expires_at <= datetime.now(timezone.utc):
                errors.append("Session expiration must be in the future")
            
            # Check maximum session duration (24 hours)
            max_duration = datetime.now(timezone.utc).replace(hour=23, minute=59, second=59)
            if expires_at > max_duration:
                errors.append("Session duration cannot exceed 24 hours")
        
        return len(errors) == 0, errors
    
    def validate_audit_log_data(self, audit_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate audit log entry data.
        
        Args:
            audit_data: Audit log data to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate required fields
        required_fields = ['admin_email', 'action_type', 'ip_address', 'is_successful']
        for field in required_fields:
            if field not in audit_data:
                errors.append(f"{field} is required")
        
        # Validate action type
        valid_actions = [
            'create', 'read', 'update', 'delete', 'login', 'logout',
            'password_change', 'password_reset', 'enable_2fa', 'disable_2fa'
        ]
        if audit_data.get('action_type') not in valid_actions:
            errors.append(f"Invalid action type: {audit_data.get('action_type')}")
        
        # Validate risk level
        valid_risk_levels = ['low', 'medium', 'high', 'critical']
        if audit_data.get('risk_level') and audit_data['risk_level'] not in valid_risk_levels:
            errors.append(f"Invalid risk level: {audit_data.get('risk_level')}")
        
        # Validate processing time
        if audit_data.get('processing_time_ms'):
            try:
                processing_time = int(audit_data['processing_time_ms'])
                if processing_time < 0:
                    errors.append("Processing time cannot be negative")
                elif processing_time > 300000:  # 5 minutes
                    errors.append("Processing time seems unrealistic (>5 minutes)")
            except (ValueError, TypeError):
                errors.append("Invalid processing time format")
        
        return len(errors) == 0, errors
    
    def validate_name(self, name: str, field_name: str) -> Tuple[bool, str]:
        """
        Validate name fields (first_name, last_name, display_name).
        
        Args:
            name: Name to validate
            field_name: Field name for error messages
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not name or not name.strip():
            return False, f"{field_name} cannot be empty"
        
        name = name.strip()
        
        # Check length
        if len(name) < 1:
            return False, f"{field_name} is too short"
        if len(name) > 100:
            return False, f"{field_name} is too long (max 100 characters)"
        
        # Check for valid characters (letters, spaces, hyphens, apostrophes)
        if not re.match(r"^[a-zA-Z\s\-']+$", name):
            return False, f"{field_name} contains invalid characters"
        
        # Check for suspicious patterns
        if re.search(r'[<>{}[\]\\]', name):
            return False, f"{field_name} contains potentially dangerous characters"
        
        return True, ""
    
    # Private helper methods
    def _email_exists(self, email: str) -> bool:
        """Check if email already exists in database."""
        from app.models.admin import AdminUser
        return self.db.query(AdminUser).filter(
            AdminUser.email == email,
            AdminUser.deleted_at.is_(None)
        ).first() is not None
    
    def _permission_exists(self, permission: str) -> bool:
        """Check if permission is valid."""
        # This would typically check against a permissions registry
        valid_permissions = [
            '*', 'users:*', 'users:create', 'users:read', 'users:update', 'users:delete',
            'roles:*', 'roles:create', 'roles:read', 'roles:update', 'roles:delete',
            'system:*', 'system:config', 'system:maintenance',
            'monitoring:*', 'monitoring:read', 'monitoring:alerts',
            'reports:*', 'reports:read', 'reports:export'
        ]
        
        # Check exact match or wildcard match
        if permission in valid_permissions:
            return True
        
        # Check wildcard permissions
        for valid_perm in valid_permissions:
            if valid_perm.endswith(':*'):
                prefix = valid_perm[:-1]  # Remove '*'
                if permission.startswith(prefix):
                    return True
        
        return False
    
    def _get_permission_level(self, permission: str, 
                            permission_levels: Dict[str, int]) -> int:
        """Get required role level for permission."""
        # Check exact match first
        if permission in permission_levels:
            return permission_levels[permission]
        
        # Check wildcard matches
        for perm_pattern, level in permission_levels.items():
            if perm_pattern.endswith(':*'):
                prefix = perm_pattern[:-1]
                if permission.startswith(prefix):
                    return level
        
        # Default to highest level for unknown permissions
        return 10
    
    def _allow_private_ips(self) -> bool:
        """Check if private IPs are allowed (typically in development)."""
        import os
        return os.getenv('ENVIRONMENT', 'production').lower() in ['development', 'testing']
    
    def _allow_loopback_ips(self) -> bool:
        """Check if loopback IPs are allowed."""
        import os
        return os.getenv('ENVIRONMENT', 'production').lower() in ['development', 'testing']
    
    def _is_ip_blacklisted(self, ip_address: str) -> bool:
        """Check if IP is in blacklist."""
        # This would typically check against a database or external service
        blacklisted_ips = [
            '0.0.0.0',
            '255.255.255.255'
        ]
        return ip_address in blacklisted_ips
```

#### Usage Examples

```python
# Example 1: Validate user creation
from app.admin.utils.validators import AdminValidator

validator = AdminValidator(db_session)

# User creation data
user_data = {
    'email': 'newadmin@example.com',
    'password': 'SecureAdminPass123!',
    'first_name': 'Jane',
    'last_name': 'Smith',
    'role_id': 'admin-role-uuid'
}

is_valid, errors = validator.validate_user_creation(user_data)
if not is_valid:
    print("Validation failed:")
    for error in errors:
        print(f"  - {error}")
else:
    print("User data is valid!")

# Example 2: Validate password strength
password = "WeakPass"
is_valid, errors = validator.validate_password(password)
print(f"Password valid: {is_valid}")
print(f"Errors: {errors}")

# Example 3: Validate role assignment
role_id = "moderator-role-uuid"
assigner_level = 8  # Admin level
is_valid, error = validator.validate_role_assignment(role_id, assigner_level)
print(f"Role assignment valid: {is_valid}")
if not is_valid:
    print(f"Error: {error}")

# Example 4: Validate session data
session_data = {
    'admin_id': 'admin-123',
    'ip_address': '192.168.1.100',
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'expires_at': datetime.now(timezone.utc) + timedelta(hours=8)
}

is_valid, errors = validator.validate_session_data(session_data)
print(f"Session data valid: {is_valid}")
if errors:
    print("Errors:", errors)
```

### 3. AdminPermissionChecker

Handles role-based access control (RBAC) and permission verification.

#### Class Definition

```python
# app/admin/utils/permissions.py

from typing import Dict, List, Any, Optional, Set, Union
from functools import wraps
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
import json
import re

class PermissionDeniedError(Exception):
    """Exception raised when permission is denied."""
    
    def __init__(self, message: str, required_permission: str = None):
        self.message = message
        self.required_permission = required_permission
        super().__init__(message)

class AdminPermissionChecker:
    """
    Comprehensive permission checking utility for admin operations.
    
    Provides methods for checking permissions, validating access rights,
    and enforcing role-based access control with inheritance support.
    """
    
    def __init__(self, db_session: Session):
        """
        Initialize permission checker with database session.
        
        Args:
            db_session: SQLAlchemy database session
        """
        self.db = db_session
        self._permission_cache = {}
        self._role_cache = {}
    
    def check_permission(self, admin_id: str, required_permission: str, 
                        resource_id: str = None) -> bool:
        """
        Check if admin has required permission.
        
        Args:
            admin_id: Admin user ID
            required_permission: Permission to check (e.g., 'users:update')
            resource_id: Optional resource ID for resource-specific permissions
            
        Returns:
            True if permission granted, False otherwise
            
        Example:
            >>> checker = AdminPermissionChecker(db_session)
            >>> has_permission = checker.check_permission(
            ...     admin_id='admin-123',
            ...     required_permission='users:update'
            ... )
            >>> if has_permission:
            ...     print("Permission granted")
        """
        try:
            # Get admin user with role
            admin = self._get_admin_with_role(admin_id)
            if not admin:
                return False
            
            # Check if admin is active
            if not admin.is_active or admin.deleted_at:
                return False
            
            # Check if role is active
            if not admin.role.is_active:
                return False
            
            # Get all permissions for the admin (including inherited)
            permissions = self._get_admin_permissions(admin)
            
            # Check permission
            return self._has_permission(permissions, required_permission, resource_id)
            
        except Exception:
            # Log error and deny permission on any exception
            return False
    
    def require_permission(self, required_permission: str, 
                          resource_id: str = None):
        """
        Decorator to require specific permission for endpoint access.
        
        Args:
            required_permission: Permission required to access the endpoint
            resource_id: Optional resource ID for resource-specific permissions
            
        Returns:
            Decorator function
            
        Example:
            >>> @require_permission('users:delete')
            ... async def delete_user(user_id: str, current_admin: AdminUser = Depends(get_current_admin)):
            ...     # Delete user logic here
            ...     pass
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract current admin from kwargs (injected by dependency)
                current_admin = kwargs.get('current_admin')
                if not current_admin:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                # Check permission
                has_permission = self.check_permission(
                    admin_id=current_admin.id,
                    required_permission=required_permission,
                    resource_id=resource_id
                )
                
                if not has_permission:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Permission denied: {required_permission}"
                    )
                
                return await func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    def check_multiple_permissions(self, admin_id: str, 
                                 permissions: List[str],
                                 require_all: bool = True) -> Dict[str, bool]:
        """
        Check multiple permissions at once.
        
        Args:
            admin_id: Admin user ID
            permissions: List of permissions to check
            require_all: If True, all permissions must be granted
            
        Returns:
            Dictionary mapping permission to boolean result
            
        Example:
            >>> permissions_to_check = ['users:read', 'users:update', 'users:delete']
            >>> results = checker.check_multiple_permissions(
            ...     admin_id='admin-123',
            ...     permissions=permissions_to_check,
            ...     require_all=False
            ... )
            >>> print(results)
            {'users:read': True, 'users:update': True, 'users:delete': False}
        """
        results = {}
        
        for permission in permissions:
            results[permission] = self.check_permission(admin_id, permission)
        
        return results
    
    def get_admin_permissions(self, admin_id: str) -> List[str]:
        """
        Get all permissions for an admin user.
        
        Args:
            admin_id: Admin user ID
            
        Returns:
            List of permission strings
        """
        admin = self._get_admin_with_role(admin_id)
        if not admin:
            return []
        
        return self._get_admin_permissions(admin)
    
    def can_assign_role(self, assigner_id: str, target_role_id: str) -> bool:
        """
        Check if an admin can assign a specific role to another user.
        
        Args:
            assigner_id: ID of admin attempting to assign role
            target_role_id: ID of role to be assigned
            
        Returns:
            True if role assignment is allowed
        """
        # Get assigner's role level
        assigner = self._get_admin_with_role(assigner_id)
        if not assigner:
            return False
        
        # Get target role
        target_role = self._get_role(target_role_id)
        if not target_role:
            return False
        
        # Check role hierarchy - can only assign roles with lower level
        if target_role.role_level >= assigner.role.role_level:
            return False
        
        # Check if assigner has role management permission
        return self.check_permission(assigner_id, 'roles:assign')
    
    def can_access_resource(self, admin_id: str, resource_type: str, 
                          resource_id: str, action: str) -> bool:
        """
        Check if admin can perform action on specific resource.
        
        Args:
            admin_id: Admin user ID
            resource_type: Type of resource (user, role, etc.)
            resource_id: Specific resource ID
            action: Action to perform (read, update, delete)
            
        Returns:
            True if access is allowed
        """
        # Build permission string
        permission = f"{resource_type}:{action}"
        
        # Check basic permission
        if not self.check_permission(admin_id, permission, resource_id):
            return False
        
        # Additional resource-specific checks
        if resource_type == 'user':
            return self._can_access_user(admin_id, resource_id, action)
        elif resource_type == 'role':
            return self._can_access_role(admin_id, resource_id, action)
        
        return True
    
    def get_accessible_resources(self, admin_id: str, 
                               resource_type: str) -> List[str]:
        """
        Get list of resource IDs that admin can access.
        
        Args:
            admin_id: Admin user ID
            resource_type: Type of resource to check
            
        Returns:
            List of accessible resource IDs
        """
        admin = self._get_admin_with_role(admin_id)
        if not admin:
            return []
        
        if resource_type == 'user':
            return self._get_accessible_users(admin)
        elif resource_type == 'role':
            return self._get_accessible_roles(admin)
        
        return []
    
    def validate_permission_hierarchy(self, admin_id: str, 
                                    permissions: List[str]) -> Tuple[bool, List[str]]:
        """
        Validate that admin can grant specific permissions.
        
        Args:
            admin_id: Admin user ID attempting to grant permissions
            permissions: List of permissions to validate
            
        Returns:
            Tuple of (is_valid, list_of_invalid_permissions)
        """
        admin = self._get_admin_with_role(admin_id)
        if not admin:
            return False, permissions
        
        admin_permissions = self._get_admin_permissions(admin)
        invalid_permissions = []
        
        for permission in permissions:
            if not self._can_grant_permission(admin_permissions, permission):
                invalid_permissions.append(permission)
        
        return len(invalid_permissions) == 0, invalid_permissions
    
    # Private helper methods
    def _get_admin_with_role(self, admin_id: str):
        """Get admin user with role information."""
        cache_key = f"admin_role_{admin_id}"
        
        if cache_key in self._role_cache:
            return self._role_cache[cache_key]
        
        from app.models.admin import AdminUser, AdminRole
        
        admin = self.db.query(AdminUser).join(AdminRole).filter(
            AdminUser.id == admin_id,
            AdminUser.deleted_at.is_(None)
        ).first()
        
        # Cache for 5 minutes
        self._role_cache[cache_key] = admin
        
        return admin
    
    def _get_role(self, role_id: str):
        """Get role by ID."""
        from app.models.admin import AdminRole
        
        return self.db.query(AdminRole).filter(
            AdminRole.id == role_id,
            AdminRole.is_active == True
        ).first()
    
    def _get_admin_permissions(self, admin) -> List[str]:
        """Get all permissions for admin including inherited permissions."""
        cache_key = f"permissions_{admin.id}_{admin.role.id}"
        
        if cache_key in self._permission_cache:
            return self._permission_cache[cache_key]
        
        permissions = set()
        
        # Get direct role permissions
        role_permissions = admin.role.permissions
        if isinstance(role_permissions, str):
            role_permissions = json.loads(role_permissions)
        
        permissions.update(role_permissions)
        
        # Get inherited permissions from parent roles
        parent_role = admin.role.parent_role
        while parent_role:
            parent_permissions = parent_role.permissions
            if isinstance(parent_permissions, str):
                parent_permissions = json.loads(parent_permissions)
            
            permissions.update(parent_permissions)
            parent_role = parent_role.parent_role
        
        permissions_list = list(permissions)
        
        # Cache for 5 minutes
        self._permission_cache[cache_key] = permissions_list
        
        return permissions_list
    
    def _has_permission(self, user_permissions: List[str], 
                       required_permission: str, resource_id: str = None) -> bool:
        """Check if user permissions include required permission."""
        # Check for wildcard permission
        if '*' in user_permissions:
            return True
        
        # Check for exact permission match
        if required_permission in user_permissions:
            return True
        
        # Check for wildcard category permissions
        permission_parts = required_permission.split(':')
        if len(permission_parts) >= 2:
            category = permission_parts[0]
            wildcard_permission = f"{category}:*"
            if wildcard_permission in user_permissions:
                return True
        
        # Check for resource-specific permissions
        if resource_id:
            resource_permission = f"{required_permission}:{resource_id}"
            if resource_permission in user_permissions:
                return True
        
        return False
    
    def _can_access_user(self, admin_id: str, target_user_id: str, action: str) -> bool:
        """Check if admin can access specific user."""
        # Admins cannot perform actions on themselves for certain operations
        if admin_id == target_user_id and action in ['delete', 'lock']:
            return False
        
        # Get target user's role level
        target_user = self._get_admin_with_role(target_user_id)
        if not target_user:
            return True  # User doesn't exist, allow action
        
        # Get current admin's role level
        current_admin = self._get_admin_with_role(admin_id)
        if not current_admin:
            return False
        
        # Can only manage users with lower role level
        return current_admin.role.role_level > target_user.role.role_level
    
    def _can_access_role(self, admin_id: str, role_id: str, action: str) -> bool:
        """Check if admin can access specific role."""
        role = self._get_role(role_id)
        if not role:
            return True  # Role doesn't exist, allow action
        
        admin = self._get_admin_with_role(admin_id)
        if not admin:
            return False
        
        # Cannot modify system roles unless super admin
        if role.is_system_role and admin.role.role_level < 10:
            return False
        
        # Can only manage roles with lower level
        return admin.role.role_level > role.role_level
    
    def _get_accessible_users(self, admin) -> List[str]:
        """Get list of user IDs that admin can access."""
        from app.models.admin import AdminUser
        
        # Get users with lower role level
        accessible_users = self.db.query(AdminUser.id).join(AdminRole).filter(
            AdminRole.role_level < admin.role.role_level,
            AdminUser.deleted_at.is_(None)
        ).all()
        
        return [user.id for user in accessible_users]
    
    def _get_accessible_roles(self, admin) -> List[str]:
        """Get list of role IDs that admin can access."""
        from app.models.admin import AdminRole
        
        # Get roles with lower level
        accessible_roles = self.db.query(AdminRole.id).filter(
            AdminRole.role_level < admin.role.role_level,
            AdminRole.is_active == True
        ).all()
        
        return [role.id for role in accessible_roles]
    
    def _can_grant_permission(self, admin_permissions: List[str], 
                            permission_to_grant: str) -> bool:
        """Check if admin can grant a specific permission."""
        # Must have the permission to grant it
        if not self._has_permission(admin_permissions, permission_to_grant):
            return False
        
        # Additional checks for sensitive permissions
        sensitive_permissions = ['*', 'system:*', 'roles:*']
        if permission_to_grant in sensitive_permissions:
            return '*' in admin_permissions
        
        return True
```

#### Usage Examples

```python
# Example 1: Basic permission checking
from app.admin.utils.permissions import AdminPermissionChecker

checker = AdminPermissionChecker(db_session)

# Check if admin can update users
admin_id = "admin-123"
can_update_users = checker.check_permission(admin_id, "users:update")
print(f"Can update users: {can_update_users}")

# Example 2: Using permission decorator
@checker.require_permission('users:delete')
async def delete_user_endpoint(
    user_id: str,
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Delete user endpoint with permission check."""
    # This function will only execute if admin has 'users:delete' permission
    await delete_user_service(user_id)
    return {"message": "User deleted successfully"}

# Example 3: Check multiple permissions
permissions_to_check = [
    'users:read',
    'users:update', 
    'users:delete',
    'roles:assign'
]

results = checker.check_multiple_permissions(
    admin_id="admin-123",
    permissions=permissions_to_check,
    require_all=False
)

print("Permission results:")
for permission, granted in results.items():
    status = "✓" if granted else "✗"
    print(f"  {status} {permission}")

# Example 4: Resource-specific access control
user_id_to_modify = "user-456"
can_modify_user = checker.can_access_resource(
    admin_id="admin-123",
    resource_type="user",
    resource_id=user_id_to_modify,
    action="update"
)

if can_modify_user:
    print("Admin can modify this user")
else:
    print("Admin cannot modify this user (insufficient privileges)")

# Example 5: Role assignment validation
assigner_id = "admin-123"
target_role_id = "moderator-role"

can_assign = checker.can_assign_role(assigner_id, target_role_id)
if can_assign:
    print("Role assignment allowed")
else:
    print("Role assignment denied - insufficient privileges")
```

### 4. AdminSessionManager

Manages admin sessions, tokens, and authentication state.

#### Class Definition

```python
# app/admin/utils/sessions.py

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
import secrets
import hashlib
import json
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
import redis
from jose import JWTError, jwt
from passlib.context import CryptContext

class SessionError(Exception):
    """Exception raised for session-related errors."""
    
    def __init__(self, message: str, code: str = None):
        self.message = message
        self.code = code
        super().__init__(message)

class AdminSessionManager:
    """
    Comprehensive session management utility for admin operations.
    
    Handles session creation, validation, cleanup, and security features
    like concurrent session limits and suspicious activity detection.
    """
    
    def __init__(self, db_session: Session, redis_client: redis.Redis = None):
        """
        Initialize session manager.
        
        Args:
            db_session: SQLAlchemy database session
            redis_client: Redis client for session caching
        """
        self.db = db_session
        self.redis = redis_client
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Session configuration
        self.session_config = {
            'default_duration': timedelta(hours=8),
            'max_duration': timedelta(hours=24),
            'max_concurrent_sessions': 3,
            'cleanup_interval': timedelta(hours=1),
            'token_length': 32
        }
        
        # JWT configuration
        self.jwt_config = {
            'secret_key': self._get_jwt_secret(),
            'algorithm': 'HS256',
            'access_token_expire': timedelta(minutes=30),
            'refresh_token_expire': timedelta(days=7)
        }
    
    def create_session(self, admin_id: str, ip_address: str, 
                      user_agent: str, remember_me: bool = False) -> Dict[str, Any]:
        """
        Create new admin session with security checks.
        
        Args:
            admin_id: Admin user ID
            ip_address: Client IP address
            user_agent: Client user agent string
            remember_me: Whether to extend session duration
            
        Returns:
            Dictionary containing session data and tokens
            
        Example:
            >>> session_manager = AdminSessionManager(db_session, redis_client)
            >>> session_data = session_manager.create_session(
            ...     admin_id='admin-123',
            ...     ip_address='192.168.1.100',
            ...     user_agent='Mozilla/5.0...',
            ...     remember_me=True
            ... )
            >>> print(session_data['access_token'])
        """
        from app.models.admin import AdminUser, AdminSession
        
        # Validate admin exists and is active
        admin = self.db.query(AdminUser).filter(
            AdminUser.id == admin_id,
            AdminUser.is_active == True,
            AdminUser.deleted_at.is_(None)
        ).first()
        
        if not admin:
            raise SessionError("Admin user not found or inactive", "ADMIN_NOT_FOUND")
        
        # Check concurrent session limit
        self._enforce_session_limit(admin_id)
        
        # Generate session tokens
        session_token = self._generate_session_token()
        refresh_token = self._generate_refresh_token()
        
        # Calculate expiration times
        if remember_me:
            expires_at = datetime.now(timezone.utc) + self.session_config['max_duration']
        else:
            expires_at = datetime.now(timezone.utc) + self.session_config['default_duration']
        
        # Create session record
        session = AdminSession(
            id=self._generate_session_id(),
            admin_id=admin_id,
            session_token=self._hash_token(session_token),
            refresh_token=self._hash_token(refresh_token),
            ip_address=ip_address,
            user_agent=user_agent[:1000],  # Truncate long user agents
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc),
            is_active=True
        )
        
        self.db.add(session)
        self.db.commit()
        
        # Generate JWT tokens
        access_token = self._create_access_token(admin_id, session.id)
        jwt_refresh_token = self._create_refresh_token(admin_id, session.id)
        
        # Cache session in Redis for fast lookup
        if self.redis:
            self._cache_session(session, session_token)
        
        # Update admin's last login
        admin.last_login = datetime.now(timezone.utc)
        admin.login_count = (admin.login_count or 0) + 1
        self.db.commit()
        
        return {
            'session_id': session.id,
            'access_token': access_token,
            'refresh_token': jwt_refresh_token,
            'session_token': session_token,
            'expires_at': expires_at.isoformat(),
            'admin_id': admin_id,
            'admin_email': admin.email
        }
    
    def validate_session(self, session_token: str, 
                        ip_address: str = None) -> Optional[Dict[str, Any]]:
        """
        Validate session token and return session data.
        
        Args:
            session_token: Session token to validate
            ip_address: Optional IP address for additional security
            
        Returns:
            Session data if valid, None otherwise
        """
        try:
            # Check Redis cache first
            if self.redis:
                cached_session = self._get_cached_session(session_token)
                if cached_session:
                    return cached_session
            
            # Query database
            from app.models.admin import AdminSession, AdminUser
            
            session = self.db.query(AdminSession).join(AdminUser).filter(
                AdminSession.session_token == self._hash_token(session_token),
                AdminSession.is_active == True,
                AdminSession.expires_at > datetime.now(timezone.utc),
                AdminUser.is_active == True,
                AdminUser.deleted_at.is_(None)
            ).first()
            
            if not session:
                return None
            
            # Additional IP validation if provided
            if ip_address and session.ip_address != ip_address:
                # Log suspicious activity
                self._log_suspicious_activity(session.admin_id, ip_address, 
                                            "IP address mismatch")
                return None
            
            # Update last activity
            session.last_activity = datetime.now(timezone.utc)
            self.db.commit()
            
            # Return session data
            session_data = {
                'session_id': session.id,
                'admin_id': session.admin_id,
                'admin_email': session.admin.email,
                'role_id': session.admin.role_id,
                'role_name': session.admin.role.name,
                'permissions': json.loads(session.admin.role.permissions),
                'expires_at': session.expires_at.isoformat(),
                'last_activity': session.last_activity.isoformat()
            }
            
            # Update cache
            if self.redis:
                self._cache_session_data(session_token, session_data)
            
            return session_data
            
        except Exception as e:
            # Log error and return None
            print(f"Session validation error: {e}")
            return None
    
    def refresh_session(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh session using refresh token.
        
        Args:
            refresh_token: JWT refresh token
            
        Returns:
            New session data with updated tokens
        """
        try:
            # Decode refresh token
            payload = jwt.decode(
                refresh_token,
                self.jwt_config['secret_key'],
                algorithms=[self.jwt_config['algorithm']]
            )
            
            admin_id = payload.get('admin_id')
            session_id = payload.get('session_id')
            
            if not admin_id or not session_id:
                return None
            
            # Validate session exists and is active
            from app.models.admin import AdminSession
            
            session = self.db.query(AdminSession).filter(
                AdminSession.id == session_id,
                AdminSession.admin_id == admin_id,
                AdminSession.is_active == True,
                AdminSession.expires_at > datetime.now(timezone.utc)
            ).first()
            
            if not session:
                return None
            
            # Generate new tokens
            new_access_token = self._create_access_token(admin_id, session_id)
            new_refresh_token = self._create_refresh_token(admin_id, session_id)
            
            # Update session activity
            session.last_activity = datetime.now(timezone.utc)
            self.db.commit()
            
            return {
                'access_token': new_access_token,
                'refresh_token': new_refresh_token,
                'expires_at': session.expires_at.isoformat()
            }
            
        except JWTError:
            return None
    
    def terminate_session(self, session_id: str, admin_id: str = None) -> bool:
        """
        Terminate specific session.
        
        Args:
            session_id: Session ID to terminate
            admin_id: Optional admin ID for additional validation
            
        Returns:
            True if session was terminated
        """
        from app.models.admin import AdminSession
        
        query = self.db.query(AdminSession).filter(AdminSession.id == session_id)
        
        if admin_id:
            query = query.filter(AdminSession.admin_id == admin_id)
        
        session = query.first()
        
        if session:
            session.is_active = False
            session.terminated_at = datetime.now(timezone.utc)
            self.db.commit()
            
            # Remove from cache
            if self.redis:
                self._remove_cached_session(session_id)
            
            return True
        
        return False
    
    def terminate_all_sessions(self, admin_id: str, 
                             except_session_id: str = None) -> int:
        """
        Terminate all sessions for an admin.
        
        Args:
            admin_id: Admin ID whose sessions to terminate
            except_session_id: Optional session ID to keep active
            
        Returns:
            Number of sessions terminated
        """
        from app.models.admin import AdminSession
        
        query = self.db.query(AdminSession).filter(
            AdminSession.admin_id == admin_id,
            AdminSession.is_active == True
        )
        
        if except_session_id:
            query = query.filter(AdminSession.id != except_session_id)
        
        sessions = query.all()
        terminated_count = 0
        
        for session in sessions:
            session.is_active = False
            session.terminated_at = datetime.now(timezone.utc)
            terminated_count += 1
            
            # Remove from cache
            if self.redis:
                self._remove_cached_session(session.id)
        
        self.db.commit()
        return terminated_count
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from database and cache.
        
        Returns:
            Number of sessions cleaned up
        """
        from app.models.admin import AdminSession
        
        # Find expired sessions
        expired_sessions = self.db.query(AdminSession).filter(
            or_(
                AdminSession.expires_at < datetime.now(timezone.utc),
                and_(
                    AdminSession.is_active == True,
                    AdminSession.last_activity < datetime.now(timezone.utc) - timedelta(days=30)
                )
            )
        ).all()
        
        cleanup_count = 0
        
        for session in expired_sessions:
            if session.is_active:
                session.is_active = False
                session.terminated_at = datetime.now(timezone.utc)
            
            # Remove from cache
            if self.redis:
                self._remove_cached_session(session.id)
            
            cleanup_count += 1
        
        self.db.commit()
        return cleanup_count
    
    def get_active_sessions(self, admin_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for an admin.
        
        Args:
            admin_id: Admin ID to get sessions for
            
        Returns:
            List of active session data
        """
        from app.models.admin import AdminSession
        
        sessions = self.db.query(AdminSession).filter(
            AdminSession.admin_id == admin_id,
            AdminSession.is_active == True,
            AdminSession.expires_at > datetime.now(timezone.utc)
        ).order_by(AdminSession.last_activity.desc()).all()
        
        session_list = []
        
        for session in sessions:
            session_data = {
                'session_id': session.id,
                'ip_address': session.ip_address,
                'user_agent': self._parse_user_agent(session.user_agent),
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'expires_at': session.expires_at.isoformat(),
                'is_current': False  # Will be set by caller if needed
            }
            session_list.append(session_data)
        
        return session_list
    
    # Private helper methods
    def _generate_session_token(self) -> str:
        """Generate secure session token."""
        return secrets.token_urlsafe(self.session_config['token_length'])
    
    def _generate_refresh_token(self) -> str:
        """Generate secure refresh token."""
        return secrets.token_urlsafe(self.session_config['token_length'])
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        return f"session_{secrets.token_hex(16)}"
    
    def _hash_token(self, token: str) -> str:
        """Hash token for secure storage."""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _get_jwt_secret(self) -> str:
        """Get JWT secret key from environment."""
        import os
        return os.getenv('JWT_SECRET_KEY', 'default-secret-key-change-in-production')
    
    def _create_access_token(self, admin_id: str, session_id: str) -> str:
        """Create JWT access token."""
        expire = datetime.now(timezone.utc) + self.jwt_config['access_token_expire']
        
        payload = {
            'admin_id': admin_id,
            'session_id': session_id,
            'exp': expire,
            'iat': datetime.now(timezone.utc),
            'type': 'access'
        }
        
        return jwt.encode(
            payload,
            self.jwt_config['secret_key'],
            algorithm=self.jwt_config['algorithm']
        )
    
    def _create_refresh_token(self, admin_id: str, session_id: str) -> str:
        """Create JWT refresh token."""
        expire = datetime.now(timezone.utc) + self.jwt_config['refresh_token_expire']
        
        payload = {
            'admin_id': admin_id,
            'session_id': session_id,
            'exp': expire,
            'iat': datetime.now(timezone.utc),
            'type': 'refresh'
        }
        
        return jwt.encode(
            payload,
            self.jwt_config['secret_key'],
            algorithm=self.jwt_config['algorithm']
        )
    
    def _enforce_session_limit(self, admin_id: str):
        """Enforce maximum concurrent sessions limit."""
        from app.models.admin import AdminSession
        
        active_sessions = self.db.query(AdminSession).filter(
            AdminSession.admin_id == admin_id,
            AdminSession.is_active == True,
            AdminSession.expires_at > datetime.now(timezone.utc)
        ).count()
        
        if active_sessions >= self.session_config['max_concurrent_sessions']:
            # Terminate oldest session
            oldest_session = self.db.query(AdminSession).filter(
                AdminSession.admin_id == admin_id,
                AdminSession.is_active == True
            ).order_by(AdminSession.last_activity.asc()).first()
            
            if oldest_session:
                self.terminate_session(oldest_session.id)
    
    def _cache_session(self, session, session_token: str):
        """Cache session data in Redis."""
        cache_key = f"admin_session:{self._hash_token(session_token)}"
        session_data = {
            'session_id': session.id,
            'admin_id': session.admin_id,
            'expires_at': session.expires_at.isoformat()
        }
        
        # Cache for session duration
        ttl = int((session.expires_at - datetime.now(timezone.utc)).total_seconds())
        self.redis.setex(cache_key, ttl, json.dumps(session_data))
    
    def _get_cached_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Get session data from Redis cache."""
        cache_key = f"admin_session:{self._hash_token(session_token)}"
        cached_data = self.redis.get(cache_key)
        
        if cached_data:
            return json.loads(cached_data)
        
        return None
    
    def _cache_session_data(self, session_token: str, session_data: Dict[str, Any]):
        """Cache detailed session data."""
        cache_key = f"admin_session_data:{self._hash_token(session_token)}"
        
        # Cache for 5 minutes
        self.redis.setex(cache_key, 300, json.dumps(session_data, default=str))
    
    def _remove_cached_session(self, session_id: str):
        """Remove session from cache."""
        # Remove all cache entries for this session
        pattern = f"admin_session*:{session_id}"
        keys = self.redis.keys(pattern)
        
        if keys:
            self.redis.delete(*keys)
    
    def _log_suspicious_activity(self, admin_id: str, ip_address: str, reason: str):
        """Log suspicious session activity."""
        from app.models.admin import AdminAuditLog
        
        audit_log = AdminAuditLog(
            admin_id=admin_id,
            action_type='suspicious_session',
            resource_type='session',
            ip_address=ip_address,
            is_successful=False,
            risk_level='high',
            additional_data=json.dumps({'reason': reason}),
            timestamp=datetime.now(timezone.utc)
        )
        
        self.db.add(audit_log)
        self.db.commit()
    
    def _parse_user_agent(self, user_agent: str) -> Dict[str, str]:
        """Parse user agent string for display."""
        if not user_agent:
            return {'browser': 'Unknown', 'os': 'Unknown'}
        
        # Simple user agent parsing (in production, use a proper library)
        browser = 'Unknown'
        os = 'Unknown'
        
        if 'Chrome' in user_agent:
            browser = 'Chrome'
        elif 'Firefox' in user_agent:
            browser = 'Firefox'
        elif 'Safari' in user_agent:
            browser = 'Safari'
        elif 'Edge' in user_agent:
            browser = 'Edge'
        
        if 'Windows' in user_agent:
            os = 'Windows'
        elif 'Mac' in user_agent:
            os = 'macOS'
        elif 'Linux' in user_agent:
            os = 'Linux'
        elif 'Android' in user_agent:
            os = 'Android'
        elif 'iOS' in user_agent:
            os = 'iOS'
        
        return {'browser': browser, 'os': os}
```

#### Usage Examples

```python
# Example 1: Create admin session
from app.admin.utils.sessions import AdminSessionManager

session_manager = AdminSessionManager(db_session, redis_client)

# Create session for admin login
session_data = session_manager.create_session(
    admin_id='admin-123',
    ip_address='192.168.1.100',
    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    remember_me=True
)

print(f"Session created: {session_data['session_id']}")
print(f"Access token: {session_data['access_token']}")

# Example 2: Validate session
session_token = session_data['session_token']
validated_session = session_manager.validate_session(
    session_token=session_token,
    ip_address='192.168.1.100'
)

if validated_session:
    print(f"Session valid for admin: {validated_session['admin_email']}")
else:
    print("Session invalid or expired")

# Example 3: Refresh tokens
refresh_token = session_data['refresh_token']
refreshed_tokens = session_manager.refresh_session(refresh_token)

if refreshed_tokens:
    print(f"New access token: {refreshed_tokens['access_token']}")
else:
    print("Token refresh failed")

# Example 4: Get active sessions
active_sessions = session_manager.get_active_sessions('admin-123')
print(f"Active sessions: {len(active_sessions)}")

for session in active_sessions:
    print(f"  Session: {session['session_id']}")
    print(f"  IP: {session['ip_address']}")
    print(f"  Browser: {session['user_agent']['browser']}")
    print(f"  Last activity: {session['last_activity']}")

# Example 5: Terminate sessions
# Terminate specific session
terminated = session_manager.terminate_session(session_data['session_id'])
print(f"Session terminated: {terminated}")

# Terminate all sessions except current
terminated_count = session_manager.terminate_all_sessions(
    admin_id='admin-123',
    except_session_id='current-session-id'
)
print(f"Terminated {terminated_count} sessions")

# Example 6: Cleanup expired sessions (run periodically)
cleaned_up = session_manager.cleanup_expired_sessions()
print(f"Cleaned up {cleaned_up} expired sessions")
```

---

### 5. AdminAuditLogger

The `AdminAuditLogger` class provides comprehensive audit logging functionality for admin operations, ensuring compliance and security monitoring.

```python
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
import json
import hashlib
import ipaddress
from enum import Enum

class AuditActionType(Enum):
    """Enumeration of audit action types."""
    LOGIN = "login"
    LOGOUT = "logout"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    VIEW = "view"
    EXPORT = "export"
    IMPORT = "import"
    CONFIG_CHANGE = "config_change"
    PERMISSION_CHANGE = "permission_change"
    SYSTEM_ACTION = "system_action"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

class RiskLevel(Enum):
    """Enumeration of risk levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AdminAuditLogger:
    """
    Comprehensive audit logging system for admin operations.
    
    Provides secure, compliant audit logging with data sanitization,
    risk assessment, and flexible querying capabilities.
    """
    
    def __init__(self, db_session: Session, admin_id: str = None):
        """
        Initialize audit logger.
        
        Args:
            db_session: SQLAlchemy database session
            admin_id: Current admin user ID for context
        """
        self.db = db_session
        self.admin_id = admin_id
        
        # Sensitive data patterns to sanitize
        self.sensitive_patterns = [
            r'password',
            r'token',
            r'secret',
            r'key',
            r'auth',
            r'credential',
            r'ssn',
            r'social_security',
            r'credit_card',
            r'card_number'
        ]
        
        # High-risk actions that require special attention
        self.high_risk_actions = {
            AuditActionType.DELETE.value,
            AuditActionType.PERMISSION_CHANGE.value,
            AuditActionType.CONFIG_CHANGE.value,
            AuditActionType.EXPORT.value
        }
    
    def log_action(self, action_type: str, resource_type: str, 
                   resource_id: str = None, is_successful: bool = True,
                   ip_address: str = None, user_agent: str = None,
                   additional_data: Dict[str, Any] = None,
                   risk_level: str = None) -> str:
        """
        Log an admin action with comprehensive details.
        
        Args:
            action_type: Type of action performed
            resource_type: Type of resource affected
            resource_id: ID of the specific resource
            is_successful: Whether the action was successful
            ip_address: Client IP address
            user_agent: Client user agent
            additional_data: Additional context data
            risk_level: Manual risk level override
            
        Returns:
            Audit log entry ID
            
        Example:
            >>> logger = AdminAuditLogger(db_session, admin_id='admin-123')
            >>> log_id = logger.log_action(
            ...     action_type='delete',
            ...     resource_type='user',
            ...     resource_id='user-456',
            ...     is_successful=True,
            ...     ip_address='192.168.1.100',
            ...     additional_data={'reason': 'Account violation'}
            ... )
            >>> print(f"Logged action: {log_id}")
        """
        from app.models.admin import AdminAuditLog
        
        # Sanitize additional data
        sanitized_data = self._sanitize_data(additional_data or {})
        
        # Assess risk level if not provided
        if not risk_level:
            risk_level = self._assess_risk_level(action_type, resource_type, 
                                               is_successful, sanitized_data)
        
        # Create audit log entry
        audit_log = AdminAuditLog(
            id=self._generate_log_id(),
            admin_id=self.admin_id,
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            is_successful=is_successful,
            ip_address=ip_address,
            user_agent=user_agent[:1000] if user_agent else None,
            risk_level=risk_level,
            additional_data=json.dumps(sanitized_data) if sanitized_data else None,
            timestamp=datetime.now(timezone.utc)
        )
        
        self.db.add(audit_log)
        self.db.commit()
        
        # Trigger alerts for high-risk actions
        if risk_level in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]:
            self._trigger_security_alert(audit_log)
        
        return audit_log.id
    
    def log_login_attempt(self, email: str, is_successful: bool,
                         ip_address: str, user_agent: str,
                         failure_reason: str = None) -> str:
        """
        Log admin login attempt with security context.
        
        Args:
            email: Admin email address
            is_successful: Whether login was successful
            ip_address: Client IP address
            user_agent: Client user agent
            failure_reason: Reason for login failure
            
        Returns:
            Audit log entry ID
        """
        additional_data = {
            'email': email,
            'ip_location': self._get_ip_location(ip_address),
            'is_suspicious_ip': self._is_suspicious_ip(ip_address)
        }
        
        if not is_successful and failure_reason:
            additional_data['failure_reason'] = failure_reason
        
        # Determine risk level based on login context
        risk_level = RiskLevel.LOW.value
        if not is_successful:
            risk_level = RiskLevel.MEDIUM.value
        if additional_data.get('is_suspicious_ip'):
            risk_level = RiskLevel.HIGH.value
        
        return self.log_action(
            action_type=AuditActionType.LOGIN.value,
            resource_type='authentication',
            is_successful=is_successful,
            ip_address=ip_address,
            user_agent=user_agent,
            additional_data=additional_data,
            risk_level=risk_level
        )
    
    def log_data_export(self, export_type: str, record_count: int,
                       filters: Dict[str, Any] = None,
                       ip_address: str = None) -> str:
        """
        Log data export operations with detailed context.
        
        Args:
            export_type: Type of data being exported
            record_count: Number of records exported
            filters: Export filters applied
            ip_address: Client IP address
            
        Returns:
            Audit log entry ID
        """
        additional_data = {
            'export_type': export_type,
            'record_count': record_count,
            'filters': self._sanitize_data(filters or {}),
            'export_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Data exports are inherently high-risk
        risk_level = RiskLevel.HIGH.value
        if record_count > 10000:  # Large exports are critical risk
            risk_level = RiskLevel.CRITICAL.value
        
        return self.log_action(
            action_type=AuditActionType.EXPORT.value,
            resource_type='data',
            is_successful=True,
            ip_address=ip_address,
            additional_data=additional_data,
            risk_level=risk_level
        )
    
    def log_configuration_change(self, config_key: str, old_value: Any,
                               new_value: Any, ip_address: str = None) -> str:
        """
        Log system configuration changes.
        
        Args:
            config_key: Configuration key that was changed
            old_value: Previous configuration value
            new_value: New configuration value
            ip_address: Client IP address
            
        Returns:
            Audit log entry ID
        """
        additional_data = {
            'config_key': config_key,
            'old_value': self._sanitize_value(old_value),
            'new_value': self._sanitize_value(new_value),
            'change_type': self._determine_change_type(old_value, new_value)
        }
        
        return self.log_action(
            action_type=AuditActionType.CONFIG_CHANGE.value,
            resource_type='configuration',
            resource_id=config_key,
            is_successful=True,
            ip_address=ip_address,
            additional_data=additional_data,
            risk_level=RiskLevel.HIGH.value
        )
    
    def log_permission_change(self, target_admin_id: str, permission_changes: List[Dict],
                            ip_address: str = None) -> str:
        """
        Log admin permission changes.
        
        Args:
            target_admin_id: ID of admin whose permissions changed
            permission_changes: List of permission changes
            ip_address: Client IP address
            
        Returns:
            Audit log entry ID
        """
        additional_data = {
            'target_admin_id': target_admin_id,
            'permission_changes': permission_changes,
            'change_count': len(permission_changes)
        }
        
        return self.log_action(
            action_type=AuditActionType.PERMISSION_CHANGE.value,
            resource_type='admin_permissions',
            resource_id=target_admin_id,
            is_successful=True,
            ip_address=ip_address,
            additional_data=additional_data,
            risk_level=RiskLevel.HIGH.value
        )
    
    def log_suspicious_activity(self, activity_type: str, details: Dict[str, Any],
                              ip_address: str = None) -> str:
        """
        Log suspicious activity detected by security monitoring.
        
        Args:
            activity_type: Type of suspicious activity
            details: Detailed information about the activity
            ip_address: Source IP address
            
        Returns:
            Audit log entry ID
        """
        additional_data = {
            'activity_type': activity_type,
            'detection_timestamp': datetime.now(timezone.utc).isoformat(),
            'details': self._sanitize_data(details)
        }
        
        return self.log_action(
            action_type=AuditActionType.SUSPICIOUS_ACTIVITY.value,
            resource_type='security',
            is_successful=False,
            ip_address=ip_address,
            additional_data=additional_data,
            risk_level=RiskLevel.CRITICAL.value
        )
    
    def get_audit_trail(self, admin_id: str = None, action_type: str = None,
                       resource_type: str = None, start_date: datetime = None,
                       end_date: datetime = None, risk_level: str = None,
                       limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieve audit trail with flexible filtering.
        
        Args:
            admin_id: Filter by admin ID
            action_type: Filter by action type
            resource_type: Filter by resource type
            start_date: Filter by start date
            end_date: Filter by end date
            risk_level: Filter by risk level
            limit: Maximum number of records
            offset: Number of records to skip
            
        Returns:
            List of audit log entries
        """
        from app.models.admin import AdminAuditLog, AdminUser
        
        query = self.db.query(AdminAuditLog).join(AdminUser, isouter=True)
        
        # Apply filters
        if admin_id:
            query = query.filter(AdminAuditLog.admin_id == admin_id)
        
        if action_type:
            query = query.filter(AdminAuditLog.action_type == action_type)
        
        if resource_type:
            query = query.filter(AdminAuditLog.resource_type == resource_type)
        
        if start_date:
            query = query.filter(AdminAuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AdminAuditLog.timestamp <= end_date)
        
        if risk_level:
            query = query.filter(AdminAuditLog.risk_level == risk_level)
        
        # Order by timestamp descending
        query = query.order_by(AdminAuditLog.timestamp.desc())
        
        # Apply pagination
        audit_logs = query.offset(offset).limit(limit).all()
        
        # Format results
        results = []
        for log in audit_logs:
            log_data = {
                'id': log.id,
                'admin_id': log.admin_id,
                'admin_email': log.admin.email if log.admin else 'Unknown',
                'action_type': log.action_type,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'is_successful': log.is_successful,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'risk_level': log.risk_level,
                'timestamp': log.timestamp.isoformat(),
                'additional_data': json.loads(log.additional_data) if log.additional_data else {}
            }
            results.append(log_data)
        
        return results
    
    def get_security_summary(self, days: int = 30) -> Dict[str, Any]:
        """
        Get security summary for the specified period.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Security summary statistics
        """
        from app.models.admin import AdminAuditLog
        from sqlalchemy import func, and_
        
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Base query for the time period
        base_query = self.db.query(AdminAuditLog).filter(
            AdminAuditLog.timestamp >= start_date
        )
        
        # Total actions
        total_actions = base_query.count()
        
        # Failed actions
        failed_actions = base_query.filter(
            AdminAuditLog.is_successful == False
        ).count()
        
        # High-risk actions
        high_risk_actions = base_query.filter(
            AdminAuditLog.risk_level.in_([RiskLevel.HIGH.value, RiskLevel.CRITICAL.value])
        ).count()
        
        # Actions by type
        action_types = self.db.query(
            AdminAuditLog.action_type,
            func.count(AdminAuditLog.id).label('count')
        ).filter(
            AdminAuditLog.timestamp >= start_date
        ).group_by(AdminAuditLog.action_type).all()
        
        # Top active admins
        top_admins = self.db.query(
            AdminAuditLog.admin_id,
            func.count(AdminAuditLog.id).label('action_count')
        ).filter(
            AdminAuditLog.timestamp >= start_date
        ).group_by(AdminAuditLog.admin_id).order_by(
            func.count(AdminAuditLog.id).desc()
        ).limit(10).all()
        
        # Suspicious activity count
        suspicious_count = base_query.filter(
            AdminAuditLog.action_type == AuditActionType.SUSPICIOUS_ACTIVITY.value
        ).count()
        
        return {
            'period_days': days,
            'total_actions': total_actions,
            'failed_actions': failed_actions,
            'success_rate': round((total_actions - failed_actions) / total_actions * 100, 2) if total_actions > 0 else 0,
            'high_risk_actions': high_risk_actions,
            'suspicious_activities': suspicious_count,
            'action_types': [{'type': at[0], 'count': at[1]} for at in action_types],
            'top_admins': [{'admin_id': ta[0], 'action_count': ta[1]} for ta in top_admins],
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
    
    # Private helper methods
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize sensitive data from audit logs."""
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        
        for key, value in data.items():
            # Check if key contains sensitive patterns
            key_lower = key.lower()
            is_sensitive = any(pattern in key_lower for pattern in self.sensitive_patterns)
            
            if is_sensitive:
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_data(value)
            elif isinstance(value, list):
                sanitized[key] = [self._sanitize_data(item) if isinstance(item, dict) else item for item in value]
            else:
                sanitized[key] = self._sanitize_value(value)
        
        return sanitized
    
    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize individual values."""
        if isinstance(value, str):
            # Check for potential sensitive data patterns
            value_lower = value.lower()
            if any(pattern in value_lower for pattern in self.sensitive_patterns):
                return '[REDACTED]'
            
            # Truncate very long strings
            if len(value) > 1000:
                return value[:1000] + '...[TRUNCATED]'
        
        return value
    
    def _assess_risk_level(self, action_type: str, resource_type: str,
                          is_successful: bool, additional_data: Dict[str, Any]) -> str:
        """Assess risk level based on action context."""
        # Failed actions are at least medium risk
        if not is_successful:
            base_risk = RiskLevel.MEDIUM.value
        else:
            base_risk = RiskLevel.LOW.value
        
        # High-risk actions
        if action_type in self.high_risk_actions:
            base_risk = RiskLevel.HIGH.value
        
        # Critical resource types
        critical_resources = ['admin_users', 'system_config', 'security_settings']
        if resource_type in critical_resources:
            if base_risk == RiskLevel.LOW.value:
                base_risk = RiskLevel.MEDIUM.value
            elif base_risk == RiskLevel.MEDIUM.value:
                base_risk = RiskLevel.HIGH.value
        
        # Check additional data for risk indicators
        if additional_data:
            if additional_data.get('is_suspicious_ip'):
                base_risk = RiskLevel.HIGH.value
            
            if additional_data.get('record_count', 0) > 10000:
                base_risk = RiskLevel.CRITICAL.value
        
        return base_risk
    
    def _generate_log_id(self) -> str:
        """Generate unique audit log ID."""
        import secrets
        return f"audit_{secrets.token_hex(16)}"
    
    def _get_ip_location(self, ip_address: str) -> Optional[str]:
        """Get approximate location for IP address."""
        if not ip_address:
            return None
        
        try:
            # Check if it's a private IP
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private:
                return "Private Network"
            
            # In production, integrate with IP geolocation service
            # For now, return placeholder
            return "Unknown Location"
        
        except ValueError:
            return "Invalid IP"
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious."""
        if not ip_address:
            return False
        
        # In production, check against threat intelligence feeds
        # For now, implement basic checks
        
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check for known suspicious ranges (example)
            suspicious_ranges = [
                # Add known malicious IP ranges
            ]
            
            for range_str in suspicious_ranges:
                if ip in ipaddress.ip_network(range_str):
                    return True
            
            return False
        
        except ValueError:
            return True  # Invalid IPs are suspicious
    
    def _determine_change_type(self, old_value: Any, new_value: Any) -> str:
        """Determine the type of configuration change."""
        if old_value is None and new_value is not None:
            return "created"
        elif old_value is not None and new_value is None:
            return "deleted"
        elif old_value != new_value:
            return "modified"
        else:
            return "no_change"
    
    def _trigger_security_alert(self, audit_log):
        """Trigger security alert for high-risk actions."""
        # In production, integrate with alerting system
        # For now, log the alert
        print(f"SECURITY ALERT: High-risk action detected - {audit_log.id}")
        
        # Could send email, Slack notification, etc.
        pass
```

#### Usage Examples

```python
# Example 1: Basic action logging
from app.admin.utils.audit import AdminAuditLogger

logger = AdminAuditLogger(db_session, admin_id='admin-123')

# Log user deletion
log_id = logger.log_action(
    action_type='delete',
    resource_type='user',
    resource_id='user-456',
    is_successful=True,
    ip_address='192.168.1.100',
    additional_data={'reason': 'Account violation', 'deleted_by': 'admin-123'}
)

print(f"Action logged: {log_id}")

# Example 2: Login attempt logging
login_log_id = logger.log_login_attempt(
    email='admin@example.com',
    is_successful=False,
    ip_address='203.0.113.1',
    user_agent='Mozilla/5.0...',
    failure_reason='Invalid password'
)

# Example 3: Data export logging
export_log_id = logger.log_data_export(
    export_type='user_data',
    record_count=5000,
    filters={'date_range': '2024-01-01 to 2024-01-31', 'status': 'active'},
    ip_address='192.168.1.100'
)

# Example 4: Configuration change logging
config_log_id = logger.log_configuration_change(
    config_key='max_login_attempts',
    old_value=3,
    new_value=5,
    ip_address='192.168.1.100'
)

# Example 5: Permission change logging
permission_log_id = logger.log_permission_change(
    target_admin_id='admin-456',
    permission_changes=[
        {'permission': 'user_delete', 'action': 'granted'},
        {'permission': 'system_config', 'action': 'revoked'}
    ],
    ip_address='192.168.1.100'
)

# Example 6: Suspicious activity logging
suspicious_log_id = logger.log_suspicious_activity(
    activity_type='multiple_failed_logins',
    details={
        'attempt_count': 10,
        'time_window': '5 minutes',
        'target_account': 'admin@example.com'
    },
    ip_address='203.0.113.1'
)

# Example 7: Retrieve audit trail
audit_trail = logger.get_audit_trail(
    admin_id='admin-123',
    action_type='delete',
    start_date=datetime.now() - timedelta(days=7),
    limit=50
)

for entry in audit_trail:
    print(f"Action: {entry['action_type']} on {entry['resource_type']}")
    print(f"Time: {entry['timestamp']}")
    print(f"Success: {entry['is_successful']}")
    print(f"Risk: {entry['risk_level']}")

# Example 8: Security summary
security_summary = logger.get_security_summary(days=30)
print(f"Total actions in last 30 days: {security_summary['total_actions']}")
print(f"Success rate: {security_summary['success_rate']}%")
print(f"High-risk actions: {security_summary['high_risk_actions']}")
---

### 6. AdminNotificationSender

The `AdminNotificationSender` class handles various types of notifications for admin operations, including email alerts, system notifications, and real-time updates.

```python
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone
from enum import Enum
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import asyncio
import aiohttp
from jinja2 import Template

class NotificationType(Enum):
    """Enumeration of notification types."""
    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    WEBHOOK = "webhook"
    SLACK = "slack"
    SYSTEM_ALERT = "system_alert"

class NotificationPriority(Enum):
    """Enumeration of notification priorities."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"

class NotificationTemplate(Enum):
    """Enumeration of notification templates."""
    SECURITY_ALERT = "security_alert"
    SYSTEM_MAINTENANCE = "system_maintenance"
    USER_ACTIVITY = "user_activity"
    PERFORMANCE_ALERT = "performance_alert"
    BACKUP_STATUS = "backup_status"
    COMPLIANCE_REPORT = "compliance_report"
    ADMIN_WELCOME = "admin_welcome"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_LOCKED = "account_locked"
    SUSPICIOUS_LOGIN = "suspicious_login"

class AdminNotificationSender:
    """
    Comprehensive notification system for admin operations.
    
    Supports multiple notification channels including email, SMS, push notifications,
    webhooks, and real-time system alerts with template management and delivery tracking.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize notification sender with configuration.
        
        Args:
            config: Configuration dictionary containing SMTP, API keys, etc.
        """
        self.config = config
        self.smtp_config = config.get('smtp', {})
        self.webhook_config = config.get('webhooks', {})
        self.slack_config = config.get('slack', {})
        self.sms_config = config.get('sms', {})
        
        # Template storage
        self.templates = self._load_templates()
        
        # Delivery tracking
        self.delivery_log = []
        
        # Rate limiting
        self.rate_limits = {
            NotificationType.EMAIL.value: {'count': 0, 'reset_time': datetime.now()},
            NotificationType.SMS.value: {'count': 0, 'reset_time': datetime.now()},
            NotificationType.SLACK.value: {'count': 0, 'reset_time': datetime.now()}
        }
    
    def send_notification(self, notification_type: str, recipients: Union[str, List[str]],
                         template: str = None, subject: str = None, 
                         message: str = None, data: Dict[str, Any] = None,
                         priority: str = NotificationPriority.NORMAL.value,
                         attachments: List[Dict] = None) -> Dict[str, Any]:
        """
        Send notification through specified channel.
        
        Args:
            notification_type: Type of notification (email, sms, etc.)
            recipients: Single recipient or list of recipients
            template: Template name to use
            subject: Notification subject (for email/push)
            message: Direct message content
            data: Template data for rendering
            priority: Notification priority level
            attachments: List of attachments (for email)
            
        Returns:
            Delivery result with status and details
            
        Example:
            >>> sender = AdminNotificationSender(config)
            >>> result = sender.send_notification(
            ...     notification_type='email',
            ...     recipients=['admin@example.com'],
            ...     template='security_alert',
            ...     data={'alert_type': 'Failed Login', 'ip': '203.0.113.1'},
            ...     priority='high'
            ... )
            >>> print(f"Sent: {result['success']}")
        """
        # Validate inputs
        if not recipients:
            return {'success': False, 'error': 'No recipients specified'}
        
        if isinstance(recipients, str):
            recipients = [recipients]
        
        # Check rate limits
        if not self._check_rate_limit(notification_type):
            return {'success': False, 'error': 'Rate limit exceeded'}
        
        # Prepare notification content
        if template and template in self.templates:
            rendered_content = self._render_template(template, data or {})
            if not message:
                message = rendered_content.get('body', '')
            if not subject:
                subject = rendered_content.get('subject', '')
        
        # Route to appropriate sender
        try:
            if notification_type == NotificationType.EMAIL.value:
                result = self._send_email(recipients, subject, message, attachments, priority)
            elif notification_type == NotificationType.SMS.value:
                result = self._send_sms(recipients, message, priority)
            elif notification_type == NotificationType.SLACK.value:
                result = self._send_slack(recipients, message, priority, data)
            elif notification_type == NotificationType.WEBHOOK.value:
                result = self._send_webhook(recipients, message, data, priority)
            elif notification_type == NotificationType.PUSH.value:
                result = self._send_push(recipients, subject, message, priority)
            else:
                result = {'success': False, 'error': f'Unsupported notification type: {notification_type}'}
            
            # Log delivery attempt
            self._log_delivery(notification_type, recipients, result, priority)
            
            return result
            
        except Exception as e:
            error_result = {'success': False, 'error': str(e)}
            self._log_delivery(notification_type, recipients, error_result, priority)
            return error_result
    
    def send_security_alert(self, alert_type: str, details: Dict[str, Any],
                           recipients: List[str] = None, 
                           channels: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Send security alert through multiple channels.
        
        Args:
            alert_type: Type of security alert
            details: Alert details and context
            recipients: Override default security team recipients
            channels: Override default notification channels
            
        Returns:
            Results from all notification channels
        """
        if not recipients:
            recipients = self.config.get('security_team_emails', [])
        
        if not channels:
            channels = ['email', 'slack']
        
        alert_data = {
            'alert_type': alert_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'severity': details.get('severity', 'medium'),
            'source_ip': details.get('ip_address'),
            'admin_id': details.get('admin_id'),
            'description': details.get('description', ''),
            'recommended_actions': details.get('actions', [])
        }
        
        results = {}
        
        for channel in channels:
            try:
                if channel == 'email':
                    result = self.send_notification(
                        notification_type='email',
                        recipients=recipients,
                        template='security_alert',
                        data=alert_data,
                        priority='high'
                    )
                elif channel == 'slack':
                    slack_channels = self.config.get('slack_security_channels', [])
                    result = self.send_notification(
                        notification_type='slack',
                        recipients=slack_channels,
                        template='security_alert',
                        data=alert_data,
                        priority='high'
                    )
                else:
                    result = {'success': False, 'error': f'Unsupported channel: {channel}'}
                
                results[channel] = result
                
            except Exception as e:
                results[channel] = {'success': False, 'error': str(e)}
        
        return {'results': results, 'alert_id': self._generate_alert_id()}
    
    def send_system_maintenance_notice(self, maintenance_details: Dict[str, Any],
                                     advance_notice_hours: int = 24) -> Dict[str, Any]:
        """
        Send system maintenance notifications to all admins.
        
        Args:
            maintenance_details: Details about the maintenance
            advance_notice_hours: Hours before maintenance to send notice
            
        Returns:
            Notification delivery results
        """
        admin_emails = self.config.get('all_admin_emails', [])
        
        maintenance_data = {
            'maintenance_type': maintenance_details.get('type', 'System Maintenance'),
            'start_time': maintenance_details.get('start_time'),
            'end_time': maintenance_details.get('end_time'),
            'duration': maintenance_details.get('duration'),
            'affected_services': maintenance_details.get('services', []),
            'impact_description': maintenance_details.get('impact', ''),
            'advance_notice_hours': advance_notice_hours,
            'contact_info': maintenance_details.get('contact', 'IT Support')
        }
        
        return self.send_notification(
            notification_type='email',
            recipients=admin_emails,
            template='system_maintenance',
            data=maintenance_data,
            priority='normal'
        )
    
    def send_performance_alert(self, metric_name: str, current_value: float,
                             threshold: float, trend: str = 'increasing') -> Dict[str, Any]:
        """
        Send performance alert when metrics exceed thresholds.
        
        Args:
            metric_name: Name of the performance metric
            current_value: Current metric value
            threshold: Alert threshold
            trend: Performance trend (increasing/decreasing)
            
        Returns:
            Notification delivery results
        """
        performance_data = {
            'metric_name': metric_name,
            'current_value': current_value,
            'threshold': threshold,
            'trend': trend,
            'severity': self._calculate_performance_severity(current_value, threshold),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'recommended_actions': self._get_performance_recommendations(metric_name, current_value, threshold)
        }
        
        recipients = self.config.get('performance_team_emails', [])
        
        return self.send_notification(
            notification_type='email',
            recipients=recipients,
            template='performance_alert',
            data=performance_data,
            priority='high' if performance_data['severity'] == 'critical' else 'normal'
        )
    
    def send_compliance_report(self, report_data: Dict[str, Any],
                             report_file_path: str = None) -> Dict[str, Any]:
        """
        Send compliance report to designated recipients.
        
        Args:
            report_data: Compliance report data
            report_file_path: Path to report file attachment
            
        Returns:
            Notification delivery results
        """
        compliance_data = {
            'report_period': report_data.get('period'),
            'compliance_score': report_data.get('score'),
            'total_checks': report_data.get('total_checks'),
            'passed_checks': report_data.get('passed_checks'),
            'failed_checks': report_data.get('failed_checks'),
            'critical_issues': report_data.get('critical_issues', []),
            'recommendations': report_data.get('recommendations', []),
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        attachments = []
        if report_file_path:
            attachments.append({
                'filename': 'compliance_report.pdf',
                'path': report_file_path,
                'content_type': 'application/pdf'
            })
        
        recipients = self.config.get('compliance_team_emails', [])
        
        return self.send_notification(
            notification_type='email',
            recipients=recipients,
            template='compliance_report',
            data=compliance_data,
            attachments=attachments,
            priority='normal'
        )
    
    def send_admin_welcome(self, admin_email: str, admin_name: str,
                          temporary_password: str, login_url: str) -> Dict[str, Any]:
        """
        Send welcome notification to new admin users.
        
        Args:
            admin_email: New admin's email address
            admin_name: New admin's full name
            temporary_password: Temporary login password
            login_url: Admin panel login URL
            
        Returns:
            Notification delivery results
        """
        welcome_data = {
            'admin_name': admin_name,
            'admin_email': admin_email,
            'temporary_password': temporary_password,
            'login_url': login_url,
            'password_reset_required': True,
            'support_contact': self.config.get('support_email', 'support@example.com'),
            'company_name': self.config.get('company_name', 'LinkShield')
        }
        
        return self.send_notification(
            notification_type='email',
            recipients=[admin_email],
            template='admin_welcome',
            data=welcome_data,
            priority='normal'
        )
    
    def send_bulk_notification(self, notifications: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Send multiple notifications in batch.
        
        Args:
            notifications: List of notification configurations
            
        Returns:
            List of delivery results
        """
        results = []
        
        for notification in notifications:
            try:
                result = self.send_notification(**notification)
                results.append({
                    'notification_id': notification.get('id', len(results)),
                    'result': result
                })
            except Exception as e:
                results.append({
                    'notification_id': notification.get('id', len(results)),
                    'result': {'success': False, 'error': str(e)}
                })
        
        return results
    
    # Private helper methods
    def _send_email(self, recipients: List[str], subject: str, message: str,
                   attachments: List[Dict] = None, priority: str = 'normal') -> Dict[str, Any]:
        """Send email notification."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config.get('from_email')
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            
            # Set priority headers
            if priority in ['high', 'urgent', 'critical']:
                msg['X-Priority'] = '1'
                msg['X-MSMail-Priority'] = 'High'
            
            # Add message body
            msg.attach(MIMEText(message, 'html' if '<html>' in message else 'plain'))
            
            # Add attachments
            if attachments:
                for attachment in attachments:
                    self._add_email_attachment(msg, attachment)
            
            # Send email
            with smtplib.SMTP(self.smtp_config.get('host'), self.smtp_config.get('port', 587)) as server:
                if self.smtp_config.get('use_tls', True):
                    server.starttls()
                
                if self.smtp_config.get('username'):
                    server.login(self.smtp_config['username'], self.smtp_config['password'])
                
                server.send_message(msg)
            
            return {'success': True, 'message_id': self._generate_message_id(), 'recipients': len(recipients)}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_sms(self, recipients: List[str], message: str, priority: str = 'normal') -> Dict[str, Any]:
        """Send SMS notification."""
        # Implementation would depend on SMS provider (Twilio, AWS SNS, etc.)
        # This is a placeholder implementation
        
        try:
            # Truncate message for SMS
            sms_message = message[:160] if len(message) > 160 else message
            
            # In production, integrate with SMS provider API
            # For now, return success simulation
            
            return {
                'success': True,
                'message_id': self._generate_message_id(),
                'recipients': len(recipients),
                'message_length': len(sms_message)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_slack(self, channels: List[str], message: str, priority: str = 'normal',
                   data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send Slack notification."""
        try:
            webhook_url = self.slack_config.get('webhook_url')
            if not webhook_url:
                return {'success': False, 'error': 'Slack webhook URL not configured'}
            
            # Format message for Slack
            slack_payload = {
                'text': message,
                'username': 'LinkShield Admin Bot',
                'icon_emoji': ':shield:',
                'attachments': []
            }
            
            # Add priority color
            color_map = {
                'low': 'good',
                'normal': '#439FE0',
                'high': 'warning',
                'urgent': 'danger',
                'critical': 'danger'
            }
            
            if data:
                attachment = {
                    'color': color_map.get(priority, '#439FE0'),
                    'fields': []
                }
                
                for key, value in data.items():
                    if key not in ['template', 'rendered_content']:
                        attachment['fields'].append({
                            'title': key.replace('_', ' ').title(),
                            'value': str(value),
                            'short': True
                        })
                
                slack_payload['attachments'].append(attachment)
            
            # Send to Slack
            import requests
            response = requests.post(webhook_url, json=slack_payload)
            
            if response.status_code == 200:
                return {'success': True, 'message_id': self._generate_message_id(), 'channels': len(channels)}
            else:
                return {'success': False, 'error': f'Slack API error: {response.status_code}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_webhook(self, urls: List[str], message: str, data: Dict[str, Any],
                     priority: str = 'normal') -> Dict[str, Any]:
        """Send webhook notification."""
        try:
            payload = {
                'message': message,
                'priority': priority,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data': data or {}
            }
            
            import requests
            results = []
            
            for url in urls:
                try:
                    response = requests.post(url, json=payload, timeout=10)
                    results.append({
                        'url': url,
                        'status_code': response.status_code,
                        'success': response.status_code < 400
                    })
                except Exception as e:
                    results.append({
                        'url': url,
                        'success': False,
                        'error': str(e)
                    })
            
            success_count = sum(1 for r in results if r.get('success', False))
            
            return {
                'success': success_count > 0,
                'message_id': self._generate_message_id(),
                'successful_webhooks': success_count,
                'total_webhooks': len(urls),
                'results': results
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _send_push(self, recipients: List[str], title: str, message: str,
                  priority: str = 'normal') -> Dict[str, Any]:
        """Send push notification."""
        # Implementation would depend on push notification service
        # This is a placeholder implementation
        
        try:
            # In production, integrate with push notification service
            # (Firebase, Apple Push Notification service, etc.)
            
            return {
                'success': True,
                'message_id': self._generate_message_id(),
                'recipients': len(recipients)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _load_templates(self) -> Dict[str, Dict[str, str]]:
        """Load notification templates."""
        # In production, load from database or template files
        # For now, return hardcoded templates
        
        return {
            'security_alert': {
                'subject': 'Security Alert: {{ alert_type }}',
                'body': '''
                <h2>Security Alert</h2>
                <p><strong>Alert Type:</strong> {{ alert_type }}</p>
                <p><strong>Timestamp:</strong> {{ timestamp }}</p>
                <p><strong>Severity:</strong> {{ severity }}</p>
                {% if source_ip %}<p><strong>Source IP:</strong> {{ source_ip }}</p>{% endif %}
                {% if admin_id %}<p><strong>Admin ID:</strong> {{ admin_id }}</p>{% endif %}
                <p><strong>Description:</strong> {{ description }}</p>
                {% if recommended_actions %}
                <h3>Recommended Actions:</h3>
                <ul>
                {% for action in recommended_actions %}
                    <li>{{ action }}</li>
                {% endfor %}
                </ul>
                {% endif %}
                '''
            },
            'system_maintenance': {
                'subject': 'Scheduled Maintenance: {{ maintenance_type }}',
                'body': '''
                <h2>Scheduled System Maintenance</h2>
                <p><strong>Maintenance Type:</strong> {{ maintenance_type }}</p>
                <p><strong>Start Time:</strong> {{ start_time }}</p>
                <p><strong>End Time:</strong> {{ end_time }}</p>
                <p><strong>Duration:</strong> {{ duration }}</p>
                <p><strong>Affected Services:</strong></p>
                <ul>
                {% for service in affected_services %}
                    <li>{{ service }}</li>
                {% endfor %}
                </ul>
                <p><strong>Impact:</strong> {{ impact_description }}</p>
                <p>This notice is being sent {{ advance_notice_hours }} hours in advance.</p>
                <p>For questions, contact: {{ contact_info }}</p>
                '''
            },
            'admin_welcome': {
                'subject': 'Welcome to {{ company_name }} Admin Panel',
                'body': '''
                <h2>Welcome to {{ company_name }}</h2>
                <p>Hello {{ admin_name }},</p>
                <p>Your admin account has been created successfully.</p>
                <p><strong>Login Details:</strong></p>
                <ul>
                    <li>Email: {{ admin_email }}</li>
                    <li>Temporary Password: {{ temporary_password }}</li>
                    <li>Login URL: <a href="{{ login_url }}">{{ login_url }}</a></li>
                </ul>
                <p><strong>Important:</strong> You will be required to change your password on first login.</p>
                <p>If you need assistance, contact: {{ support_contact }}</p>
                '''
            }
        }
    
    def _render_template(self, template_name: str, data: Dict[str, Any]) -> Dict[str, str]:
        """Render notification template with data."""
        template_config = self.templates.get(template_name, {})
        
        rendered = {}
        
        for key, template_str in template_config.items():
            template = Template(template_str)
            rendered[key] = template.render(**data)
        
        return rendered
    
    def _check_rate_limit(self, notification_type: str) -> bool:
        """Check if notification type is within rate limits."""
        now = datetime.now()
        rate_limit = self.rate_limits.get(notification_type)
        
        if not rate_limit:
            return True
        
        # Reset counter if hour has passed
        if (now - rate_limit['reset_time']).total_seconds() > 3600:
            rate_limit['count'] = 0
            rate_limit['reset_time'] = now
        
        # Check limits (configurable per type)
        limits = {
            NotificationType.EMAIL.value: 1000,  # 1000 emails per hour
            NotificationType.SMS.value: 100,     # 100 SMS per hour
            NotificationType.SLACK.value: 500    # 500 Slack messages per hour
        }
        
        limit = limits.get(notification_type, 100)
        
        if rate_limit['count'] >= limit:
            return False
        
        rate_limit['count'] += 1
        return True
    
    def _log_delivery(self, notification_type: str, recipients: List[str],
                     result: Dict[str, Any], priority: str):
        """Log notification delivery attempt."""
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type': notification_type,
            'recipients': recipients,
            'success': result.get('success', False),
            'priority': priority,
            'message_id': result.get('message_id'),
            'error': result.get('error')
        }
        
        self.delivery_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.delivery_log) > 1000:
            self.delivery_log = self.delivery_log[-1000:]
    
    def _add_email_attachment(self, msg: MIMEMultipart, attachment: Dict[str, Any]):
        """Add attachment to email message."""
        try:
            with open(attachment['path'], 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {attachment["filename"]}'
            )
            
            msg.attach(part)
            
        except Exception as e:
            print(f"Failed to add attachment {attachment['filename']}: {e}")
    
    def _generate_message_id(self) -> str:
        """Generate unique message ID."""
        import secrets
        return f"msg_{secrets.token_hex(8)}"
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        import secrets
        return f"alert_{secrets.token_hex(12)}"
    
    def _calculate_performance_severity(self, current_value: float, threshold: float) -> str:
        """Calculate performance alert severity."""
        ratio = current_value / threshold
        
        if ratio >= 2.0:
            return 'critical'
        elif ratio >= 1.5:
            return 'high'
        elif ratio >= 1.2:
            return 'medium'
        else:
            return 'low'
    
    def _get_performance_recommendations(self, metric_name: str, current_value: float,
                                       threshold: float) -> List[str]:
        """Get performance recommendations based on metric."""
        recommendations = {
            'cpu_usage': [
                'Check for resource-intensive processes',
                'Consider scaling up server resources',
                'Review application performance optimizations'
            ],
            'memory_usage': [
                'Investigate memory leaks',
                'Optimize database queries',
                'Consider increasing available memory'
            ],
            'disk_usage': [
                'Clean up temporary files',
                'Archive old log files',
                'Consider expanding disk space'
            ],
            'response_time': [
                'Optimize database queries',
                'Review application code performance',
                'Check network connectivity'
            ]
        }
        
        return recommendations.get(metric_name, ['Contact system administrator'])
```

#### Usage Examples

```python
# Example 1: Basic email notification
from app.admin.utils.notifications import AdminNotificationSender

config = {
    'smtp': {
        'host': 'smtp.gmail.com',
        'port': 587,
        'username': 'admin@example.com',
        'password': 'app_password',
        'from_email': 'admin@example.com',
        'use_tls': True
    },
    'slack': {
        'webhook_url': 'https://hooks.slack.com/services/...'
    },
    'security_team_emails': ['security@example.com'],
    'all_admin_emails': ['admin1@example.com', 'admin2@example.com']
}

sender = AdminNotificationSender(config)

# Send security alert
result = sender.send_security_alert(
    alert_type='Multiple Failed Login Attempts',
    details={
        'severity': 'high',
        'ip_address': '203.0.113.1',
        'admin_id': 'admin-123',
        'description': '10 failed login attempts in 5 minutes',
        'actions': ['Block IP address', 'Review admin account security']
    }
)

print(f"Security alert sent: {result}")

# Example 2: System maintenance notice
maintenance_result = sender.send_system_maintenance_notice(
    maintenance_details={
        'type': 'Database Upgrade',
        'start_time': '2024-02-15 02:00 UTC',
        'end_time': '2024-02-15 06:00 UTC',
        'duration': '4 hours',
        'services': ['User Management', 'Reporting Dashboard'],
        'impact': 'Admin panel will be unavailable during maintenance',
        'contact': 'IT Support: support@example.com'
    },
    advance_notice_hours=48
)

# Example 3: Performance alert
performance_result = sender.send_performance_alert(
    metric_name='cpu_usage',
    current_value=85.5,
    threshold=80.0,
    trend='increasing'
)

# Example 4: Welcome new admin
welcome_result = sender.send_admin_welcome(
    admin_email='newadmin@example.com',
    admin_name='John Doe',
    temporary_password='TempPass123!',
    login_url='https://admin.example.com/login'
)

# Example 5: Custom notification with template
custom_result = sender.send_notification(
    notification_type='email',
    recipients=['admin@example.com'],
    template='security_alert',
    data={
        'alert_type': 'Suspicious Activity',
        'timestamp': '2024-01-15T10:30:00Z',
        'severity': 'medium',
        'description': 'Unusual access pattern detected'
    },
    priority='high'
)

# Example 6: Bulk notifications
bulk_notifications = [
    {
        'notification_type': 'email',
        'recipients': ['admin1@example.com'],
        'subject': 'Daily Report',
        'message': 'Your daily admin report is ready.',
        'priority': 'normal'
    },
    {
        'notification_type': 'slack',
        'recipients': ['#admin-alerts'],
        'message': 'System backup completed successfully',
        'priority': 'low'
    }
]

bulk_results = sender.send_bulk_notification(bulk_notifications)

---

### 7. AdminReportGenerator

The `AdminReportGenerator` class provides comprehensive reporting capabilities for admin operations, including system analytics, user activity reports, security summaries, and compliance documentation.

```python
from typing import Dict, Any, List, Optional, Union, Tuple
from datetime import datetime, timezone, timedelta
from enum import Enum
import json
import csv
import io
from dataclasses import dataclass, asdict
import matplotlib.pyplot as plt
import pandas as pd
from jinja2 import Template
import base64
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

class ReportFormat(Enum):
    """Enumeration of report output formats."""
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    HTML = "html"
    EXCEL = "excel"

class ReportType(Enum):
    """Enumeration of report types."""
    SYSTEM_ANALYTICS = "system_analytics"
    USER_ACTIVITY = "user_activity"
    SECURITY_SUMMARY = "security_summary"
    PERFORMANCE_METRICS = "performance_metrics"
    COMPLIANCE_AUDIT = "compliance_audit"
    ADMIN_ACTIVITY = "admin_activity"
    THREAT_INTELLIGENCE = "threat_intelligence"
    FINANCIAL_SUMMARY = "financial_summary"
    CUSTOM_QUERY = "custom_query"

class ReportPeriod(Enum):
    """Enumeration of report time periods."""
    LAST_HOUR = "last_hour"
    LAST_24_HOURS = "last_24_hours"
    LAST_7_DAYS = "last_7_days"
    LAST_30_DAYS = "last_30_days"
    LAST_90_DAYS = "last_90_days"
    LAST_YEAR = "last_year"
    CUSTOM = "custom"

@dataclass
class ReportMetadata:
    """Report metadata structure."""
    report_id: str
    report_type: str
    format: str
    generated_at: str
    generated_by: str
    period_start: str
    period_end: str
    total_records: int
    file_size: int
    parameters: Dict[str, Any]

@dataclass
class ChartConfig:
    """Chart configuration for reports."""
    chart_type: str  # bar, line, pie, scatter
    title: str
    x_label: str
    y_label: str
    data: List[Dict[str, Any]]
    colors: List[str] = None
    width: int = 800
    height: int = 600

class AdminReportGenerator:
    """
    Comprehensive report generation system for admin operations.
    
    Supports multiple output formats (PDF, CSV, JSON, HTML, Excel) with
    customizable templates, charts, and automated scheduling capabilities.
    """
    
    def __init__(self, config: Dict[str, Any], database_connection=None):
        """
        Initialize report generator with configuration.
        
        Args:
            config: Configuration dictionary
            database_connection: Database connection for data queries
        """
        self.config = config
        self.db = database_connection
        self.output_directory = config.get('output_directory', './reports')
        self.template_directory = config.get('template_directory', './templates')
        
        # Report templates
        self.templates = self._load_templates()
        
        # Chart styling
        self.chart_style = {
            'figure.figsize': (10, 6),
            'axes.titlesize': 14,
            'axes.labelsize': 12,
            'xtick.labelsize': 10,
            'ytick.labelsize': 10,
            'legend.fontsize': 10
        }
        
        # Apply chart styling
        plt.rcParams.update(self.chart_style)
    
    def generate_report(self, report_type: str, format: str = ReportFormat.PDF.value,
                       period: str = ReportPeriod.LAST_30_DAYS.value,
                       custom_start: datetime = None, custom_end: datetime = None,
                       filters: Dict[str, Any] = None,
                       include_charts: bool = True,
                       admin_id: str = None) -> Dict[str, Any]:
        """
        Generate comprehensive admin report.
        
        Args:
            report_type: Type of report to generate
            format: Output format (pdf, csv, json, html, excel)
            period: Time period for the report
            custom_start: Custom start date (if period is 'custom')
            custom_end: Custom end date (if period is 'custom')
            filters: Additional filters for data
            include_charts: Whether to include charts in the report
            admin_id: ID of admin generating the report
            
        Returns:
            Report generation result with file path and metadata
            
        Example:
            >>> generator = AdminReportGenerator(config, db_connection)
            >>> result = generator.generate_report(
            ...     report_type='system_analytics',
            ...     format='pdf',
            ...     period='last_30_days',
            ...     include_charts=True,
            ...     admin_id='admin-123'
            ... )
            >>> print(f"Report generated: {result['file_path']}")
        """
        try:
            # Calculate date range
            start_date, end_date = self._calculate_date_range(period, custom_start, custom_end)
            
            # Generate report ID
            report_id = self._generate_report_id(report_type, format)
            
            # Collect data based on report type
            if report_type == ReportType.SYSTEM_ANALYTICS.value:
                data = self._collect_system_analytics_data(start_date, end_date, filters)
            elif report_type == ReportType.USER_ACTIVITY.value:
                data = self._collect_user_activity_data(start_date, end_date, filters)
            elif report_type == ReportType.SECURITY_SUMMARY.value:
                data = self._collect_security_summary_data(start_date, end_date, filters)
            elif report_type == ReportType.PERFORMANCE_METRICS.value:
                data = self._collect_performance_metrics_data(start_date, end_date, filters)
            elif report_type == ReportType.COMPLIANCE_AUDIT.value:
                data = self._collect_compliance_audit_data(start_date, end_date, filters)
            elif report_type == ReportType.ADMIN_ACTIVITY.value:
                data = self._collect_admin_activity_data(start_date, end_date, filters)
            elif report_type == ReportType.THREAT_INTELLIGENCE.value:
                data = self._collect_threat_intelligence_data(start_date, end_date, filters)
            else:
                return {'success': False, 'error': f'Unsupported report type: {report_type}'}
            
            # Generate charts if requested
            charts = []
            if include_charts:
                charts = self._generate_charts(report_type, data)
            
            # Create report metadata
            metadata = ReportMetadata(
                report_id=report_id,
                report_type=report_type,
                format=format,
                generated_at=datetime.now(timezone.utc).isoformat(),
                generated_by=admin_id or 'system',
                period_start=start_date.isoformat(),
                period_end=end_date.isoformat(),
                total_records=len(data.get('records', [])),
                file_size=0,  # Will be updated after file creation
                parameters={
                    'period': period,
                    'filters': filters or {},
                    'include_charts': include_charts
                }
            )
            
            # Generate report file
            file_path = self._generate_report_file(
                report_type, format, data, charts, metadata
            )
            
            # Update file size in metadata
            import os
            if os.path.exists(file_path):
                metadata.file_size = os.path.getsize(file_path)
            
            # Log report generation
            self._log_report_generation(metadata, admin_id)
            
            return {
                'success': True,
                'report_id': report_id,
                'file_path': file_path,
                'metadata': asdict(metadata),
                'download_url': self._generate_download_url(file_path)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def generate_system_analytics_report(self, period: str = ReportPeriod.LAST_30_DAYS.value,
                                       format: str = ReportFormat.PDF.value) -> Dict[str, Any]:
        """
        Generate comprehensive system analytics report.
        
        Args:
            period: Time period for the report
            format: Output format
            
        Returns:
            Report generation result
        """
        start_date, end_date = self._calculate_date_range(period)
        
        # Collect comprehensive system data
        system_data = {
            'overview': {
                'total_users': self._get_total_users(),
                'active_users': self._get_active_users(start_date, end_date),
                'total_requests': self._get_total_requests(start_date, end_date),
                'error_rate': self._get_error_rate(start_date, end_date),
                'avg_response_time': self._get_avg_response_time(start_date, end_date)
            },
            'traffic_analytics': self._get_traffic_analytics(start_date, end_date),
            'geographic_distribution': self._get_geographic_distribution(start_date, end_date),
            'device_analytics': self._get_device_analytics(start_date, end_date),
            'performance_trends': self._get_performance_trends(start_date, end_date),
            'resource_utilization': self._get_resource_utilization(start_date, end_date)
        }
        
        # Generate charts
        charts = [
            ChartConfig(
                chart_type='line',
                title='Daily Active Users',
                x_label='Date',
                y_label='Active Users',
                data=system_data['traffic_analytics']['daily_users']
            ),
            ChartConfig(
                chart_type='bar',
                title='Top Countries by Traffic',
                x_label='Country',
                y_label='Requests',
                data=system_data['geographic_distribution']['top_countries']
            ),
            ChartConfig(
                chart_type='pie',
                title='Device Type Distribution',
                x_label='',
                y_label='',
                data=system_data['device_analytics']['device_types']
            )
        ]
        
        return self._create_formatted_report(
            'system_analytics', format, system_data, charts
        )
    
    def generate_security_summary_report(self, period: str = ReportPeriod.LAST_7_DAYS.value,
                                       format: str = ReportFormat.PDF.value,
                                       include_details: bool = True) -> Dict[str, Any]:
        """
        Generate security summary report with threat analysis.
        
        Args:
            period: Time period for the report
            format: Output format
            include_details: Whether to include detailed security events
            
        Returns:
            Report generation result
        """
        start_date, end_date = self._calculate_date_range(period)
        
        security_data = {
            'summary': {
                'total_security_events': self._get_security_events_count(start_date, end_date),
                'blocked_threats': self._get_blocked_threats_count(start_date, end_date),
                'failed_logins': self._get_failed_logins_count(start_date, end_date),
                'suspicious_activities': self._get_suspicious_activities_count(start_date, end_date),
                'security_score': self._calculate_security_score(start_date, end_date)
            },
            'threat_categories': self._get_threat_categories(start_date, end_date),
            'attack_sources': self._get_attack_sources(start_date, end_date),
            'vulnerability_assessments': self._get_vulnerability_assessments(start_date, end_date),
            'compliance_status': self._get_compliance_status()
        }
        
        if include_details:
            security_data['detailed_events'] = self._get_detailed_security_events(
                start_date, end_date, limit=100
            )
        
        # Generate security-focused charts
        charts = [
            ChartConfig(
                chart_type='bar',
                title='Security Events by Category',
                x_label='Category',
                y_label='Count',
                data=security_data['threat_categories']
            ),
            ChartConfig(
                chart_type='pie',
                title='Attack Sources Distribution',
                x_label='',
                y_label='',
                data=security_data['attack_sources']
            )
        ]
        
        return self._create_formatted_report(
            'security_summary', format, security_data, charts
        )
    
    def generate_compliance_audit_report(self, compliance_framework: str = 'SOC2',
                                       format: str = ReportFormat.PDF.value) -> Dict[str, Any]:
        """
        Generate compliance audit report for specified framework.
        
        Args:
            compliance_framework: Compliance framework (SOC2, GDPR, HIPAA, etc.)
            format: Output format
            
        Returns:
            Report generation result
        """
        compliance_data = {
            'framework': compliance_framework,
            'audit_date': datetime.now(timezone.utc).isoformat(),
            'overall_score': self._calculate_compliance_score(compliance_framework),
            'control_assessments': self._assess_compliance_controls(compliance_framework),
            'findings': self._get_compliance_findings(compliance_framework),
            'recommendations': self._get_compliance_recommendations(compliance_framework),
            'evidence_collection': self._collect_compliance_evidence(compliance_framework),
            'remediation_plan': self._create_remediation_plan(compliance_framework)
        }
        
        # Generate compliance charts
        charts = [
            ChartConfig(
                chart_type='bar',
                title='Control Assessment Results',
                x_label='Control Category',
                y_label='Compliance Score',
                data=compliance_data['control_assessments']
            )
        ]
        
        return self._create_formatted_report(
            'compliance_audit', format, compliance_data, charts
        )
    
    def generate_custom_report(self, query: str, title: str,
                             format: str = ReportFormat.PDF.value,
                             chart_configs: List[ChartConfig] = None) -> Dict[str, Any]:
        """
        Generate custom report based on SQL query.
        
        Args:
            query: SQL query to execute
            title: Report title
            format: Output format
            chart_configs: Optional chart configurations
            
        Returns:
            Report generation result
        """
        try:
            # Execute custom query
            if self.db:
                results = self.db.execute(query).fetchall()
                columns = list(results[0].keys()) if results else []
                
                custom_data = {
                    'title': title,
                    'query': query,
                    'columns': columns,
                    'records': [dict(row) for row in results],
                    'total_records': len(results),
                    'generated_at': datetime.now(timezone.utc).isoformat()
                }
            else:
                return {'success': False, 'error': 'Database connection not available'}
            
            charts = chart_configs or []
            
            return self._create_formatted_report(
                'custom_query', format, custom_data, charts
            )
            
        except Exception as e:
            return {'success': False, 'error': f'Query execution failed: {str(e)}'}
    
    def schedule_report(self, report_config: Dict[str, Any],
                       schedule: str, recipients: List[str]) -> Dict[str, Any]:
        """
        Schedule automatic report generation and delivery.
        
        Args:
            report_config: Report configuration
            schedule: Cron-style schedule string
            recipients: Email recipients for the report
            
        Returns:
            Scheduling result
        """
        schedule_id = self._generate_schedule_id()
        
        scheduled_report = {
            'schedule_id': schedule_id,
            'report_config': report_config,
            'schedule': schedule,
            'recipients': recipients,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'status': 'active',
            'last_run': None,
            'next_run': self._calculate_next_run(schedule)
        }
        
        # Store schedule in database or configuration
        self._store_report_schedule(scheduled_report)
        
        return {
            'success': True,
            'schedule_id': schedule_id,
            'next_run': scheduled_report['next_run']
        }
    
    def export_data(self, data: Dict[str, Any], format: str,
                   filename: str = None) -> str:
        """
        Export data in specified format.
        
        Args:
            data: Data to export
            format: Export format
            filename: Optional filename
            
        Returns:
            File path of exported data
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"export_{timestamp}.{format}"
        
        file_path = f"{self.output_directory}/{filename}"
        
        if format == ReportFormat.JSON.value:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        
        elif format == ReportFormat.CSV.value:
            records = data.get('records', [])
            if records:
                df = pd.DataFrame(records)
                df.to_csv(file_path, index=False)
        
        elif format == ReportFormat.EXCEL.value:
            records = data.get('records', [])
            if records:
                df = pd.DataFrame(records)
                df.to_excel(file_path, index=False)
        
        return file_path
    
    # Private helper methods
    def _calculate_date_range(self, period: str, custom_start: datetime = None,
                            custom_end: datetime = None) -> Tuple[datetime, datetime]:
        """Calculate start and end dates for the specified period."""
        now = datetime.now(timezone.utc)
        
        if period == ReportPeriod.CUSTOM.value:
            return custom_start or now, custom_end or now
        
        period_map = {
            ReportPeriod.LAST_HOUR.value: timedelta(hours=1),
            ReportPeriod.LAST_24_HOURS.value: timedelta(days=1),
            ReportPeriod.LAST_7_DAYS.value: timedelta(days=7),
            ReportPeriod.LAST_30_DAYS.value: timedelta(days=30),
            ReportPeriod.LAST_90_DAYS.value: timedelta(days=90),
            ReportPeriod.LAST_YEAR.value: timedelta(days=365)
        }
        
        delta = period_map.get(period, timedelta(days=30))
        start_date = now - delta
        
        return start_date, now
    
    def _collect_system_analytics_data(self, start_date: datetime, end_date: datetime,
                                     filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect system analytics data from database."""
        # This would typically query your database
        # For now, return mock data structure
        
        return {
            'overview': {
                'total_users': 15420,
                'active_users': 8934,
                'total_requests': 2847392,
                'error_rate': 0.023,
                'avg_response_time': 245
            },
            'records': [],  # Detailed records would go here
            'summary_stats': {},
            'trends': {}
        }
    
    def _collect_user_activity_data(self, start_date: datetime, end_date: datetime,
                                  filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect user activity data."""
        return {
            'total_sessions': 45678,
            'unique_users': 12345,
            'avg_session_duration': 1847,
            'top_pages': [],
            'user_flows': [],
            'records': []
        }
    
    def _collect_security_summary_data(self, start_date: datetime, end_date: datetime,
                                     filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect security summary data."""
        return {
            'security_events': 234,
            'blocked_threats': 89,
            'failed_logins': 156,
            'suspicious_activities': 23,
            'records': []
        }
    
    def _collect_performance_metrics_data(self, start_date: datetime, end_date: datetime,
                                        filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect performance metrics data."""
        return {
            'avg_response_time': 245,
            'throughput': 1250,
            'error_rate': 0.023,
            'cpu_usage': 67.5,
            'memory_usage': 78.2,
            'records': []
        }
    
    def _collect_compliance_audit_data(self, start_date: datetime, end_date: datetime,
                                     filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect compliance audit data."""
        return {
            'compliance_score': 87.5,
            'passed_controls': 45,
            'failed_controls': 3,
            'pending_controls': 2,
            'records': []
        }
    
    def _collect_admin_activity_data(self, start_date: datetime, end_date: datetime,
                                   filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect admin activity data."""
        return {
            'total_admin_actions': 1234,
            'unique_admins': 12,
            'high_risk_actions': 23,
            'failed_actions': 5,
            'records': []
        }
    
    def _collect_threat_intelligence_data(self, start_date: datetime, end_date: datetime,
                                        filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect threat intelligence data."""
        return {
            'total_threats': 456,
            'blocked_ips': 234,
            'malware_detected': 12,
            'phishing_attempts': 34,
            'records': []
        }
    
    def _generate_charts(self, report_type: str, data: Dict[str, Any]) -> List[str]:
        """Generate charts for the report."""
        charts = []
        
        # This would generate actual charts based on data
        # For now, return empty list
        
        return charts
    
    def _generate_report_file(self, report_type: str, format: str,
                            data: Dict[str, Any], charts: List[str],
                            metadata: ReportMetadata) -> str:
        """Generate the actual report file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{report_type}_{timestamp}.{format}"
        file_path = f"{self.output_directory}/{filename}"
        
        if format == ReportFormat.PDF.value:
            return self._generate_pdf_report(file_path, data, charts, metadata)
        elif format == ReportFormat.HTML.value:
            return self._generate_html_report(file_path, data, charts, metadata)
        elif format == ReportFormat.CSV.value:
            return self._generate_csv_report(file_path, data, metadata)
        elif format == ReportFormat.JSON.value:
            return self._generate_json_report(file_path, data, metadata)
        elif format == ReportFormat.EXCEL.value:
            return self._generate_excel_report(file_path, data, charts, metadata)
        
        return file_path
    
    def _generate_pdf_report(self, file_path: str, data: Dict[str, Any],
                           charts: List[str], metadata: ReportMetadata) -> str:
        """Generate PDF report."""
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        
        story.append(Paragraph(f"{metadata.report_type.replace('_', ' ').title()} Report", title_style))
        story.append(Spacer(1, 12))
        
        # Metadata
        story.append(Paragraph(f"Generated: {metadata.generated_at}", styles['Normal']))
        story.append(Paragraph(f"Period: {metadata.period_start} to {metadata.period_end}", styles['Normal']))
        story.append(Paragraph(f"Total Records: {metadata.total_records}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Add data sections
        for section_name, section_data in data.items():
            if section_name != 'records':
                story.append(Paragraph(section_name.replace('_', ' ').title(), styles['Heading2']))
                
                if isinstance(section_data, dict):
                    for key, value in section_data.items():
                        story.append(Paragraph(f"{key}: {value}", styles['Normal']))
                else:
                    story.append(Paragraph(str(section_data), styles['Normal']))
                
                story.append(Spacer(1, 12))
        
        # Add charts
        for chart_path in charts:
            if chart_path:
                story.append(Image(chart_path, width=6*inch, height=4*inch))
                story.append(Spacer(1, 12))
        
        doc.build(story)
        return file_path
    
    def _generate_html_report(self, file_path: str, data: Dict[str, Any],
                            charts: List[str], metadata: ReportMetadata) -> str:
        """Generate HTML report."""
        template = self.templates.get('html_report', self._get_default_html_template())
        
        html_content = template.render(
            metadata=asdict(metadata),
            data=data,
            charts=charts
        )
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return file_path
    
    def _generate_csv_report(self, file_path: str, data: Dict[str, Any],
                           metadata: ReportMetadata) -> str:
        """Generate CSV report."""
        records = data.get('records', [])
        
        if records:
            df = pd.DataFrame(records)
            df.to_csv(file_path, index=False)
        else:
            # Create CSV with summary data
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Report Type', 'Generated At', 'Period Start', 'Period End'])
                writer.writerow([
                    metadata.report_type,
                    metadata.generated_at,
                    metadata.period_start,
                    metadata.period_end
                ])
        
        return file_path
    
    def _generate_json_report(self, file_path: str, data: Dict[str, Any],
                            metadata: ReportMetadata) -> str:
        """Generate JSON report."""
        report_data = {
            'metadata': asdict(metadata),
            'data': data
        }
        
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return file_path
    
    def _generate_excel_report(self, file_path: str, data: Dict[str, Any],
                             charts: List[str], metadata: ReportMetadata) -> str:
        """Generate Excel report."""
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = {
                'Report Type': [metadata.report_type],
                'Generated At': [metadata.generated_at],
                'Period Start': [metadata.period_start],
                'Period End': [metadata.period_end],
                'Total Records': [metadata.total_records]
            }
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Data sheets
            records = data.get('records', [])
            if records:
                records_df = pd.DataFrame(records)
                records_df.to_excel(writer, sheet_name='Data', index=False)
        
        return file_path
    
    def _load_templates(self) -> Dict[str, Template]:
        """Load report templates."""
        return {
            'html_report': Template(self._get_default_html_template())
        }
    
    def _get_default_html_template(self) -> str:
        """Get default HTML template."""
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ metadata.report_type.replace('_', ' ').title() }} Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { text-align: center; margin-bottom: 30px; }
                .metadata { background-color: #f5f5f5; padding: 15px; margin-bottom: 20px; }
                .section { margin-bottom: 25px; }
                .chart { text-align: center; margin: 20px 0; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ metadata.report_type.replace('_', ' ').title() }} Report</h1>
            </div>
            
            <div class="metadata">
                <p><strong>Generated:</strong> {{ metadata.generated_at }}</p>
                <p><strong>Period:</strong> {{ metadata.period_start }} to {{ metadata.period_end }}</p>
                <p><strong>Total Records:</strong> {{ metadata.total_records }}</p>
            </div>
            
            {% for section_name, section_data in data.items() %}
                {% if section_name != 'records' %}
                <div class="section">
                    <h2>{{ section_name.replace('_', ' ').title() }}</h2>
                    {% if section_data is mapping %}
                        {% for key, value in section_data.items() %}
                            <p><strong>{{ key }}:</strong> {{ value }}</p>
                        {% endfor %}
                    {% else %}
                        <p>{{ section_data }}</p>
                    {% endif %}
                </div>
                {% endif %}
            {% endfor %}
            
            {% for chart in charts %}
                <div class="chart">
                    <img src="{{ chart }}" alt="Chart">
                </div>
            {% endfor %}
        </body>
        </html>
        '''
    
    def _generate_report_id(self, report_type: str, format: str) -> str:
        """Generate unique report ID."""
        import secrets
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return f"{report_type}_{format}_{timestamp}_{secrets.token_hex(4)}"
    
    def _generate_schedule_id(self) -> str:
        """Generate unique schedule ID."""
        import secrets
        return f"schedule_{secrets.token_hex(8)}"
    
    def _generate_download_url(self, file_path: str) -> str:
        """Generate download URL for the report."""
        filename = file_path.split('/')[-1]
        return f"{self.config.get('base_url', '')}/reports/download/{filename}"
    
    def _log_report_generation(self, metadata: ReportMetadata, admin_id: str):
        """Log report generation activity."""
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'admin_id': admin_id,
            'report_id': metadata.report_id,
            'report_type': metadata.report_type,
            'format': metadata.format,
            'file_size': metadata.file_size,
            'generation_time': 'calculated_duration'  # Would calculate actual duration
        }
        
        # In production, store this in audit log
        print(f"Report generated: {log_entry}")
    
    def _create_formatted_report(self, report_type: str, format: str,
                               data: Dict[str, Any], charts: List[ChartConfig]) -> Dict[str, Any]:
        """Create formatted report with charts."""
        # Generate chart images
        chart_paths = []
        for chart_config in charts:
            chart_path = self._create_chart(chart_config)
            if chart_path:
                chart_paths.append(chart_path)
        
        # Create metadata
        metadata = ReportMetadata(
            report_id=self._generate_report_id(report_type, format),
            report_type=report_type,
            format=format,
            generated_at=datetime.now(timezone.utc).isoformat(),
            generated_by='system',
            period_start=datetime.now(timezone.utc).isoformat(),
            period_end=datetime.now(timezone.utc).isoformat(),
            total_records=len(data.get('records', [])),
            file_size=0,
            parameters={}
        )
        
        # Generate report file
        file_path = self._generate_report_file(report_type, format, data, chart_paths, metadata)
        
        return {
            'success': True,
            'report_id': metadata.report_id,
            'file_path': file_path,
            'metadata': asdict(metadata)
        }
    
    def _create_chart(self, chart_config: ChartConfig) -> str:
        """Create chart image from configuration."""
        try:
            plt.figure(figsize=(chart_config.width/100, chart_config.height/100))
            
            if chart_config.chart_type == 'bar':
                x_values = [item.get('x', '') for item in chart_config.data]
                y_values = [item.get('y', 0) for item in chart_config.data]
                plt.bar(x_values, y_values, color=chart_config.colors or 'blue')
            
            elif chart_config.chart_type == 'line':
                x_values = [item.get('x', '') for item in chart_config.data]
                y_values = [item.get('y', 0) for item in chart_config.data]
                plt.plot(x_values, y_values, color=chart_config.colors[0] if chart_config.colors else 'blue')
            
            elif chart_config.chart_type == 'pie':
                labels = [item.get('label', '') for item in chart_config.data]
                values = [item.get('value', 0) for item in chart_config.data]
                plt.pie(values, labels=labels, colors=chart_config.colors, autopct='%1.1f%%')
            
            plt.title(chart_config.title)
            plt.xlabel(chart_config.x_label)
            plt.ylabel(chart_config.y_label)
            
            # Save chart
            chart_filename = f"chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(chart_config.title)}.png"
            chart_path = f"{self.output_directory}/{chart_filename}"
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            print(f"Failed to create chart: {e}")
            return None
```

#### Usage Examples

```python
# Example 1: Generate system analytics report
from app.admin.utils.reports import AdminReportGenerator

config = {
    'output_directory': './reports',
    'template_directory': './templates',
    'base_url': 'https://admin.example.com'
}

generator = AdminReportGenerator(config, database_connection)

# Generate comprehensive system analytics report
result = generator.generate_system_analytics_report(
    period='last_30_days',
    format='pdf'
)

print(f"Report generated: {result['file_path']}")

# Example 2: Generate security summary report
security_result = generator.generate_security_summary_report(
    period='last_7_days',
    format='html',
    include_details=True
)

# Example 3: Generate compliance audit report
compliance_result = generator.generate_compliance_audit_report(
    compliance_framework='SOC2',
    format='pdf'
)

# Example 4: Generate custom report with SQL query
custom_result = generator.generate_custom_report(
    query="""
        SELECT DATE(created_at) as date, COUNT(*) as user_count
        FROM users 
        WHERE created_at >= NOW() - INTERVAL 30 DAY
        GROUP BY DATE(created_at)
        ORDER BY date
    """,
    title='User Registration Trends',
    format='excel',
    chart_configs=[
        ChartConfig(
            chart_type='line',
            title='Daily User Registrations',
            x_label='Date',
            y_label='New Users',
            data=[]  # Would be populated from query results
        )
    ]
)

# Example 5: Schedule automated reports
schedule_result = generator.schedule_report(
    report_config={
        'report_type': 'system_analytics',
        'format': 'pdf',
        'period': 'last_7_days',
        'include_charts': True
    },
    schedule='0 9 * * 1',  # Every Monday at 9 AM
    recipients=['admin@example.com', 'manager@example.com']
)

print(f"Report scheduled: {schedule_result['schedule_id']}")

# Example 6: Export data in multiple formats
data_to_export = {
    'records': [
        {'date': '2024-01-01', 'users': 100, 'revenue': 5000},
        {'date': '2024-01-02', 'users': 120, 'revenue': 6000},
        {'date': '2024-01-03', 'users': 95, 'revenue': 4750}
    ]
}

# Export as CSV
csv_path = generator.export_data(data_to_export, 'csv', 'daily_metrics.csv')

# Export as JSON
json_path = generator.export_data(data_to_export, 'json', 'daily_metrics.json')

# Export as Excel
excel_path = generator.export_data(data_to_export, 'excel', 'daily_metrics.xlsx')

print(f"Data exported to: {csv_path}, {json_path}, {excel_path}")
```

---

## Integration Examples

### Complete Admin Helper Integration

```python
# Example: Comprehensive admin operation with all helpers
from app.admin.utils.helpers import (
    AdminDataFormatter, AdminValidator, AdminPermissionChecker,
    AdminSessionManager, AdminAuditLogger, AdminNotificationSender,
    AdminReportGenerator
)

class AdminOperationService:
    """Service that integrates all admin helper utilities."""
    
    def __init__(self, config: Dict[str, Any], db_connection):
        self.formatter = AdminDataFormatter()
        self.validator = AdminValidator()
        self.permission_checker = AdminPermissionChecker(config['permissions'])
        self.session_manager = AdminSessionManager(config['session'])
        self.audit_logger = AdminAuditLogger(config['audit'])
        self.notification_sender = AdminNotificationSender(config['notifications'])
        self.report_generator = AdminReportGenerator(config['reports'], db_connection)
    
    async def perform_admin_action(self, admin_id: str, action: str, 
                                 data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive admin action with full logging and validation."""
        
        # 1. Validate session
        session_valid = await self.session_manager.validate_session(admin_id)
        if not session_valid['valid']:
            return {'success': False, 'error': 'Invalid session'}
        
        # 2. Check permissions
        has_permission = await self.permission_checker.check_permission(
            admin_id, action, data.get('resource_type')
        )
        if not has_permission:
            await self.audit_logger.log_action(
                admin_id, action, data, 'PERMISSION_DENIED', 'high'
            )
            return {'success': False, 'error': 'Permission denied'}
        
        # 3. Validate input data
        validation_result = self.validator.validate_admin_data(data, action)
        if not validation_result['valid']:
            return {'success': False, 'errors': validation_result['errors']}
        
        # 4. Format data
        formatted_data = self.formatter.format_admin_response(data)
        
        # 5. Perform action (implementation specific)
        try:
            result = await self._execute_action(action, formatted_data)
            
            # 6. Log successful action
            await self.audit_logger.log_action(
                admin_id, action, formatted_data, 'SUCCESS', 'medium'
            )
            
            # 7. Send notification if needed
            if action in ['user_suspension', 'security_alert', 'system_maintenance']:
                await self.notification_sender.send_security_alert(
                    alert_type=f'Admin Action: {action}',
                    details={
                        'admin_id': admin_id,
                        'action': action,
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'medium'
                    }
                )
            
            return {'success': True, 'result': result}
            
        except Exception as e:
            # 8. Log failed action
            await self.audit_logger.log_action(
                admin_id, action, formatted_data, 'ERROR', 'high'
            )
            
            return {'success': False, 'error': str(e)}
    
    async def generate_admin_dashboard_report(self, admin_id: str) -> Dict[str, Any]:
        """Generate comprehensive dashboard report."""
        
        # Check permissions
        has_permission = await self.permission_checker.check_permission(
            admin_id, 'generate_report', 'dashboard'
        )
        if not has_permission:
            return {'success': False, 'error': 'Permission denied'}
        
        # Generate report
        report_result = self.report_generator.generate_system_analytics_report(
            period='last_30_days',
            format='pdf'
        )
        
        # Log report generation
        await self.audit_logger.log_action(
            admin_id, 'generate_report', {'report_type': 'dashboard'}, 'SUCCESS', 'low'
        )
        
        # Send notification
        await self.notification_sender.send_notification(
            notification_type='email',
            recipients=[await self._get_admin_email(admin_id)],
            subject='Dashboard Report Generated',
            message=f'Your dashboard report has been generated and is ready for download.',
            priority='normal'
        )
        
        return report_result
    
    async def _execute_action(self, action: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the specific admin action."""
        # Implementation would depend on the specific action
        return {'action': action, 'data': data, 'executed_at': datetime.now().isoformat()}
    
    async def _get_admin_email(self, admin_id: str) -> str:
        """Get admin email address."""
        # Implementation would query database
        return f"admin-{admin_id}@example.com"

# Usage
config = {
    'permissions': {'roles_file': 'admin_roles.json'},
    'session': {'secret_key': 'your-secret-key', 'expire_hours': 8},
    'audit': {'log_file': 'admin_audit.log', 'db_connection': db},
    'notifications': {'smtp': {...}, 'slack': {...}},
    'reports': {'output_directory': './reports'}
}

admin_service = AdminOperationService(config, db_connection)

# Perform admin action
result = await admin_service.perform_admin_action(
    admin_id='admin-123',
    action='suspend_user',
    data={'user_id': 'user-456', 'reason': 'Policy violation'}
)

# Generate dashboard report
report_result = await admin_service.generate_admin_dashboard_report('admin-123')
```

This comprehensive documentation covers all seven admin helper classes with practical examples, integration patterns, and real-world usage scenarios. Each class is designed to work independently or as part of a larger admin management system.