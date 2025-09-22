# Admin Audit System Documentation

## Overview

The Admin Audit System provides comprehensive logging and monitoring of all administrative actions within LinkShield. This system ensures accountability, compliance, and security by tracking every admin operation, maintaining detailed audit trails, and providing tools for audit analysis and reporting.

**Key Features:**
- Real-time audit logging of all admin actions
- Data sanitization and PII protection
- Comprehensive audit trail with full context
- Advanced search and filtering capabilities
- Compliance reporting and export functionality
- Automated anomaly detection and alerting
- Integration with security monitoring systems

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Admin Audit System                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Audit          │  │  Data           │  │  Security       │ │
│  │  Middleware     │  │  Sanitizer      │  │  Monitor        │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│           │                     │                     │         │
│           ▼                     ▼                     ▼         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Audit          │  │  Audit          │  │  Alert          │ │
│  │  Logger         │  │  Database       │  │  System         │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│           │                     │                     │         │
│           ▼                     ▼                     ▼         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Audit          │  │  Compliance     │  │  Reporting      │ │
│  │  Analyzer       │  │  Engine         │  │  Service        │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Middleware Architecture

The audit system is implemented as FastAPI middleware that intercepts all admin requests:

```python
# File: app/middleware/audit_middleware.py

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable
import time
import json
import uuid
from datetime import datetime

class AdminAuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware for auditing all admin actions and API calls.
    
    This middleware captures:
    - Request details (method, path, headers, body)
    - Response details (status, headers, body)
    - User context (admin ID, role, IP address)
    - Timing information
    - Security context
    """
    
    def __init__(self, app, audit_service: AuditService):
        super().__init__(app)
        self.audit_service = audit_service
        self.excluded_paths = [
            "/api/v1/admin/health",
            "/api/v1/admin/monitoring/health",
            "/docs",
            "/openapi.json"
        ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip audit for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)
        
        # Generate audit ID for request tracking
        audit_id = str(uuid.uuid4())
        start_time = time.time()
        
        # Extract request context
        request_context = await self._extract_request_context(request, audit_id)
        
        try:
            # Process the request
            response = await call_next(request)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Extract response context
            response_context = await self._extract_response_context(response, processing_time)
            
            # Log the audit entry
            await self._log_audit_entry(request_context, response_context)
            
            return response
            
        except Exception as e:
            # Log failed requests
            processing_time = time.time() - start_time
            error_context = {
                "error": str(e),
                "error_type": type(e).__name__,
                "processing_time_ms": round(processing_time * 1000, 2)
            }
            
            await self._log_audit_entry(request_context, error_context, is_error=True)
            raise
```

### Data Model

#### Audit Log Entry Schema

```python
# File: app/models/audit.py

from sqlalchemy import Column, String, DateTime, Text, Integer, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID
from app.database.base import Base
import uuid
from datetime import datetime

class AdminAuditLog(Base):
    """
    Admin audit log entry model.
    
    Stores comprehensive information about admin actions including:
    - Request/response details
    - User context and authentication
    - Security and compliance metadata
    - Performance metrics
    """
    
    __tablename__ = "admin_audit_logs"
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(String(36), unique=True, nullable=False, index=True)
    
    # Timestamp information
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    date_partition = Column(String(10), nullable=False, index=True)  # YYYY-MM-DD for partitioning
    
    # User context
    admin_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    admin_email = Column(String(255), nullable=False)
    admin_role = Column(String(50), nullable=False)
    
    # Request information
    http_method = Column(String(10), nullable=False)
    endpoint_path = Column(String(500), nullable=False, index=True)
    full_url = Column(Text, nullable=False)
    user_agent = Column(Text)
    
    # Network context
    client_ip = Column(String(45), nullable=False, index=True)  # IPv6 support
    forwarded_for = Column(String(255))  # X-Forwarded-For header
    country_code = Column(String(2))  # Geolocation
    
    # Request/Response details
    request_headers = Column(JSON)
    request_body_hash = Column(String(64))  # SHA-256 hash of request body
    request_size_bytes = Column(Integer)
    
    response_status = Column(Integer, nullable=False, index=True)
    response_headers = Column(JSON)
    response_body_hash = Column(String(64))  # SHA-256 hash of response body
    response_size_bytes = Column(Integer)
    
    # Performance metrics
    processing_time_ms = Column(Integer, nullable=False)
    database_queries_count = Column(Integer, default=0)
    database_time_ms = Column(Integer, default=0)
    
    # Security context
    session_id = Column(String(128), index=True)
    jwt_token_id = Column(String(36))  # JWT jti claim
    authentication_method = Column(String(50))  # jwt, api_key, etc.
    
    # Action classification
    action_category = Column(String(50), nullable=False, index=True)  # user_management, system_config, etc.
    action_type = Column(String(50), nullable=False, index=True)      # create, read, update, delete
    resource_type = Column(String(50), index=True)                    # user, configuration, etc.
    resource_id = Column(String(100), index=True)                     # ID of affected resource
    
    # Risk and compliance
    risk_level = Column(String(20), default="low", index=True)        # low, medium, high, critical
    compliance_flags = Column(JSON)                                   # GDPR, SOX, etc.
    sensitive_data_accessed = Column(Boolean, default=False, index=True)
    
    # Status and metadata
    is_successful = Column(Boolean, nullable=False, index=True)
    is_suspicious = Column(Boolean, default=False, index=True)
    error_code = Column(String(50))
    error_message = Column(Text)
    
    # Additional context
    business_context = Column(JSON)  # Business-specific metadata
    technical_context = Column(JSON)  # Technical metadata
    tags = Column(JSON)  # Searchable tags
    
    # Data retention
    retention_policy = Column(String(50), default="standard")  # standard, extended, permanent
    archived_at = Column(DateTime)
    
    def __repr__(self):
        return f"<AdminAuditLog {self.audit_id}: {self.admin_email} {self.http_method} {self.endpoint_path}>"
```

#### Audit Configuration Model

```python
# File: app/models/audit_config.py

class AdminAuditConfig(Base):
    """
    Configuration for audit system behavior.
    """
    
    __tablename__ = "admin_audit_config"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    config_key = Column(String(100), unique=True, nullable=False)
    config_value = Column(JSON, nullable=False)
    description = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(UUID(as_uuid=True), nullable=False)
    
    is_active = Column(Boolean, default=True)
    environment = Column(String(20), default="production")  # production, staging, development
```

## Data Sanitization

### Sensitive Data Protection

The audit system implements comprehensive data sanitization to protect sensitive information:

```python
# File: app/services/audit_sanitizer.py

import re
import hashlib
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

@dataclass
class SanitizationRule:
    """Configuration for data sanitization rules."""
    pattern: str
    replacement: str
    field_names: List[str]
    is_regex: bool = True
    hash_original: bool = False

class AuditDataSanitizer:
    """
    Sanitizes sensitive data in audit logs while preserving audit integrity.
    
    Features:
    - PII detection and masking
    - Credential sanitization
    - Configurable sanitization rules
    - Hash preservation for data integrity
    - Compliance with data protection regulations
    """
    
    def __init__(self):
        self.sanitization_rules = self._load_sanitization_rules()
        self.sensitive_headers = {
            'authorization', 'cookie', 'x-api-key', 'x-auth-token',
            'x-csrf-token', 'x-session-id', 'authentication'
        }
        self.pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
    
    def sanitize_request_data(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize request data for audit logging.
        
        Args:
            request_data: Raw request data including headers, body, etc.
            
        Returns:
            Sanitized request data safe for audit logging
        """
        sanitized = request_data.copy()
        
        # Sanitize headers
        if 'headers' in sanitized:
            sanitized['headers'] = self._sanitize_headers(sanitized['headers'])
        
        # Sanitize request body
        if 'body' in sanitized:
            sanitized['body'] = self._sanitize_body(sanitized['body'])
        
        # Sanitize query parameters
        if 'query_params' in sanitized:
            sanitized['query_params'] = self._sanitize_query_params(sanitized['query_params'])
        
        return sanitized
    
    def sanitize_response_data(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize response data for audit logging.
        
        Args:
            response_data: Raw response data including headers, body, etc.
            
        Returns:
            Sanitized response data safe for audit logging
        """
        sanitized = response_data.copy()
        
        # Sanitize response headers
        if 'headers' in sanitized:
            sanitized['headers'] = self._sanitize_headers(sanitized['headers'])
        
        # Sanitize response body
        if 'body' in sanitized:
            sanitized['body'] = self._sanitize_response_body(sanitized['body'])
        
        return sanitized
    
    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize HTTP headers by masking sensitive values."""
        sanitized = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            if key_lower in self.sensitive_headers:
                # Mask sensitive headers but preserve structure
                if value.startswith('Bearer '):
                    sanitized[key] = 'Bearer [REDACTED]'
                elif value.startswith('Basic '):
                    sanitized[key] = 'Basic [REDACTED]'
                else:
                    sanitized[key] = '[REDACTED]'
            else:
                # Apply PII sanitization to other headers
                sanitized[key] = self._sanitize_text(value)
        
        return sanitized
    
    def _sanitize_body(self, body: Any) -> Any:
        """Sanitize request/response body data."""
        if isinstance(body, dict):
            return self._sanitize_dict(body)
        elif isinstance(body, list):
            return [self._sanitize_body(item) for item in body]
        elif isinstance(body, str):
            return self._sanitize_text(body)
        else:
            return body
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize dictionary data recursively."""
        sanitized = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if field contains sensitive data
            if self._is_sensitive_field(key_lower):
                if isinstance(value, str) and value:
                    # Hash sensitive values for integrity while hiding content
                    sanitized[key] = f"[HASHED:{self._hash_value(value)[:16]}]"
                else:
                    sanitized[key] = "[REDACTED]"
            else:
                # Recursively sanitize nested data
                sanitized[key] = self._sanitize_body(value)
        
        return sanitized
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize text content by masking PII patterns."""
        if not isinstance(text, str):
            return text
        
        sanitized = text
        
        # Apply PII pattern sanitization
        for pii_type, pattern in self.pii_patterns.items():
            sanitized = re.sub(pattern, f'[{pii_type.upper()}_REDACTED]', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field name indicates sensitive data."""
        sensitive_keywords = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'key',
            'auth', 'credential', 'private', 'confidential', 'ssn',
            'social_security', 'credit_card', 'card_number', 'cvv',
            'pin', 'otp', 'verification_code'
        }
        
        return any(keyword in field_name for keyword in sensitive_keywords)
    
    def _hash_value(self, value: str) -> str:
        """Generate SHA-256 hash of sensitive value for integrity checking."""
        return hashlib.sha256(value.encode('utf-8')).hexdigest()
    
    def _load_sanitization_rules(self) -> List[SanitizationRule]:
        """Load configurable sanitization rules."""
        return [
            SanitizationRule(
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                replacement='[EMAIL_REDACTED]',
                field_names=['email', 'user_email', 'admin_email'],
                is_regex=True
            ),
            SanitizationRule(
                pattern=r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                replacement='[CARD_REDACTED]',
                field_names=['credit_card', 'card_number'],
                is_regex=True,
                hash_original=True
            )
        ]
```

## Security Features

### Access Control and Authorization

```python
# File: app/services/audit_security.py

from enum import Enum
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, status

class AuditAccessLevel(Enum):
    """Audit access levels for role-based access control."""
    READ_OWN = "read_own"           # Can read own audit logs only
    READ_TEAM = "read_team"         # Can read team audit logs
    READ_ALL = "read_all"           # Can read all audit logs
    ADMIN = "admin"                 # Full audit administration access
    SYSTEM = "system"               # System-level audit access

class AuditSecurityService:
    """
    Security service for audit system access control and monitoring.
    """
    
    def __init__(self):
        self.role_permissions = {
            "admin": [AuditAccessLevel.READ_OWN, AuditAccessLevel.READ_TEAM],
            "super_admin": [AuditAccessLevel.READ_ALL, AuditAccessLevel.ADMIN],
            "security_officer": [AuditAccessLevel.READ_ALL, AuditAccessLevel.ADMIN],
            "system": [AuditAccessLevel.SYSTEM]
        }
        
        self.sensitive_endpoints = {
            "/api/v1/admin/users/*/delete",
            "/api/v1/admin/system/config",
            "/api/v1/admin/security/settings",
            "/api/v1/admin/audit/export"
        }
    
    def check_audit_access(self, user_role: str, requested_access: AuditAccessLevel, 
                          target_admin_id: Optional[str] = None) -> bool:
        """
        Check if user has required audit access level.
        
        Args:
            user_role: User's role
            requested_access: Required access level
            target_admin_id: ID of admin whose logs are being accessed
            
        Returns:
            True if access is granted, False otherwise
        """
        user_permissions = self.role_permissions.get(user_role, [])
        
        if requested_access not in user_permissions:
            return False
        
        # Additional checks for specific access levels
        if requested_access == AuditAccessLevel.READ_OWN and target_admin_id:
            # User can only access their own logs
            return target_admin_id == self._get_current_user_id()
        
        return True
    
    def classify_action_risk(self, endpoint: str, method: str, 
                           user_role: str, request_data: Dict[str, Any]) -> str:
        """
        Classify the risk level of an admin action.
        
        Args:
            endpoint: API endpoint being accessed
            method: HTTP method
            user_role: User's role
            request_data: Request data
            
        Returns:
            Risk level: "low", "medium", "high", "critical"
        """
        risk_score = 0
        
        # Base risk by HTTP method
        method_risk = {
            "GET": 1,
            "POST": 2,
            "PUT": 3,
            "PATCH": 3,
            "DELETE": 4
        }
        risk_score += method_risk.get(method, 1)
        
        # Endpoint-specific risk
        if any(pattern in endpoint for pattern in self.sensitive_endpoints):
            risk_score += 3
        
        # Role-based risk adjustment
        role_risk = {
            "admin": 1,
            "super_admin": 2,
            "security_officer": 1
        }
        risk_score += role_risk.get(user_role, 0)
        
        # Data sensitivity risk
        if self._contains_sensitive_data(request_data):
            risk_score += 2
        
        # Convert score to risk level
        if risk_score <= 2:
            return "low"
        elif risk_score <= 4:
            return "medium"
        elif risk_score <= 6:
            return "high"
        else:
            return "critical"
    
    def detect_suspicious_activity(self, audit_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect suspicious patterns in audit entries.
        
        Args:
            audit_entries: List of recent audit entries
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        # Check for rapid successive actions
        anomalies.extend(self._detect_rapid_actions(audit_entries))
        
        # Check for unusual access patterns
        anomalies.extend(self._detect_unusual_access(audit_entries))
        
        # Check for privilege escalation attempts
        anomalies.extend(self._detect_privilege_escalation(audit_entries))
        
        # Check for data exfiltration patterns
        anomalies.extend(self._detect_data_exfiltration(audit_entries))
        
        return anomalies
    
    def _detect_rapid_actions(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusually rapid successive actions."""
        anomalies = []
        
        # Group entries by admin and check timing
        admin_actions = {}
        for entry in entries:
            admin_id = entry.get('admin_id')
            if admin_id not in admin_actions:
                admin_actions[admin_id] = []
            admin_actions[admin_id].append(entry)
        
        for admin_id, actions in admin_actions.items():
            if len(actions) >= 10:  # 10+ actions
                # Check if actions occurred within 1 minute
                timestamps = [action['timestamp'] for action in actions]
                timestamps.sort()
                
                if (timestamps[-1] - timestamps[0]).total_seconds() < 60:
                    anomalies.append({
                        'type': 'rapid_actions',
                        'severity': 'medium',
                        'admin_id': admin_id,
                        'action_count': len(actions),
                        'time_window_seconds': (timestamps[-1] - timestamps[0]).total_seconds(),
                        'description': f'Admin performed {len(actions)} actions in {(timestamps[-1] - timestamps[0]).total_seconds():.1f} seconds'
                    })
        
        return anomalies
    
    def _contains_sensitive_data(self, data: Dict[str, Any]) -> bool:
        """Check if request data contains sensitive information."""
        sensitive_keys = {
            'password', 'secret', 'token', 'key', 'credential',
            'ssn', 'social_security', 'credit_card', 'bank_account'
        }
        
        def check_dict(d):
            if isinstance(d, dict):
                for key, value in d.items():
                    if any(sensitive in key.lower() for sensitive in sensitive_keys):
                        return True
                    if isinstance(value, (dict, list)):
                        if check_dict(value):
                            return True
            elif isinstance(d, list):
                for item in d:
                    if check_dict(item):
                        return True
            return False
        
        return check_dict(data)
```

## Audit Trail Management

### Comprehensive Logging Service

```python
# File: app/services/audit_service.py

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import asyncio
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc, func
from app.models.audit import AdminAuditLog
from app.services.audit_sanitizer import AuditDataSanitizer
from app.services.audit_security import AuditSecurityService

class AdminAuditService:
    """
    Comprehensive audit service for admin actions.
    
    Features:
    - Asynchronous audit logging
    - Data sanitization and security
    - Advanced search and filtering
    - Compliance reporting
    - Anomaly detection
    """
    
    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self.sanitizer = AuditDataSanitizer()
        self.security = AuditSecurityService()
        self.batch_size = 100
        self.batch_timeout = 5.0  # seconds
        self._batch_queue = []
        self._batch_task = None
    
    async def log_admin_action(self, audit_data: Dict[str, Any]) -> str:
        """
        Log an admin action to the audit trail.
        
        Args:
            audit_data: Complete audit information
            
        Returns:
            Audit ID for the logged entry
        """
        # Sanitize sensitive data
        sanitized_data = self.sanitizer.sanitize_request_data(audit_data)
        
        # Classify risk level
        risk_level = self.security.classify_action_risk(
            audit_data.get('endpoint_path', ''),
            audit_data.get('http_method', ''),
            audit_data.get('admin_role', ''),
            audit_data.get('request_data', {})
        )
        
        # Create audit log entry
        audit_entry = AdminAuditLog(
            audit_id=audit_data['audit_id'],
            timestamp=datetime.utcnow(),
            date_partition=datetime.utcnow().strftime('%Y-%m-%d'),
            
            # User context
            admin_id=audit_data['admin_id'],
            admin_email=audit_data['admin_email'],
            admin_role=audit_data['admin_role'],
            
            # Request information
            http_method=audit_data['http_method'],
            endpoint_path=audit_data['endpoint_path'],
            full_url=audit_data['full_url'],
            user_agent=audit_data.get('user_agent'),
            
            # Network context
            client_ip=audit_data['client_ip'],
            forwarded_for=audit_data.get('forwarded_for'),
            country_code=audit_data.get('country_code'),
            
            # Request/Response details
            request_headers=sanitized_data.get('request_headers'),
            request_body_hash=audit_data.get('request_body_hash'),
            request_size_bytes=audit_data.get('request_size_bytes', 0),
            
            response_status=audit_data['response_status'],
            response_headers=sanitized_data.get('response_headers'),
            response_body_hash=audit_data.get('response_body_hash'),
            response_size_bytes=audit_data.get('response_size_bytes', 0),
            
            # Performance metrics
            processing_time_ms=audit_data['processing_time_ms'],
            database_queries_count=audit_data.get('database_queries_count', 0),
            database_time_ms=audit_data.get('database_time_ms', 0),
            
            # Security context
            session_id=audit_data.get('session_id'),
            jwt_token_id=audit_data.get('jwt_token_id'),
            authentication_method=audit_data.get('authentication_method', 'jwt'),
            
            # Action classification
            action_category=audit_data.get('action_category', 'general'),
            action_type=audit_data.get('action_type', 'read'),
            resource_type=audit_data.get('resource_type'),
            resource_id=audit_data.get('resource_id'),
            
            # Risk and compliance
            risk_level=risk_level,
            compliance_flags=audit_data.get('compliance_flags', {}),
            sensitive_data_accessed=audit_data.get('sensitive_data_accessed', False),
            
            # Status
            is_successful=audit_data['response_status'] < 400,
            error_code=audit_data.get('error_code'),
            error_message=audit_data.get('error_message'),
            
            # Additional context
            business_context=audit_data.get('business_context', {}),
            technical_context=audit_data.get('technical_context', {}),
            tags=audit_data.get('tags', [])
        )
        
        # Add to batch queue for efficient processing
        await self._add_to_batch(audit_entry)
        
        return audit_entry.audit_id
    
    async def search_audit_logs(self, filters: Dict[str, Any], 
                               page: int = 1, per_page: int = 100) -> Dict[str, Any]:
        """
        Search audit logs with advanced filtering.
        
        Args:
            filters: Search filters
            page: Page number (1-based)
            per_page: Items per page
            
        Returns:
            Search results with pagination
        """
        query = select(AdminAuditLog)
        
        # Apply filters
        conditions = []
        
        if filters.get('admin_id'):
            conditions.append(AdminAuditLog.admin_id == filters['admin_id'])
        
        if filters.get('admin_email'):
            conditions.append(AdminAuditLog.admin_email.ilike(f"%{filters['admin_email']}%"))
        
        if filters.get('start_date'):
            conditions.append(AdminAuditLog.timestamp >= filters['start_date'])
        
        if filters.get('end_date'):
            conditions.append(AdminAuditLog.timestamp <= filters['end_date'])
        
        if filters.get('action_category'):
            conditions.append(AdminAuditLog.action_category == filters['action_category'])
        
        if filters.get('action_type'):
            conditions.append(AdminAuditLog.action_type == filters['action_type'])
        
        if filters.get('risk_level'):
            conditions.append(AdminAuditLog.risk_level == filters['risk_level'])
        
        if filters.get('is_successful') is not None:
            conditions.append(AdminAuditLog.is_successful == filters['is_successful'])
        
        if filters.get('endpoint_path'):
            conditions.append(AdminAuditLog.endpoint_path.ilike(f"%{filters['endpoint_path']}%"))
        
        if filters.get('client_ip'):
            conditions.append(AdminAuditLog.client_ip == filters['client_ip'])
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Apply ordering
        query = query.order_by(desc(AdminAuditLog.timestamp))
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await self.db.execute(query)
        logs = result.scalars().all()
        
        # Get total count
        count_query = select(func.count(AdminAuditLog.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        count_result = await self.db.execute(count_query)
        total_count = count_result.scalar()
        
        return {
            'logs': [self._serialize_audit_log(log) for log in logs],
            'pagination': {
                'current_page': page,
                'per_page': per_page,
                'total_items': total_count,
                'total_pages': (total_count + per_page - 1) // per_page,
                'has_next': page * per_page < total_count,
                'has_previous': page > 1
            }
        }
    
    async def generate_compliance_report(self, report_type: str, 
                                       start_date: datetime, 
                                       end_date: datetime) -> Dict[str, Any]:
        """
        Generate compliance reports for audit data.
        
        Args:
            report_type: Type of report (gdpr, sox, hipaa, etc.)
            start_date: Report start date
            end_date: Report end date
            
        Returns:
            Compliance report data
        """
        query = select(AdminAuditLog).where(
            and_(
                AdminAuditLog.timestamp >= start_date,
                AdminAuditLog.timestamp <= end_date
            )
        )
        
        result = await self.db.execute(query)
        logs = result.scalars().all()
        
        # Generate report based on type
        if report_type == 'gdpr':
            return self._generate_gdpr_report(logs, start_date, end_date)
        elif report_type == 'sox':
            return self._generate_sox_report(logs, start_date, end_date)
        elif report_type == 'general':
            return self._generate_general_report(logs, start_date, end_date)
        else:
            raise ValueError(f"Unsupported report type: {report_type}")
    
    def _serialize_audit_log(self, log: AdminAuditLog) -> Dict[str, Any]:
        """Serialize audit log entry for API response."""
        return {
            'id': str(log.id),
            'audit_id': log.audit_id,
            'timestamp': log.timestamp.isoformat(),
            'admin_id': str(log.admin_id),
            'admin_email': log.admin_email,
            'admin_role': log.admin_role,
            'http_method': log.http_method,
            'endpoint_path': log.endpoint_path,
            'client_ip': log.client_ip,
            'response_status': log.response_status,
            'processing_time_ms': log.processing_time_ms,
            'action_category': log.action_category,
            'action_type': log.action_type,
            'resource_type': log.resource_type,
            'resource_id': log.resource_id,
            'risk_level': log.risk_level,
            'is_successful': log.is_successful,
            'is_suspicious': log.is_suspicious,
            'error_code': log.error_code,
            'tags': log.tags
        }
```

## Configuration and Integration

### Environment Configuration

```python
# File: app/config/audit_config.py

from pydantic import BaseSettings
from typing import List, Dict, Any

class AuditConfig(BaseSettings):
    """Configuration for the audit system."""
    
    # Database settings
    AUDIT_DB_RETENTION_DAYS: int = 2555  # 7 years default
    AUDIT_DB_PARTITION_ENABLED: bool = True
    AUDIT_DB_COMPRESSION_ENABLED: bool = True
    
    # Logging settings
    AUDIT_LOG_LEVEL: str = "INFO"
    AUDIT_BATCH_SIZE: int = 100
    AUDIT_BATCH_TIMEOUT: float = 5.0
    AUDIT_ASYNC_ENABLED: bool = True
    
    # Security settings
    AUDIT_ENCRYPTION_ENABLED: bool = True
    AUDIT_HASH_ALGORITHM: str = "SHA-256"
    AUDIT_SANITIZATION_ENABLED: bool = True
    
    # Compliance settings
    AUDIT_GDPR_ENABLED: bool = True
    AUDIT_SOX_ENABLED: bool = False
    AUDIT_HIPAA_ENABLED: bool = False
    
    # Alert settings
    AUDIT_ANOMALY_DETECTION_ENABLED: bool = True
    AUDIT_ALERT_THRESHOLDS: Dict[str, int] = {
        "rapid_actions": 10,
        "failed_logins": 5,
        "privilege_escalation": 1
    }
    
    # Export settings
    AUDIT_EXPORT_FORMATS: List[str] = ["json", "csv", "pdf"]
    AUDIT_EXPORT_MAX_RECORDS: int = 10000
    
    # Performance settings
    AUDIT_CACHE_ENABLED: bool = True
    AUDIT_CACHE_TTL: int = 300  # 5 minutes
    
    class Config:
        env_prefix = "AUDIT_"
        case_sensitive = True
```

### Integration Examples

#### FastAPI Integration

```python
# File: app/main.py

from fastapi import FastAPI
from app.middleware.audit_middleware import AdminAuditMiddleware
from app.services.audit_service import AdminAuditService

app = FastAPI(title="LinkShield Admin API")

# Add audit middleware
audit_service = AdminAuditService()
app.add_middleware(AdminAuditMiddleware, audit_service=audit_service)

# Audit endpoints
@app.get("/api/v1/admin/audit/logs")
async def get_audit_logs(filters: dict = None):
    """Get audit logs with filtering."""
    return await audit_service.search_audit_logs(filters or {})

@app.get("/api/v1/admin/audit/reports/{report_type}")
async def generate_audit_report(report_type: str, start_date: str, end_date: str):
    """Generate compliance reports."""
    return await audit_service.generate_compliance_report(
        report_type, 
        datetime.fromisoformat(start_date),
        datetime.fromisoformat(end_date)
    )
```

#### Database Migration

```sql
-- File: migrations/create_audit_tables.sql

-- Create audit logs table with partitioning
CREATE TABLE admin_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(36) UNIQUE NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    date_partition VARCHAR(10) NOT NULL,
    
    -- User context
    admin_id UUID NOT NULL,
    admin_email VARCHAR(255) NOT NULL,
    admin_role VARCHAR(50) NOT NULL,
    
    -- Request information
    http_method VARCHAR(10) NOT NULL,
    endpoint_path VARCHAR(500) NOT NULL,
    full_url TEXT NOT NULL,
    user_agent TEXT,
    
    -- Network context
    client_ip VARCHAR(45) NOT NULL,
    forwarded_for VARCHAR(255),
    country_code VARCHAR(2),
    
    -- Request/Response details
    request_headers JSONB,
    request_body_hash VARCHAR(64),
    request_size_bytes INTEGER,
    response_status INTEGER NOT NULL,
    response_headers JSONB,
    response_body_hash VARCHAR(64),
    response_size_bytes INTEGER,
    
    -- Performance metrics
    processing_time_ms INTEGER NOT NULL,
    database_queries_count INTEGER DEFAULT 0,
    database_time_ms INTEGER DEFAULT 0,
    
    -- Security context
    session_id VARCHAR(128),
    jwt_token_id VARCHAR(36),
    authentication_method VARCHAR(50),
    
    -- Action classification
    action_category VARCHAR(50) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    
    -- Risk and compliance
    risk_level VARCHAR(20) DEFAULT 'low',
    compliance_flags JSONB,
    sensitive_data_accessed BOOLEAN DEFAULT FALSE,
    
    -- Status
    is_successful BOOLEAN NOT NULL,
    is_suspicious BOOLEAN DEFAULT FALSE,
    error_code VARCHAR(50),
    error_message TEXT,
    
    -- Additional context
    business_context JSONB,
    technical_context JSONB,
    tags JSONB,
    
    -- Data retention
    retention_policy VARCHAR(50) DEFAULT 'standard',
    archived_at TIMESTAMP WITH TIME ZONE
) PARTITION BY RANGE (timestamp);

-- Create indexes for efficient querying
CREATE INDEX idx_audit_logs_timestamp ON admin_audit_logs (timestamp);
CREATE INDEX idx_audit_logs_admin_id ON admin_audit_logs (admin_id);
CREATE INDEX idx_audit_logs_endpoint ON admin_audit_logs (endpoint_path);
CREATE INDEX idx_audit_logs_risk_level ON admin_audit_logs (risk_level);
CREATE INDEX idx_audit_logs_action_category ON admin_audit_logs (action_category);
CREATE INDEX idx_audit_logs_client_ip ON admin_audit_logs (client_ip);
CREATE INDEX idx_audit_logs_is_successful ON admin_audit_logs (is_successful);
CREATE INDEX idx_audit_logs_date_partition ON admin_audit_logs (date_partition);

-- Create monthly partitions (example for 2024)
CREATE TABLE admin_audit_logs_2024_01 PARTITION OF admin_audit_logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE admin_audit_logs_2024_02 PARTITION OF admin_audit_logs
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

-- Create audit configuration table
CREATE TABLE admin_audit_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    environment VARCHAR(20) DEFAULT 'production'
);
```

## Best Practices

### Implementation Guidelines

1. **Asynchronous Processing**: Use async/await for all audit operations to avoid blocking request processing
2. **Batch Processing**: Implement batching for high-volume audit logging to improve performance
3. **Data Sanitization**: Always sanitize sensitive data before logging
4. **Retention Policies**: Implement appropriate data retention and archival policies
5. **Monitoring**: Monitor audit system performance and health
6. **Testing**: Comprehensive testing of audit functionality and security features

### Security Considerations

1. **Access Control**: Implement strict RBAC for audit data access
2. **Data Integrity**: Use cryptographic hashing to ensure audit log integrity
3. **Encryption**: Encrypt sensitive audit data at rest and in transit
4. **Anomaly Detection**: Implement real-time anomaly detection and alerting
5. **Compliance**: Ensure compliance with relevant regulations (GDPR, SOX, etc.)

### Performance Optimization

1. **Database Partitioning**: Use time-based partitioning for large audit tables
2. **Indexing Strategy**: Create appropriate indexes for common query patterns
3. **Caching**: Implement caching for frequently accessed audit data
4. **Archival**: Archive old audit data to maintain performance
5. **Compression**: Use database compression for audit data storage

---

*This documentation covers the comprehensive admin audit system implementation. The system provides enterprise-grade audit capabilities with strong security, compliance, and performance characteristics.*