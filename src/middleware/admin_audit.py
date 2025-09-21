#!/usr/bin/env python3
"""
LinkShield Backend Admin Audit Middleware

Middleware for automatically logging admin actions and maintaining
comprehensive audit trails for administrative operations.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, Any, Optional

from fastapi import Request, Response
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.database import get_db_session
from src.models.admin import AdminAction, ActionType
from src.models.user import User, UserRole
from src.services.security_service import SecurityService


class AdminAuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware that automatically logs admin actions for audit purposes.
    
    Tracks all admin API calls, captures request/response data (excluding sensitive info),
    and maintains comprehensive audit logs for compliance and security monitoring.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.sensitive_fields = {
            'password', 'token', 'secret', 'key', 'credentials', 
            'authorization', 'cookie', 'session'
        }
        self.admin_paths = {'/admin'}  # Paths that trigger audit logging
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request through admin audit middleware.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            Response: HTTP response
        """
        # Check if this is an admin route
        if not self._should_audit_request(request):
            return await call_next(request)
        
        # Record request start time
        start_time = time.time()
        
        # Extract user information
        user_info = await self._extract_user_info(request)
        
        # Skip audit if not an admin user
        if not user_info or not self._is_admin_user(user_info):
            return await call_next(request)
        
        # Generate audit ID for tracking
        audit_id = str(uuid.uuid4())
        
        # Capture request data
        request_data = await self._capture_request_data(request)
        
        # Log audit start
        logger.info(f"Admin audit started - ID: {audit_id}, User: {user_info.get('email')}, Path: {request.url.path}")
        
        # Process request
        response = None
        error_info = None
        
        try:
            response = await call_next(request)
        except Exception as e:
            error_info = {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            logger.error(f"Admin audit error - ID: {audit_id}, Error: {e}")
            raise
        finally:
            # Calculate processing time
            process_time = time.time() - start_time
            
            # Capture response data
            response_data = self._capture_response_data(response) if response else None
            
            # Create audit log entry
            await self._create_audit_log(
                audit_id=audit_id,
                user_info=user_info,
                request_data=request_data,
                response_data=response_data,
                error_info=error_info,
                process_time=process_time,
                request=request
            )
        
        return response
    
    def _should_audit_request(self, request: Request) -> bool:
        """
        Determine if request should be audited.
        
        Args:
            request: HTTP request
            
        Returns:
            bool: True if request should be audited
        """
        path = request.url.path
        
        # Check if path starts with admin prefix
        for admin_path in self.admin_paths:
            if path.startswith(admin_path):
                return True
        
        return False
    
    async def _extract_user_info(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Extract user information from request.
        
        Args:
            request: HTTP request
            
        Returns:
            Optional[Dict]: User information or None
        """
        try:
            # Get authorization header
            auth_header = request.headers.get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return None
            
            token = auth_header.split(" ")[1]
            
            # Get database session
            db_gen = get_db_session()
            db: AsyncSession = await db_gen.__anext__()
            
            try:
                # Verify token and get user
                security_service = SecurityService()
                token_data = security_service.verify_jwt_token(token)
                
                if not token_data:
                    return None
                
                user_id = token_data.get("user_id")
                if not user_id:
                    return None
                
                # Get user from database
                user = await db.get(User, user_id)
                if not user:
                    return None
                
                return {
                    "id": str(user.id),
                    "email": user.email,
                    "role": user.role.value if user.role else None,
                    "full_name": getattr(user, 'full_name', None)
                }
            
            finally:
                await db.close()
        
        except Exception as e:
            logger.warning(f"Failed to extract user info for audit: {e}")
            return None
    
    def _is_admin_user(self, user_info: Dict[str, Any]) -> bool:
        """
        Check if user has admin privileges.
        
        Args:
            user_info: User information dictionary
            
        Returns:
            bool: True if user is admin
        """
        role = user_info.get("role")
        return role in [UserRole.ADMIN.value, UserRole.SUPER_ADMIN.value]
    
    async def _capture_request_data(self, request: Request) -> Dict[str, Any]:
        """
        Capture request data for audit log.
        
        Args:
            request: HTTP request
            
        Returns:
            Dict: Sanitized request data
        """
        try:
            # Basic request info
            data = {
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "headers": self._sanitize_headers(dict(request.headers)),
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Capture request body for POST/PUT/PATCH requests
            if request.method in ["POST", "PUT", "PATCH"]:
                try:
                    # Read body
                    body = await request.body()
                    if body:
                        # Try to parse as JSON
                        try:
                            body_data = json.loads(body.decode('utf-8'))
                            data["body"] = self._sanitize_data(body_data)
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            # Store as string if not JSON
                            data["body"] = body.decode('utf-8', errors='ignore')[:1000]  # Limit size
                except Exception as e:
                    logger.warning(f"Failed to capture request body: {e}")
                    data["body"] = "<failed to capture>"
            
            return data
        
        except Exception as e:
            logger.error(f"Failed to capture request data: {e}")
            return {
                "method": request.method,
                "path": request.url.path,
                "error": "Failed to capture request data"
            }
    
    def _capture_response_data(self, response: Response) -> Dict[str, Any]:
        """
        Capture response data for audit log.
        
        Args:
            response: HTTP response
            
        Returns:
            Dict: Response data
        """
        try:
            data = {
                "status_code": response.status_code,
                "headers": self._sanitize_headers(dict(response.headers)),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Note: We don't capture response body to avoid performance issues
            # and potential memory problems with large responses
            
            return data
        
        except Exception as e:
            logger.error(f"Failed to capture response data: {e}")
            return {
                "status_code": getattr(response, 'status_code', 500),
                "error": "Failed to capture response data"
            }
    
    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize headers by removing sensitive information.
        
        Args:
            headers: Request/response headers
            
        Returns:
            Dict: Sanitized headers
        """
        sanitized = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            # Check if header contains sensitive information
            if any(sensitive in key_lower for sensitive in self.sensitive_fields):
                sanitized[key] = "<redacted>"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_data(self, data: Any) -> Any:
        """
        Recursively sanitize data by removing sensitive fields.
        
        Args:
            data: Data to sanitize
            
        Returns:
            Any: Sanitized data
        """
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                key_lower = key.lower()
                
                # Check if field is sensitive
                if any(sensitive in key_lower for sensitive in self.sensitive_fields):
                    sanitized[key] = "<redacted>"
                else:
                    sanitized[key] = self._sanitize_data(value)
            
            return sanitized
        
        elif isinstance(data, list):
            return [self._sanitize_data(item) for item in data]
        
        else:
            return data
    
    def _determine_action_type(self, request: Request) -> ActionType:
        """
        Determine the type of admin action based on request.
        
        Args:
            request: HTTP request
            
        Returns:
            ActionType: Type of action
        """
        path = request.url.path.lower()
        method = request.method.upper()
        
        # Configuration management
        if "config" in path:
            if method in ["PUT", "PATCH", "POST"]:
                return ActionType.CONFIG_UPDATE
            else:
                return ActionType.CONFIG_VIEW
        
        # User management
        elif "users" in path:
            if method in ["PUT", "PATCH"]:
                return ActionType.USER_UPDATE
            elif method == "DELETE":
                return ActionType.USER_DELETE
            else:
                return ActionType.USER_VIEW
        
        # System management
        elif "system" in path or "health" in path:
            return ActionType.SYSTEM_ACCESS
        
        # Dashboard/analytics
        elif "dashboard" in path or "analytics" in path:
            return ActionType.DASHBOARD_ACCESS
        
        # Default
        else:
            return ActionType.OTHER
    
    async def _create_audit_log(
        self,
        audit_id: str,
        user_info: Dict[str, Any],
        request_data: Dict[str, Any],
        response_data: Optional[Dict[str, Any]],
        error_info: Optional[Dict[str, Any]],
        process_time: float,
        request: Request
    ) -> None:
        """
        Create audit log entry in database.
        
        Args:
            audit_id: Unique audit identifier
            user_info: User information
            request_data: Request data
            response_data: Response data
            error_info: Error information if any
            process_time: Request processing time
            request: Original request object
        """
        try:
            # Get database session
            db_gen = get_db_session()
            db: AsyncSession = await db_gen.__anext__()
            
            try:
                # Create audit log entry
                audit_log = AdminAction(
                    id=uuid.UUID(audit_id),
                    user_id=uuid.UUID(user_info["id"]),
                    action_type=self._determine_action_type(request),
                    resource_type="admin_api",
                    resource_id=request.url.path,
                    details={
                        "request": request_data,
                        "response": response_data,
                        "error": error_info,
                        "process_time": process_time,
                        "user_info": {
                            "email": user_info["email"],
                            "role": user_info["role"],
                            "full_name": user_info.get("full_name")
                        }
                    },
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                    success=error_info is None,
                    created_at=datetime.now(timezone.utc)
                )
                
                # Add to database
                db.add(audit_log)
                await db.commit()
                
                logger.info(f"Admin audit log created - ID: {audit_id}")
            
            finally:
                await db.close()
        
        except Exception as e:
            logger.error(f"Failed to create audit log entry: {e}")
            # Don't raise exception to avoid breaking the request flow


# Decorator for manual audit logging
def audit_admin_action(action_type: ActionType, resource_type: str = "manual"):
    """
    Decorator for manually auditing admin actions.
    
    Args:
        action_type: Type of action being performed
        resource_type: Type of resource being acted upon
        
    Returns:
        Decorator function
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # This is a placeholder for manual audit logging
            # In a real implementation, you would extract user info and log the action
            logger.info(f"Manual admin action: {action_type.value} on {resource_type}")
            return await func(*args, **kwargs)
        return wrapper
    return decorator