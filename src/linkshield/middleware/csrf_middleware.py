#!/usr/bin/env python3
"""
CSRF Protection Middleware

FastAPI middleware for automatic CSRF protection using Double Submit Cookie pattern.
Protects state-changing HTTP methods and provides token generation for safe methods.
"""

import json
from typing import Callable, Optional, Set, List
from urllib.parse import parse_qs

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from linkshield.security.csrf_protection import (
    get_csrf_service,
    CSRFProtectionService,
    CSRFTokenMissingError,
    CSRFTokenInvalidError
)
from linkshield.authentication.dependencies import get_current_user_optional


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection Middleware
    
    Automatically protects state-changing requests and provides CSRF tokens
    for safe requests. Uses Double Submit Cookie pattern for validation.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        csrf_service: Optional[CSRFProtectionService] = None,
        protected_methods: Optional[Set[str]] = None,
        exempt_paths: Optional[List[str]] = None,
        api_prefix: str = "/api",
        require_auth: bool = True
    ):
        """
        Initialize CSRF middleware.
        
        Args:
            app: ASGI application
            csrf_service: CSRF protection service instance
            protected_methods: HTTP methods that require CSRF protection
            exempt_paths: Paths exempt from CSRF protection
            api_prefix: API path prefix for JSON responses
            require_auth: Whether to require authentication for CSRF protection
        """
        super().__init__(app)
        self.csrf_service = csrf_service or get_csrf_service()
        
        # Methods that require CSRF protection (state-changing)
        self.protected_methods = protected_methods or {
            "POST", "PUT", "PATCH", "DELETE"
        }
        
        # Paths exempt from CSRF protection
        self.exempt_paths = exempt_paths or [
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh",
            "/api/webhooks/",  # Webhook endpoints
            "/api/health",
            "/docs",
            "/redoc",
            "/openapi.json"
        ]
        
        self.api_prefix = api_prefix
        self.require_auth = require_auth
    
    def _is_exempt_path(self, path: str) -> bool:
        """
        Check if path is exempt from CSRF protection.
        
        Args:
            path: Request path
            
        Returns:
            True if path is exempt
        """
        for exempt_path in self.exempt_paths:
            if path.startswith(exempt_path):
                return True
        return False
    
    def _is_safe_method(self, method: str) -> bool:
        """
        Check if HTTP method is considered safe (doesn't change state).
        
        Args:
            method: HTTP method
            
        Returns:
            True if method is safe
        """
        return method not in self.protected_methods
    
    def _is_api_request(self, path: str) -> bool:
        """
        Check if request is to API endpoint.
        
        Args:
            path: Request path
            
        Returns:
            True if API request
        """
        return path.startswith(self.api_prefix)
    
    async def _get_user_info(self, request: Request) -> tuple[Optional[str], Optional[str]]:
        """
        Extract user and session information from request.
        
        Args:
            request: FastAPI request
            
        Returns:
            Tuple of (user_id, session_id)
        """
        try:
            # Try to get current user (this might fail if not authenticated)
            user = await get_current_user_optional(request)
            if user:
                # Extract session ID from JWT token if available
                auth_header = request.headers.get("Authorization")
                session_id = None
                
                if auth_header and auth_header.startswith("Bearer "):
                    # In a real implementation, you'd decode the JWT to get session_id
                    # For now, we'll use a placeholder
                    session_id = "session_placeholder"
                
                return str(user.id), session_id
            
            return None, None
            
        except Exception:
            return None, None
    
    async def _extract_form_csrf_token(self, request: Request) -> Optional[str]:
        """
        Extract CSRF token from form data.
        
        Args:
            request: FastAPI request
            
        Returns:
            CSRF token if found
        """
        try:
            content_type = request.headers.get("content-type", "")
            
            if "application/x-www-form-urlencoded" in content_type:
                # Read form data
                body = await request.body()
                form_data = parse_qs(body.decode())
                
                csrf_field = self.csrf_service.config.form_field_name
                if csrf_field in form_data:
                    return form_data[csrf_field][0]
            
            elif "multipart/form-data" in content_type:
                # For multipart forms, we'd need to parse the multipart data
                # This is more complex and would typically be handled by FastAPI
                pass
            
            return None
            
        except Exception:
            return None
    
    async def _generate_csrf_response(
        self,
        request: Request,
        response: Response,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> None:
        """
        Generate and set CSRF token for safe requests.
        
        Args:
            request: FastAPI request
            response: FastAPI response
            user_id: Optional user ID
            session_id: Optional session ID
        """
        try:
            # Generate CSRF token
            token_data = await self.csrf_service.generate_csrf_token(
                user_id=user_id,
                session_id=session_id
            )
            
            # Set CSRF cookie
            self.csrf_service.set_csrf_cookie(
                response,
                token_data["cookie_token"]
            )
            
            # For API requests, also include token in response headers
            if self._is_api_request(request.url.path):
                response.headers["X-CSRF-Token"] = token_data["validation_token"]
            
        except Exception:
            # Log error in production, but don't fail the request
            pass
    
    async def _validate_csrf_token(
        self,
        request: Request,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> bool:
        """
        Validate CSRF token for protected requests.
        
        Args:
            request: FastAPI request
            user_id: Optional user ID
            session_id: Optional session ID
            
        Returns:
            True if token is valid
            
        Raises:
            CSRFTokenMissingError: If token is missing
            CSRFTokenInvalidError: If token is invalid
        """
        # Get cookie token
        cookie_token = self.csrf_service.get_csrf_cookie_from_request(request)
        if not cookie_token:
            raise CSRFTokenMissingError("CSRF cookie token missing")
        
        # Get submitted token (from header or form)
        submitted_token = self.csrf_service.extract_csrf_token_from_request(request)
        
        # If not in header, try form data
        if not submitted_token:
            submitted_token = await self._extract_form_csrf_token(request)
        
        if not submitted_token:
            raise CSRFTokenMissingError("CSRF token missing from request")
        
        # Validate token
        is_valid = await self.csrf_service.validate_csrf_token(
            cookie_token=cookie_token,
            submitted_token=submitted_token,
            user_id=user_id,
            session_id=session_id,
            consume_token=True  # One-time use for security
        )
        
        if not is_valid:
            raise CSRFTokenInvalidError("Invalid or expired CSRF token")
        
        return True
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request through CSRF protection middleware.
        
        Args:
            request: FastAPI request
            call_next: Next middleware/handler
            
        Returns:
            Response with CSRF protection applied
        """
        path = request.url.path
        method = request.method
        
        # Skip CSRF protection for exempt paths
        if self._is_exempt_path(path):
            return await call_next(request)
        
        # Get user information
        user_id, session_id = await self._get_user_info(request)
        
        # If authentication is required and user is not authenticated, skip CSRF
        if self.require_auth and not user_id:
            return await call_next(request)
        
        try:
            # For safe methods, generate CSRF token
            if self._is_safe_method(method):
                response = await call_next(request)
                
                # Generate CSRF token for authenticated users or all users
                if user_id or not self.require_auth:
                    await self._generate_csrf_response(
                        request, response, user_id, session_id
                    )
                
                return response
            
            # For protected methods, validate CSRF token
            else:
                await self._validate_csrf_token(request, user_id, session_id)
                return await call_next(request)
        
        except CSRFTokenMissingError as e:
            if self._is_api_request(path):
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "CSRF_TOKEN_MISSING",
                        "message": str(e),
                        "details": "CSRF token is required for this request"
                    }
                )
            else:
                # For non-API requests, return HTML error page
                return Response(
                    content="<h1>403 Forbidden</h1><p>CSRF token missing</p>",
                    status_code=403,
                    media_type="text/html"
                )
        
        except CSRFTokenInvalidError as e:
            if self._is_api_request(path):
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "CSRF_TOKEN_INVALID",
                        "message": str(e),
                        "details": "CSRF token is invalid or expired"
                    }
                )
            else:
                return Response(
                    content="<h1>403 Forbidden</h1><p>Invalid CSRF token</p>",
                    status_code=403,
                    media_type="text/html"
                )
        
        except Exception as e:
            # Log unexpected errors in production
            if self._is_api_request(path):
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": "CSRF_VALIDATION_ERROR",
                        "message": "CSRF validation failed",
                        "details": "An error occurred during CSRF validation"
                    }
                )
            else:
                return Response(
                    content="<h1>500 Internal Server Error</h1><p>CSRF validation error</p>",
                    status_code=500,
                    media_type="text/html"
                )


def create_csrf_middleware(
    exempt_paths: Optional[List[str]] = None,
    require_auth: bool = True
) -> CSRFMiddleware:
    """
    Create CSRF middleware with custom configuration.
    
    Args:
        exempt_paths: Additional paths to exempt from CSRF protection
        require_auth: Whether to require authentication for CSRF protection
        
    Returns:
        Configured CSRF middleware
    """
    default_exempt_paths = [
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/refresh",
        "/api/webhooks/",
        "/api/health",
        "/docs",
        "/redoc",
        "/openapi.json"
    ]
    
    if exempt_paths:
        default_exempt_paths.extend(exempt_paths)
    
    return CSRFMiddleware(
        app=None,  # Will be set by FastAPI
        exempt_paths=default_exempt_paths,
        require_auth=require_auth
    )