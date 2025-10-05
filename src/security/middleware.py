#!/usr/bin/env python3
"""
LinkShield Backend Security Middleware

Security middleware for handling security headers, request validation,
and other security-related functionality.
"""

import time
import re
import secrets
import base64
from typing import Callable, Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from src.config.settings import get_settings
# from src.services.advanced_rate_limiter import get_rate_limiter, AdvancedRateLimiter

# Get settings instance
settings = get_settings()


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware that adds security headers and handles security-related functionality.
    Includes nonce-based CSP for enhanced security.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.start_time = time.time()
    
    def _generate_nonce(self) -> str:
        """
        Generate a cryptographically secure nonce for CSP.
        
        Returns:
            Base64-encoded nonce string
        """
        # Generate 16 bytes of random data
        nonce_bytes = secrets.token_bytes(16)
        # Encode as base64 for use in CSP header
        return base64.b64encode(nonce_bytes).decode('ascii')
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request through security middleware.
        """
        # Record request start time
        start_time = time.time()
        
        # Generate nonce for this request
        nonce = self._generate_nonce()
        
        # Store nonce in request state for use in templates/responses
        request.state.csp_nonce = nonce
        
        # Log incoming request in debug mode
        if settings.DEBUG:
            logger.debug(
                f"Incoming request: {request.method} {request.url.path} "
                f"from {request.client.host if request.client else 'unknown'}"
            )
        
        # Validate request size
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.MAX_FILE_SIZE:
            return JSONResponse(
                status_code=413,
                content={
                    "success": False,
                    "error": "Request entity too large",
                    "detail": f"Maximum allowed size is {settings.MAX_FILE_SIZE} bytes"
                }
            )
        
        # Check for suspicious patterns in URL
        if self._is_suspicious_request(request):
            logger.warning(f"Suspicious request detected: {request.url.path}")
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error": "Bad request",
                }
            )
        
        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(f"Unhandled exception in middleware: {e}", exc_info=True)
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": "Internal server error",
                }
            )
        
        # Add security headers with nonce
        self._add_security_headers(response, nonce)
        
        # Add performance headers
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        
        # Log response in debug mode
        if settings.DEBUG:
            logger.debug(
                f"Response: {response.status_code} for {request.method} {request.url.path} "
                f"in {process_time:.4f}s"
            )
        
        return response
    
    def _add_security_headers(self, response: Response, nonce: str) -> None:
        """
        Add security headers to response with nonce-based CSP.
        
        Args:
            response: FastAPI response object
            nonce: Cryptographically secure nonce for CSP
        """
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Enhanced Content Security Policy with nonce support and violation reporting
        if settings.ENVIRONMENT == "production":
            # Strict CSP with nonce-based script and style loading
            csp_policy = (
                f"default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                f"style-src 'self' 'nonce-{nonce}'; "
                f"img-src 'self' data: https:; "
                f"font-src 'self' data:; "
                f"connect-src 'self'; "
                f"object-src 'none'; "
                f"base-uri 'self'; "
                f"form-action 'self'; "
                f"frame-ancestors 'none'; "
                f"upgrade-insecure-requests; "
                f"report-uri /api/security/csp-report;"
            )
        else:
            # Development CSP - secure with nonce-based loading only
            csp_policy = (
                f"default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval'; "
                f"style-src 'self' 'nonce-{nonce}'; "
                f"img-src 'self' data: https: http://localhost:*; "
                f"font-src 'self' data:; "
                f"connect-src 'self' http://localhost:* ws://localhost:*; "
                f"object-src 'none'; "
                f"base-uri 'self'; "
                f"form-action 'self'; "
                f"frame-ancestors 'none'; "
                f"report-uri /api/security/csp-report;"
            )
        
        response.headers["Content-Security-Policy"] = csp_policy
        
        # Also set CSP Report-Only for monitoring (optional)
        if settings.ENVIRONMENT == "production":
            response.headers["Content-Security-Policy-Report-Only"] = csp_policy
        
        # Strict Transport Security (HTTPS only)
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        # Enhanced Permissions Policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=(), "
            "fullscreen=(self), display-capture=(), "
            "web-share=(), clipboard-read=(), clipboard-write=()"
        )
        
        # Server identification
        response.headers["Server"] = "LinkShield-API/1.0"
        
        # API version
        response.headers["X-API-Version"] = settings.APP_VERSION
        
        # Add nonce to response headers for client-side access
        response.headers["X-CSP-Nonce"] = nonce
    
    def _is_suspicious_request(self, request: Request) -> bool:
        """
        Check if request contains suspicious patterns.
        """
        path = request.url.path.lower()
        
        # Common attack patterns
        suspicious_patterns = [
            "../",  # Path traversal
            "..%2f",  # Encoded path traversal
            "%2e%2e%2f",  # Double encoded path traversal
            "<script",  # XSS attempt
            "javascript:",  # JavaScript injection
            "vbscript:",  # VBScript injection
            "onload=",  # Event handler injection
            "onerror=",  # Event handler injection
            "eval(",  # Code injection
            "union select",  # SQL injection
            "drop table",  # SQL injection
            "insert into",  # SQL injection
            "delete from",  # SQL injection
            "update set",  # SQL injection
            "exec(",  # Command injection
            "system(",  # Command injection
            "cmd.exe",  # Command injection
            "/bin/sh",  # Command injection
            "wget ",  # Command injection
            "curl ",  # Command injection
        ]
        
        # Check path for suspicious patterns
        for pattern in suspicious_patterns:
            if pattern in path:
                return True
        
        # Check query parameters
        query_string = str(request.url.query).lower()
        for pattern in suspicious_patterns:
            if pattern in query_string:
                return True
        
        # Check for excessively long paths (potential buffer overflow)
        if len(path) > 2048:
            return True
        
        # Check for too many query parameters (potential DoS)
        if len(request.query_params) > 50:
            return True
        
        return False


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for detailed request/response logging.
    Only active in development mode.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Log detailed request and response information.
        """
        if not settings.DEBUG:
            return await call_next(request)
        
        # Log request details
        logger.debug(f"Request Headers: {dict(request.headers)}")
        logger.debug(f"Request Query Params: {dict(request.query_params)}")
        
        # Process request
        response = await call_next(request)
        
        # Log response details
        logger.debug(f"Response Status: {response.status_code}")
        logger.debug(f"Response Headers: {dict(response.headers)}")
        
        return response


# class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Advanced rate limiting middleware using AdvancedRateLimiter service.
    Lazy-loads the rate limiter to avoid Pydantic ForwardRef errors.
    """
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.rate_limiter = None  # don't initialize here

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)

        # Lazy initialize rate limiter
        if self.rate_limiter is None:
            try:
                from src.services.advanced_rate_limiter import get_rate_limiter
                self.rate_limiter = get_rate_limiter()
            except Exception as e:
                logger.error(f"Failed to initialize rate limiter (allowing request): {e}")
                return await call_next(request)

        client_ip = self._get_client_ip(request)
        identifier = client_ip
        scope = self._determine_limit_scope(request)

        try:
            result = await self.rate_limiter.check_rate_limit(identifier=identifier, scope=scope)
        except Exception as e:
            msg = str(e)
            # If it's a Pydantic forward-ref error, rebuild models dynamically
            if "not fully defined" in msg or "ForwardRef" in msg:
                try:
                    import inspect
                    from pydantic import BaseModel as PydanticBaseModel
                    from src.controllers import dashboard_models
                    for name, obj in inspect.getmembers(dashboard_models):
                        if inspect.isclass(obj) and issubclass(obj, PydanticBaseModel):
                            obj.model_rebuild()
                            logger.debug(f"Rebuilt Pydantic model {name}")
                    # Retry after rebuild
                    result = await self.rate_limiter.check_rate_limit(identifier=identifier, scope=scope)
                except Exception as e2:
                    logger.exception(f"Rate limiting failed after model_rebuild: {e2}")
                    return await call_next(request)
            else:
                logger.error(f"Rate limiting error: {e}")
                return await call_next(request)

        # Rate limit exceeded
        if not result.allowed:
            logger.warning(f"Rate limit exceeded: {identifier} ({scope.value}) - {result.current}/{result.limit}")
            return JSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "error": "Rate limit exceeded",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests. Please try again later.",
                    "details": {
                        "limit": result.limit,
                        "current": result.current,
                        "remaining": result.remaining,
                        "reset_time": result.reset_time.isoformat(),
                        "retry_after": result.retry_after,
                        "scope": scope.value
                    }
                },
                headers=self.rate_limiter.get_rate_limit_headers(result)
            )

        # Normal request path: add headers and continue
        response = await call_next(request)
        headers = self.rate_limiter.get_rate_limit_headers(result)
        for key, value in headers.items():
            response.headers[key] = value
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get client IP address, considering proxy headers.
        """
        # Check for forwarded headers (when behind proxy/load balancer)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"
    
    def _determine_limit_scope(self, request: Request):
        """
        Determine appropriate rate limit scope based on request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            RateLimitScope enum value
        """
        from src.services.advanced_rate_limiter import RateLimitScope
        
        path = request.url.path
        method = request.method
        
        # API endpoints
        if path.startswith("/api/"):
            if path.startswith("/api/auth/"):
                if "login" in path:
                    return RateLimitScope.API_ANONYMOUS  # Failed logins handled by auth
                return RateLimitScope.API_ANONYMOUS
            
            # Project management endpoints
            if "/projects" in path:
                if method == "POST":
                    return RateLimitScope.PROJECT_CREATION
                elif method in ["PUT", "DELETE"]:
                    return RateLimitScope.PROJECT_MODIFICATION
                return RateLimitScope.API_AUTHENTICATED
            
            # Team management endpoints
            if "/team" in path or "/members" in path:
                if method == "POST" or "invite" in path:
                    return RateLimitScope.TEAM_INVITATION
                return RateLimitScope.API_AUTHENTICATED
            
            # Alert endpoints
            if "/alerts" in path:
                if method == "POST":
                    return RateLimitScope.ALERT_CREATION
                elif method in ["PUT", "PATCH", "DELETE"]:
                    return RateLimitScope.ALERT_MODIFICATION
                return RateLimitScope.API_AUTHENTICATED
            
            # URL checking endpoints
            if "/check" in path or "/analyze" in path:
                return RateLimitScope.API_AUTHENTICATED
            
            # AI analysis endpoints
            if "/ai/" in path or "/analysis" in path:
                return RateLimitScope.API_AUTHENTICATED
            
            # Report endpoints
            if "/reports" in path:
                return RateLimitScope.API_AUTHENTICATED
            
            # Default authenticated API limit
            return RateLimitScope.API_AUTHENTICATED
        
        # Default limit for non-API requests
        return RateLimitScope.API_ANONYMOUS