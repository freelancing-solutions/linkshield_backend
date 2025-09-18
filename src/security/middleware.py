#!/usr/bin/env python3
"""
LinkShield Backend Security Middleware

Security middleware for handling security headers, request validation,
and other security-related functionality.
"""

import time
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from src.config.settings import get_settings

# Get settings instance
settings = get_settings()


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware that adds security headers and handles security-related functionality.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.start_time = time.time()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request through security middleware.
        """
        # Record request start time
        start_time = time.time()
        
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
        
        # Add security headers
        self._add_security_headers(response)
        
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
    
    def _add_security_headers(self, response: Response) -> None:
        """
        Add security headers to response.
        """
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy (basic)
        if settings.ENVIRONMENT == "production":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )
        
        # Strict Transport Security (HTTPS only)
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )
        
        # Server identification
        response.headers["Server"] = "LinkShield-API/1.0"
        
        # API version
        response.headers["X-API-Version"] = settings.APP_VERSION
    
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


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Basic rate limiting middleware.
    Note: For production, consider using Redis-based rate limiting.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.request_counts = {}  # In-memory storage (not suitable for production)
        self.window_size = 3600  # 1 hour window
        self.max_requests = 1000  # Max requests per window
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Apply basic rate limiting.
        """
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        current_time = int(time.time())
        window_start = current_time - (current_time % self.window_size)
        
        # Clean old entries
        self._cleanup_old_entries(window_start)
        
        # Check rate limit
        key = f"{client_ip}:{window_start}"
        current_count = self.request_counts.get(key, 0)
        
        if current_count >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "error": "Rate limit exceeded",
                    "detail": "Too many requests. Please try again later."
                },
                headers={
                    "Retry-After": str(self.window_size),
                    "X-RateLimit-Limit": str(self.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(window_start + self.window_size),
                }
            )
        
        # Increment counter
        self.request_counts[key] = current_count + 1
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(self.max_requests - current_count - 1)
        response.headers["X-RateLimit-Reset"] = str(window_start + self.window_size)
        
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
    
    def _cleanup_old_entries(self, current_window: int) -> None:
        """
        Remove old rate limit entries to prevent memory leaks.
        """
        keys_to_remove = []
        for key in self.request_counts:
            window = int(key.split(":")[1])
            if window < current_window:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.request_counts[key]