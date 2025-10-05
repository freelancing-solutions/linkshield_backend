#!/usr/bin/env python3
"""
LinkShield Backend JWT Validation Middleware

Middleware for validating JWT tokens and checking against the blacklist.
Provides comprehensive JWT validation with blacklist integration.
"""

import logging
from typing import Optional, Dict, Any, Callable
from datetime import datetime, timezone
from fastapi import HTTPException, status, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from linkshield.services.token_service import get_token_service, TokenService, TokenValidationError
from linkshield.security.jwt_blacklist import get_jwt_blacklist_service, JWTBlacklistService

logger = logging.getLogger(__name__)


class JWTValidationError(Exception):
    """Exception raised when JWT validation fails."""
    pass


class TokenBlacklistedError(JWTValidationError):
    """Exception raised when token is blacklisted."""
    pass


class JWTValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for validating JWT tokens on protected routes.
    
    Automatically validates JWT tokens and checks against the blacklist
    for all requests to protected endpoints.
    """
    
    def __init__(
        self,
        app,
        token_service: Optional[TokenService] = None,
        protected_paths: Optional[list] = None,
        excluded_paths: Optional[list] = None
    ):
        """
        Initialize JWT validation middleware.
        
        Args:
            app: FastAPI application instance
            token_service: Token service instance
            protected_paths: List of paths that require JWT validation
            excluded_paths: List of paths to exclude from JWT validation
        """
        super().__init__(app)
        self.token_service = token_service or get_token_service()
        self.logger = logger
        
        # Default protected paths (API endpoints)
        self.protected_paths = protected_paths or [
            "/api/v1/",
            "/admin/",
            "/dashboard/"
        ]
        
        # Default excluded paths (public endpoints)
        self.excluded_paths = excluded_paths or [
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/v1/health",
            "/docs",
            "/redoc",
            "/openapi.json"
        ]
    
    async def dispatch(self, request: Request, call_next: Callable):
        """
        Process request and validate JWT token if required.
        
        Args:
            request: HTTP request
            call_next: Next middleware/handler
            
        Returns:
            HTTP response
        """
        try:
            # Check if path requires JWT validation
            if not self._requires_jwt_validation(request.url.path):
                return await call_next(request)
            
            # Extract JWT token from request
            token = self._extract_token(request)
            if not token:
                return self._create_error_response(
                    "Missing authentication token",
                    status.HTTP_401_UNAUTHORIZED
                )
            
            # Validate JWT token using token service
            try:
                payload = await self.token_service.validate_token(token)
                
                # Add user information to request state
                request.state.user_id = payload.get("sub")
                request.state.username = payload.get("username")
                request.state.user_roles = payload.get("roles", [])
                request.state.token_jti = payload.get("jti")
                request.state.token_type = payload.get("type")
                
            except TokenValidationError as e:
                error_msg = str(e)
                if "blacklisted" in error_msg.lower():
                    return self._create_error_response(
                        f"Token revoked: {error_msg}",
                        status.HTTP_401_UNAUTHORIZED
                    )
                else:
                    return self._create_error_response(
                        f"Invalid token: {error_msg}",
                        status.HTTP_401_UNAUTHORIZED
                    )
            
            # Continue to next middleware/handler
            response = await call_next(request)
            return response
            
        except Exception as e:
            self.logger.error(f"JWT validation middleware error: {e}")
            return self._create_error_response(
                "Authentication error",
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _requires_jwt_validation(self, path: str) -> bool:
        """
        Check if a path requires JWT validation.
        
        Args:
            path: Request path
            
        Returns:
            True if JWT validation is required
        """
        # Check excluded paths first
        for excluded_path in self.excluded_paths:
            if path.startswith(excluded_path):
                return False
        
        # Check protected paths
        for protected_path in self.protected_paths:
            if path.startswith(protected_path):
                return True
        
        return False
    
    def _extract_token(self, request: Request) -> Optional[str]:
        """
        Extract JWT token from request headers.
        
        Args:
            request: HTTP request
            
        Returns:
            JWT token string or None
        """
        # Check Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]  # Remove "Bearer " prefix
        
        # Check for token in cookies (optional)
        token_cookie = request.cookies.get("access_token")
        if token_cookie:
            return token_cookie
        
        return None
    
    def _create_error_response(self, message: str, status_code: int) -> JSONResponse:
        """
        Create standardized error response.
        
        Args:
            message: Error message
            status_code: HTTP status code
            
        Returns:
            JSON error response
        """
        return JSONResponse(
            status_code=status_code,
            content={
                "error": "authentication_error",
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )


class JWTBearerAuth(HTTPBearer):
    """
    FastAPI HTTPBearer authentication with JWT validation and blacklist checking.
    
    Can be used as a dependency in FastAPI route handlers for automatic
    JWT validation and user authentication.
    """
    
    def __init__(
        self,
        token_service: Optional[TokenService] = None,
        auto_error: bool = True
    ):
        """
        Initialize JWT Bearer authentication.
        
        Args:
            token_service: Token service instance
            auto_error: Whether to automatically raise HTTPException on error
        """
        super().__init__(auto_error=auto_error)
        self.token_service = token_service or get_token_service()
        self.logger = logger
    
    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token from Authorization header.
        
        Args:
            request: HTTP request
            
        Returns:
            Decoded token payload
            
        Raises:
            HTTPException: If authentication fails
        """
        try:
            # Get credentials from parent class
            credentials: HTTPAuthorizationCredentials = await super().__call__(request)
            
            if not credentials:
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Missing authentication credentials"
                    )
                return None
            
            # Validate JWT token using token service
            token = credentials.credentials
            payload = await self.token_service.validate_token(token)
            
            return payload
            
        except HTTPException:
            raise  # Re-raise HTTP exceptions
        except TokenValidationError as e:
            error_msg = str(e)
            if self.auto_error:
                if "blacklisted" in error_msg.lower():
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Token revoked: {error_msg}"
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Invalid token: {error_msg}"
                    )
            return None
        except Exception as e:
            self.logger.error(f"JWT Bearer authentication error: {e}")
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Authentication error"
                )
            return None
    



# FastAPI dependency for getting current user from JWT token
async def get_current_user_from_token(
    payload: Dict[str, Any] = Depends(JWTBearerAuth())
) -> Dict[str, Any]:
    """
    FastAPI dependency to get current user information from JWT token.
    
    Args:
        payload: JWT token payload from JWTBearerAuth
        
    Returns:
        User information dictionary
        
    Raises:
        HTTPException: If user information is invalid
    """
    try:
        # Extract user information from token payload
        user_info = {
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "email": payload.get("email"),
            "roles": payload.get("roles", []),
            "token_jti": payload.get("jti"),
            "token_type": payload.get("type")
        }
        
        # Validate required user information
        if not user_info["user_id"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user information in token"
            )
        
        return user_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error extracting user from token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing authentication"
        )


# Global instances for easy access
_jwt_bearer_auth: Optional[JWTBearerAuth] = None


def get_jwt_bearer_auth(token_service: Optional[TokenService] = None) -> JWTBearerAuth:
    """
    Get or create the global JWT Bearer authentication instance.
    
    Args:
        token_service: Token service instance
        
    Returns:
        JWTBearerAuth instance
    """
    global _jwt_bearer_auth
    
    if _jwt_bearer_auth is None:
        _jwt_bearer_auth = JWTBearerAuth(token_service=token_service)
    
    return _jwt_bearer_auth