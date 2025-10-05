#!/usr/bin/env python3
"""
CSRF Protection Service

Implements Cross-Site Request Forgery protection using the Double Submit Cookie pattern.
Provides secure token generation, validation, and middleware integration.
"""

import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import redis.asyncio as redis
from redis.asyncio import Redis
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from linkshield.config.settings import get_settings


@dataclass
class CSRFConfig:
    """CSRF protection configuration."""
    token_length: int = 32
    cookie_name: str = "csrf_token"
    header_name: str = "X-CSRF-Token"
    form_field_name: str = "csrf_token"
    token_ttl: int = 3600  # 1 hour
    secure_cookie: bool = True
    samesite: str = "strict"
    httponly: bool = False  # Must be False for JavaScript access


class CSRFError(Exception):
    """Base exception for CSRF protection errors."""
    pass


class CSRFTokenMissingError(CSRFError):
    """Raised when CSRF token is missing from request."""
    pass


class CSRFTokenInvalidError(CSRFError):
    """Raised when CSRF token is invalid or expired."""
pass


class CSRFProtectionService:
    """
    CSRF Protection Service
    
    Implements Double Submit Cookie pattern for CSRF protection.
    Generates secure tokens, validates requests, and manages token lifecycle.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None, config: Optional[CSRFConfig] = None):
        """
        Initialize CSRF protection service.
        
        Args:
            redis_client: Optional Redis client instance
            config: Optional CSRF configuration
        """
        self.settings = get_settings()
        self.redis = redis_client
        self.config = config or CSRFConfig()
        self.key_prefix = "csrf_token:"
        
        # CSRF secret key for token signing (derived from main secret)
        self.csrf_secret = self._derive_csrf_secret()
        
    async def _get_redis(self) -> Redis:
        """
        Get Redis client instance.
        
        Returns:
            Redis client
        """
        if not self.redis:
            self.redis = redis.from_url(
                self.settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        return self.redis
    
    def _derive_csrf_secret(self) -> bytes:
        """
        Derive CSRF secret key from main application secret.
        
        Returns:
            CSRF secret key bytes
        """
        # Use HMAC to derive a separate secret for CSRF tokens
        return hmac.new(
            self.settings.SECRET_KEY.encode(),
            b"csrf_protection",
            hashlib.sha256
        ).digest()
    
    def _generate_token_pair(self) -> tuple[str, str]:
        """
        Generate CSRF token pair (cookie token and validation token).
        
        Returns:
            Tuple of (cookie_token, validation_token)
        """
        # Generate random token
        random_token = secrets.token_urlsafe(self.config.token_length)
        
        # Create signed validation token
        validation_token = self._sign_token(random_token)
        
        return random_token, validation_token
    
    def _sign_token(self, token: str) -> str:
        """
        Sign token with CSRF secret.
        
        Args:
            token: Token to sign
            
        Returns:
            Signed token
        """
        signature = hmac.new(
            self.csrf_secret,
            token.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{token}.{signature}"
    
    def _verify_token_signature(self, signed_token: str) -> Optional[str]:
        """
        Verify token signature and extract original token.
        
        Args:
            signed_token: Signed token to verify
            
        Returns:
            Original token if valid, None otherwise
        """
        try:
            token, signature = signed_token.rsplit(".", 1)
            
            # Verify signature
            expected_signature = hmac.new(
                self.csrf_secret,
                token.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if hmac.compare_digest(signature, expected_signature):
                return token
            
            return None
            
        except ValueError:
            return None
    
    async def generate_csrf_token(
        self,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate CSRF token pair for a request.
        
        Args:
            user_id: Optional user ID for token binding
            session_id: Optional session ID for token binding
            
        Returns:
            Dictionary with cookie_token and validation_token
        """
        redis_client = await self._get_redis()
        
        # Generate token pair
        cookie_token, validation_token = self._generate_token_pair()
        
        # Store token metadata in Redis
        token_key = f"{self.key_prefix}{cookie_token}"
        token_data = {
            "validation_token": validation_token,
            "user_id": user_id or "",
            "session_id": session_id or "",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "used": False
        }
        
        # Store with TTL
        await redis_client.hset(token_key, mapping=token_data)
        await redis_client.expire(token_key, self.config.token_ttl)
        
        return {
            "cookie_token": cookie_token,
            "validation_token": validation_token
        }
    
    async def validate_csrf_token(
        self,
        cookie_token: str,
        submitted_token: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        consume_token: bool = True
    ) -> bool:
        """
        Validate CSRF token using Double Submit Cookie pattern.
        
        Args:
            cookie_token: Token from cookie
            submitted_token: Token from form/header
            user_id: Optional user ID for binding validation
            session_id: Optional session ID for binding validation
            consume_token: Whether to mark token as used (one-time use)
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            redis_client = await self._get_redis()
            
            # Get token data from Redis
            token_key = f"{self.key_prefix}{cookie_token}"
            token_data = await redis_client.hgetall(token_key)
            
            if not token_data:
                return False
            
            # Check if token was already used (if one-time use is enabled)
            if consume_token and token_data.get("used") == "True":
                return False
            
            # Verify the submitted token matches the stored validation token
            stored_validation_token = token_data.get("validation_token")
            if not stored_validation_token:
                return False
            
            # Verify signature of submitted token
            original_token = self._verify_token_signature(submitted_token)
            if not original_token:
                return False
            
            # Verify the original token matches the cookie token
            if not hmac.compare_digest(original_token, cookie_token):
                return False
            
            # Verify user/session binding if provided
            if user_id and token_data.get("user_id") != user_id:
                return False
            
            if session_id and token_data.get("session_id") != session_id:
                return False
            
            # Mark token as used if consume_token is True
            if consume_token:
                await redis_client.hset(token_key, "used", "True")
            
            return True
            
        except Exception:
            # Log error in production
            return False
    
    def set_csrf_cookie(
        self,
        response: Response,
        cookie_token: str,
        secure: Optional[bool] = None
    ) -> None:
        """
        Set CSRF token cookie in response.
        
        Args:
            response: FastAPI response object
            cookie_token: CSRF cookie token
            secure: Override secure flag
        """
        secure_flag = secure if secure is not None else self.config.secure_cookie
        
        response.set_cookie(
            key=self.config.cookie_name,
            value=cookie_token,
            max_age=self.config.token_ttl,
            secure=secure_flag,
            httponly=self.config.httponly,
            samesite=self.config.samesite
        )
    
    def extract_csrf_token_from_request(self, request: Request) -> Optional[str]:
        """
        Extract CSRF token from request (header or form data).
        
        Args:
            request: FastAPI request object
            
        Returns:
            CSRF token if found, None otherwise
        """
        # Try header first
        token = request.headers.get(self.config.header_name)
        if token:
            return token
        
        # Try form data (for form submissions)
        # Note: This requires the request body to be parsed
        # In practice, this would be handled by middleware
        return None
    
    def get_csrf_cookie_from_request(self, request: Request) -> Optional[str]:
        """
        Extract CSRF cookie from request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            CSRF cookie value if found, None otherwise
        """
        return request.cookies.get(self.config.cookie_name)
    
    async def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired CSRF tokens.
        
        Returns:
            Number of tokens cleaned up
        """
        redis_client = await self._get_redis()
        
        # Get all CSRF token keys
        pattern = f"{self.key_prefix}*"
        keys = await redis_client.keys(pattern)
        
        cleaned_count = 0
        
        for key in keys:
            # Check if key still exists (TTL might have expired)
            if not await redis_client.exists(key):
                cleaned_count += 1
        
        return cleaned_count
    
    async def get_csrf_stats(self) -> Dict[str, int]:
        """
        Get CSRF protection statistics.
        
        Returns:
            Dictionary with CSRF statistics
        """
        redis_client = await self._get_redis()
        
        # Count active CSRF tokens
        pattern = f"{self.key_prefix}*"
        token_keys = await redis_client.keys(pattern)
        
        # Count used vs unused tokens
        used_count = 0
        unused_count = 0
        
        for key in token_keys:
            token_data = await redis_client.hgetall(key)
            if token_data.get("used") == "True":
                used_count += 1
            else:
                unused_count += 1
        
        return {
            "total_tokens": len(token_keys),
            "used_tokens": used_count,
            "unused_tokens": unused_count
        }
    
    async def revoke_user_csrf_tokens(self, user_id: str) -> int:
        """
        Revoke all CSRF tokens for a specific user.
        
        Args:
            user_id: User ID whose tokens to revoke
            
        Returns:
            Number of tokens revoked
        """
        redis_client = await self._get_redis()
        
        # Get all CSRF token keys
        pattern = f"{self.key_prefix}*"
        token_keys = await redis_client.keys(pattern)
        
        revoked_count = 0
        
        for key in token_keys:
            token_data = await redis_client.hgetall(key)
            if token_data.get("user_id") == user_id:
                await redis_client.delete(key)
                revoked_count += 1
        
        return revoked_count
    
    async def close(self):
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()


# Global instance for dependency injection
_csrf_service: Optional[CSRFProtectionService] = None


def get_csrf_service() -> CSRFProtectionService:
    """
    Get CSRF protection service instance.
    
    Returns:
        CSRFProtectionService instance
    """
    global _csrf_service
    if _csrf_service is None:
        _csrf_service = CSRFProtectionService()
    return _csrf_service