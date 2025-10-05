#!/usr/bin/env python3
"""
JWT Token Blacklist Service

Handles JWT token revocation and blacklist management using Redis for distributed storage.
Provides secure token invalidation capabilities for logout, security incidents, and administrative actions.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum

import jwt
import redis.asyncio as redis
from redis.asyncio import Redis

from linkshield.config.settings import get_settings


class BlacklistReason(Enum):
    """Enumeration of reasons for token blacklisting."""
    LOGOUT = "logout"
    USER_LOGOUT = "user_logout"  # Alias for LOGOUT
    SECURITY_INCIDENT = "security_incident"
    ADMIN_REVOCATION = "admin_revocation"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_SUSPENSION = "account_suspension"
    TOKEN_COMPROMISE = "token_compromise"


@dataclass
class TokenRevocationRequest:
    """Request model for token revocation."""
    token: str
    jti: str
    user_id: str
    reason: str  # String reason that will be validated
    expires_at: datetime
    admin_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class BulkRevocationRequest:
    """Request model for bulk token revocation."""
    user_id: str
    reason: BlacklistReason
    admin_id: Optional[str] = None
    exclude_current_session: bool = True
    current_session_id: Optional[str] = None


@dataclass
class BlacklistStats:
    """Statistics about blacklisted tokens."""
    total_blacklisted_tokens: int
    users_with_blacklisted_tokens: int
    tokens_by_reason: Dict[str, int]
    recent_revocations: int  # Last 24 hours


@dataclass
class BlacklistEntry:
    """
    Represents a blacklisted JWT token entry.
    """
    jti: str  # JWT ID (unique token identifier)
    user_id: str
    reason: BlacklistReason
    revoked_at: datetime
    expires_at: datetime
    session_id: Optional[str] = None
    admin_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if the blacklist entry has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def to_json(self) -> str:
        """Convert the entry to JSON string."""
        data = {
            'jti': self.jti,
            'user_id': self.user_id,
            'reason': self.reason.value if isinstance(self.reason, BlacklistReason) else self.reason,
            'revoked_at': self.revoked_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'session_id': self.session_id,
            'admin_id': self.admin_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }
        return json.dumps(data)

    @classmethod
    def from_json(cls, json_str: str) -> 'BlacklistEntry':
        """Create a BlacklistEntry from JSON string."""
        data = json.loads(json_str)
        return cls(
            jti=data['jti'],
            user_id=data['user_id'],
            reason=BlacklistReason(data['reason']) if isinstance(data['reason'], str) else data['reason'],
            revoked_at=datetime.fromisoformat(data['revoked_at']),
            expires_at=datetime.fromisoformat(data['expires_at']),
            session_id=data.get('session_id'),
            admin_id=data.get('admin_id'),
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent')
        )


class JWTBlacklistError(Exception):
    """Base exception for JWT blacklist operations."""
    pass


class TokenAlreadyBlacklistedError(JWTBlacklistError):
    """Raised when attempting to blacklist an already blacklisted token."""
    pass


class JWTBlacklistService:
    """
    JWT Token Blacklist Service
    
    Manages JWT token revocation using Redis as a distributed blacklist store.
    Provides methods for token revocation, validation, and cleanup.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """
        Initialize JWT blacklist service.
        
        Args:
            redis_client: Optional Redis client instance
        """
        self.settings = get_settings()
        self.redis = redis_client
        self.key_prefix = "jwt_blacklist:"
        self.user_tokens_prefix = "user_tokens:"
        
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
    
    def _extract_token_claims(self, token: str) -> Dict[str, Any]:
        """
        Extract claims from JWT token without verification.
        
        Args:
            token: JWT token string
            
        Returns:
            Token claims dictionary
            
        Raises:
            JWTBlacklistError: If token format is invalid
        """
        try:
            # Decode without verification to extract claims
            # We only need the claims for blacklist operations
            return jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError as e:
            raise JWTBlacklistError(f"Invalid token format: {str(e)}")
    
    def _generate_jti(self, token_claims: Dict[str, Any]) -> str:
        """
        Generate or extract JWT ID (jti) from token claims.
        
        Args:
            token_claims: JWT token claims
            
        Returns:
            JWT ID string
        """
        # Use existing jti if present, otherwise generate from user_id + session_id + iat
        if "jti" in token_claims:
            return token_claims["jti"]
        
        # Generate deterministic jti from token components
        user_id = token_claims.get("user_id", "")
        session_id = token_claims.get("session_id", "")
        iat = token_claims.get("iat", 0)
        
        jti_source = f"{user_id}:{session_id}:{iat}"
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, jti_source))
    
    def _calculate_ttl(self, token_claims: Dict[str, Any]) -> int:
        """
        Calculate TTL for blacklist entry based on token expiration.
        
        Args:
            token_claims: JWT token claims
            
        Returns:
            TTL in seconds
        """
        exp = token_claims.get("exp")
        if not exp:
            # Default TTL if no expiration in token
            return 86400  # 24 hours
        
        exp_datetime = datetime.fromtimestamp(exp, tz=timezone.utc)
        current_time = datetime.now(timezone.utc)
        
        if exp_datetime <= current_time:
            # Token already expired, short TTL for cleanup
            return 300  # 5 minutes
        
        ttl_seconds = int((exp_datetime - current_time).total_seconds())
        return max(ttl_seconds, 60)  # Minimum 1 minute TTL
    
    async def blacklist_token(
        self,
        token: str,
        reason: str = "user_logout",
        admin_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> BlacklistEntry:
        """
        Add JWT token to blacklist.
        
        Args:
            token: JWT token to blacklist
            reason: Reason for blacklisting
            admin_id: ID of admin who revoked the token (if applicable)
            ip_address: IP address of the request
            user_agent: User agent of the request
            
        Returns:
            BlacklistEntry object
            
        Raises:
            JWTBlacklistError: If token is invalid or already blacklisted
        """
        redis_client = await self._get_redis()
        
        # Extract token claims
        token_claims = self._extract_token_claims(token)
        jti = self._generate_jti(token_claims)
        
        # Check if token is already blacklisted
        blacklist_key = f"{self.key_prefix}{jti}"
        if await redis_client.exists(blacklist_key):
            raise TokenAlreadyBlacklistedError(f"Token {jti} is already blacklisted")
        
        # Create blacklist entry
        entry = BlacklistEntry(
            jti=jti,
            user_id=token_claims.get("user_id", ""),
            session_id=token_claims.get("session_id", ""),
            revoked_at=datetime.now(timezone.utc),
            reason=reason,
            admin_id=admin_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Calculate TTL based on token expiration
        ttl = self._calculate_ttl(token_claims)
        
        # Store in Redis with TTL
        entry_data = asdict(entry)
        # Convert datetime to ISO string for JSON serialization
        entry_data["revoked_at"] = entry.revoked_at.isoformat()
        
        await redis_client.setex(
            blacklist_key,
            ttl,
            json.dumps(entry_data)
        )
        
        # Also track by user for bulk operations
        user_tokens_key = f"{self.user_tokens_prefix}{entry.user_id}"
        await redis_client.sadd(user_tokens_key, jti)
        await redis_client.expire(user_tokens_key, ttl)
        
        return entry
    
    async def is_token_blacklisted(self, token: str) -> bool:
        """
        Check if JWT token is blacklisted.
        
        Args:
            token: JWT token to check
            
        Returns:
            True if token is blacklisted, False otherwise
        """
        try:
            redis_client = await self._get_redis()
            
            # Extract token claims
            token_claims = self._extract_token_claims(token)
            jti = self._generate_jti(token_claims)
            
            # Check blacklist
            blacklist_key = f"{self.key_prefix}{jti}"
            return await redis_client.exists(blacklist_key) > 0
            
        except JWTBlacklistError:
            # If token is malformed, consider it invalid/blacklisted
            return True
        except Exception:
            # On Redis errors, fail open (don't block valid tokens)
            # Log this error in production
            return False
    
    async def get_blacklist_entry(self, token: str) -> Optional[BlacklistEntry]:
        """
        Get blacklist entry for a token.
        
        Args:
            token: JWT token
            
        Returns:
            BlacklistEntry if found, None otherwise
        """
        try:
            redis_client = await self._get_redis()
            
            # Extract token claims
            token_claims = self._extract_token_claims(token)
            jti = self._generate_jti(token_claims)
            
            # Get blacklist entry
            blacklist_key = f"{self.key_prefix}{jti}"
            entry_data = await redis_client.get(blacklist_key)
            
            if not entry_data:
                return None
            
            # Parse entry data
            entry_dict = json.loads(entry_data)
            # Convert ISO string back to datetime
            entry_dict["revoked_at"] = datetime.fromisoformat(entry_dict["revoked_at"])
            
            return BlacklistEntry(**entry_dict)
            
        except (JWTBlacklistError, json.JSONDecodeError, TypeError):
            return None
    
    async def blacklist_user_tokens(
        self,
        user_id: str,
        reason: str = "security_incident",
        admin_id: Optional[str] = None
    ) -> int:
        """
        Blacklist all tokens for a specific user.
        
        Args:
            user_id: User ID whose tokens to blacklist
            reason: Reason for blacklisting
            admin_id: ID of admin performing the action
            
        Returns:
            Number of tokens blacklisted
        """
        redis_client = await self._get_redis()
        
        # Get all tokens for user
        user_tokens_key = f"{self.user_tokens_prefix}{user_id}"
        token_jtis = await redis_client.smembers(user_tokens_key)
        
        blacklisted_count = 0
        
        for jti in token_jtis:
            blacklist_key = f"{self.key_prefix}{jti}"
            
            # Check if already blacklisted
            if await redis_client.exists(blacklist_key):
                continue
            
            # Create blacklist entry for this jti
            entry = BlacklistEntry(
                jti=jti,
                user_id=user_id,
                session_id="",  # Unknown for bulk operations
                revoked_at=datetime.now(timezone.utc),
                reason=reason,
                admin_id=admin_id
            )
            
            entry_data = asdict(entry)
            entry_data["revoked_at"] = entry.revoked_at.isoformat()
            
            # Use default TTL for bulk operations
            await redis_client.setex(
                blacklist_key,
                86400,  # 24 hours default
                json.dumps(entry_data)
            )
            
            blacklisted_count += 1
        
        return blacklisted_count
    
    async def cleanup_expired_entries(self) -> int:
        """
        Clean up expired blacklist entries.
        
        This is typically handled automatically by Redis TTL,
        but this method can be used for manual cleanup or monitoring.
        
        Returns:
            Number of entries cleaned up
        """
        redis_client = await self._get_redis()
        
        # Get all blacklist keys
        pattern = f"{self.key_prefix}*"
        keys = await redis_client.keys(pattern)
        
        cleaned_count = 0
        
        for key in keys:
            # Check if key still exists (TTL might have expired)
            if not await redis_client.exists(key):
                cleaned_count += 1
        
        return cleaned_count
    
    async def get_blacklist_stats(self) -> Dict[str, int]:
        """
        Get blacklist statistics.
        
        Returns:
            Dictionary with blacklist statistics
        """
        redis_client = await self._get_redis()
        
        # Count blacklisted tokens
        pattern = f"{self.key_prefix}*"
        blacklist_keys = await redis_client.keys(pattern)
        
        # Count user token sets
        user_pattern = f"{self.user_tokens_prefix}*"
        user_keys = await redis_client.keys(user_pattern)
        
        return {
            "total_blacklisted_tokens": len(blacklist_keys),
            "users_with_blacklisted_tokens": len(user_keys)
        }
    
    async def close(self):
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()


# Global instance for dependency injection
_jwt_blacklist_service: Optional[JWTBlacklistService] = None


def get_jwt_blacklist_service() -> JWTBlacklistService:
    """
    Get JWT blacklist service instance.
    
    Returns:
        JWTBlacklistService instance
    """
    global _jwt_blacklist_service
    if _jwt_blacklist_service is None:
        _jwt_blacklist_service = JWTBlacklistService()
    return _jwt_blacklist_service