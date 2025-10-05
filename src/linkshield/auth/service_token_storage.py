#!/usr/bin/env python3
"""
Service Token Storage

Redis-based persistent storage for service tokens, replacing in-memory storage
to ensure tokens survive application restarts and support distributed deployments.
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

import redis.asyncio as redis
from redis.asyncio import Redis
from redis.exceptions import RedisError, ConnectionError, TimeoutError

from linkshield.config.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass
class ServiceTokenEntry:
    """Service token entry with metadata."""
    service_name: str
    token_data: Dict[str, Any]
    issued_at: datetime
    expires_at: datetime
    created_by: Optional[str] = None
    last_used: Optional[datetime] = None
    usage_count: int = 0


class ServiceTokenStorageError(Exception):
    """Base exception for service token storage operations."""
    pass


class RedisConnectionError(ServiceTokenStorageError):
    """Raised when Redis connection fails."""
    pass


class TokenNotFoundError(ServiceTokenStorageError):
    """Raised when a token is not found in storage."""
    pass


class TokenExpiredError(ServiceTokenStorageError):
    """Raised when a token has expired."""
    pass


class ServiceTokenStorage:
    """
    Redis-based Service Token Storage
    
    Provides persistent storage for service tokens with automatic expiration,
    usage tracking, and cleanup mechanisms. Replaces in-memory storage to
    support distributed deployments and application restarts.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """
        Initialize service token storage.
        
        Args:
            redis_client: Optional Redis client instance
        """
        self.settings = get_settings()
        self.redis = redis_client
        self.key_prefix = "service_token:"
        self.stats_key = "service_token_stats"
        self.logger = logging.getLogger(__name__)
        
        # Fallback storage for when Redis is unavailable
        self._fallback_storage: Dict[str, Dict[str, Any]] = {}
        self._redis_available = True
        
    async def _get_redis(self) -> Redis:
        """
        Get Redis client instance with connection validation.
        
        Returns:
            Redis client
            
        Raises:
            RedisConnectionError: If Redis connection fails
        """
        if not self.redis:
            try:
                self.redis = redis.from_url(
                    self.settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_timeout=5.0,
                    socket_connect_timeout=5.0,
                    retry_on_timeout=True,
                    health_check_interval=30
                )
                # Test connection
                await self.redis.ping()
                self._redis_available = True
            except (RedisError, ConnectionError, TimeoutError) as e:
                self.logger.error(f"Redis connection failed: {e}")
                self._redis_available = False
                raise RedisConnectionError(f"Failed to connect to Redis: {e}")
        
        return self.redis
    
    def _get_token_key(self, token_id: str) -> str:
        """Get Redis key for token storage."""
        return f"{self.key_prefix}{token_id}"
    
    def _get_service_index_key(self, service_name: str) -> str:
        """Get Redis key for service token index."""
        return f"service_index:{service_name}"
    
    def _calculate_ttl(self, expires_at: datetime) -> int:
        """
        Calculate TTL in seconds for Redis expiration.
        
        Args:
            expires_at: Token expiration datetime
            
        Returns:
            TTL in seconds
        """
        now = datetime.now(timezone.utc)
        if expires_at <= now:
            return 0
        return int((expires_at - now).total_seconds())
    
    async def store_token(
        self,
        token_id: str,
        service_name: str,
        token_data: Dict[str, Any],
        expires_at: datetime,
        created_by: Optional[str] = None
    ) -> ServiceTokenEntry:
        """
        Store a service token with fallback to in-memory storage.
        
        Args:
            token_id: Unique token identifier
            service_name: Name of the service
            token_data: Token payload data
            expires_at: Token expiration time
            created_by: Optional creator identifier
            
        Returns:
            ServiceTokenEntry instance
            
        Raises:
            ServiceTokenStorageError: If storage operation fails
        """
        try:
            redis_client = await self._get_redis()
            
            # Create token entry
            entry = ServiceTokenEntry(
                service_name=service_name,
                token_data=token_data,
                issued_at=datetime.now(timezone.utc),
                expires_at=expires_at,
                created_by=created_by
            )
            
            # Calculate TTL
            ttl = self._calculate_ttl(expires_at)
            if ttl <= 0:
                raise ServiceTokenStorageError("Token is already expired")
            
            # Prepare data for storage
            entry_data = asdict(entry)
            # Convert datetime objects to ISO strings for JSON serialization
            entry_data["issued_at"] = entry.issued_at.isoformat()
            entry_data["expires_at"] = entry.expires_at.isoformat()
            if entry.last_used:
                entry_data["last_used"] = entry.last_used.isoformat()
            
            # Store token with TTL
            token_key = self._get_token_key(token_id)
            await redis_client.setex(
                token_key,
                ttl,
                json.dumps(entry_data)
            )
            
            # Add to service index for bulk operations
            service_index_key = self._get_service_index_key(service_name)
            await redis_client.sadd(service_index_key, token_id)
            await redis_client.expire(service_index_key, ttl)
            
            logger.info(f"Stored service token for {service_name} in Redis, expires in {ttl}s")
            return entry
            
        except (RedisError, ConnectionError, TimeoutError) as e:
            logger.error(f"Redis store_token error: {e}, falling back to in-memory storage")
            self._redis_available = False
            
            # Fallback to in-memory storage
            entry = ServiceTokenEntry(
                service_name=service_name,
                token_data=token_data,
                issued_at=datetime.now(timezone.utc),
                expires_at=expires_at,
                created_by=created_by
            )
            
            entry_data = asdict(entry)
            entry_data["issued_at"] = entry.issued_at.isoformat()
            entry_data["expires_at"] = entry.expires_at.isoformat()
            if entry.last_used:
                entry_data["last_used"] = entry.last_used.isoformat()
            
            self._fallback_storage[token_id] = entry_data
            logger.warning(f"Token {token_id} stored in fallback memory storage")
            return entry
            
        except Exception as e:
            logger.error(f"Failed to store service token: {e}")
            raise ServiceTokenStorageError(f"Failed to store token: {e}")
    
    async def get_token(self, token_id: str) -> ServiceTokenEntry:
        """
        Retrieve a service token with fallback to in-memory storage.
        
        Args:
            token_id: Token identifier
            
        Returns:
            ServiceTokenEntry instance
            
        Raises:
            TokenNotFoundError: If token is not found
            TokenExpiredError: If token has expired
            ServiceTokenStorageError: If retrieval operation fails
        """
        try:
            # Try Redis first if available
            if self._redis_available:
                redis_client = await self._get_redis()
                token_key = self._get_token_key(token_id)
                
                # Get token data
                token_data = await redis_client.get(token_key)
                if token_data:
                    # Parse token data
                    entry_data = json.loads(token_data)
                    
                    # Convert ISO strings back to datetime objects
                    entry_data["issued_at"] = datetime.fromisoformat(entry_data["issued_at"])
                    entry_data["expires_at"] = datetime.fromisoformat(entry_data["expires_at"])
                    if entry_data.get("last_used"):
                        entry_data["last_used"] = datetime.fromisoformat(entry_data["last_used"])
                    
                    entry = ServiceTokenEntry(**entry_data)
                    
                    # Check if token has expired
                    if entry.expires_at <= datetime.now(timezone.utc):
                        # Clean up expired token
                        await self.revoke_token(token_id)
                        raise TokenExpiredError(f"Token {token_id} has expired")
                    
                    return entry
                    
        except (RedisError, ConnectionError, TimeoutError) as e:
            self.logger.error(f"Redis get_token error: {e}, checking fallback storage")
            self._redis_available = False
        except (TokenNotFoundError, TokenExpiredError):
            raise
        except Exception as e:
            logger.error(f"Failed to retrieve service token from Redis: {e}")
            
        # Check fallback storage
        if token_id in self._fallback_storage:
            entry_data = self._fallback_storage[token_id].copy()
            
            # Convert ISO strings back to datetime objects
            entry_data["issued_at"] = datetime.fromisoformat(entry_data["issued_at"])
            entry_data["expires_at"] = datetime.fromisoformat(entry_data["expires_at"])
            if entry_data.get("last_used"):
                entry_data["last_used"] = datetime.fromisoformat(entry_data["last_used"])
            
            entry = ServiceTokenEntry(**entry_data)
            
            # Check if token has expired
            if entry.expires_at <= datetime.now(timezone.utc):
                del self._fallback_storage[token_id]  # Clean up expired token
                raise TokenExpiredError(f"Token {token_id} has expired")
            
            self.logger.info(f"Token {token_id} retrieved from fallback storage")
            return entry
            
        # Token not found in either storage
        raise TokenNotFoundError(f"Token {token_id} not found")
    
    async def update_token_usage(self, token_id: str) -> None:
        """
        Update token last used timestamp with fallback support.
        
        Args:
            token_id: Token identifier
        """
        try:
            # Try Redis first if available
            if self._redis_available:
                redis_client = await self._get_redis()
                token_key = self._get_token_key(token_id)
                
                # Get current token data
                token_data = await redis_client.get(token_key)
                if token_data:
                    entry_data = json.loads(token_data)
                    entry_data["last_used"] = datetime.now(timezone.utc).isoformat()
                    
                    # Update with same TTL
                    ttl = await redis_client.ttl(token_key)
                    if ttl > 0:
                        await redis_client.setex(token_key, ttl, json.dumps(entry_data))
                        
                    # Update statistics
                    await redis_client.hincrby(self.stats_key, "tokens_used", 1)
                    return
                    
        except (RedisError, ConnectionError, TimeoutError) as e:
            self.logger.error(f"Redis update_token_usage error: {e}, updating fallback storage")
            self._redis_available = False
            
        # Update fallback storage
        if token_id in self._fallback_storage:
            self._fallback_storage[token_id]["last_used"] = datetime.now(timezone.utc).isoformat()
            self.logger.info(f"Token {token_id} usage updated in fallback storage")
    
    async def update_token_metadata(self, token_id: str, metadata: Dict[str, Any]) -> None:
        """
        Update token metadata with fallback support.
        
        Args:
            token_id: Token identifier
            metadata: New metadata to merge with existing token data
        """
        try:
            # Try Redis first if available
            if self._redis_available:
                redis_client = await self._get_redis()
                token_key = self._get_token_key(token_id)
                
                # Get current token data
                token_data = await redis_client.get(token_key)
                if token_data:
                    entry_data = json.loads(token_data)
                    
                    # Update token_data with new metadata
                    if "token_data" not in entry_data:
                        entry_data["token_data"] = {}
                    entry_data["token_data"].update(metadata)
                    
                    # Update with same TTL
                    ttl = await redis_client.ttl(token_key)
                    if ttl > 0:
                        await redis_client.setex(token_key, ttl, json.dumps(entry_data))
                        self.logger.info(f"Token {token_id} metadata updated in Redis")
                        return
                    
        except (RedisError, ConnectionError, TimeoutError) as e:
            self.logger.error(f"Redis update_token_metadata error: {e}, updating fallback storage")
            self._redis_available = False
            
        # Update fallback storage
        if token_id in self._fallback_storage:
            if "token_data" not in self._fallback_storage[token_id]:
                self._fallback_storage[token_id]["token_data"] = {}
            self._fallback_storage[token_id]["token_data"].update(metadata)
            self.logger.info(f"Token {token_id} metadata updated in fallback storage")
    
    async def revoke_token(self, token_id: str) -> bool:
        """
        Revoke service token with fallback support.
        
        Args:
            token_id: Token identifier
            
        Returns:
            True if token was revoked, False if not found
        """
        revoked = False
        
        try:
            # Try Redis first if available
            if self._redis_available:
                redis_client = await self._get_redis()
                token_key = self._get_token_key(token_id)
                
                # Check if token exists and get service name for index cleanup
                token_data = await redis_client.get(token_key)
                if token_data:
                    entry_data = json.loads(token_data)
                    service_name = entry_data.get("service_name")
                    
                    # Remove from Redis
                    await redis_client.delete(token_key)
                    
                    # Remove from service index if service name is available
                    if service_name:
                        service_index_key = self._get_service_index_key(service_name)
                        await redis_client.srem(service_index_key, token_id)
                    
                    # Update statistics
                    await redis_client.hincrby(self.stats_key, "tokens_revoked", 1)
                    revoked = True
                    
        except (RedisError, ConnectionError, TimeoutError) as e:
            self.logger.error(f"Redis revoke_token error: {e}, checking fallback storage")
            self._redis_available = False
            
        # Check and remove from fallback storage
        if token_id in self._fallback_storage:
            del self._fallback_storage[token_id]
            self.logger.info(f"Token {token_id} revoked from fallback storage")
            revoked = True
            
        return revoked
    
    async def revoke_service_tokens(self, service_name: str) -> int:
        """
        Revoke all tokens for a specific service.
        
        Args:
            service_name: Service name
            
        Returns:
            Number of tokens revoked
            
        Raises:
            ServiceTokenStorageError: If revocation operation fails
        """
        try:
            redis_client = await self._get_redis()
            service_index_key = self._get_service_index_key(service_name)
            
            # Get all token IDs for the service
            token_ids = await redis_client.smembers(service_index_key)
            
            revoked_count = 0
            for token_id in token_ids:
                if await self.revoke_token(token_id):
                    revoked_count += 1
            
            # Clean up service index
            await redis_client.delete(service_index_key)
            
            logger.info(f"Revoked {revoked_count} tokens for service {service_name}")
            return revoked_count
            
        except Exception as e:
            logger.error(f"Failed to revoke service tokens: {e}")
            raise ServiceTokenStorageError(f"Failed to revoke service tokens: {e}")
    
    async def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired tokens with fallback support.
        
        Returns:
            Number of tokens cleaned up
            
        Raises:
            ServiceTokenStorageError: If cleanup operation fails
        """
        cleaned_count = 0
        
        try:
            # Try Redis cleanup first if available
            if self._redis_available:
                redis_client = await self._get_redis()
                
                # Redis automatically handles TTL expiration, but we can clean up
                # any tokens that might have expired but not been accessed
                # This is mainly for statistics and service index cleanup
                
                # Get all service indices to check for expired tokens
                service_pattern = f"service_index:*"
                service_keys = await redis_client.keys(service_pattern)
                
                for service_key in service_keys:
                    token_ids = await redis_client.smembers(service_key)
                    expired_tokens = []
                    
                    for token_id in token_ids:
                        token_key = self._get_token_key(token_id)
                        if not await redis_client.exists(token_key):
                            expired_tokens.append(token_id)
                    
                    # Remove expired tokens from service index
                    if expired_tokens:
                        await redis_client.srem(service_key, *expired_tokens)
                        cleaned_count += len(expired_tokens)
                        
                # Update statistics
                if cleaned_count > 0:
                    await redis_client.hincrby(self.stats_key, "tokens_cleaned", cleaned_count)
                    
        except (RedisError, ConnectionError, TimeoutError) as e:
            self.logger.error(f"Redis cleanup_expired_tokens error: {e}, cleaning fallback storage")
            self._redis_available = False
            
        # Clean up fallback storage
        current_time = datetime.now(timezone.utc)
        expired_tokens = []
        
        for token_id, token_data in self._fallback_storage.items():
            expires_at = datetime.fromisoformat(token_data["expires_at"])
            if expires_at <= current_time:
                expired_tokens.append(token_id)
        
        # Remove expired tokens from fallback storage
        for token_id in expired_tokens:
            del self._fallback_storage[token_id]
            cleaned_count += 1
            
        if expired_tokens:
            self.logger.info(f"Cleaned {len(expired_tokens)} expired tokens from fallback storage")
            
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} expired service tokens")
            
        return cleaned_count
    
    async def get_service_token_stats(self, service_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get service token statistics with fallback support.
        
        Args:
            service_name: Optional service name to filter stats
            
        Returns:
            Dictionary containing token statistics
        """
        stats = {
            "total_tokens": 0,
            "active_tokens": 0,
            "tokens_stored": 0,
            "tokens_retrieved": 0,
            "tokens_used": 0,
            "tokens_revoked": 0,
            "tokens_cleaned": 0,
            "redis_available": self._redis_available,
            "fallback_tokens": len(self._fallback_storage)
        }
        
        try:
            # Try Redis stats first if available
            if self._redis_available:
                redis_client = await self._get_redis()
                
                # Get global statistics
                redis_stats = await redis_client.hgetall(self.stats_key)
                for key, value in redis_stats.items():
                    if key in stats:
                        stats[key] = int(value)
                
                # Count active tokens
                if service_name:
                    service_index_key = self._get_service_index_key(service_name)
                    stats["active_tokens"] = await redis_client.scard(service_index_key)
                else:
                    # Count all active tokens across all services
                    pattern = f"service_index:*"
                    service_keys = await redis_client.keys(pattern)
                    total_active = 0
                    for service_key in service_keys:
                        total_active += await redis_client.scard(service_key)
                    stats["active_tokens"] = total_active
                    
        except (RedisError, ConnectionError, TimeoutError) as e:
            self.logger.error(f"Redis get_service_token_stats error: {e}, using fallback data")
            self._redis_available = False
            
        # Add fallback storage stats
        if service_name:
            fallback_count = sum(1 for token_data in self._fallback_storage.values() 
                               if token_data.get("service_name") == service_name)
            stats["active_tokens"] += fallback_count
        else:
            stats["active_tokens"] += len(self._fallback_storage)
            
        stats["total_tokens"] = stats["active_tokens"]
        
        return stats
    
    async def close(self):
        """
        Close Redis connection and clean up resources.
        """
        try:
            if self.redis:
                await self.redis.close()
                self.logger.info("Redis connection closed")
        except Exception as e:
            self.logger.error(f"Error closing Redis connection: {e}")
        finally:
            self.redis = None
            self._fallback_storage.clear()