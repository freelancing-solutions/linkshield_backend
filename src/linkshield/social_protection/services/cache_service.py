#!/usr/bin/env python3
"""
Cache Service for Social Protection

Provides Redis-based caching for scan results, profile data, and analysis results
with automatic expiration and cache invalidation support.
"""

import json
import hashlib
from typing import Any, Dict, Optional
from datetime import timedelta
from uuid import UUID

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    aioredis = None
    REDIS_AVAILABLE = False

from linkshield.social_protection.logging_utils import get_logger
from linkshield.social_protection.exceptions import CacheServiceError

logger = get_logger("CacheService")


class CacheService:
    """
    Redis-based cache service for social protection operations.
    
    Provides caching for:
    - Profile scan results
    - Content analysis results
    - Platform adapter responses
    - Comprehensive assessments
    """
    
    def __init__(self, redis_url: str, namespace: str = "sp"):
        """
        Initialize cache service.
        
        Args:
            redis_url: Redis connection URL
            namespace: Cache key namespace prefix
        """
        self.redis_url = redis_url
        self.namespace = namespace
        self._redis: Optional[aioredis.Redis] = None
        self._enabled = REDIS_AVAILABLE
        
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, caching disabled")
    
    async def connect(self) -> None:
        """Establish Redis connection"""
        if not self._enabled:
            return
        
        try:
            self._redis = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            await self._redis.ping()
            logger.info("Connected to Redis cache")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            self._enabled = False
            self._redis = None
    
    async def close(self) -> None:
        """Close Redis connection"""
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Closed Redis connection")
    
    def _make_key(self, key_type: str, identifier: str) -> str:
        """
        Generate cache key with namespace.
        
        Args:
            key_type: Type of cached data (scan, profile, analysis)
            identifier: Unique identifier for the data
            
        Returns:
            Formatted cache key
        """
        return f"{self.namespace}:{key_type}:{identifier}"
    
    def _hash_content(self, content: str) -> str:
        """
        Generate hash for content-based caching.
        
        Args:
            content: Content to hash
            
        Returns:
            SHA256 hash of content
        """
        return hashlib.sha256(content.encode()).hexdigest()
    
    async def get_scan_result(self, scan_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Get cached scan result.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Cached scan result or None if not found
        """
        if not self._enabled or not self._redis:
            return None
        
        try:
            key = self._make_key("scan", str(scan_id))
            data = await self._redis.get(key)
            
            if data:
                logger.debug(f"Cache hit for scan {scan_id}")
                return json.loads(data)
            
            logger.debug(f"Cache miss for scan {scan_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting scan from cache: {str(e)}")
            return None
    
    async def set_scan_result(
        self,
        scan_id: UUID,
        result: Dict[str, Any],
        ttl_seconds: int = 3600
    ) -> bool:
        """
        Cache scan result.
        
        Args:
            scan_id: Scan identifier
            result: Scan result data
            ttl_seconds: Time to live in seconds (default: 1 hour)
            
        Returns:
            True if cached successfully
        """
        if not self._enabled or not self._redis:
            return False
        
        try:
            key = self._make_key("scan", str(scan_id))
            data = json.dumps(result)
            await self._redis.setex(key, ttl_seconds, data)
            
            logger.debug(f"Cached scan result for {scan_id}, TTL: {ttl_seconds}s")
            return True
            
        except Exception as e:
            logger.error(f"Error caching scan result: {str(e)}")
            return False
    
    async def get_profile_data(
        self,
        platform: str,
        profile_url: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached profile data.
        
        Args:
            platform: Platform name
            profile_url: Profile URL
            
        Returns:
            Cached profile data or None if not found
        """
        if not self._enabled or not self._redis:
            return None
        
        try:
            url_hash = self._hash_content(profile_url)
            key = self._make_key("profile", f"{platform}:{url_hash}")
            data = await self._redis.get(key)
            
            if data:
                logger.debug(f"Cache hit for profile {platform}:{profile_url}")
                return json.loads(data)
            
            logger.debug(f"Cache miss for profile {platform}:{profile_url}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting profile from cache: {str(e)}")
            return None
    
    async def set_profile_data(
        self,
        platform: str,
        profile_url: str,
        data: Dict[str, Any],
        ttl_seconds: int = 1800
    ) -> bool:
        """
        Cache profile data.
        
        Args:
            platform: Platform name
            profile_url: Profile URL
            data: Profile data
            ttl_seconds: Time to live in seconds (default: 30 minutes)
            
        Returns:
            True if cached successfully
        """
        if not self._enabled or not self._redis:
            return False
        
        try:
            url_hash = self._hash_content(profile_url)
            key = self._make_key("profile", f"{platform}:{url_hash}")
            json_data = json.dumps(data)
            await self._redis.setex(key, ttl_seconds, json_data)
            
            logger.debug(f"Cached profile data for {platform}:{profile_url}, TTL: {ttl_seconds}s")
            return True
            
        except Exception as e:
            logger.error(f"Error caching profile data: {str(e)}")
            return False
    
    async def get_analysis_result(
        self,
        content_hash: str,
        platform: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached content analysis result.
        
        Args:
            content_hash: Hash of analyzed content
            platform: Platform name
            
        Returns:
            Cached analysis result or None if not found
        """
        if not self._enabled or not self._redis:
            return None
        
        try:
            key = self._make_key("analysis", f"{platform}:{content_hash}")
            data = await self._redis.get(key)
            
            if data:
                logger.debug(f"Cache hit for analysis {platform}:{content_hash}")
                return json.loads(data)
            
            logger.debug(f"Cache miss for analysis {platform}:{content_hash}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting analysis from cache: {str(e)}")
            return None
    
    async def set_analysis_result(
        self,
        content_hash: str,
        platform: str,
        result: Dict[str, Any],
        ttl_seconds: int = 300
    ) -> bool:
        """
        Cache content analysis result.
        
        Args:
            content_hash: Hash of analyzed content
            platform: Platform name
            result: Analysis result
            ttl_seconds: Time to live in seconds (default: 5 minutes)
            
        Returns:
            True if cached successfully
        """
        if not self._enabled or not self._redis:
            return False
        
        try:
            key = self._make_key("analysis", f"{platform}:{content_hash}")
            data = json.dumps(result)
            await self._redis.setex(key, ttl_seconds, data)
            
            logger.debug(f"Cached analysis result for {platform}:{content_hash}, TTL: {ttl_seconds}s")
            return True
            
        except Exception as e:
            logger.error(f"Error caching analysis result: {str(e)}")
            return False
    
    async def invalidate_scan(self, scan_id: UUID) -> bool:
        """
        Invalidate cached scan result.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            True if invalidated successfully
        """
        if not self._enabled or not self._redis:
            return False
        
        try:
            key = self._make_key("scan", str(scan_id))
            await self._redis.delete(key)
            logger.debug(f"Invalidated cache for scan {scan_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error invalidating scan cache: {str(e)}")
            return False
    
    async def invalidate_profile(self, platform: str, profile_url: str) -> bool:
        """
        Invalidate cached profile data.
        
        Args:
            platform: Platform name
            profile_url: Profile URL
            
        Returns:
            True if invalidated successfully
        """
        if not self._enabled or not self._redis:
            return False
        
        try:
            url_hash = self._hash_content(profile_url)
            key = self._make_key("profile", f"{platform}:{url_hash}")
            await self._redis.delete(key)
            logger.debug(f"Invalidated cache for profile {platform}:{profile_url}")
            return True
            
        except Exception as e:
            logger.error(f"Error invalidating profile cache: {str(e)}")
            return False
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        if not self._enabled or not self._redis:
            return {
                "enabled": False,
                "connected": False
            }
        
        try:
            info = await self._redis.info("stats")
            return {
                "enabled": True,
                "connected": True,
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
                "total_commands_processed": info.get("total_commands_processed", 0)
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {str(e)}")
            return {
                "enabled": True,
                "connected": False,
                "error": str(e)
            }


# Global cache service instance
_cache_service: Optional[CacheService] = None


def get_cache_service(redis_url: Optional[str] = None) -> CacheService:
    """
    Get or create global cache service instance.
    
    Args:
        redis_url: Optional Redis URL (uses default if not provided)
        
    Returns:
        CacheService instance
    """
    global _cache_service
    
    if _cache_service is None:
        from linkshield.config.settings import get_settings
        settings = get_settings()
        url = redis_url or settings.REDIS_URL
        _cache_service = CacheService(url)
    
    return _cache_service
