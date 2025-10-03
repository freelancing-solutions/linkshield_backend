"""
Social Protection Caching Service

Provides caching capabilities for expensive operations including content analysis,
profile scans, and extension responses.
"""

import asyncio
import hashlib
import json
import time
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta
from collections import OrderedDict

from src.social_protection.logging_utils import get_logger

logger = get_logger("SocialProtectionCache")

try:
    import aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("aioredis not available, using in-memory cache only")


class CacheService:
    """Base cache service interface"""
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        raise NotImplementedError
    
    async def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        """Set value in cache with TTL in seconds"""
        raise NotImplementedError
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        raise NotImplementedError
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        raise NotImplementedError
    
    async def clear(self, pattern: Optional[str] = None) -> int:
        """Clear cache entries matching pattern"""
        raise NotImplementedError
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        raise NotImplementedError
    
    async def close(self) -> None:
        """Close cache connections"""
        pass


class InMemoryCache(CacheService):
    """
    In-memory LRU cache implementation
    
    Suitable for single-instance deployments and extension responses.
    Uses LRU eviction policy when max size is reached.
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        """
        Initialize in-memory cache
        
        Args:
            max_size: Maximum number of entries
            default_ttl: Default TTL in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict = OrderedDict()
        self._expiry: Dict[str, float] = {}
        self._lock = asyncio.Lock()
        
        # Statistics
        self._hits = 0
        self._misses = 0
        self._sets = 0
        self._deletes = 0
        self._evictions = 0
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        async with self._lock:
            # Check if key exists and not expired
            if key in self._cache:
                if key in self._expiry and time.time() > self._expiry[key]:
                    # Expired, remove it
                    del self._cache[key]
                    del self._expiry[key]
                    self._misses += 1
                    return None
                
                # Move to end (most recently used)
                self._cache.move_to_end(key)
                self._hits += 1
                return self._cache[key]
            
            self._misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache with TTL"""
        async with self._lock:
            ttl = ttl or self.default_ttl
            
            # Check if we need to evict
            if key not in self._cache and len(self._cache) >= self.max_size:
                # Remove oldest entry (LRU)
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                if oldest_key in self._expiry:
                    del self._expiry[oldest_key]
                self._evictions += 1
            
            # Set value and expiry
            self._cache[key] = value
            self._cache.move_to_end(key)
            self._expiry[key] = time.time() + ttl
            self._sets += 1
            
            return True
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._expiry:
                    del self._expiry[key]
                self._deletes += 1
                return True
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists and not expired"""
        async with self._lock:
            if key in self._cache:
                if key in self._expiry and time.time() > self._expiry[key]:
                    # Expired
                    del self._cache[key]
                    del self._expiry[key]
                    return False
                return True
            return False
    
    async def clear(self, pattern: Optional[str] = None) -> int:
        """Clear cache entries"""
        async with self._lock:
            if pattern is None:
                count = len(self._cache)
                self._cache.clear()
                self._expiry.clear()
                return count
            
            # Pattern matching (simple prefix match)
            keys_to_delete = [k for k in self._cache.keys() if k.startswith(pattern.rstrip('*'))]
            for key in keys_to_delete:
                del self._cache[key]
                if key in self._expiry:
                    del self._expiry[key]
            
            return len(keys_to_delete)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        async with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0.0
            
            # Calculate size in bytes (approximate)
            size_bytes = sum(len(str(k)) + len(str(v)) for k, v in self._cache.items())
            
            return {
                "type": "in_memory",
                "entries": len(self._cache),
                "max_size": self.max_size,
                "size_bytes": size_bytes,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(hit_rate, 2),
                "sets": self._sets,
                "deletes": self._deletes,
                "evictions": self._evictions
            }
    
    async def cleanup_expired(self) -> int:
        """Remove expired entries"""
        async with self._lock:
            current_time = time.time()
            expired_keys = [k for k, exp in self._expiry.items() if current_time > exp]
            
            for key in expired_keys:
                del self._cache[key]
                del self._expiry[key]
            
            return len(expired_keys)


class RedisCache(CacheService):
    """
    Redis-backed cache implementation
    
    Suitable for multi-instance deployments and distributed caching.
    """
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        namespace: str = "sp_cache",
        default_ttl: int = 300
    ):
        """
        Initialize Redis cache
        
        Args:
            redis_url: Redis connection URL
            namespace: Key namespace prefix
            default_ttl: Default TTL in seconds
        """
        if not REDIS_AVAILABLE:
            raise RuntimeError("aioredis is required for RedisCache but is not installed")
        
        self.redis_url = redis_url
        self.namespace = namespace
        self.default_ttl = default_ttl
        self._redis = None
        
        # Statistics (stored in Redis)
        self._stats_key = f"{namespace}:stats"
    
    async def _get_redis(self):
        """Get or create Redis connection"""
        if self._redis is None:
            self._redis = await aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
        return self._redis
    
    def _make_key(self, key: str) -> str:
        """Create namespaced key"""
        return f"{self.namespace}:{key}"
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            redis = await self._get_redis()
            namespaced_key = self._make_key(key)
            
            value = await redis.get(namespaced_key)
            
            # Update stats
            if value is not None:
                await redis.hincrby(self._stats_key, "hits", 1)
                # Deserialize JSON
                return json.loads(value)
            else:
                await redis.hincrby(self._stats_key, "misses", 1)
                return None
        
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            return None
    
    async def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache with TTL"""
        try:
            redis = await self._get_redis()
            namespaced_key = self._make_key(key)
            ttl = ttl or self.default_ttl
            
            # Serialize to JSON
            serialized = json.dumps(value)
            
            await redis.setex(namespaced_key, ttl, serialized)
            await redis.hincrby(self._stats_key, "sets", 1)
            
            return True
        
        except Exception as e:
            logger.error(f"Redis set error: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        try:
            redis = await self._get_redis()
            namespaced_key = self._make_key(key)
            
            result = await redis.delete(namespaced_key)
            
            if result > 0:
                await redis.hincrby(self._stats_key, "deletes", 1)
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        try:
            redis = await self._get_redis()
            namespaced_key = self._make_key(key)
            
            return await redis.exists(namespaced_key) > 0
        
        except Exception as e:
            logger.error(f"Redis exists error: {e}")
            return False
    
    async def clear(self, pattern: Optional[str] = None) -> int:
        """Clear cache entries matching pattern"""
        try:
            redis = await self._get_redis()
            
            if pattern is None:
                pattern = "*"
            
            search_pattern = self._make_key(pattern)
            
            # Find all matching keys
            keys = []
            async for key in redis.scan_iter(match=search_pattern):
                keys.append(key)
            
            if keys:
                deleted = await redis.delete(*keys)
                return deleted
            
            return 0
        
        except Exception as e:
            logger.error(f"Redis clear error: {e}")
            return 0
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            redis = await self._get_redis()
            
            stats = await redis.hgetall(self._stats_key)
            
            hits = int(stats.get("hits", 0))
            misses = int(stats.get("misses", 0))
            total_requests = hits + misses
            hit_rate = (hits / total_requests * 100) if total_requests > 0 else 0.0
            
            # Get approximate key count
            key_count = 0
            async for _ in redis.scan_iter(match=f"{self.namespace}:*"):
                key_count += 1
            
            return {
                "type": "redis",
                "entries": key_count,
                "hits": hits,
                "misses": misses,
                "hit_rate": round(hit_rate, 2),
                "sets": int(stats.get("sets", 0)),
                "deletes": int(stats.get("deletes", 0))
            }
        
        except Exception as e:
            logger.error(f"Redis stats error: {e}")
            return {
                "type": "redis",
                "error": str(e)
            }
    
    async def close(self) -> None:
        """Close Redis connection"""
        if self._redis is not None:
            await self._redis.close()
            self._redis = None


class CacheManager:
    """
    Unified cache manager supporting multiple cache backends
    
    Provides a single interface for caching with automatic fallback
    from Redis to in-memory cache.
    """
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        use_redis: bool = True,
        namespace: str = "sp_cache",
        default_ttl: int = 300,
        in_memory_max_size: int = 1000
    ):
        """
        Initialize cache manager
        
        Args:
            redis_url: Redis connection URL (optional)
            use_redis: Whether to use Redis if available
            namespace: Cache key namespace
            default_ttl: Default TTL in seconds
            in_memory_max_size: Max size for in-memory cache
        """
        self.namespace = namespace
        self.default_ttl = default_ttl
        
        # Try to initialize Redis cache
        self.redis_cache = None
        if use_redis and REDIS_AVAILABLE and redis_url:
            try:
                self.redis_cache = RedisCache(redis_url, namespace, default_ttl)
                logger.info("Redis cache initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Redis cache: {e}")
        
        # Always have in-memory cache as fallback
        self.memory_cache = InMemoryCache(in_memory_max_size, default_ttl)
        logger.info("In-memory cache initialized")
    
    @property
    def primary_cache(self) -> CacheService:
        """Get primary cache (Redis if available, otherwise in-memory)"""
        return self.redis_cache if self.redis_cache else self.memory_cache
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        return await self.primary_cache.get(key)
    
    async def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache"""
        return await self.primary_cache.set(key, value, ttl or self.default_ttl)
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        return await self.primary_cache.delete(key)
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        return await self.primary_cache.exists(key)
    
    async def clear(self, pattern: Optional[str] = None) -> int:
        """Clear cache entries"""
        return await self.primary_cache.clear(pattern)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return await self.primary_cache.get_stats()
    
    async def close(self) -> None:
        """Close all cache connections"""
        if self.redis_cache:
            await self.redis_cache.close()
    
    def generate_key(self, *parts: str) -> str:
        """
        Generate cache key from parts
        
        Args:
            *parts: Key components
            
        Returns:
            Cache key string
        """
        # Create hash of parts for consistent key generation
        key_str = ":".join(str(p) for p in parts)
        key_hash = hashlib.md5(key_str.encode()).hexdigest()[:16]
        return f"{':'.join(parts[:2])}:{key_hash}"


# Global cache manager instance
_cache_manager: Optional[CacheManager] = None


def get_cache_manager(
    redis_url: Optional[str] = None,
    use_redis: bool = True,
    namespace: str = "sp_cache"
) -> CacheManager:
    """
    Get or create global cache manager instance
    
    Args:
        redis_url: Redis connection URL
        use_redis: Whether to use Redis
        namespace: Cache namespace
        
    Returns:
        CacheManager instance
    """
    global _cache_manager
    
    if _cache_manager is None:
        _cache_manager = CacheManager(
            redis_url=redis_url,
            use_redis=use_redis,
            namespace=namespace
        )
    
    return _cache_manager
