"""Cache Service using Redis for performance optimization."""

import json
import hashlib
from typing import Any, Optional
from datetime import timedelta

import redis


class CacheService:
    """Service for caching frequently accessed data in Redis."""
    
    _instance = None
    _redis = None
    
    # Default TTLs in seconds
    DEFAULT_TTL = 300  # 5 minutes
    STATS_TTL = 300    # 5 minutes
    SEARCH_TTL = 60    # 1 minute
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize Redis connection."""
        import os
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        
        try:
            self._redis = redis.from_url(redis_url, decode_responses=True)
            # Test connection
            self._redis.ping()
        except Exception as e:
            print(f"Warning: Redis connection failed: {e}")
            self._redis = None
    
    def _generate_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate a cache key from prefix and arguments."""
        key_data = f"{prefix}:{json.dumps(args, sort_keys=True)}:{json.dumps(kwargs, sort_keys=True)}"
        key_hash = hashlib.md5(key_data.encode()).hexdigest()
        return f"elasmisp:{prefix}:{key_hash}"
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get a value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        if not self._redis:
            return None
        
        try:
            value = self._redis.get(key)
            if value:
                return json.loads(value)
        except Exception:
            pass
        
        return None
    
    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """
        Set a value in cache.
        
        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
            ttl: Time-to-live in seconds
            
        Returns:
            True if successful
        """
        if not self._redis:
            return False
        
        try:
            ttl = ttl or self.DEFAULT_TTL
            serialized = json.dumps(value)
            self._redis.setex(key, ttl, serialized)
            return True
        except Exception:
            return False
    
    def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        if not self._redis:
            return False
        
        try:
            self._redis.delete(key)
            return True
        except Exception:
            return False
    
    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern."""
        if not self._redis:
            return 0
        
        try:
            keys = self._redis.keys(pattern)
            if keys:
                return self._redis.delete(*keys)
        except Exception:
            pass
        
        return 0
    
    def invalidate_ioc_cache(self):
        """Invalidate all IOC-related caches."""
        self.delete_pattern("elasmisp:stats:*")
        self.delete_pattern("elasmisp:ioc_list:*")
        self.delete_pattern("elasmisp:search:*")
    
    def invalidate_stats_cache(self):
        """Invalidate stats cache."""
        self.delete_pattern("elasmisp:stats:*")
    
    # High-level caching methods
    def cache_stats(self, stats: dict) -> bool:
        """Cache IOC statistics."""
        key = self._generate_key("stats", "ioc")
        return self.set(key, stats, self.STATS_TTL)
    
    def get_cached_stats(self) -> Optional[dict]:
        """Get cached IOC statistics."""
        key = self._generate_key("stats", "ioc")
        return self.get(key)
    
    def cache_search_results(self, query: str, filters: dict, results: dict) -> bool:
        """Cache search results."""
        key = self._generate_key("search", query, **filters)
        return self.set(key, results, self.SEARCH_TTL)
    
    def get_cached_search_results(self, query: str, filters: dict) -> Optional[dict]:
        """Get cached search results."""
        key = self._generate_key("search", query, **filters)
        return self.get(key)
    
    def cache_ioc_list(self, page: int, per_page: int, filters: dict, results: dict) -> bool:
        """Cache IOC list results."""
        key = self._generate_key("ioc_list", page, per_page, **filters)
        return self.set(key, results, self.DEFAULT_TTL)
    
    def get_cached_ioc_list(self, page: int, per_page: int, filters: dict) -> Optional[dict]:
        """Get cached IOC list results."""
        key = self._generate_key("ioc_list", page, per_page, **filters)
        return self.get(key)
    
    # Metrics
    def get_cache_stats(self) -> dict:
        """Get cache statistics."""
        if not self._redis:
            return {'connected': False}
        
        try:
            info = self._redis.info()
            keys = len(self._redis.keys("elasmisp:*"))
            
            return {
                'connected': True,
                'used_memory': info.get('used_memory_human', 'unknown'),
                'connected_clients': info.get('connected_clients', 0),
                'total_keys': keys,
                'hits': info.get('keyspace_hits', 0),
                'misses': info.get('keyspace_misses', 0),
                'hit_rate': round(
                    info.get('keyspace_hits', 0) / 
                    max(info.get('keyspace_hits', 0) + info.get('keyspace_misses', 0), 1) * 100, 
                    2
                )
            }
        except Exception as e:
            return {'connected': False, 'error': str(e)}


# Singleton instance
_cache_service: Optional[CacheService] = None


def get_cache_service() -> CacheService:
    """Get the singleton cache service instance."""
    global _cache_service
    if _cache_service is None:
        _cache_service = CacheService()
    return _cache_service
