import redis
import json
from typing import Optional, Any, Dict, List
from datetime import timedelta
import os
from dotenv import load_dotenv

load_dotenv()

class RedisCache:
    def __init__(self):
        redis_enabled = os.getenv("REDIS_ENABLED", "true").lower() == "true"
        
        if redis_enabled:
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
            try:
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                # Test connection
                self.redis_client.ping()
                print("Redis connection established")
            except (redis.ConnectionError, Exception):
                print("Warning: Redis not available, using memory cache fallback")
                self.redis_client = None
                self._memory_cache = {}
        else:
            print("Redis disabled, using memory cache")
            self.redis_client = None
            self._memory_cache = {}
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            if self.redis_client:
                value = self.redis_client.get(key)
                return json.loads(value) if value else None
            else:
                return self._memory_cache.get(key)
        except Exception as e:
            print(f"Cache get error: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL in seconds"""
        try:
            if self.redis_client:
                json_value = json.dumps(value, default=str)
                if ttl:
                    return self.redis_client.setex(key, ttl, json_value)
                else:
                    return self.redis_client.set(key, json_value)
            else:
                self._memory_cache[key] = value
                return True
        except Exception as e:
            print(f"Cache set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            if self.redis_client:
                return bool(self.redis_client.delete(key))
            else:
                return bool(self._memory_cache.pop(key, None))
        except Exception as e:
            print(f"Cache delete error: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            if self.redis_client:
                return bool(self.redis_client.exists(key))
            else:
                return key in self._memory_cache
        except Exception as e:
            print(f"Cache exists error: {e}")
            return False
    
    def keys(self, pattern: str = "*") -> list:
        """Get keys matching pattern"""
        try:
            if self.redis_client:
                return self.redis_client.keys(pattern)
            else:
                import fnmatch
                return [k for k in self._memory_cache.keys() if fnmatch.fnmatch(k, pattern)]
        except Exception as e:
            print(f"Cache keys error: {e}")
            return []
    
    def clear(self) -> bool:
        """Clear all cache"""
        try:
            if self.redis_client:
                return bool(self.redis_client.flushdb())
            else:
                self._memory_cache.clear()
                return True
        except Exception as e:
            print(f"Cache clear error: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            if self.redis_client:
                info = self.redis_client.info()
                return {
                    "type": "redis",
                    "connected_clients": info.get("connected_clients", 0),
                    "used_memory": info.get("used_memory_human", "unknown"),
                    "total_keys": self.redis_client.dbsize(),
                    "hits": info.get("keyspace_hits", 0),
                    "misses": info.get("keyspace_misses", 0)
                }
            else:
                return {
                    "type": "memory",
                    "total_keys": len(self._memory_cache),
                    "status": "fallback_mode"
                }
        except Exception as e:
            return {"error": str(e)}

# Global cache instance
cache = RedisCache()

# Redis key patterns and TTL configuration
REDIS_KEYS = {
    'logs': 'logs:{window}',           # Redis keys logs:{window}
    'incident_analysis': 'incident_analysis:{incident_id}',
    'ip_intel': 'ip_intel:{ip}',
    'user_context': 'user_context:{user}',
    'detection': 'detection:{logs_hash}'
}

REDIS_TTL = {
    'logs': 7200,          # ttl=2h (7200 seconds)
    'incident_analysis': 3600,   # 1 hour
    'ip_intel': 86400,           # 24 hours
    'user_context': 1800,        # 30 minutes
    'detection': 1800            # 30 minutes
}

# Convenience functions for common caching patterns
def cache_logs_window(window: str, logs: List[Dict[str, Any]]) -> bool:
    """Cache logs for window with 2h TTL"""
    key = REDIS_KEYS['logs'].format(window=window)
    return cache.set(key, logs, REDIS_TTL['logs'])

def get_cached_logs_window(window: str) -> Optional[List[Dict[str, Any]]]:
    """Get cached logs for window"""
    key = REDIS_KEYS['logs'].format(window=window)
    return cache.get(key)

def cache_incident_analysis(incident_id: str, analysis: Dict[str, Any]) -> bool:
    """Cache incident analysis for 1 hour"""
    key = REDIS_KEYS['incident_analysis'].format(incident_id=incident_id)
    return cache.set(key, analysis, REDIS_TTL['incident_analysis'])

def get_cached_incident_analysis(incident_id: str) -> Optional[Dict[str, Any]]:
    """Get cached incident analysis"""
    key = REDIS_KEYS['incident_analysis'].format(incident_id=incident_id)
    return cache.get(key)

def cache_ip_intel(ip: str, intel: Dict[str, Any]) -> bool:
    """Cache IP intelligence for 24 hours"""
    key = REDIS_KEYS['ip_intel'].format(ip=ip)
    return cache.set(key, intel, REDIS_TTL['ip_intel'])

def get_cached_ip_intel(ip: str) -> Optional[Dict[str, Any]]:
    """Get cached IP intelligence"""
    key = REDIS_KEYS['ip_intel'].format(ip=ip)
    return cache.get(key)

def cache_user_context(user: str, context: Dict[str, Any]) -> bool:
    """Cache user context for 30 minutes"""
    key = REDIS_KEYS['user_context'].format(user=user)
    return cache.set(key, context, REDIS_TTL['user_context'])

def get_cached_user_context(user: str) -> Optional[Dict[str, Any]]:
    """Get cached user context"""
    key = REDIS_KEYS['user_context'].format(user=user)
    return cache.get(key)

def cache_detection_results(logs_hash: str, results: list) -> bool:
    """Cache detection results for 30 minutes"""
    key = REDIS_KEYS['detection'].format(logs_hash=logs_hash)
    return cache.set(key, results, REDIS_TTL['detection'])

def get_cached_detection_results(logs_hash: str) -> Optional[list]:
    """Get cached detection results"""
    key = REDIS_KEYS['detection'].format(logs_hash=logs_hash)
    return cache.get(key)