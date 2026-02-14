import redis
import json
import hashlib
from functools import wraps
from config import config

class CacheManager:
    """Manage API response caching"""
    
    def __init__(self):
        self.redis_client = None
        self.cache_timeout = config.CACHE_TIMEOUT
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.from_url(config.REDIS_URL)
            self.redis_client.ping()
        except:
            print("Redis not available, using in-memory cache")
            self.redis_client = None
            self.memory_cache = {}
    
    def _generate_key(self, data):
        """Generate cache key from data"""
        if isinstance(data, str):
            data_str = data
        else:
            data_str = json.dumps(data, sort_keys=True)
        return hashlib.md5(data_str.encode()).hexdigest()
    
    def get(self, key_prefix, data):
        """Get cached data"""
        cache_key = f"{key_prefix}:{self._generate_key(data)}"
        
        if self.redis_client:
            cached = self.redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        else:
            if cache_key in self.memory_cache:
                data, timestamp = self.memory_cache[cache_key]
                if time.time() - timestamp < self.cache_timeout:
                    return data
        return None
    
    def set(self, key_prefix, data, value):
        """Cache data"""
        cache_key = f"{key_prefix}:{self._generate_key(data)}"
        
        if self.redis_client:
            self.redis_client.setex(
                cache_key, 
                self.cache_timeout, 
                json.dumps(value)
            )
        else:
            self.memory_cache[cache_key] = (value, time.time())
    
    def clear(self):
        """Clear all cache"""
        if self.redis_client:
            self.redis_client.flushdb()
        else:
            self.memory_cache.clear()

# Cache decorator
def cached(key_prefix, timeout=None):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            cache = CacheManager()
            cache_key_data = f"{func.__name__}:{args}:{kwargs}"
            
            # Try to get from cache
            cached_result = cache.get(key_prefix, cache_key_data)
            if cached_result:
                return cached_result
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Cache result
            cache.set(key_prefix, cache_key_data, result)
            return result
        return wrapper
    return decorator