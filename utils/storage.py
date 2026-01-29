"""
Storage abstraction layer for session management.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: str, expiry_seconds: Optional[int] = None) -> bool:
        """Set value with optional expiry."""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a key."""
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        pass
    
    @abstractmethod
    def keys(self, pattern: str = "*") -> list:
        """Get keys matching pattern."""
        pass


class InMemoryStorage(StorageBackend):
    """
    In-memory storage backend for development.
    Data is lost on restart.
    """
    
    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}
        logger.info("Initialized in-memory storage backend")
    
    def get(self, key: str) -> Optional[str]:
        """Get value by key, checking expiry."""
        if key not in self._store:
            return None
        
        item = self._store[key]
        
        # Check expiry
        if item.get("expiry") and datetime.utcnow() > item["expiry"]:
            del self._store[key]
            return None
        
        return item["value"]
    
    def set(self, key: str, value: str, expiry_seconds: Optional[int] = None) -> bool:
        """Set value with optional expiry."""
        try:
            item = {"value": value, "expiry": None}
            
            if expiry_seconds:
                item["expiry"] = datetime.utcnow() + timedelta(seconds=expiry_seconds)
            
            self._store[key] = item
            return True
        except Exception as e:
            logger.error(f"Error setting key {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete a key."""
        if key in self._store:
            del self._store[key]
            return True
        return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists and not expired."""
        return self.get(key) is not None
    
    def keys(self, pattern: str = "*") -> list:
        """Get all keys (pattern matching simplified)."""
        self._cleanup_expired()
        if pattern == "*":
            return list(self._store.keys())
        # Simple prefix matching
        prefix = pattern.rstrip("*")
        return [k for k in self._store.keys() if k.startswith(prefix)]
    
    def _cleanup_expired(self):
        """Remove expired keys."""
        now = datetime.utcnow()
        expired = [
            k for k, v in self._store.items()
            if v.get("expiry") and now > v["expiry"]
        ]
        for key in expired:
            del self._store[key]
    
    def size(self) -> int:
        """Get number of stored items."""
        self._cleanup_expired()
        return len(self._store)


class RedisStorage(StorageBackend):
    """
    Redis storage backend for production.
    Requires redis-py package and running Redis server.
    """
    
    def __init__(self, url: str = "redis://localhost:6379"):
        try:
            import redis
            self._client = redis.from_url(url, decode_responses=True)
            self._client.ping()  # Test connection
            logger.info(f"Connected to Redis at {url}")
        except ImportError:
            raise ImportError("redis package required for Redis storage. Install with: pip install redis")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        try:
            return self._client.get(key)
        except Exception as e:
            logger.error(f"Redis GET error for {key}: {e}")
            return None
    
    def set(self, key: str, value: str, expiry_seconds: Optional[int] = None) -> bool:
        """Set value with optional expiry."""
        try:
            if expiry_seconds:
                self._client.setex(key, expiry_seconds, value)
            else:
                self._client.set(key, value)
            return True
        except Exception as e:
            logger.error(f"Redis SET error for {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete a key."""
        try:
            return self._client.delete(key) > 0
        except Exception as e:
            logger.error(f"Redis DELETE error for {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        try:
            return self._client.exists(key) > 0
        except Exception as e:
            logger.error(f"Redis EXISTS error for {key}: {e}")
            return False
    
    def keys(self, pattern: str = "*") -> list:
        """Get keys matching pattern."""
        try:
            return self._client.keys(pattern)
        except Exception as e:
            logger.error(f"Redis KEYS error for {pattern}: {e}")
            return []


def get_storage_backend(use_redis: bool = False, redis_url: str = None) -> StorageBackend:
    """
    Factory function to get appropriate storage backend.
    
    Args:
        use_redis: Whether to use Redis (production)
        redis_url: Redis connection URL
        
    Returns:
        StorageBackend instance
    """
    if use_redis:
        url = redis_url or "redis://localhost:6379"
        try:
            return RedisStorage(url)
        except Exception as e:
            logger.warning(f"Failed to initialize Redis, falling back to in-memory: {e}")
            return InMemoryStorage()
    else:
        return InMemoryStorage()
