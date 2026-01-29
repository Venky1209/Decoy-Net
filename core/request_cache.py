"""
Request caching and deduplication for concurrent API requests.
Prevents duplicate LLM calls when multiple identical requests arrive simultaneously.
"""
import asyncio
import hashlib
import time
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from collections import OrderedDict

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Cache entry with result and metadata."""
    result: Any
    created_at: float
    ttl_seconds: float
    pending: asyncio.Future = None
    
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_seconds


class RequestCache:
    """
    In-memory cache for API request results with deduplication.
    
    When multiple identical requests arrive:
    1. First request starts processing and creates a "pending" entry
    2. Subsequent requests wait on the same future
    3. When first request completes, all waiting requests get the same result
    
    This prevents:
    - Duplicate LLM API calls (saves quota)
    - Inconsistent results for same message
    - Rate limiting issues
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: float = 60.0):
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._lock = asyncio.Lock()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "pending_joins": 0,
            "evictions": 0
        }
    
    def _make_key(self, message: str, session_id: str = None) -> str:
        """Create cache key from message (and optionally session)."""
        # Use message hash for key (same message = same key)
        content = message.strip().lower()
        return hashlib.sha256(content.encode()).hexdigest()[:32]
    
    async def get_or_execute(
        self,
        key: str,
        executor: callable,
        ttl: float = None
    ) -> Any:
        """
        Get cached result or execute and cache.
        
        If a request for the same key is already in progress,
        wait for it instead of starting a new one.
        """
        async with self._lock:
            # Check if we have a cached or pending result
            if key in self.cache:
                entry = self.cache[key]
                
                # If result exists and not expired, return it
                if entry.result is not None and not entry.is_expired():
                    self._stats["hits"] += 1
                    logger.debug(f"Cache hit for key {key[:8]}...")
                    return entry.result
                
                # If pending, wait for the result
                if entry.pending is not None and not entry.pending.done():
                    self._stats["pending_joins"] += 1
                    logger.info(f"Joining pending request for key {key[:8]}...")
                    # Release lock while waiting
                
            else:
                self._stats["misses"] += 1
        
        # Check again if we need to join a pending request (outside lock)
        if key in self.cache and self.cache[key].pending is not None:
            try:
                return await self.cache[key].pending
            except Exception:
                pass  # If pending failed, we'll try again
        
        # Create pending entry
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        
        async with self._lock:
            self.cache[key] = CacheEntry(
                result=None,
                created_at=time.time(),
                ttl_seconds=ttl or self.default_ttl,
                pending=future
            )
            self._evict_if_needed()
        
        # Execute
        try:
            result = await executor()
            
            async with self._lock:
                self.cache[key].result = result
                self.cache[key].pending = None
                self.cache[key].created_at = time.time()
            
            # Resolve future for any waiting requests
            if not future.done():
                future.set_result(result)
            
            return result
            
        except Exception as e:
            # Remove failed entry
            async with self._lock:
                if key in self.cache:
                    del self.cache[key]
            
            # Reject future for any waiting requests
            if not future.done():
                future.set_exception(e)
            
            raise
    
    def _evict_if_needed(self):
        """Evict oldest entries if cache is full."""
        while len(self.cache) > self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self._stats["evictions"] += 1
    
    def invalidate(self, key: str):
        """Remove a specific key from cache."""
        if key in self.cache:
            del self.cache[key]
    
    def clear(self):
        """Clear all cache entries."""
        self.cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            **self._stats,
            "size": len(self.cache),
            "max_size": self.max_size
        }


# Global instance for LLM detection cache
llm_detection_cache = RequestCache(max_size=500, default_ttl=30.0)

# Global instance for API response cache (longer TTL)
api_response_cache = RequestCache(max_size=1000, default_ttl=60.0)
