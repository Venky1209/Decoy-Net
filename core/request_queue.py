"""
Rate-Limit Aware Request Queue with Multi-Provider Waterfall.
Implements:
- Option A: Multi-provider failover (Gemini → Groq → Together → Local)
- Option B: Request throttling with semaphore
"""
import asyncio
import time
import logging
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ProviderStatus(str, Enum):
    """Provider availability status."""
    AVAILABLE = "available"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


@dataclass
class ProviderState:
    """Track state of each LLM provider."""
    name: str
    status: ProviderStatus = ProviderStatus.AVAILABLE
    rate_limit_until: float = 0
    consecutive_errors: int = 0
    total_requests: int = 0
    total_successes: int = 0
    
    def is_available(self) -> bool:
        """Check if provider is available for requests."""
        if self.status == ProviderStatus.RATE_LIMITED:
            if time.time() > self.rate_limit_until:
                self.status = ProviderStatus.AVAILABLE
                return True
            return False
        return self.status == ProviderStatus.AVAILABLE
    
    def mark_rate_limited(self, cooldown_seconds: float = 60):
        """Mark provider as rate limited."""
        self.status = ProviderStatus.RATE_LIMITED
        self.rate_limit_until = time.time() + cooldown_seconds
        logger.warning(f"Provider {self.name} rate limited for {cooldown_seconds}s")
    
    def mark_success(self):
        """Mark successful request."""
        self.status = ProviderStatus.AVAILABLE
        self.consecutive_errors = 0
        self.total_requests += 1
        self.total_successes += 1
    
    def mark_error(self):
        """Mark failed request."""
        self.consecutive_errors += 1
        self.total_requests += 1
        if self.consecutive_errors >= 3:
            self.status = ProviderStatus.ERROR


class RateLimitAwareQueue:
    """
    Request queue with rate limiting awareness.
    
    Features:
    - Semaphore-based concurrent request limiting
    - Multi-provider waterfall failover
    - Exponential backoff on rate limits
    - Request deduplication via cache
    """
    
    def __init__(
        self,
        max_concurrent: int = 3,
        cache_ttl_seconds: int = 300,
        provider_order: List[str] = None
    ):
        self.max_concurrent = max_concurrent
        self.cache_ttl = cache_ttl_seconds
        self.provider_order = provider_order or ["gemini", "groq", "together", "local"]
        
        # Semaphore for throttling
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Provider states
        self.providers: Dict[str, ProviderState] = {
            name: ProviderState(name=name) for name in self.provider_order
        }
        
        # Request cache
        self.cache: Dict[str, Dict[str, Any]] = {}
        
        # Queue for pending requests
        self.pending_queue: asyncio.Queue = asyncio.Queue()
        
        # Stats
        self.stats = {
            "total_requests": 0,
            "cache_hits": 0,
            "failovers": 0,
            "local_fallbacks": 0
        }
    
    async def execute_with_failover(
        self,
        cache_key: str,
        provider_functions: Dict[str, Callable],
        local_fallback: Callable
    ) -> Dict[str, Any]:
        """
        Execute request with automatic failover on rate limit.
        
        Args:
            cache_key: Unique key for caching
            provider_functions: Dict mapping provider name to async function
            local_fallback: Sync function for local-only detection
            
        Returns:
            Detection result from first successful provider
        """
        self.stats["total_requests"] += 1
        
        # Check cache first
        cached = self._get_cached(cache_key)
        if cached:
            self.stats["cache_hits"] += 1
            return cached
        
        # Acquire semaphore for rate limiting
        async with self.semaphore:
            result = None
            used_provider = None
            
            # Try providers in order
            for provider_name in self.provider_order:
                if provider_name == "local":
                    continue  # Handle local separately
                
                provider = self.providers.get(provider_name)
                if not provider or not provider.is_available():
                    continue
                
                func = provider_functions.get(provider_name)
                if not func:
                    continue
                
                try:
                    result = await func()
                    provider.mark_success()
                    used_provider = provider_name
                    break
                    
                except Exception as e:
                    error_str = str(e).lower()
                    
                    # Check for rate limit errors
                    if any(x in error_str for x in ["429", "rate_limit", "resource_exhausted", "quota"]):
                        provider.mark_rate_limited(cooldown_seconds=60)
                        self.stats["failovers"] += 1
                        logger.warning(f"Rate limit hit on {provider_name}, failing over...")
                    else:
                        provider.mark_error()
                        logger.error(f"Error from {provider_name}: {e}")
            
            # Fallback to local if all providers failed
            if result is None:
                try:
                    result = local_fallback()
                    used_provider = "local"
                    self.stats["local_fallbacks"] += 1
                    logger.info("Using local fallback detection")
                except Exception as e:
                    logger.error(f"Local fallback also failed: {e}")
                    result = self._default_result()
                    used_provider = "default"
            
            # Add metadata
            result["_provider"] = used_provider
            result["_cached"] = False
            
            # Cache result
            self._cache_result(cache_key, result)
            
            return result
    
    def _get_cached(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if valid."""
        if key in self.cache:
            cached = self.cache[key]
            if time.time() < cached["expires_at"]:
                result = cached["result"].copy()
                result["_cached"] = True
                return result
            else:
                del self.cache[key]
        return None
    
    def _cache_result(self, key: str, result: Dict[str, Any]):
        """Cache a result."""
        self.cache[key] = {
            "result": result,
            "expires_at": time.time() + self.cache_ttl
        }
        
        # Clean old entries if cache too large
        if len(self.cache) > 1000:
            self._cleanup_cache()
    
    def _cleanup_cache(self):
        """Remove expired cache entries."""
        now = time.time()
        expired = [k for k, v in self.cache.items() if v["expires_at"] < now]
        for k in expired:
            del self.cache[k]
    
    def _default_result(self) -> Dict[str, Any]:
        """Default result when all methods fail."""
        return {
            "is_scam": False,
            "confidence": 0.5,
            "scam_type": None,
            "reasoning": "Detection unavailable, defaulting to neutral",
            "error": True
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        provider_stats = {}
        for name, state in self.providers.items():
            provider_stats[name] = {
                "status": state.status.value,
                "total_requests": state.total_requests,
                "success_rate": state.total_successes / max(state.total_requests, 1),
                "consecutive_errors": state.consecutive_errors
            }
        
        return {
            **self.stats,
            "cache_size": len(self.cache),
            "providers": provider_stats
        }
    
    def get_available_providers(self) -> List[str]:
        """Get list of currently available providers."""
        return [name for name, state in self.providers.items() 
                if state.is_available() and name != "local"]


# Global instance with NEW provider order: Pollinations → Cerebras → Groq → Gemini
llm_request_queue = RateLimitAwareQueue(
    max_concurrent=3,
    cache_ttl_seconds=300,
    provider_order=["pollinations", "cerebras", "groq", "gemini", "local"]
)
