"""
Agent Memory System - Makes the AI agent learn and remember.

Features:
1. Response Cache - Avoid repeated LLM calls for similar messages
2. Engagement Memory - Remember what responses worked (got more intel)
3. Scam Pattern Learning - Auto-learn new patterns from detections

This makes the agent:
- Faster (cached responses)
- Smarter (learns from successes)
- More accurate (growing pattern database)
"""
import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import re

logger = logging.getLogger(__name__)


@dataclass
class CachedResponse:
    """Cached LLM response."""
    message_hash: str
    scam_type: str
    persona: str
    response: str
    created_at: str
    hit_count: int = 0
    avg_intel_score: float = 0.0  # How much intel this response typically extracts


@dataclass
class EngagementSuccess:
    """Record of successful engagement."""
    session_id: str
    scam_type: str
    persona_used: str
    response_used: str
    intel_extracted: int  # Count of intel items
    timestamp: str


class AgentMemory:
    """
    Persistent memory for the AI agent.
    Learns from interactions to improve over time.
    """
    
    def __init__(self, storage_path: str = "agent_memory.json"):
        self.storage_path = storage_path
        
        # Response cache - message_hash -> CachedResponse
        self.response_cache: Dict[str, Dict] = {}
        
        # Successful engagements by scam type
        self.successful_responses: Dict[str, List[Dict]] = defaultdict(list)
        
        # Learned scam patterns (new ones discovered during runtime)
        self.learned_patterns: Dict[str, Dict] = {}
        
        # Scammer behavior fingerprints
        self.scammer_fingerprints: Dict[str, Dict] = {}
        
        # Stats
        self.cache_hits = 0
        self.cache_misses = 0
        self.patterns_learned = 0
        
        self._load_memory()
    
    def _load_memory(self):
        """Load memory from disk."""
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
                self.response_cache = data.get("response_cache", {})
                self.successful_responses = defaultdict(list, data.get("successful_responses", {}))
                self.learned_patterns = data.get("learned_patterns", {})
                self.scammer_fingerprints = data.get("scammer_fingerprints", {})
                self.cache_hits = data.get("stats", {}).get("cache_hits", 0)
                self.cache_misses = data.get("stats", {}).get("cache_misses", 0)
                self.patterns_learned = data.get("stats", {}).get("patterns_learned", 0)
                
                logger.info(
                    f"Agent memory loaded: {len(self.response_cache)} cached responses, "
                    f"{self.patterns_learned} learned patterns"
                )
        except FileNotFoundError:
            logger.info("No agent memory found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading agent memory: {e}")
    
    def _save_memory(self):
        """Save memory to disk."""
        try:
            data = {
                "response_cache": self.response_cache,
                "successful_responses": dict(self.successful_responses),
                "learned_patterns": self.learned_patterns,
                "scammer_fingerprints": self.scammer_fingerprints,
                "stats": {
                    "cache_hits": self.cache_hits,
                    "cache_misses": self.cache_misses,
                    "patterns_learned": self.patterns_learned
                },
                "last_updated": datetime.utcnow().isoformat()
            }
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving agent memory: {e}")
    
    def _hash_message(self, message: str, scam_type: str = None) -> str:
        """Create hash for message lookup.
        
        Uses normalized message + scam type for context-aware caching.
        """
        # Normalize: lowercase, remove extra spaces, remove numbers (they vary)
        normalized = message.lower().strip()
        normalized = re.sub(r'\s+', ' ', normalized)
        normalized = re.sub(r'\d+', 'NUM', normalized)  # Replace numbers with placeholder
        
        key = f"{normalized}|{scam_type or 'unknown'}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    def _similarity_match(self, message: str, scam_type: str = None) -> Optional[str]:
        """Find similar cached message using fuzzy matching.
        
        Returns cache key if similar message found.
        """
        # First try exact hash
        exact_hash = self._hash_message(message, scam_type)
        if exact_hash in self.response_cache:
            return exact_hash
        
        # Try without scam type
        generic_hash = self._hash_message(message, None)
        if generic_hash in self.response_cache:
            return generic_hash
        
        # TODO: Could add semantic similarity here with embeddings
        return None
    
    def get_cached_response(
        self, 
        message: str, 
        scam_type: str = None,
        persona: str = None
    ) -> Optional[str]:
        """Get cached response for similar message.
        
        Returns:
            Cached response string if found, None otherwise
        """
        cache_key = self._similarity_match(message, scam_type)
        
        if cache_key and cache_key in self.response_cache:
            cached = self.response_cache[cache_key]
            
            # Check if persona matches (or no specific persona required)
            if persona and cached.get("persona") and cached["persona"] != persona:
                return None
            
            # Update hit count
            cached["hit_count"] = cached.get("hit_count", 0) + 1
            self.cache_hits += 1
            
            logger.info(f"Cache HIT for message (hits: {self.cache_hits})")
            return cached.get("response")
        
        self.cache_misses += 1
        return None
    
    def cache_response(
        self,
        message: str,
        scam_type: str,
        persona: str,
        response: str,
        intel_score: float = 0.0
    ):
        """Cache an LLM response for future use."""
        cache_key = self._hash_message(message, scam_type)
        
        if cache_key in self.response_cache:
            # Update existing - rolling average of intel score
            existing = self.response_cache[cache_key]
            existing["hit_count"] = existing.get("hit_count", 0) + 1
            old_avg = existing.get("avg_intel_score", 0)
            hits = existing["hit_count"]
            existing["avg_intel_score"] = (old_avg * (hits - 1) + intel_score) / hits
        else:
            # New entry
            self.response_cache[cache_key] = {
                "message_hash": cache_key,
                "scam_type": scam_type,
                "persona": persona,
                "response": response,
                "created_at": datetime.utcnow().isoformat(),
                "hit_count": 1,
                "avg_intel_score": intel_score
            }
        
        # Save periodically (every 10 new entries)
        if len(self.response_cache) % 10 == 0:
            self._save_memory()
    
    def record_successful_engagement(
        self,
        session_id: str,
        scam_type: str,
        persona: str,
        response: str,
        intel_count: int
    ):
        """Record a response that successfully extracted intelligence.
        
        These responses are prioritized for similar scams.
        """
        if intel_count < 1:
            return  # Only record if we got intel
        
        success = {
            "session_id": session_id,
            "persona": persona,
            "response": response,
            "intel_extracted": intel_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Keep top 20 most successful for each scam type
        self.successful_responses[scam_type].append(success)
        self.successful_responses[scam_type] = sorted(
            self.successful_responses[scam_type],
            key=lambda x: x["intel_extracted"],
            reverse=True
        )[:20]
        
        logger.info(f"Recorded successful engagement: {scam_type} -> {intel_count} intel items")
    
    def get_best_response_template(self, scam_type: str) -> Optional[str]:
        """Get the most successful response template for a scam type."""
        if scam_type in self.successful_responses:
            successes = self.successful_responses[scam_type]
            if successes:
                # Return the response with highest intel extraction
                return successes[0].get("response")
        return None
    
    def learn_pattern(
        self,
        message: str,
        scam_type: str,
        confidence: float,
        keywords: List[str],
        intel: Dict[str, List]
    ):
        """Learn a new scam pattern from a confirmed detection.
        
        Called when scam is detected with high confidence.
        """
        if confidence < 0.7:
            return  # Only learn from high-confidence detections
        
        # Extract key phrases
        key_phrases = self._extract_key_phrases(message)
        
        pattern_id = hashlib.md5(
            f"{scam_type}|{'|'.join(sorted(key_phrases))}".encode()
        ).hexdigest()[:12]
        
        if pattern_id not in self.learned_patterns:
            self.learned_patterns[pattern_id] = {
                "scam_type": scam_type,
                "key_phrases": key_phrases,
                "keywords": keywords,
                "example_intel": {
                    "phones": intel.get("phone_numbers", [])[:2],
                    "upis": intel.get("upi_ids", [])[:2],
                    "urls": intel.get("urls", [])[:2]
                },
                "times_seen": 1,
                "first_seen": datetime.utcnow().isoformat(),
                "confidence_avg": confidence
            }
            self.patterns_learned += 1
            logger.info(f"Learned new pattern: {scam_type} (total: {self.patterns_learned})")
        else:
            # Update existing
            pattern = self.learned_patterns[pattern_id]
            pattern["times_seen"] += 1
            # Rolling average confidence
            n = pattern["times_seen"]
            pattern["confidence_avg"] = (pattern["confidence_avg"] * (n-1) + confidence) / n
        
        self._save_memory()
    
    def _extract_key_phrases(self, message: str) -> List[str]:
        """Extract key phrases from a scam message."""
        # Common scam phrase patterns
        phrase_patterns = [
            r'account.*block',
            r'verify.*immediately',
            r'otp.*share',
            r'kyc.*expire',
            r'police.*case',
            r'arrest.*warrant',
            r'send.*money',
            r'transfer.*urgent',
            r'win.*lottery',
            r'prize.*claim',
            r'job.*offer',
            r'work.*home',
            r'investment.*return',
            r'double.*money',
        ]
        
        message_lower = message.lower()
        found = []
        
        for pattern in phrase_patterns:
            if re.search(pattern, message_lower):
                found.append(pattern)
        
        return found[:5]  # Limit to 5 key phrases
    
    def check_learned_patterns(self, message: str) -> Optional[Dict]:
        """Check if message matches any learned patterns.
        
        Returns:
            Pattern dict if matched, None otherwise
        """
        message_lower = message.lower()
        best_match = None
        best_score = 0
        
        for pattern_id, pattern in self.learned_patterns.items():
            # Count matching key phrases
            matches = sum(
                1 for phrase in pattern.get("key_phrases", [])
                if re.search(phrase, message_lower)
            )
            
            if matches > 0:
                # Score based on matches and times seen
                score = matches * (1 + pattern.get("times_seen", 1) * 0.1)
                
                if score > best_score:
                    best_score = score
                    best_match = pattern
        
        if best_match and best_score >= 1.5:
            logger.info(f"Matched learned pattern: {best_match['scam_type']} (score: {best_score:.2f})")
            return best_match
        
        return None
    
    def add_scammer_fingerprint(
        self,
        session_id: str,
        phone: str = None,
        upi: str = None,
        url: str = None,
        scam_type: str = None
    ):
        """Track scammer identifiers for cross-session recognition."""
        identifiers = [x for x in [phone, upi, url] if x]
        
        for identifier in identifiers:
            if identifier not in self.scammer_fingerprints:
                self.scammer_fingerprints[identifier] = {
                    "sessions": [],
                    "scam_types": [],
                    "first_seen": datetime.utcnow().isoformat(),
                    "times_seen": 0
                }
            
            fp = self.scammer_fingerprints[identifier]
            if session_id not in fp["sessions"]:
                fp["sessions"].append(session_id)
            if scam_type and scam_type not in fp["scam_types"]:
                fp["scam_types"].append(scam_type)
            fp["times_seen"] += 1
            fp["last_seen"] = datetime.utcnow().isoformat()
    
    def is_known_scammer(self, phone: str = None, upi: str = None, url: str = None) -> Tuple[bool, int]:
        """Check if identifier belongs to a known scammer.
        
        Returns:
            (is_known, times_seen)
        """
        for identifier in [phone, upi, url]:
            if identifier and identifier in self.scammer_fingerprints:
                fp = self.scammer_fingerprints[identifier]
                return True, fp.get("times_seen", 1)
        return False, 0
    
    def get_stats(self) -> Dict:
        """Get memory statistics."""
        return {
            "cached_responses": len(self.response_cache),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.cache_hits / max(1, self.cache_hits + self.cache_misses),
            "patterns_learned": self.patterns_learned,
            "known_scammers": len(self.scammer_fingerprints),
            "successful_templates": sum(len(v) for v in self.successful_responses.values())
        }
    
    def save(self):
        """Force save memory to disk."""
        self._save_memory()


# Global instance
_agent_memory: Optional[AgentMemory] = None


def get_agent_memory() -> AgentMemory:
    """Get or create the global agent memory instance."""
    global _agent_memory
    if _agent_memory is None:
        _agent_memory = AgentMemory()
    return _agent_memory
