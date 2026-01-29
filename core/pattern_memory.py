"""
Pattern Memory System - Remembers scam patterns for instant recognition.
Stores message hashes, keywords, phone numbers, UPIs, URLs with frequency counts.
"""
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    """Represents a matched pattern."""
    pattern_type: str  # message_hash, phone, upi, url, keyword_combo
    pattern_value: str
    times_seen: int
    first_seen: str
    last_seen: str
    associated_scam_types: List[str]
    confidence_boost: float


class PatternMemory:
    """
    Persistent pattern memory for scam detection.
    Remembers patterns and boosts confidence when seen again.
    """
    
    def __init__(self, storage_path: str = "pattern_memory.json"):
        self.storage_path = storage_path
        
        # In-memory stores
        self.message_hashes: Dict[str, Dict] = {}  # hash -> {count, first_seen, last_seen, scam_types}
        self.phone_numbers: Dict[str, Dict] = {}
        self.upi_ids: Dict[str, Dict] = {}
        self.urls: Dict[str, Dict] = {}
        self.keyword_combos: Dict[str, Dict] = {}  # "keyword1|keyword2|..." -> count
        self.scammer_fingerprints: Dict[str, Dict] = {}  # fingerprint -> {sessions, patterns}
        
        # Load existing patterns
        self._load_patterns()
    
    def _load_patterns(self):
        """Load patterns from storage."""
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
                self.message_hashes = data.get("message_hashes", {})
                self.phone_numbers = data.get("phone_numbers", {})
                self.upi_ids = data.get("upi_ids", {})
                self.urls = data.get("urls", {})
                self.keyword_combos = data.get("keyword_combos", {})
                self.scammer_fingerprints = data.get("scammer_fingerprints", {})
                logger.info(f"Loaded {len(self.message_hashes)} message patterns, "
                           f"{len(self.phone_numbers)} phones, {len(self.upi_ids)} UPIs")
        except FileNotFoundError:
            logger.info("No existing pattern memory found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading patterns: {e}")
    
    def _save_patterns(self):
        """Save patterns to storage."""
        try:
            data = {
                "message_hashes": self.message_hashes,
                "phone_numbers": self.phone_numbers,
                "upi_ids": self.upi_ids,
                "urls": self.urls,
                "keyword_combos": self.keyword_combos,
                "scammer_fingerprints": self.scammer_fingerprints,
                "last_updated": datetime.utcnow().isoformat()
            }
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving patterns: {e}")
    
    def _hash_message(self, message: str) -> str:
        """Create normalized hash of message."""
        # Normalize: lowercase, remove extra spaces, remove numbers
        normalized = ' '.join(message.lower().split())
        # Remove variable parts (numbers, specific names)
        import re
        normalized = re.sub(r'\d+', 'NUM', normalized)
        normalized = re.sub(r'[^\w\s]', '', normalized)
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def check_patterns(
        self, 
        message: str, 
        intelligence: Dict[str, Any]
    ) -> List[PatternMatch]:
        """
        Check if message or its components match known patterns.
        Returns list of matches with confidence boosts.
        """
        matches = []
        now = datetime.utcnow().isoformat()
        
        # Check message hash
        msg_hash = self._hash_message(message)
        if msg_hash in self.message_hashes:
            pattern = self.message_hashes[msg_hash]
            matches.append(PatternMatch(
                pattern_type="message_template",
                pattern_value=msg_hash,
                times_seen=pattern["count"],
                first_seen=pattern["first_seen"],
                last_seen=pattern["last_seen"],
                associated_scam_types=pattern.get("scam_types", []),
                confidence_boost=min(pattern["count"] * 0.1, 0.4)  # Max 40% boost
            ))
        
        # Check phone numbers
        for phone in intelligence.get("phone_numbers", []):
            if phone in self.phone_numbers:
                pattern = self.phone_numbers[phone]
                matches.append(PatternMatch(
                    pattern_type="known_scam_phone",
                    pattern_value=phone,
                    times_seen=pattern["count"],
                    first_seen=pattern["first_seen"],
                    last_seen=pattern["last_seen"],
                    associated_scam_types=pattern.get("scam_types", []),
                    confidence_boost=min(pattern["count"] * 0.15, 0.5)  # Max 50% boost
                ))
        
        # Check UPI IDs
        for upi in intelligence.get("upi_ids", []):
            if upi in self.upi_ids:
                pattern = self.upi_ids[upi]
                matches.append(PatternMatch(
                    pattern_type="known_scam_upi",
                    pattern_value=upi,
                    times_seen=pattern["count"],
                    first_seen=pattern["first_seen"],
                    last_seen=pattern["last_seen"],
                    associated_scam_types=pattern.get("scam_types", []),
                    confidence_boost=min(pattern["count"] * 0.15, 0.5)
                ))
        
        # Check URLs
        for url in intelligence.get("urls", []):
            # Normalize URL
            url_key = url.lower().replace("https://", "").replace("http://", "").rstrip("/")
            if url_key in self.urls:
                pattern = self.urls[url_key]
                matches.append(PatternMatch(
                    pattern_type="known_scam_url",
                    pattern_value=url,
                    times_seen=pattern["count"],
                    first_seen=pattern["first_seen"],
                    last_seen=pattern["last_seen"],
                    associated_scam_types=pattern.get("scam_types", []),
                    confidence_boost=min(pattern["count"] * 0.2, 0.6)  # Max 60% boost
                ))
        
        # Check keyword combinations
        keywords = sorted(intelligence.get("keywords", [])[:5])  # Top 5 keywords
        if len(keywords) >= 2:
            combo_key = "|".join(keywords)
            if combo_key in self.keyword_combos:
                pattern = self.keyword_combos[combo_key]
                matches.append(PatternMatch(
                    pattern_type="keyword_combination",
                    pattern_value=combo_key,
                    times_seen=pattern["count"],
                    first_seen=pattern["first_seen"],
                    last_seen=pattern["last_seen"],
                    associated_scam_types=pattern.get("scam_types", []),
                    confidence_boost=min(pattern["count"] * 0.05, 0.2)
                ))
        
        return matches
    
    def record_pattern(
        self, 
        message: str, 
        intelligence: Dict[str, Any],
        scam_type: Optional[str] = None,
        is_confirmed_scam: bool = False
    ):
        """
        Record patterns from a message for future detection.
        Only records if scam is confirmed (confidence > threshold).
        """
        now = datetime.utcnow().isoformat()
        
        # Record message hash
        msg_hash = self._hash_message(message)
        if msg_hash not in self.message_hashes:
            self.message_hashes[msg_hash] = {
                "count": 0,
                "first_seen": now,
                "last_seen": now,
                "scam_types": []
            }
        self.message_hashes[msg_hash]["count"] += 1
        self.message_hashes[msg_hash]["last_seen"] = now
        if scam_type and scam_type not in self.message_hashes[msg_hash]["scam_types"]:
            self.message_hashes[msg_hash]["scam_types"].append(scam_type)
        
        # Record phone numbers (only if likely scam)
        if is_confirmed_scam:
            for phone in intelligence.get("phone_numbers", []):
                if phone not in self.phone_numbers:
                    self.phone_numbers[phone] = {
                        "count": 0,
                        "first_seen": now,
                        "last_seen": now,
                        "scam_types": []
                    }
                self.phone_numbers[phone]["count"] += 1
                self.phone_numbers[phone]["last_seen"] = now
                if scam_type:
                    if scam_type not in self.phone_numbers[phone]["scam_types"]:
                        self.phone_numbers[phone]["scam_types"].append(scam_type)
            
            # Record UPI IDs
            for upi in intelligence.get("upi_ids", []):
                if upi not in self.upi_ids:
                    self.upi_ids[upi] = {
                        "count": 0,
                        "first_seen": now,
                        "last_seen": now,
                        "scam_types": []
                    }
                self.upi_ids[upi]["count"] += 1
                self.upi_ids[upi]["last_seen"] = now
                if scam_type:
                    if scam_type not in self.upi_ids[upi]["scam_types"]:
                        self.upi_ids[upi]["scam_types"].append(scam_type)
            
            # Record URLs
            for url in intelligence.get("urls", []):
                url_key = url.lower().replace("https://", "").replace("http://", "").rstrip("/")
                if url_key not in self.urls:
                    self.urls[url_key] = {
                        "count": 0,
                        "first_seen": now,
                        "last_seen": now,
                        "scam_types": []
                    }
                self.urls[url_key]["count"] += 1
                self.urls[url_key]["last_seen"] = now
                if scam_type:
                    if scam_type not in self.urls[url_key]["scam_types"]:
                        self.urls[url_key]["scam_types"].append(scam_type)
        
        # Record keyword combinations
        keywords = sorted(intelligence.get("keywords", [])[:5])
        if len(keywords) >= 2:
            combo_key = "|".join(keywords)
            if combo_key not in self.keyword_combos:
                self.keyword_combos[combo_key] = {
                    "count": 0,
                    "first_seen": now,
                    "last_seen": now,
                    "scam_types": []
                }
            self.keyword_combos[combo_key]["count"] += 1
            self.keyword_combos[combo_key]["last_seen"] = now
            if scam_type:
                if scam_type not in self.keyword_combos[combo_key]["scam_types"]:
                    self.keyword_combos[combo_key]["scam_types"].append(scam_type)
        
        # Save periodically
        total_patterns = (len(self.message_hashes) + len(self.phone_numbers) + 
                         len(self.upi_ids) + len(self.urls))
        if total_patterns % 10 == 0:  # Save every 10 new patterns
            self._save_patterns()
    
    def calculate_memory_boost(self, matches: List[PatternMatch]) -> float:
        """Calculate total confidence boost from pattern matches."""
        if not matches:
            return 0.0
        
        # Take the highest individual boost plus small bonuses for additional matches
        boosts = sorted([m.confidence_boost for m in matches], reverse=True)
        total_boost = boosts[0]  # Primary boost
        
        # Add 50% of remaining boosts
        for boost in boosts[1:]:
            total_boost += boost * 0.5
        
        return min(total_boost, 0.8)  # Cap at 80% total boost
    
    def get_stats(self) -> Dict[str, int]:
        """Get pattern memory statistics."""
        return {
            "message_templates": len(self.message_hashes),
            "known_phones": len(self.phone_numbers),
            "known_upis": len(self.upi_ids),
            "known_urls": len(self.urls),
            "keyword_combos": len(self.keyword_combos),
            "scammer_fingerprints": len(self.scammer_fingerprints)
        }
    
    def create_scammer_fingerprint(
        self,
        session_id: str,
        message_patterns: List[str],
        timing_info: Optional[Dict] = None,
        language_patterns: Optional[List[str]] = None
    ) -> str:
        """
        Create a behavioral fingerprint for a scammer.
        Used to identify same scammer across sessions.
        """
        # Create fingerprint from patterns
        fingerprint_data = {
            "message_patterns": sorted(message_patterns),
            "language": language_patterns or []
        }
        fingerprint = hashlib.md5(json.dumps(fingerprint_data, sort_keys=True).encode()).hexdigest()[:12]
        
        now = datetime.utcnow().isoformat()
        
        if fingerprint not in self.scammer_fingerprints:
            self.scammer_fingerprints[fingerprint] = {
                "sessions": [],
                "first_seen": now,
                "last_seen": now,
                "total_encounters": 0
            }
        
        self.scammer_fingerprints[fingerprint]["sessions"].append(session_id)
        self.scammer_fingerprints[fingerprint]["last_seen"] = now
        self.scammer_fingerprints[fingerprint]["total_encounters"] += 1
        
        return fingerprint


# Global pattern memory instance
pattern_memory = PatternMemory()
