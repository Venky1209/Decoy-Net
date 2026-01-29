"""
Enhanced Scam Detector with Pattern Memory, Multi-LLM Ensemble, and 2025 Patterns.
Combines keyword detection + pattern memory + LLM consensus + local ML for maximum accuracy.
"""
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from utils.patterns import (
    URGENCY_KEYWORDS, FINANCIAL_KEYWORDS, AUTHORITY_KEYWORDS,
    THREAT_KEYWORDS, REWARD_KEYWORDS, JOB_KEYWORDS, PHISHING_KEYWORDS,
    SCAM_TYPE_PATTERNS, SCAMMER_TYPE_PATTERNS
)
from core.pattern_memory import pattern_memory, PatternMatch
from core.multi_llm_detector import multi_llm_detector
from core.request_cache import llm_detection_cache
from core.local_classifier import local_classifier
from utils.scam_patterns_2025 import scam_engine_2025

logger = logging.getLogger(__name__)


@dataclass
class EnhancedScamResult:
    """Enhanced scam detection result with all features."""
    is_scam: bool
    confidence: float
    scam_type: Optional[str]
    threat_level: int  # 1-10
    
    # Score breakdown
    keyword_score: float
    pattern_score: float
    context_score: float
    memory_boost: float  # From pattern memory
    llm_confidence: float  # From multi-LLM ensemble
    
    # Details
    tactics: List[str]
    scammer_type: Optional[str]
    reasoning: str
    
    # Pattern memory info
    pattern_matches: List[Dict]
    times_seen_before: int
    
    # LLM ensemble info
    llm_consensus: Optional[Dict]
    
    def to_dict(self) -> Dict:
        return {
            "is_scam": self.is_scam,
            "confidence": round(self.confidence, 3),
            "scam_type": self.scam_type,
            "threat_level": self.threat_level,
            "score_breakdown": {
                "keyword": round(self.keyword_score, 3),
                "pattern": round(self.pattern_score, 3),
                "context": round(self.context_score, 3),
                "memory_boost": round(self.memory_boost, 3),
                "llm_confidence": round(self.llm_confidence, 3)
            },
            "tactics": self.tactics,
            "scammer_type": self.scammer_type,
            "reasoning": self.reasoning,
            "pattern_matches": self.pattern_matches,
            "times_seen_before": self.times_seen_before,
            "llm_consensus": self.llm_consensus
        }


class EnhancedScamDetector:
    """
    Advanced scam detector combining:
    1. Keyword analysis
    2. Pattern matching
    3. Context analysis
    4. Pattern memory (remembers past scams)
    5. Multi-LLM ensemble (consensus from multiple AIs)
    """
    
    # Scoring weights (tuned for high LLM accuracy)
    WEIGHTS = {
        "keyword": 0.10,
        "pattern": 0.10,
        "context": 0.05,
        "memory": 0.25,  # Pattern memory is powerful for repeat scams
        "llm": 0.50  # LLM gets highest weight (both Gemini 3 + Groq now reliable)
    }
    
    def __init__(self, use_llm: bool = True, use_memory: bool = True):
        self.use_llm = use_llm
        self.use_memory = use_memory
    
    async def detect(
        self,
        message: str,
        conversation_history: Optional[List] = None,
        intelligence: Optional[Dict] = None
    ) -> EnhancedScamResult:
        """
        Perform enhanced scam detection using PARALLEL detection strategy.
        
        Strategy:
        1. Run 2025 Engine + Local Classifier IMMEDIATELY (fast, no API)
        2. Run LLM Ensemble in PARALLEL (slower, but more accurate)
        3. COMBINE results intelligently:
           - If LLM succeeds: Boost LLM result with 2025 engine findings
           - If LLM fails: Use SMART fallback (2025 engine + local classifier)
        """
        import asyncio
        
        # ============================================
        # PARALLEL STAGE 1: Fast Local Detection (no API)
        # These run IMMEDIATELY while LLM is being called
        # ============================================
        
        # 2025 Scam Engine (keywords + semantic + templates)
        engine_2025_result = scam_engine_2025.analyze(message)
        
        # Local Classifier (rule-based patterns)
        _, local_result = local_classifier.should_call_llm(message)
        
        # Legacy Keyword Analysis
        keyword_result = self._analyze_keywords(message)
        
        # Pattern Analysis
        pattern_result = self._analyze_patterns(message)
        
        # Context Analysis
        context_result = self._analyze_context(message, conversation_history or [])
        
        # Pattern Memory Check
        memory_result = {"boost": 0.0, "matches": [], "times_seen": 0}
        if self.use_memory and intelligence:
            memory_result = self._check_pattern_memory(message, intelligence)
        
        # ============================================
        # PARALLEL STAGE 2: LLM Ensemble (async API call)
        # ============================================
        llm_result = {"confidence": 0.0, "is_scam": False, "consensus": None}
        llm_succeeded = False
        
        if self.use_llm:
            try:
                llm_result = await self._get_llm_consensus(message)
                llm_succeeded = True
                logger.info(f"LLM succeeded: is_scam={llm_result.get('is_scam')}, conf={llm_result.get('confidence'):.2f}")
            except Exception as e:
                logger.error(f"LLM detection failed: {e}")
                llm_succeeded = False
        
        # ============================================
        # COMBINATION STAGE: Smart Result Merging
        # ============================================
        
        # Calculate 2025 engine boost (ALWAYS applied, not just fallback)
        engine_2025_boost = 0.0
        if engine_2025_result["confidence"] >= 0.3:
            # Scale boost: 0.3 conf = 0.05 boost, 0.6 conf = 0.15 boost, 0.9 conf = 0.25 boost
            engine_2025_boost = min(engine_2025_result["confidence"] * 0.28, 0.25)
            logger.info(f"2025 engine boost: {engine_2025_boost:.2f} (conf={engine_2025_result['confidence']:.2f})")
        
        # Combine keyword scores from both engines (take best)
        keyword_result["score"] = max(
            keyword_result["score"],
            engine_2025_result["keyword_matches"]["confidence"]
        )
        
        # Combine pattern scores from 2025 engine
        pattern_result["score"] = max(
            pattern_result["score"],
            engine_2025_result["semantic_matches"]["confidence"],
            engine_2025_result["template_matches"]["confidence"]
        )
        
        if llm_succeeded:
            # LLM worked - BOOST its result with 2025 engine findings
            # This makes LLM result even more accurate
            
            # If 2025 engine agrees with LLM, increase confidence
            if engine_2025_result["is_scam"] == llm_result.get("is_scam"):
                agreement_boost = engine_2025_boost * 1.5  # Extra boost for agreement
                logger.info(f"LLM + 2025 engine AGREE: +{agreement_boost:.2f} boost")
            else:
                agreement_boost = 0.0
                logger.warning(f"LLM + 2025 engine DISAGREE: LLM={llm_result.get('is_scam')}, 2025={engine_2025_result['is_scam']}")
            
            # Final LLM confidence with boosts
            llm_result["confidence"] = min(
                llm_result["confidence"] + engine_2025_boost + agreement_boost,
                1.0
            )
            
            # If 2025 found a category but LLM didn't, use 2025's category
            if not llm_result.get("scam_type") and engine_2025_result["category"]:
                llm_result["scam_type"] = engine_2025_result["category"]
                
        else:
            # LLM FAILED - Use SMART fallback (not basic!)
            # Combine 2025 engine + local classifier + keyword/pattern results
            logger.warning("Using SMART fallback (2025 engine + local classifier)")
            
            # Calculate smart fallback confidence
            # Weight: 2025 engine (50%) + local classifier (30%) + patterns (20%)
            smart_confidence = (
                engine_2025_result["confidence"] * 0.50 +
                local_result.confidence * 0.30 +
                max(keyword_result["score"], pattern_result["score"]) * 0.20
            )
            
            # Boost if multiple methods agree
            methods_agree = 0
            if engine_2025_result["is_scam"]:
                methods_agree += 1
            if local_result.is_scam:
                methods_agree += 1
            if keyword_result["score"] >= 0.3:
                methods_agree += 1
                
            if methods_agree >= 3:
                smart_confidence = min(smart_confidence * 1.4, 0.95)  # 40% boost, cap at 95%
            elif methods_agree >= 2:
                smart_confidence = min(smart_confidence * 1.25, 0.9)  # 25% boost
            
            # Determine if scam based on smart analysis
            is_scam_smart = (
                smart_confidence >= 0.5 or
                engine_2025_result["is_scam"] or
                (local_result.is_scam and local_result.confidence >= 0.6)
            )
            
            llm_result = {
                "confidence": round(smart_confidence, 3),
                "is_scam": is_scam_smart,
                "scam_type": engine_2025_result["category"] or local_result.category,
                "consensus": {
                    "method": "smart_fallback",
                    "engine_2025": {
                        "is_scam": engine_2025_result["is_scam"],
                        "confidence": engine_2025_result["confidence"],
                        "category": engine_2025_result["category"],
                        "threat_level": engine_2025_result["threat_level"]
                    },
                    "local_classifier": {
                        "is_scam": local_result.is_scam,
                        "confidence": local_result.confidence,
                        "matched_rules": local_result.matched_rules
                    },
                    "methods_agree": methods_agree,
                    "reasoning": f"Smart fallback: {methods_agree} methods agree, 2025 engine: {engine_2025_result['category']}"
                }
            }
            logger.info(f"Smart fallback result: is_scam={is_scam_smart}, conf={smart_confidence:.2f}")
        
        # Calculate combined confidence (includes all sources)
        combined_confidence = self._calculate_combined_confidence(
            keyword_result["score"],
            pattern_result["score"],
            context_result["score"],
            memory_result["boost"] + engine_2025_boost,  # Include 2025 boost
            llm_result["confidence"],
            llm_result.get("consensus")
        )
        
        # WHITELIST CHECK: Reduce false positives for legitimate messages
        whitelist_reduction = engine_2025_result.get("whitelist_reduction", 0)
        if whitelist_reduction > 0:
            combined_confidence = max(0, combined_confidence - whitelist_reduction)
            logger.info(f"Whitelist reduction applied: -{whitelist_reduction:.2f}, new confidence: {combined_confidence:.2f}")
        
        # Determine if scam
        # If whitelist matched significantly, don't mark as scam even if LLM said so
        if whitelist_reduction >= 0.25:
            is_scam = combined_confidence >= 0.6  # Higher threshold when whitelist matched
        else:
            is_scam = combined_confidence >= 0.5 or llm_result.get("is_scam", False)
        
        # Determine scam type (prioritize LLM, then pattern analysis)
        scam_type = (
            llm_result.get("scam_type") or 
            pattern_result.get("scam_type") or 
            self._infer_scam_type(keyword_result, pattern_result)
        ) if is_scam else None
        
        # Calculate threat level
        threat_level = self._calculate_threat_level(
            combined_confidence,
            keyword_result,
            memory_result
        )
        
        # Detect tactics used
        tactics = self._detect_tactics(keyword_result, pattern_result)
        
        # Determine scammer type
        scammer_type = self._determine_scammer_type(message, pattern_result)
        
        # Build reasoning
        reasoning = self._build_reasoning(
            keyword_result, pattern_result, context_result,
            memory_result, llm_result
        )
        
        # Record this pattern for future detection
        if self.use_memory and is_scam and intelligence:
            pattern_memory.record_pattern(
                message, 
                intelligence, 
                scam_type,
                is_confirmed_scam=(combined_confidence >= 0.7)
            )
        
        return EnhancedScamResult(
            is_scam=is_scam,
            confidence=combined_confidence,
            scam_type=scam_type,
            threat_level=threat_level,
            keyword_score=keyword_result["score"],
            pattern_score=pattern_result["score"],
            context_score=context_result["score"],
            memory_boost=memory_result["boost"],
            llm_confidence=llm_result["confidence"],
            tactics=tactics,
            scammer_type=scammer_type,
            reasoning=reasoning,
            pattern_matches=[m.__dict__ if hasattr(m, '__dict__') else m for m in memory_result["matches"]],
            times_seen_before=memory_result["times_seen"],
            llm_consensus=llm_result.get("consensus")
        )
    
    def _analyze_keywords(self, message: str) -> Dict:
        """Analyze message for scam keywords."""
        message_lower = message.lower()
        
        matches = {
            "urgency": [],
            "financial": [],
            "authority": [],
            "threat": [],
            "reward": [],
            "job": [],
            "phishing": []
        }
        
        # Check each category
        for word in URGENCY_KEYWORDS:
            if word.lower() in message_lower:
                matches["urgency"].append(word)
        
        for word in FINANCIAL_KEYWORDS:
            if word.lower() in message_lower:
                matches["financial"].append(word)
        
        for word in AUTHORITY_KEYWORDS:
            if word.lower() in message_lower:
                matches["authority"].append(word)
        
        for word in THREAT_KEYWORDS:
            if word.lower() in message_lower:
                matches["threat"].append(word)
        
        for word in REWARD_KEYWORDS:
            if word.lower() in message_lower:
                matches["reward"].append(word)
        
        for word in JOB_KEYWORDS:
            if word.lower() in message_lower:
                matches["job"].append(word)
        
        for word in PHISHING_KEYWORDS:
            if word.lower() in message_lower:
                matches["phishing"].append(word)
        
        # Calculate score
        total_matches = sum(len(v) for v in matches.values())
        categories_hit = sum(1 for v in matches.values() if v)
        
        # Score based on matches and category diversity
        base_score = min(total_matches * 0.05, 0.5)
        diversity_bonus = min(categories_hit * 0.08, 0.3)
        
        score = min(base_score + diversity_bonus, 0.8)
        
        return {
            "score": score,
            "matches": matches,
            "total_matches": total_matches,
            "categories_hit": categories_hit
        }
    
    def _analyze_patterns(self, message: str) -> Dict:
        """Analyze message for scam patterns."""
        from utils.patterns import BANK_ACCOUNT_PATTERNS, UPI_PATTERNS, PHONE_PATTERNS, URL_PATTERNS
        
        pattern_matches = {
            "bank_account": False,
            "upi": False,
            "phone": False,
            "url": False,
            "ip_address": False
        }
        
        # Check patterns
        for pattern in BANK_ACCOUNT_PATTERNS:
            if pattern.search(message):
                pattern_matches["bank_account"] = True
                break
        
        for pattern in UPI_PATTERNS:
            if pattern.search(message):
                pattern_matches["upi"] = True
                break
        
        for pattern in PHONE_PATTERNS:
            if pattern.search(message):
                pattern_matches["phone"] = True
                break
        
        for pattern in URL_PATTERNS:
            if pattern.search(message):
                pattern_matches["url"] = True
                break
        
        # Check for IP address (highly suspicious)
        import re
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', message):
            pattern_matches["ip_address"] = True
        
        # Determine scam type from patterns
        scam_type = None
        message_lower = message.lower()
        for stype, keywords in SCAM_TYPE_PATTERNS.items():
            if any(kw in message_lower for kw in keywords):
                scam_type = stype
                break
        
        # Calculate score
        matches_found = sum(1 for v in pattern_matches.values() if v)
        score = min(matches_found * 0.15, 0.6)
        
        # IP address is very suspicious
        if pattern_matches["ip_address"]:
            score = min(score + 0.2, 0.8)
        
        return {
            "score": score,
            "matches": pattern_matches,
            "scam_type": scam_type
        }
    
    def _analyze_context(self, message: str, history: List) -> Dict:
        """Analyze conversation context."""
        score = 0.0
        indicators = []
        
        message_lower = message.lower()
        
        # Check for urgency language
        urgency_phrases = [
            "immediately", "right now", "asap", "urgent", 
            "within 24 hours", "before it expires", "last chance"
        ]
        for phrase in urgency_phrases:
            if phrase in message_lower:
                score += 0.1
                indicators.append("urgency")
                break
        
        # Check for authority claims
        authority_phrases = [
            "this is from", "calling from", "official", 
            "bank manager", "security team", "government"
        ]
        for phrase in authority_phrases:
            if phrase in message_lower:
                score += 0.1
                indicators.append("authority_claim")
                break
        
        # Check for action demands
        action_phrases = [
            "click here", "send otp", "transfer", "pay now",
            "share your", "verify your"
        ]
        for phrase in action_phrases:
            if phrase in message_lower:
                score += 0.15
                indicators.append("action_demand")
                break
        
        # Check conversation escalation
        if history:
            # If scammer is getting more aggressive/urgent
            if len(history) >= 2:
                score += 0.05
                indicators.append("multi_turn")
        
        return {
            "score": min(score, 0.5),
            "indicators": indicators
        }
    
    def _check_pattern_memory(self, message: str, intelligence: Dict) -> Dict:
        """Check pattern memory for known scam patterns."""
        matches = pattern_memory.check_patterns(message, intelligence)
        
        if not matches:
            return {"boost": 0.0, "matches": [], "times_seen": 0}
        
        boost = pattern_memory.calculate_memory_boost(matches)
        times_seen = max(m.times_seen for m in matches)
        
        logger.info(f"Pattern memory: {len(matches)} matches, boost={boost:.2f}, seen={times_seen}x")
        
        return {
            "boost": boost,
            "matches": matches,
            "times_seen": times_seen
        }
    
    async def _get_llm_consensus(self, message: str) -> Dict:
        """Get consensus from multi-LLM ensemble (with caching for concurrent requests)."""
        import hashlib
        
        # Create cache key from message
        cache_key = hashlib.sha256(message.strip().lower().encode()).hexdigest()[:32]
        
        async def execute_detection():
            return await multi_llm_detector.detect_with_ensemble(message)
        
        # Use cache to deduplicate concurrent requests
        result = await llm_detection_cache.get_or_execute(cache_key, execute_detection)
        
        return {
            "confidence": result.get("ensemble_confidence", 0.0),
            "is_scam": result.get("is_scam", False),
            "scam_type": result.get("scam_type"),
            "consensus": result
        }
    
    def _calculate_combined_confidence(
        self,
        keyword_score: float,
        pattern_score: float,
        context_score: float,
        memory_boost: float,
        llm_confidence: float,
        llm_consensus: Dict = None
    ) -> float:
        """Calculate weighted combined confidence with consensus boost."""
        # Base weighted average
        base_confidence = (
            keyword_score * self.WEIGHTS["keyword"] +
            pattern_score * self.WEIGHTS["pattern"] +
            context_score * self.WEIGHTS["context"] +
            llm_confidence * self.WEIGHTS["llm"]
        )
        
        # Consensus boost: When both LLMs agree with high confidence
        consensus_boost = 0.0
        if llm_consensus:
            votes = llm_consensus.get("votes", {})
            total_votes = votes.get("total", 0)
            scam_votes = votes.get("scam", 0)
            
            # If 2+ LLMs unanimously agree it's a scam with high confidence
            if total_votes >= 2 and scam_votes == total_votes and llm_confidence >= 0.8:
                consensus_boost = 0.20  # Strong boost for unanimous high-confidence
            elif total_votes >= 2 and scam_votes == total_votes:
                consensus_boost = 0.10  # Moderate boost for unanimous detection
        
        # Add memory boost (multiplicative for strong memory matches)
        if memory_boost > 0.3:
            # Strong memory match - boost significantly
            combined = base_confidence + (memory_boost * 0.5) + consensus_boost
        else:
            combined = base_confidence + (memory_boost * 0.3) + consensus_boost
        
        return min(max(combined, 0.0), 1.0)
    
    def _calculate_threat_level(
        self,
        confidence: float,
        keyword_result: Dict,
        memory_result: Dict
    ) -> int:
        """Calculate threat level 1-10."""
        base_level = int(confidence * 10)
        
        # Boost for specific dangerous keywords
        if keyword_result["matches"].get("threat"):
            base_level += 1
        if keyword_result["matches"].get("authority"):
            base_level += 1
        
        # Boost for repeat offenders
        if memory_result["times_seen"] >= 3:
            base_level += 2
        elif memory_result["times_seen"] >= 1:
            base_level += 1
        
        return min(max(base_level, 1), 10)
    
    def _detect_tactics(self, keyword_result: Dict, pattern_result: Dict) -> List[str]:
        """Detect scam tactics used."""
        tactics = []
        matches = keyword_result["matches"]
        
        if matches.get("urgency"):
            tactics.append("urgency")
        if matches.get("authority"):
            tactics.append("authority")
        if matches.get("threat"):
            tactics.append("fear")
        if matches.get("reward"):
            tactics.append("greed")
        if matches.get("financial"):
            tactics.append("financial_request")
        if pattern_result["matches"].get("url") or pattern_result["matches"].get("ip_address"):
            tactics.append("phishing_link")
        
        return tactics
    
    def _determine_scammer_type(self, message: str, pattern_result: Dict) -> Optional[str]:
        """Determine scammer behavior type."""
        message_lower = message.lower()
        
        for behavior_type, keywords in SCAMMER_TYPE_PATTERNS.items():
            if any(kw in message_lower for kw in keywords):
                return behavior_type
        
        return "unknown"
    
    def _infer_scam_type(self, keyword_result: Dict, pattern_result: Dict) -> Optional[str]:
        """Infer scam type from analysis results."""
        matches = keyword_result["matches"]
        
        if matches.get("phishing") or pattern_result["matches"].get("url"):
            return "phishing"
        if matches.get("financial") and matches.get("authority"):
            return "banking"
        if matches.get("reward"):
            return "lottery"
        if matches.get("job"):
            return "job"
        if matches.get("threat"):
            return "extortion"
        
        return None
    
    def _build_reasoning(
        self,
        keyword_result: Dict,
        pattern_result: Dict,
        context_result: Dict,
        memory_result: Dict,
        llm_result: Dict
    ) -> str:
        """Build human-readable reasoning."""
        parts = []
        
        if keyword_result["total_matches"] > 0:
            parts.append(f"Found {keyword_result['total_matches']} scam keywords in {keyword_result['categories_hit']} categories")
        
        if pattern_result["scam_type"]:
            parts.append(f"Pattern analysis suggests {pattern_result['scam_type']} scam")
        
        if context_result["indicators"]:
            parts.append(f"Context indicators: {', '.join(context_result['indicators'])}")
        
        if memory_result["times_seen"] > 0:
            parts.append(f"⚠️ KNOWN PATTERN: Seen {memory_result['times_seen']} time(s) before!")
        
        if llm_result.get("consensus"):
            votes = llm_result["consensus"].get("votes", {})
            parts.append(f"LLM consensus: {votes.get('scam', 0)}/{votes.get('total', 0)} AIs flagged as scam")
        
        return "; ".join(parts) if parts else "No strong scam indicators detected"
