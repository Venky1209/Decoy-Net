"""
Scam detection engine with multi-stage analysis.
"""
import re
import json
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from utils.patterns import (
    URGENCY_KEYWORDS,
    FINANCIAL_KEYWORDS,
    AUTHORITY_KEYWORDS,
    THREAT_KEYWORDS,
    REWARD_KEYWORDS,
    JOB_KEYWORDS,
    PHISHING_KEYWORDS,
    SCAM_TYPE_PATTERNS,
    SCAMMER_TYPE_PATTERNS,
    TACTIC_PATTERNS,
    WHITELIST_PHRASES
)

logger = logging.getLogger(__name__)


@dataclass
class ScamDetectionResult:
    """Result of scam detection analysis."""
    is_scam: bool = False
    confidence: float = 0.0
    scam_type: Optional[str] = None
    scammer_type: Optional[str] = None
    threat_level: int = 1
    tactics: List[str] = field(default_factory=list)
    suspicious_elements: List[str] = field(default_factory=list)
    reasoning: str = ""
    keyword_score: float = 0.0
    pattern_score: float = 0.0
    context_score: float = 0.0


class ScamDetector:
    """
    Multi-stage scam detection engine.
    Uses keyword analysis, pattern matching, and LLM-assisted classification.
    """
    
    def __init__(self, confidence_threshold: float = 0.7):
        self.confidence_threshold = confidence_threshold
        self._llm_client = None
    
    async def detect(
        self,
        message: str,
        conversation_history: Optional[List] = None,
        metadata: Optional[Any] = None
    ) -> ScamDetectionResult:
        """
        Perform multi-stage scam detection.
        
        Args:
            message: Current message to analyze
            conversation_history: Previous conversation messages
            metadata: Additional message metadata
            
        Returns:
            ScamDetectionResult with detection details
        """
        result = ScamDetectionResult()
        
        # Normalize message
        message_lower = message.lower()
        
        # Check whitelist first (reduce false positives)
        if self._is_whitelisted(message_lower):
            result.reasoning = "Message matches whitelist pattern"
            return result
        
        # Stage 1: Keyword Analysis
        keyword_result = self._analyze_keywords(message_lower)
        result.keyword_score = keyword_result["score"]
        result.suspicious_elements.extend(keyword_result["matches"])
        
        # Stage 2: Pattern Analysis
        pattern_result = self._analyze_patterns(message_lower)
        result.pattern_score = pattern_result["score"]
        result.scam_type = pattern_result["scam_type"]
        result.scammer_type = pattern_result["scammer_type"]
        result.tactics = pattern_result["tactics"]
        
        # Stage 3: Context Analysis (conversation history)
        context_result = self._analyze_context(message, conversation_history)
        result.context_score = context_result["score"]
        
        # Calculate final confidence
        result.confidence = self._calculate_confidence(
            keyword_score=result.keyword_score,
            pattern_score=result.pattern_score,
            context_score=result.context_score
        )
        
        # Determine if scam
        result.is_scam = result.confidence >= self.confidence_threshold
        
        # Calculate threat level (1-10)
        result.threat_level = self._calculate_threat_level(result)
        
        # Generate reasoning
        result.reasoning = self._generate_reasoning(result)
        
        logger.info(
            f"Scam detection: is_scam={result.is_scam}, "
            f"confidence={result.confidence:.2f}, "
            f"type={result.scam_type}"
        )
        
        return result
    
    def _is_whitelisted(self, message: str) -> bool:
        """Check if message matches whitelist patterns."""
        for phrase in WHITELIST_PHRASES:
            if phrase in message:
                return True
        return False
    
    def _analyze_keywords(self, message: str) -> Dict:
        """
        Analyze message for suspicious keywords.
        Returns score (0-1) and list of matched keywords.
        """
        matches = []
        scores = []
        
        # Check each keyword category with different weights
        keyword_categories = [
            (URGENCY_KEYWORDS, 0.8, "urgency"),
            (FINANCIAL_KEYWORDS, 0.9, "financial"),
            (AUTHORITY_KEYWORDS, 0.7, "authority"),
            (THREAT_KEYWORDS, 0.85, "threat"),
            (REWARD_KEYWORDS, 0.75, "reward"),
            (JOB_KEYWORDS, 0.6, "job"),
            (PHISHING_KEYWORDS, 0.85, "phishing")
        ]
        
        for keywords, weight, category in keyword_categories:
            category_matches = [kw for kw in keywords if kw in message]
            if category_matches:
                matches.extend(category_matches)
                # Score based on number of matches and weight
                category_score = min(len(category_matches) * 0.15 * weight, weight)
                scores.append(category_score)
        
        # Calculate overall keyword score
        if scores:
            final_score = min(sum(scores) / len(scores) + 0.1 * len(matches), 1.0)
        else:
            final_score = 0.0
        
        return {"score": final_score, "matches": matches}
    
    def _analyze_patterns(self, message: str) -> Dict:
        """
        Analyze message for scam patterns.
        Classifies scam type and scammer behavior.
        """
        scam_type = None
        scammer_type = None
        tactics = []
        max_score = 0.0
        
        # Detect scam type
        for stype, keywords in SCAM_TYPE_PATTERNS.items():
            matches = sum(1 for kw in keywords if kw in message)
            if matches > 0:
                score = matches / len(keywords)
                if score > max_score:
                    max_score = score
                    scam_type = stype
        
        # Detect scammer behavior type
        scammer_max = 0.0
        for stype, keywords in SCAMMER_TYPE_PATTERNS.items():
            matches = sum(1 for kw in keywords if kw in message)
            if matches > 0:
                score = matches / len(keywords)
                if score > scammer_max:
                    scammer_max = score
                    scammer_type = stype
        
        # Detect psychological tactics
        for tactic, keywords in TACTIC_PATTERNS.items():
            if any(kw in message for kw in keywords):
                tactics.append(tactic)
        
        return {
            "score": max_score,
            "scam_type": scam_type,
            "scammer_type": scammer_type,
            "tactics": tactics
        }
    
    def _analyze_context(
        self, 
        message: str, 
        conversation_history: Optional[List]
    ) -> Dict:
        """
        Analyze conversation context for scam patterns.
        """
        score = 0.0
        
        if not conversation_history:
            return {"score": score}
        
        # Count scam indicators across conversation
        all_messages = " ".join([
            msg.content if hasattr(msg, 'content') else str(msg)
            for msg in conversation_history
        ]) + " " + message
        
        all_messages_lower = all_messages.lower()
        
        # Progressive disclosure pattern (common in scams)
        if len(conversation_history) > 2:
            # Check if urgency increases over time
            recent = all_messages_lower[-500:]
            early = all_messages_lower[:500]
            
            recent_urgency = sum(1 for kw in URGENCY_KEYWORDS if kw in recent)
            early_urgency = sum(1 for kw in URGENCY_KEYWORDS if kw in early)
            
            if recent_urgency > early_urgency:
                score += 0.2
        
        # Check for escalating financial requests
        financial_density = sum(1 for kw in FINANCIAL_KEYWORDS if kw in all_messages_lower)
        score += min(financial_density * 0.05, 0.3)
        
        # Check for typical scam conversation flow
        if "verify" in all_messages_lower and "account" in all_messages_lower:
            score += 0.15
        if "otp" in all_messages_lower or "pin" in all_messages_lower:
            score += 0.2
        
        return {"score": min(score, 1.0)}
    
    def _calculate_confidence(
        self,
        keyword_score: float,
        pattern_score: float,
        context_score: float
    ) -> float:
        """
        Calculate overall confidence using weighted scoring.
        
        Formula:
        confidence = keyword * 0.3 + pattern * 0.4 + context * 0.3
        """
        confidence = (
            keyword_score * 0.3 +
            pattern_score * 0.4 +
            context_score * 0.3
        )
        
        # Boost if multiple high scores
        high_scores = sum(1 for s in [keyword_score, pattern_score, context_score] if s > 0.6)
        if high_scores >= 2:
            confidence = min(confidence * 1.15, 1.0)
        
        return round(confidence, 3)
    
    def _calculate_threat_level(self, result: ScamDetectionResult) -> int:
        """
        Calculate threat level (1-10) based on detection results.
        """
        level = 1
        
        # Base on confidence
        level += int(result.confidence * 5)
        
        # Boost for dangerous scam types
        dangerous_types = ["banking", "upi", "phishing"]
        if result.scam_type in dangerous_types:
            level += 2
        
        # Boost for aggressive tactics
        if "fear" in result.tactics or "urgency" in result.tactics:
            level += 1
        
        return min(max(level, 1), 10)
    
    def _generate_reasoning(self, result: ScamDetectionResult) -> str:
        """Generate human-readable reasoning for detection result."""
        if not result.is_scam:
            return "No significant scam indicators detected."
        
        parts = []
        
        if result.scam_type:
            parts.append(f"Detected {result.scam_type} scam pattern.")
        
        if result.suspicious_elements:
            top_elements = result.suspicious_elements[:5]
            parts.append(f"Suspicious keywords: {', '.join(top_elements)}.")
        
        if result.tactics:
            parts.append(f"Psychological tactics: {', '.join(result.tactics)}.")
        
        parts.append(f"Threat level: {result.threat_level}/10.")
        
        return " ".join(parts)


class ScammerProfiler:
    """
    Build behavioral profile of scammer based on conversation analysis.
    """
    
    def build_profile(
        self,
        conversation_history: List,
        detection_result: ScamDetectionResult
    ) -> Dict[str, Any]:
        """
        Build comprehensive scammer profile.
        """
        profile = {
            "scam_type": detection_result.scam_type,
            "scammer_type": detection_result.scammer_type,
            "threat_level": detection_result.threat_level,
            "tactics_used": detection_result.tactics,
            "behavioral_fingerprint": {},
            "sophistication_level": "low",
            "persistence_score": 0
        }
        
        if not conversation_history:
            return profile
        
        # Analyze message patterns
        all_text = " ".join([
            msg.content if hasattr(msg, 'content') else str(msg)
            for msg in conversation_history
        ]).lower()
        
        # Detect sophistication level
        technical_terms = ["verification", "protocol", "system", "process", "department"]
        tech_count = sum(1 for t in technical_terms if t in all_text)
        
        if tech_count > 5:
            profile["sophistication_level"] = "high"
        elif tech_count > 2:
            profile["sophistication_level"] = "medium"
        
        # Calculate persistence (how many messages they've sent)
        profile["persistence_score"] = min(len(conversation_history) / 10, 1.0)
        
        # Behavioral fingerprint
        profile["behavioral_fingerprint"] = {
            "uses_urgency": "urgency" in detection_result.tactics,
            "uses_authority": "authority" in detection_result.tactics,
            "uses_fear": "fear" in detection_result.tactics,
            "uses_greed": "greed" in detection_result.tactics,
            "message_length_avg": self._avg_message_length(conversation_history),
            "response_pattern": self._detect_response_pattern(conversation_history)
        }
        
        return profile
    
    def _avg_message_length(self, history: List) -> str:
        """Categorize average message length."""
        if not history:
            return "unknown"
        
        lengths = [
            len(msg.content) if hasattr(msg, 'content') else len(str(msg))
            for msg in history
        ]
        avg = sum(lengths) / len(lengths)
        
        if avg < 50:
            return "short"
        elif avg < 150:
            return "medium"
        else:
            return "long"
    
    def _detect_response_pattern(self, history: List) -> str:
        """Detect scammer's response pattern."""
        if len(history) < 3:
            return "unknown"
        
        # Simple heuristic based on conversation flow
        return "scripted"  # Most scams follow scripts
