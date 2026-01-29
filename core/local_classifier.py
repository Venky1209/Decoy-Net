"""
Local Scam Classifier - Fast detection without LLM API calls.
For obvious cases, skip LLM entirely to avoid rate limits.

Implements:
- TF-IDF-like scoring
- Rule-based detection
- Confidence thresholds for LLM bypass
"""
import re
import math
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class LocalClassifierResult:
    """Result from local classification."""
    is_scam: bool
    confidence: float
    category: Optional[str]
    skip_llm: bool  # True if confidence is high enough to skip LLM
    matched_rules: List[str]
    reasoning: str


class LocalScamClassifier:
    """
    Fast local scam classifier using rules and TF-IDF-like scoring.
    
    Purpose: Skip LLM API calls for obvious scams/non-scams
    - confidence > 0.75: Obvious scam, skip LLM
    - confidence < 0.20: Obvious safe, skip LLM
    - 0.20 <= confidence <= 0.75: Uncertain, call LLM
    """
    
    # High-confidence scam indicators (if 2+ match = likely scam)
    DEFINITE_SCAM_PATTERNS = [
        # Digital arrest (very specific)
        (r'\b(cbi|ed|cyber\s*cell)\b.*\b(arrest|warrant|case)\b', "digital_arrest", 0.4),
        (r'\bstay\s+on\s+(video\s+)?call\b', "digital_arrest", 0.35),
        (r'\bmoney\s+laundering\b', "digital_arrest", 0.35),
        
        # UPI fraud (very specific)
        (r'\benter\s+(upi\s+)?pin\s+to\s+receive\b', "upi_fraud", 0.5),
        (r'\bscan\s+(qr|code)\s+to\s+(receive|get)\s+money\b', "upi_fraud", 0.5),
        
        # Lottery (classic patterns)
        (r'\b(won|winner)\b.*\b(lottery|prize|lucky\s*draw)\b', "lottery", 0.4),
        (r'\b(jio|airtel|amazon|flipkart)\s*(lottery|lucky\s*draw|winner)\b', "lottery", 0.45),
        
        # Job scam (fee + job combo)
        (r'\b(registration|joining)\s*fee\b.*\b(job|work|earn)\b', "job_scam", 0.4),
        (r'\bearn\s+\d+\s*(k|lakh|rs|₹).*\b(daily|per\s*day|month)\b', "job_scam", 0.35),
        
        # Investment scam
        (r'\bdouble\s+(your\s+)?(money|bitcoin|investment)\b', "investment", 0.5),
        (r'\bguaranteed\s+(return|profit|income)\b', "investment", 0.4),
        
        # OTP/PIN scam
        (r'\bshare\s+(otp|pin|password)\b', "phishing", 0.45),
        (r'\b(otp|pin)\s+is\s+\d{4,6}\b', "phishing", 0.3),
    ]
    
    # Safe message indicators - EXPANDED to reduce false positives
    SAFE_PATTERNS = [
        # Greetings (legitimate)
        (r'^(hi|hello|hey|good\s*(morning|evening|afternoon))\b', 0.20),
        (r'\b(thank\s*you|thanks)\s+(for|very\s+much)\b', 0.15),
        
        # E-commerce / Orders (legitimate)
        (r'\byour\s+order\s+(has\s+been\s+)?(shipped|delivered|confirmed)\b', 0.35),
        (r'\b(order|package|delivery)\s+(tracking|status|update)\b', 0.30),
        (r'\btrack\s+your\s+(order|package|delivery)\b', 0.30),
        (r'\barriv(e|ing|ed)\s+(tomorrow|today|soon)\b', 0.25),
        (r'\bflipkart\.(com|in)\/track\b', 0.35),
        (r'\bamazon\.(com|in)\/track\b', 0.35),
        
        # Appointments / Reminders (legitimate)
        (r'\bappointment\s+(reminder|confirmed|scheduled)\b', 0.30),
        (r'\breminder\s*(:|for)\b', 0.20),
        (r'\bplease\s+arrive\b', 0.20),
        
        # Bank / OTP (legitimate notifications)
        (r'\byour\s+otp\s+is\b', 0.15),
        (r'\baccount\s+(credited|debited)\s+with\b', 0.25),
        (r'\bavailable\s+balance\b', 0.20),
        (r'\btransaction\s+ref(erence)?\s*:\b', 0.25),
        
        # Thank you / Shopping (legitimate)
        (r'\bthank\s+you\s+for\s+(shopping|ordering|your\s+order)\b', 0.35),
        (r'\bwe\s+appreciate\s+your\s+(business|order)\b', 0.30),
    ]
    
    # Keyword scores (presence adds to confidence)
    KEYWORD_SCORES = {
        # High risk keywords
        "urgently": 0.08, "immediately": 0.08, "urgent": 0.08,
        "blocked": 0.07, "suspended": 0.07, "freeze": 0.07,
        "arrest": 0.10, "warrant": 0.10, "police": 0.08,
        "transfer": 0.05, "send money": 0.08, "pay now": 0.08,
        "prize": 0.08, "won": 0.07, "lottery": 0.10,
        "registration fee": 0.12, "joining fee": 0.12,
        "guaranteed": 0.08, "100%": 0.07,
        
        # Medium risk
        "verify": 0.04, "update": 0.03, "confirm": 0.03,
        "otp": 0.05, "pin": 0.04, "password": 0.05,
        "click": 0.04, "link": 0.03,
        
        # Context modifiers (reduce if present with certain patterns)
        "order": -0.05, "delivery": -0.05, "appointment": -0.08,
        "reminder": -0.05, "scheduled": -0.05,
    }
    
    # Thresholds - VERY CONSERVATIVE to avoid missing scams
    # Only skip LLM for absolutely obvious cases
    HIGH_CONFIDENCE_THRESHOLD = 0.95  # Almost never skip LLM for scams (was 0.75)
    LOW_CONFIDENCE_THRESHOLD = 0.05   # Almost never skip LLM for safe (was 0.20)
    
    # IMPORTANT: This classifier is now primarily used as FALLBACK when LLM fails
    # NOT as a way to skip LLM calls. LLM should always be preferred.
    
    def classify(self, message: str) -> LocalClassifierResult:
        """
        Classify message locally without LLM.
        
        Returns:
            LocalClassifierResult with skip_llm=True if confident enough
        """
        message_lower = message.lower()
        
        total_score = 0.0
        matched_rules = []
        detected_category = None
        
        # Check definite scam patterns
        for pattern, category, score in self.DEFINITE_SCAM_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                total_score += score
                matched_rules.append(f"pattern:{category}")
                if not detected_category:
                    detected_category = category
        
        # Check safe patterns (reduce score)
        for pattern, reduction in self.SAFE_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                total_score -= reduction
                matched_rules.append(f"safe_pattern")
        
        # Keyword scoring
        for keyword, score in self.KEYWORD_SCORES.items():
            if keyword in message_lower:
                total_score += score
                if score > 0:
                    matched_rules.append(f"keyword:{keyword}")
        
        # Clamp confidence
        confidence = max(0.0, min(1.0, total_score))
        
        # Determine if LLM should be skipped
        skip_llm = False
        if confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
            skip_llm = True
            is_scam = True
            reasoning = f"High-confidence local detection ({len(matched_rules)} indicators)"
        elif confidence <= self.LOW_CONFIDENCE_THRESHOLD:
            skip_llm = True
            is_scam = False
            reasoning = "Low-confidence local detection (appears safe)"
        else:
            is_scam = confidence >= 0.5
            skip_llm = False
            reasoning = "Uncertain, requires LLM verification"
        
        return LocalClassifierResult(
            is_scam=is_scam,
            confidence=round(confidence, 3),
            category=detected_category,
            skip_llm=skip_llm,
            matched_rules=matched_rules,
            reasoning=reasoning
        )
    
    def should_call_llm(self, message: str) -> Tuple[bool, LocalClassifierResult]:
        """
        Determine if LLM should be called for this message.
        
        Returns:
            (should_call_llm: bool, local_result: LocalClassifierResult)
        """
        result = self.classify(message)
        
        # If skip_llm=True, we're confident enough to not call LLM
        should_call = not result.skip_llm
        
        if not should_call:
            logger.info(f"Skipping LLM: local confidence={result.confidence:.2f}, category={result.category}")
        
        return should_call, result
    
    def get_quick_verdict(self, message: str) -> Dict[str, Any]:
        """
        Get quick verdict without LLM for API fallback.
        
        Returns:
            Dict compatible with LLM response format
        """
        result = self.classify(message)
        
        return {
            "is_scam": result.is_scam,
            "confidence": result.confidence,
            "scam_type": result.category,
            "reasoning": result.reasoning,
            "method": "local_classifier",
            "matched_rules": result.matched_rules
        }


# Global instance
local_classifier = LocalScamClassifier()
