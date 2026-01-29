"""
Intelligence extraction system.
Extracts bank accounts, UPI IDs, phone numbers, URLs, and keywords from messages.
"""
import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from utils.patterns import (
    BANK_ACCOUNT_PATTERNS,
    UPI_PATTERNS,
    PHONE_PATTERNS,
    URL_PATTERNS,
    EMAIL_PATTERN,
    IFSC_PATTERN,
    URGENCY_KEYWORDS,
    FINANCIAL_KEYWORDS,
    THREAT_KEYWORDS
)

logger = logging.getLogger(__name__)


@dataclass
class ExtractedEntity:
    """Represents an extracted intelligence entity."""
    value: str
    entity_type: str
    confidence: float
    context: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "value": self.value,
            "type": self.entity_type,
            "confidence": self.confidence,
            "context": self.context
        }


class IntelligenceExtractor:
    """Extracts and scores intelligence from conversation messages."""
    
    INTEL_POINTS = {
        "bank_accounts": 7,
        "upi_ids": 5,
        "phone_numbers": 3,
        "urls": 6,
        "emails": 4,
        "ifsc_codes": 4,
        "keywords": 1
    }
    
    def __init__(self):
        self._seen_entities: Dict[str, set] = {
            "bank_accounts": set(),
            "upi_ids": set(),
            "phone_numbers": set(),
            "urls": set(),
            "emails": set()
        }
    
    def extract_all(self, message: str, conversation_history: Optional[List] = None) -> Dict[str, Any]:
        """Extract all intelligence types from message and history."""
        all_text = message
        if conversation_history:
            history_text = " ".join([
                msg.content if hasattr(msg, 'content') else str(msg.get('content', ''))
                for msg in conversation_history
            ])
            all_text = f"{history_text} {message}"
        
        intelligence = {
            "bank_accounts": self.extract_bank_accounts(all_text),
            "upi_ids": self.extract_upi_ids(all_text),
            "phone_numbers": self.extract_phone_numbers(all_text),
            "urls": self.extract_urls(all_text),
            "emails": self.extract_emails(all_text),
            "ifsc_codes": self.extract_ifsc_codes(all_text),
            "keywords": self.extract_keywords(all_text),
            "confidence_scores": {}
        }
        
        for intel_type, values in intelligence.items():
            if intel_type != "confidence_scores" and values:
                avg_conf = self._calculate_type_confidence(intel_type, values, all_text)
                intelligence["confidence_scores"][intel_type] = avg_conf
        
        return intelligence
    
    def extract_bank_accounts(self, text: str) -> List[str]:
        """Extract bank account numbers from text."""
        accounts = set()
        for pattern in BANK_ACCOUNT_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                clean = re.sub(r'[-\s]', '', match)
                if 9 <= len(clean) <= 18 and clean.isdigit():
                    if not self._is_likely_phone(clean) and not self._is_common_number(clean):
                        accounts.add(clean)
        return list(accounts)
    
    def extract_upi_ids(self, text: str) -> List[str]:
        """Extract UPI IDs from text."""
        upi_ids = set()
        for pattern in UPI_PATTERNS:
            matches = pattern.findall(text.lower())
            for match in matches:
                if self._is_valid_upi(match):
                    upi_ids.add(match.lower())
        return list(upi_ids)
    
    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract Indian phone numbers from text."""
        phones = set()
        for pattern in PHONE_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                clean = re.sub(r'[\s\-+]', '', match)
                if clean.startswith('91') and len(clean) == 12:
                    clean = clean[2:]
                elif clean.startswith('0') and len(clean) == 11:
                    clean = clean[1:]
                if len(clean) == 10 and clean[0] in '6789':
                    phones.add(clean)
        return list(phones)
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        urls = set()
        for pattern in URL_PATTERNS:
            matches = pattern.findall(text)
            for url in matches:
                url = url.strip('.,;:)>')
                if len(url) > 5:
                    urls.add(url)
        return list(urls)
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        matches = EMAIL_PATTERN.findall(text)
        return list(set(matches))
    
    def extract_ifsc_codes(self, text: str) -> List[str]:
        """Extract IFSC codes."""
        matches = IFSC_PATTERN.findall(text.upper())
        return list(set(matches))
    
    def extract_keywords(self, text: str) -> List[str]:
        """Extract suspicious keywords from text."""
        text_lower = text.lower()
        keywords = set()
        all_keywords = URGENCY_KEYWORDS + FINANCIAL_KEYWORDS + THREAT_KEYWORDS
        for keyword in all_keywords:
            if keyword.lower() in text_lower:
                keywords.add(keyword)
        return list(keywords)[:15]
    
    def calculate_quality_score(self, intelligence: Dict[str, Any]) -> float:
        """
        Calculate Intelligence Quality Score (IQS).
        Returns score from 0.0 to 10.0 (capped).
        """
        total_score = 0.0
        confidence_scores = intelligence.get("confidence_scores", {})
        
        for intel_type, points in self.INTEL_POINTS.items():
            items = intelligence.get(intel_type, [])
            if items:
                count = len(items)
                confidence = confidence_scores.get(intel_type, 0.5)
                type_score = count * points * confidence
                total_score += type_score
        
        # Bonus for multiple types
        types_found = sum(1 for k, v in intelligence.items() 
                         if k not in ["confidence_scores", "keywords"] and v)
        if types_found >= 3:
            total_score *= 1.2
        if types_found >= 4:
            total_score *= 1.1
        
        # Cap at 10.0
        return round(min(total_score, 10.0), 2)
    
    def _is_valid_upi(self, upi: str) -> bool:
        """Validate UPI ID format."""
        if '@' not in upi:
            return False
        parts = upi.split('@')
        if len(parts) != 2:
            return False
        username, handle = parts
        if len(username) < 3 or len(username) > 50:
            return False
        known_handles = ['ybl', 'okhdfcbank', 'oksbi', 'okicici', 'paytm', 
                        'upi', 'apl', 'ibl', 'sbi', 'axl', 'axis', 'icici',
                        'hdfc', 'kotak', 'barodampay', 'mahb', 'pnb']
        if handle.lower() in known_handles:
            return True
        return len(handle) >= 2 and handle.isalnum()
    
    def _is_likely_phone(self, number: str) -> bool:
        """Check if number is likely a phone number."""
        if len(number) == 10 and number[0] in '6789':
            return True
        if len(number) == 12 and number.startswith('91'):
            return True
        return False
    
    def _is_common_number(self, number: str) -> bool:
        """Check for false positive patterns."""
        if len(set(number)) == 1:
            return True
        if number in '12345678901234567890':
            return True
        if len(number) < 9:
            return True
        return False
    
    def _calculate_type_confidence(self, intel_type: str, values: List, context: str) -> float:
        """Calculate confidence for an intelligence type."""
        if not values:
            return 0.0
        base_confidence = 0.5
        mention_boost = min(len(values) * 0.1, 0.3)
        context_lower = context.lower()
        if any(kw in context_lower for kw in ['send', 'transfer', 'pay', 'account']):
            context_boost = 0.15
        else:
            context_boost = 0.0
        return min(base_confidence + mention_boost + context_boost, 1.0)
    
    def _summarize(self, intelligence: Dict) -> str:
        """Create summary string of extracted intelligence."""
        parts = []
        for key, values in intelligence.items():
            if key != "confidence_scores" and values:
                parts.append(f"{key}:{len(values)}")
        return ", ".join(parts) if parts else "none"
