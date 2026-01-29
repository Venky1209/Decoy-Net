"""
Phone number extractor for Indian numbers.
"""
import re
from typing import List, Dict

# Phone patterns
PHONE_PATTERNS = [
    re.compile(r'\+91[-\s]?(\d{10})\b'),  # +91
    re.compile(r'\b91[-\s]?(\d{10})\b'),   # 91
    re.compile(r'\b0(\d{10})\b'),          # 0 prefix
    re.compile(r'\b([6-9]\d{9})\b'),       # Raw 10-digit
]


def extract_phone_numbers(text: str) -> List[Dict]:
    """
    Extract Indian phone numbers from text.
    
    Args:
        text: Text to extract from
        
    Returns:
        List of dicts with value, confidence, context
    """
    phones = []
    seen = set()
    
    for pattern in PHONE_PATTERNS:
        for match in pattern.finditer(text):
            # Get the 10-digit number
            if match.groups():
                number = match.group(1)
            else:
                number = match.group()
            
            # Normalize
            normalized = normalize_phone(number)
            
            if normalized and normalized not in seen:
                seen.add(normalized)
                
                # Get context
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()
                
                phones.append({
                    "value": normalized,
                    "confidence": calculate_confidence(normalized, context),
                    "context": context
                })
    
    return phones


def normalize_phone(number: str) -> str:
    """
    Normalize phone number to 10-digit format.
    
    Args:
        number: Raw phone number
        
    Returns:
        Normalized 10-digit number or empty string if invalid
    """
    # Remove common separators
    clean = re.sub(r'[-\s+]', '', number)
    
    # Remove country code
    if clean.startswith('91') and len(clean) == 12:
        clean = clean[2:]
    elif clean.startswith('0') and len(clean) == 11:
        clean = clean[1:]
    
    # Validate final format
    if len(clean) == 10 and clean[0] in '6789' and clean.isdigit():
        return clean
    
    return ""


def calculate_confidence(number: str, context: str) -> float:
    """Calculate confidence for phone number."""
    confidence = 0.6
    context_lower = context.lower()
    
    # Boost if call/phone words nearby
    if any(word in context_lower for word in ['call', 'phone', 'mobile', 'whatsapp', 'contact']):
        confidence += 0.2
    
    # Boost if formatted with country code originally
    if '+91' in context or '91 ' in context:
        confidence += 0.1
    
    return min(confidence, 1.0)


def format_phone(number: str, with_country_code: bool = True) -> str:
    """Format phone number for display."""
    if with_country_code:
        return f"+91 {number[:5]} {number[5:]}"
    return f"{number[:5]} {number[5:]}"
