"""
UPI ID extractor.
"""
import re
from typing import List, Dict

# Known UPI handles
KNOWN_HANDLES = [
    'ybl', 'okhdfcbank', 'oksbi', 'okicici', 'okaxis', 'paytm', 
    'upi', 'apl', 'axl', 'ibl', 'sbi', 'barodampay', 'mahb', 
    'pnb', 'icici', 'hdfc', 'axis', 'kotak', 'indus', 'federal'
]

# UPI pattern
UPI_PATTERN = re.compile(r'\b([\w.-]+@[\w]+)\b', re.IGNORECASE)


def extract_upi_ids(text: str) -> List[Dict]:
    """
    Extract UPI IDs from text.
    
    Args:
        text: Text to extract from
        
    Returns:
        List of dicts with value, confidence, context
    """
    upi_ids = []
    seen = set()
    
    for match in UPI_PATTERN.finditer(text):
        upi = match.group(1).lower()
        
        if validate_upi(upi) and upi not in seen:
            seen.add(upi)
            
            # Get context
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            context = text[start:end].strip()
            
            upi_ids.append({
                "value": upi,
                "confidence": calculate_confidence(upi, context),
                "context": context
            })
    
    return upi_ids


def validate_upi(upi: str) -> bool:
    """
    Validate UPI ID format.
    
    Args:
        upi: Potential UPI ID
        
    Returns:
        True if valid format
    """
    if '@' not in upi:
        return False
    
    parts = upi.split('@')
    if len(parts) != 2:
        return False
    
    username, handle = parts
    
    # Username validation
    if len(username) < 2 or len(username) > 50:
        return False
    
    # Filter out emails
    if handle in ['gmail', 'yahoo', 'hotmail', 'outlook', 'email']:
        return False
    if '.' in handle:  # Email domain
        return False
    
    # Handle validation
    if len(handle) < 2 or len(handle) > 20:
        return False
    
    return True


def calculate_confidence(upi: str, context: str) -> float:
    """Calculate confidence score for UPI ID."""
    confidence = 0.5
    context_lower = context.lower()
    
    # Check if handle is known
    handle = upi.split('@')[1] if '@' in upi else ''
    if handle in KNOWN_HANDLES:
        confidence += 0.3
    
    # Boost if payment words nearby
    if any(word in context_lower for word in ['pay', 'upi', 'transfer', 'send']):
        confidence += 0.15
    
    return min(confidence, 1.0)


def get_bank_from_handle(handle: str) -> str:
    """Get bank name from UPI handle."""
    handle_map = {
        'ybl': 'Yes Bank',
        'okhdfcbank': 'HDFC Bank',
        'oksbi': 'SBI',
        'okicici': 'ICICI Bank',
        'okaxis': 'Axis Bank',
        'paytm': 'Paytm Payments Bank',
        'sbi': 'SBI',
        'hdfc': 'HDFC Bank',
        'icici': 'ICICI Bank',
        'axis': 'Axis Bank',
        'kotak': 'Kotak Bank',
        'pnb': 'PNB'
    }
    return handle_map.get(handle.lower(), 'Unknown Bank')
