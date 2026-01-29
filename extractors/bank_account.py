"""
Bank account number extractor.
"""
import re
from typing import List, Dict

# Bank account patterns
ACCOUNT_PATTERNS = [
    re.compile(r'\b\d{9,18}\b'),  # 9-18 digit numbers
    re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{0,6}\b'),  # Formatted
    re.compile(r'(?:account|a/c|ac)[:\s#]*(\d{9,18})', re.IGNORECASE),
]


def extract_bank_accounts(text: str) -> List[Dict]:
    """
    Extract bank account numbers from text.
    
    Args:
        text: Text to extract from
        
    Returns:
        List of dicts with value, confidence, context
    """
    accounts = []
    seen = set()
    
    for pattern in ACCOUNT_PATTERNS:
        for match in pattern.finditer(text):
            # Get the matched number
            if match.groups():
                number = match.group(1)
            else:
                number = match.group()
            
            # Clean
            clean = re.sub(r'[-\s]', '', number)
            
            # Validate
            if validate_bank_account(clean) and clean not in seen:
                seen.add(clean)
                
                # Get context
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()
                
                accounts.append({
                    "value": clean,
                    "confidence": calculate_confidence(clean, context),
                    "context": context
                })
    
    return accounts


def validate_bank_account(number: str) -> bool:
    """
    Validate a potential bank account number.
    
    Args:
        number: Cleaned account number (digits only)
        
    Returns:
        True if valid format
    """
    # Must be digits only
    if not number.isdigit():
        return False
    
    # Length check (9-18 digits for Indian banks)
    if len(number) < 9 or len(number) > 18:
        return False
    
    # Filter out phone numbers (10 digits starting with 6-9)
    if len(number) == 10 and number[0] in '6789':
        return False
    
    # Filter out obvious patterns
    if len(set(number)) == 1:  # All same digits
        return False
    
    if number in '12345678901234567890':  # Sequential
        return False
    
    return True


def calculate_confidence(number: str, context: str) -> float:
    """Calculate confidence score for extracted account."""
    confidence = 0.5
    context_lower = context.lower()
    
    # Boost if account-related words nearby
    if any(word in context_lower for word in ['account', 'a/c', 'ac no', 'acct']):
        confidence += 0.2
    
    # Boost if bank name nearby
    banks = ['sbi', 'hdfc', 'icici', 'axis', 'pnb', 'kotak', 'bob', 'canara']
    if any(bank in context_lower for bank in banks):
        confidence += 0.15
    
    # Boost if transfer words nearby
    if any(word in context_lower for word in ['transfer', 'send', 'deposit']):
        confidence += 0.1
    
    return min(confidence, 1.0)
