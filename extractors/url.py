"""
URL extractor for suspicious links.
"""
import re
from typing import List, Dict
from urllib.parse import urlparse

# URL patterns
URL_PATTERNS = [
    re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
    re.compile(r'www\.[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
    re.compile(r'\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly)/[\w]+', re.IGNORECASE),
    re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?'),  # IP addresses
]

# Suspicious URL indicators
SUSPICIOUS_INDICATORS = [
    'login', 'verify', 'confirm', 'secure', 'update', 'banking',
    'account', 'password', 'signin', 'authenticate'
]

# URL shorteners
SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'tr.im']


def extract_urls(text: str) -> List[Dict]:
    """
    Extract URLs from text.
    
    Args:
        text: Text to extract from
        
    Returns:
        List of dicts with value, confidence, context, classification
    """
    urls = []
    seen = set()
    
    for pattern in URL_PATTERNS:
        for match in pattern.finditer(text):
            url = match.group().strip('.,;:)>')
            
            if len(url) > 5 and url not in seen:
                seen.add(url)
                
                # Get context
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()
                
                classification = classify_url(url)
                
                urls.append({
                    "value": url,
                    "confidence": calculate_confidence(url, context),
                    "context": context,
                    "classification": classification
                })
    
    return urls


def classify_url(url: str) -> str:
    """
    Classify URL as suspicious, shortener, or normal.
    
    Args:
        url: URL to classify
        
    Returns:
        Classification string
    """
    url_lower = url.lower()
    
    # Check for IP address (highly suspicious)
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        return "ip_address"
    
    # Check for shortener
    for shortener in SHORTENERS:
        if shortener in url_lower:
            return "shortened"
    
    # Check for suspicious keywords in URL
    for indicator in SUSPICIOUS_INDICATORS:
        if indicator in url_lower:
            return "phishing_suspected"
    
    # Check for misspelled domains
    misspellings = {
        'googe': 'google', 'googel': 'google',
        'facebok': 'facebook', 'facbook': 'facebook',
        'paytim': 'paytm', 'pytm': 'paytm',
        'amazan': 'amazon', 'amzon': 'amazon'
    }
    for misspell, _ in misspellings.items():
        if misspell in url_lower:
            return "typosquatting"
    
    return "normal"


def calculate_confidence(url: str, context: str) -> float:
    """Calculate confidence for URL extraction."""
    confidence = 0.6
    context_lower = context.lower()
    
    classification = classify_url(url)
    
    # Boost for suspicious URLs
    if classification in ['ip_address', 'phishing_suspected', 'typosquatting']:
        confidence += 0.25
    elif classification == 'shortened':
        confidence += 0.15
    
    # Boost if click/verify words nearby
    if any(word in context_lower for word in ['click', 'verify', 'visit', 'open', 'link']):
        confidence += 0.1
    
    return min(confidence, 1.0)


def get_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except Exception:
        return url
