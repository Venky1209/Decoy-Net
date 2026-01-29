"""
Suspicious keyword extractor.
"""
from typing import List, Dict, Set

# Keyword categories with weights
KEYWORD_CATEGORIES = {
    "urgency": {
        "keywords": [
            "urgent", "urgently", "immediately", "right now", "asap",
            "hurry", "quick", "fast", "within 24 hours", "limited time",
            "last chance", "act now", "don't delay"
        ],
        "weight": 0.8
    },
    "financial": {
        "keywords": [
            "bank account", "account number", "ifsc", "transfer",
            "upi", "paytm", "phonepe", "gpay", "bhim",
            "otp", "pin", "cvv", "card number", "atm",
            "payment", "rupees", "rs", "inr",
            "kyc", "pan", "aadhar", "aadhaar"
        ],
        "weight": 0.9
    },
    "threat": {
        "keywords": [
            "blocked", "suspended", "deactivated", "expired",
            "legal action", "arrest", "case filed", "fir",
            "penalty", "fine", "court", "police",
            "freeze", "locked", "terminated"
        ],
        "weight": 0.85
    },
    "authority": {
        "keywords": [
            "bank manager", "security team", "customer care",
            "rbi", "reserve bank", "government", "police",
            "income tax", "customs", "cyber cell",
            "officer", "official", "department"
        ],
        "weight": 0.75
    },
    "reward": {
        "keywords": [
            "won", "winner", "prize", "lottery", "jackpot",
            "congratulations", "selected", "eligible",
            "cashback", "reward", "bonus", "free", "gift"
        ],
        "weight": 0.7
    },
    "action": {
        "keywords": [
            "click here", "click link", "verify", "confirm",
            "update", "submit", "send", "share",
            "download", "install", "open"
        ],
        "weight": 0.75
    }
}


def extract_suspicious_keywords(text: str) -> List[Dict]:
    """
    Extract suspicious keywords from text.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of dicts with keyword, category, weight
    """
    text_lower = text.lower()
    found_keywords = []
    seen: Set[str] = set()
    
    for category, data in KEYWORD_CATEGORIES.items():
        for keyword in data["keywords"]:
            if keyword in text_lower and keyword not in seen:
                seen.add(keyword)
                found_keywords.append({
                    "keyword": keyword,
                    "category": category,
                    "weight": data["weight"]
                })
    
    # Sort by weight
    found_keywords.sort(key=lambda x: x["weight"], reverse=True)
    
    return found_keywords


def get_keyword_score(text: str) -> float:
    """
    Calculate overall suspicion score based on keywords.
    
    Args:
        text: Text to analyze
        
    Returns:
        Score from 0.0 to 1.0
    """
    keywords = extract_suspicious_keywords(text)
    
    if not keywords:
        return 0.0
    
    # Calculate weighted score
    total_weight = sum(kw["weight"] for kw in keywords)
    category_coverage = len(set(kw["category"] for kw in keywords))
    
    # Score based on total weight and category coverage
    base_score = min(total_weight / 5.0, 0.7)
    coverage_bonus = category_coverage * 0.05
    
    return min(base_score + coverage_bonus, 1.0)


def categorize_keywords(keywords: List[Dict]) -> Dict[str, List[str]]:
    """Group keywords by category."""
    categories: Dict[str, List[str]] = {}
    
    for kw in keywords:
        cat = kw["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(kw["keyword"])
    
    return categories
