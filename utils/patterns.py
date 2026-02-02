"""
Utility patterns for scam detection and intelligence extraction.
"""
import re
from typing import List, Pattern

# ============================================
# SCAM DETECTION PATTERNS
# ============================================

# Urgency keywords (English + Hindi transliteration)
URGENCY_KEYWORDS = [
    # English
    "urgent", "urgently", "immediately", "right now", "asap", "emergency",
    "blocked", "suspended", "deactivated", "expired", "limited time",
    "within 24 hours", "last chance", "act now", "hurry", "quick",
    # Hindi transliteration
    "turant", "abhi", "jaldi", "fauran"
]

# Financial keywords
FINANCIAL_KEYWORDS = [
    "bank account", "account number", "ifsc", "swift", "branch",
    "upi", "paytm", "phonepe", "gpay", "google pay", "bhim",
    "otp", "pin", "cvv", "card number", "atm", "debit card", "credit card",
    "transfer", "payment", "rupees", "rs", "₹", "inr",
    "verify", "verification", "confirm", "update",
    "kyc", "pan", "aadhar", "aadhaar",
    # Hindi transliteration
    "khata", "paisa", "bhejna"
]

# Authority impersonation keywords
AUTHORITY_KEYWORDS = [
    "bank manager", "security team", "customer care", "support team",
    "rbi", "reserve bank", "government", "police", "cyber cell",
    "income tax", "it department", "customs", "court order",
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb",
    "officer", "official", "department", "ministry"
]

# Threat keywords
THREAT_KEYWORDS = [
    "legal action", "arrest", "case filed", "fir", "court",
    "penalty", "fine", "jail", "imprisonment",
    "account freeze", "account blocked", "money lost",
    "warrant", "summons", "notice"
]

# Reward/lottery keywords
REWARD_KEYWORDS = [
    "won", "winner", "prize", "lottery", "jackpot", "lucky",
    "congratulations", "selected", "eligible", "offer",
    "cashback", "reward", "bonus", "free", "gift"
]

# Job scam keywords
JOB_KEYWORDS = [
    "work from home", "earn money", "part time", "full time",
    "no experience", "registration fee", "joining fee",
    "data entry", "typing job", "online job",
    "guaranteed income", "daily payment"
]

# Phishing keywords
PHISHING_KEYWORDS = [
    "click here", "click link", "verify link", "update link",
    "login", "log in", "sign in", "password",
    "reset", "expired session", "reactivate"
]

# Crypto scam keywords
CRYPTO_KEYWORDS = [
    "bitcoin", "btc", "ethereum", "eth", "crypto", "wallet",
    "trading", "investment", "profit", "return", "mining",
    "binance", "coinbase", "trust wallet", "metamask",
    "usdt", "doubling", "forex", "signal"
]

# Romance scam keywords
ROMANCE_KEYWORDS = [
    "love", "darling", "honey", "soulmate", "relationship",
    "stuck", "airport", "customs", "gift", "parcel",
    "meet", "marry", "husband", "wife", "doctor",
    "peacekeeping", "military", "widower"
]

# Tech support keywords
TECH_SUPPORT_KEYWORDS = [
    "microsoft", "windows", "computer", "virus", "hacked",
    "defender", "firewall", "teamviewer", "anydesk", "quicksupport",
    "remote", "access", "refund", "subscription", "expire",
    "call center", "engineer"
]

# Digital Arrest / Courier keywords
ARREST_KEYWORDS = [
    "cbi", "crime branch", "narcotics", "customs", "illegal",
    "parcel", "fedex", "dhl", "courier", "trafficking",
    "aadhar", "video call", "skype", "statement",
    "police", "arrest", "warrant", "cyber crime"
]

# ============================================
# INTELLIGENCE EXTRACTION PATTERNS
# ============================================

# Bank account patterns (Indian formats)
BANK_ACCOUNT_PATTERNS: List[Pattern] = [
    re.compile(r'\b\d{9,18}\b'),  # 9-18 digit account numbers
    re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{0,4}\b'),  # Formatted account
    re.compile(r'(?:account|a/c|ac)[\s:]*#?[\s]*(\d{9,18})', re.IGNORECASE),
]

# IFSC code pattern
IFSC_PATTERN = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')

# UPI ID patterns
UPI_PATTERNS: List[Pattern] = [
    re.compile(r'\b[\w.-]+@(?:ybl|okhdfcbank|oksbi|okicici|okaxis|paytm|upi|apl|axl|ibl|sbi|barodampay|mahb|pnb)\b', re.IGNORECASE),
    re.compile(r'\b[\w.-]+@[\w]+\b'),  # Generic UPI pattern
]

# Phone number patterns (Indian)
PHONE_PATTERNS: List[Pattern] = [
    re.compile(r'\+91[\s\-]?\d{5}[\s\-]?\d{5}\b'),  # +91 format with optional space
    re.compile(r'\b91[\s\-]?\d{5}[\s\-]?\d{5}\b'),  # 91 format with optional space
    re.compile(r'\+91[\s-]?\d{10}\b'),  # +91 format compact
    re.compile(r'\b91[\s-]?\d{10}\b'),  # 91 format compact
    re.compile(r'\b0\d{10}\b'),  # 0 prefix format
    re.compile(r'\b[6-9]\d{9}\b'),  # Indian mobile (starts with 6-9)
    re.compile(r'\b[6-9]\d{4}[\s\-]?\d{5}\b'),  # With space/dash in middle
]

# Email patterns
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# Crypto Wallet Patterns
CRYPTO_WALLET_PATTERNS: List[Pattern] = [
    re.compile(r'\b(?:1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}\b'),  # Bitcoin (Legacy/Segwit) - Non-capturing group
    re.compile(r'\bbc1[a-z0-9]{39,59}\b'),  # Bitcoin (Bech32)
    re.compile(r'\b0x[a-fA-F0-9]{40}\b'),  # Ethereum/BSC/Polygon
    re.compile(r'\bT[A-Za-z1-9]{33}\b'),  # TRON (USDT common)
]

# URL patterns
URL_PATTERNS: List[Pattern] = [
    re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
    re.compile(r'www\.[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
    re.compile(r'\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|tr\.im)/[\w]+', re.IGNORECASE),
    re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?'),  # IP addresses
]

# ============================================
# SCAM TYPE CLASSIFICATION
# ============================================

SCAM_TYPE_PATTERNS = {
    "banking": ["bank", "account", "blocked", "suspended", "kyc", "verification", "otp"],
    "upi": ["upi", "paytm", "phonepe", "gpay", "payment", "transfer"],
    "phishing": ["click", "link", "login", "password", "verify", "update"],
    "lottery": ["won", "prize", "lottery", "jackpot", "winner", "claim"],
    "job": ["job", "work from home", "part time", "earning", "income"],
    "impersonation": ["officer", "police", "rbi", "government", "court", "legal"],
    "tech_support": ["computer", "virus", "malware", "microsoft", "apple", "support"]
}

# Scammer behavior types
SCAMMER_TYPE_PATTERNS = {
    "aggressive": ["immediately", "now", "urgent", "quick", "hurry", "!"],
    "patient": ["dear", "kindly", "please", "request", "help"],
    "technical": ["system", "server", "database", "technical", "error", "process"],
    "social": ["trust", "help", "understand", "worry", "believe"]
}

# Psychological tactics
TACTIC_PATTERNS = {
    "urgency": URGENCY_KEYWORDS,
    "authority": AUTHORITY_KEYWORDS,
    "fear": THREAT_KEYWORDS,
    "greed": REWARD_KEYWORDS,
    "scarcity": ["limited", "only", "exclusive", "last", "few remaining"]
}

# ============================================
# WHITELIST PATTERNS (False Positive Reduction)
# ============================================

# Common legitimate phrases that might trigger false positives
WHITELIST_PHRASES = [
    "customer service",
    "how can i help",
    "thank you for calling",
    "your reference number",
    "official statement"
]

# Legitimate domain patterns
LEGITIMATE_DOMAINS = [
    r"\.gov\.in$",
    r"\.nic\.in$",
    r"sbi\.co\.in$",
    r"hdfcbank\.com$",
    r"icicibank\.com$"
]
