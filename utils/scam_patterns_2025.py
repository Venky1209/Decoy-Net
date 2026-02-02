"""
2025 Indian Scam Detection Patterns, Templates, and Semantic Engine.
Based on research: Digital arrest, UPI fraud, AI voice clone, task scams, etc.
"""
import re
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum


class ScamCategory(str, Enum):
    """2025 Scam Categories by prevalence and danger."""
    DIGITAL_ARREST = "digital_arrest"      # ₹2000 Cr losses
    UPI_FRAUD = "upi_fraud"                # ₹1087 Cr losses
    AI_VOICE_CLONE = "ai_voice_clone"      # Emerging threat
    TASK_JOB_SCAM = "task_job_scam"        # High volume
    INVESTMENT_CRYPTO = "investment_crypto" # ₹500+ Cr
    IMPERSONATION = "impersonation"        # RBI/NPCI/Bank
    LOTTERY_REWARD = "lottery_reward"      # Classic
    PHISHING = "phishing"                  # Persistent
    ROMANCE_SCAM = "romance_scam"          # Growing
    SIM_SWAP = "sim_swap"                  # Identity theft
    COURIER_PARCEL = "courier_parcel"      # FedEx/DHL scams
    TRAFFIC_CHALLAN = "traffic_challan"    # Fake e-challan
    APK_MALWARE = "apk_malware"            # Malicious apps
    CSR_FUNDING = "csr_funding"            # NGO fraud


# ============================================
# OPTION A: 2025 KEYWORD LISTS
# ============================================

SCAM_KEYWORDS_2025 = {
    ScamCategory.DIGITAL_ARREST: [
        # Core digital arrest terms
        "digital arrest", "cyber arrest", "virtual arrest", "online arrest",
        "video call arrest", "stay on video", "don't disconnect", "do not disconnect",
        "video verification", "verification required",
        # Authority impersonation
        "cbi officer", "cbi case", "cbi cyber", "ed notice", "enforcement directorate",
        "ed has", "ed officer", "ed frozen", " ed ", "ncb officer", "ncb",
        "cyber cell", "cyber crime branch", "narcotics bureau", "narcotics control",
        "supreme court order", "supreme court", "high court notice", "court summons",
        "mumbai cyber", "delhi cyber", "inspector", "officer sharma", "officer verma",
        # Threats
        "money laundering", "hawala", "hawala transaction", "terror funding",
        "illegal transaction", "suspicious activity", "suspicious transaction",
        "your aadhaar linked", "your pan misused", "account under scanner",
        "frozen", "account frozen", "has frozen", "non-bailable warrant",
        "tax evasion", "drug trafficking", "imprisonment", "10 years",
        # Tactics
        "verification call", "identity verification", "stay on line",
        "transfer to safe", "rbi safe custody", "your money unsafe",
        "secure the funds", "safe account", "government safe",
        "immediate transfer", "transfer amount", "police station", "fir registered",
        "cooperate", "do not leave", "do not inform", "settlement amount",
        "skype", "stay on skype", "video call pe", "disconnect mat"
    ],
    
    ScamCategory.UPI_FRAUD: [
        # NPCI 2025 patterns
        "enter pin to receive", "enter upi pin", "upi pin to receive",
        "enter your upi pin", "share upi pin", "type pin",
        "scan to receive", "scan qr", "scan this qr",
        "qr code to receive", "scan qr for payment",
        "collect request", "payment request pending", "payment request",
        "refund pending", "refund of rs", "your refund",
        "cashback credited", "cashback", "receive cashback",
        # Fake payment confirmations
        "payment of rs", "credited to your", "transaction successful",
        "payment confirmation", "screenshot attached",
        # UPI ID patterns
        "send to upi", "pay to upi id", "transfer to",
        # Fake apps
        "download our app", "use this link for payment",
        "new upi app", "verify upi id",
        # Click/Claim patterns
        "click here to claim", "click to receive", "claim your",
        "to receive the amount", "receive the amount",
        "limited time offer", "limited time",
        # OLX/Marketplace scams
        "olx buyer", "olx seller", "advance via qr", "scan to receive advance",
        # Utility bill scams
        "electricity bill", "disconnected in", "bill overdue", "pay immediately",
        # Collect request scams (AMAZON-REFUND style)
        "enter pin to accept", "accept the payment", "amazon-refund", "bonus",
        "received a payment request", "from amazon"
    ],
    
    ScamCategory.AI_VOICE_CLONE: [
        # Emergency family scams
        "accident happened", "in hospital", "papa/mummy accident",
        "son/daughter arrested", "family emergency",
        "need money immediately", "don't tell anyone else",
        "send money now", "western union", "wire transfer",
        # Voice verification red flags
        "is this really you", "sound different", "bad connection",
        "can't video call", "phone problem", "borrowed phone",
        # Hindi patterns
        "papa maine", "mummy ko mat batana", "turant bhejo",
        "battery khatam", "jaldi karo", "hospital mein hoon",
        "accident kar diya", "bail", "stuck at airport",
        "don't tell mom", "don't tell dad", "don't tell papa",
        "friend ka accident", "operation ke liye", "pareshan"
    ],
    
    ScamCategory.TASK_JOB_SCAM: [
        # Task-based scams (Telegram/WhatsApp)
        "daily task", "simple task", "earn per task", "task payment",
        "like and subscribe", "review task", "rating task", "rating tasks",
        "telegram channel", "telegram group", "join our channel",
        "join telegram", "on telegram", "doing simple",
        # Registration fees
        "registration fee", "joining fee", "activation fee", 
        "security deposit", "refundable deposit",
        "pay rs", "pay ₹", "fee to start",
        # Fake promises
        "earn rs", "earn ₹", "50000 per month", "per month",
        "earn daily", "start earning", "guaranteed income",
        "no investment required", "work 2 hours",
        "part time job", "amazon job", "flipkart job",
        "data entry", "typing work", "copy paste job",
        "no experience", "simple rating",
        # Hindi patterns
        "video like karo", "like karo", "kamao", "roz", "ghante kaam",
        "monthly pakka", "deposit do", "limited seats", "youtube like",
        "per like", "paisa kamao", "earn karo"
    ],
    
    ScamCategory.INVESTMENT_CRYPTO: [
        # Crypto scams
        "double your bitcoin", "btc doubler", "crypto investment",
        "guaranteed returns", "100% profit", "fixed returns",
        "binary trading", "forex trading", "stock tips",
        # Celebrity endorsement scams
        "elon musk", "mukesh ambani", "ratan tata",
        "celebrity investment", "verified by", "celebrity endorsed",
        # Platform scams
        "new trading app", "exclusive platform", "early investor bonus",
        "referral bonus", "deposit bonus", "withdrawal pending",
        # High return promises
        "500% return", "monthly returns", "weekly returns",
        "sebi registered", "premium group", "subscription",
        "minimum investment", "withdraw profits", "withdraw anytime",
        "expert signals", "vip membership", "trading signals"
    ],
    
    ScamCategory.IMPERSONATION: [
        # RBI/NPCI impersonation
        "rbi order", "rbi directive", "rbi notice",
        "npci notification", "npci order", "upi will be blocked",
        "account freeze order", "central bank notice",
        # Bank impersonation (SBI, HDFC, ICICI, etc.)
        "bank security alert", "account compromised",
        "suspicious login", "card blocked", "debit card expired",
        "credit limit exceeded", "emi bounce",
        "sbi account", "hdfc bank", "icici", "axis bank", "pnb", "kotak",
        "your account will be blocked", "blocked in 24", "blocked in 48",
        "incomplete kyc", "kyc update", "update your kyc", "link your aadhaar",
        "click this link", "update your aadhaar", "service disruption",
        # OTP/CVV scams  
        "share otp", "share cvv", "expiry date", "card number",
        "verify cvv", "unblock now", "temporarily blocked",
        "unusual login", "new device", "if not you",
        # Government
        "income tax refund", "gst refund", "pm kisan yojana",
        "government scheme", "subsidy amount"
    ],
    
    ScamCategory.LOTTERY_REWARD: [
        # Modern lottery scams
        "jio lottery", "jio number won", "jio lucky",
        "airtel lucky draw", "amazon lucky draw",
        "flipkart winner", "google lottery", "whatsapp lottery",
        "iphone winner", "car winner", "bike winner",
        "lucky draw", "our lucky draw", "in lucky draw",
        "won rs", "won ₹", "lakh", "25 lakh", "50 lakh",
        "your number won", "number has won", "you won",
        "congratulations", "winner", "prize",
        # Processing fees
        "processing fee", "pay processing", "pay rs", "pay ₹",
        "tax deduction", "courier charge", "to claim your",
        "insurance fee", "gst charges", "claim charges",
        "contact now", "claim your prize", "claim prize",
        # International lottery patterns
        "won $", "usd", "dollars", "million", "1,000,000",
        "transfer fee", "western union", "money transfer",
        "send name", "send address", "lottery code", "lottery winner"
    ],
    
    ScamCategory.PHISHING: [
        # Modern phishing
        "verify your account", "account will be suspended",
        "unusual activity", "login from new device",
        "reset password now", "confirm identity",
        "click to verify", "tap to confirm",
        # Fake links
        "bit.ly", "tinyurl", "short link", "click below",
        # Tech support scams
        "microsoft security", "microsoft alert", "microsoft support",
        "windows license", "computer compromised", "pc at risk",
        "call toll-free", "call immediately", "technician",
        "anydesk", "teamviewer", "remote access",
        "hackers may steal", "security patch", ".exe",
        "lifetime license", "renew now"
    ],
    
    ScamCategory.SIM_SWAP: [
        # SIM swap indicators
        "new sim card", "sim upgrade", "4g to 5g upgrade",
        "sim replacement", "port your number",
        "aadhaar otp", "verify with otp", "share otp",
        "one time password", "6 digit code"
    ],
    
    ScamCategory.COURIER_PARCEL: [
        # Courier impersonation (FedEx, DHL, India Post)
        "fedex alert", "fedex parcel", "fedex", "dhl delivery", "dhl package", "dhl",
        "india post", "speed post", "parcel seized", "parcel intercepted",
        "illegal items", "fake passports", "banned drugs", "contraband",
        "customs officer", "customs seized", "customs helpline", "customs",
        "mumbai airport", "delhi airport", "airport customs", "airport",
        "criminal charges", "press 1", "press 2",
        "reference number", "tracking number",
        "package from china", "parcel from", "delivery failed",
        "your parcel", "containing illegal", "avoid arrest", "notified"
    ],
    
    ScamCategory.TRAFFIC_CHALLAN: [
        # E-challan scams (TOI Jan 2026)
        "traffic challan", "e-challan", "challan alert",
        "vehicle violated", "violated signal", "over-speeding", "overspeeding",
        "fine rs", "fine ₹", "penalty rs", "penalty ₹", "penalty:",
        "license suspended", "license may be", "court case", "pay now to avoid",
        "echallan-gov", "paytm.challan", "challan.pay",
        "your vehicle", "vehicle was caught", "caught over", "download challan",
        "challan notice", "e-challan notice"
    ],
    
    ScamCategory.APK_MALWARE: [
        # Malicious APK downloads (TOI Jan 2026)
        "download apk", ".apk", "install app",
        "itr-refund.apk", "kisanpay.apk", "cryptotrading.apk",
        "download official", "government app", "refund app",
        "link aadhaar", "link bank account", "verify bank details",
        "pm kisan", "income tax app", "gst app"
    ],
    
    ScamCategory.CSR_FUNDING: [
        # CSR/NGO fraud (TOI Jan 2026 - 1.31 Cr loss)
        "csr funding", "corporate funding", "ngo funding",
        "crore funding", "liaison officer", "government liaison",
        "processing fee for funding", "eligible for funding",
        # FD Fraud patterns (TOI Jan 2026)
        "special fd", "fd offer", "12% interest", "senior citizens",
        "doorstep service", "relationship manager", "limited period scheme",
        "fixed deposit offer", "high interest fd"
    ]
}


# ============================================
# OPTION B: SEMANTIC PATTERN MATCHING
# ============================================

@dataclass
class SemanticPattern:
    """Pattern that requires multiple indicator categories to match."""
    name: str
    category: ScamCategory
    required_categories: List[str]  # ALL must be present
    optional_categories: List[str]  # BONUS if present
    min_required: int = 2
    confidence_boost: float = 0.3


SEMANTIC_PATTERNS = [
    # Digital Arrest Pattern
    SemanticPattern(
        name="digital_arrest_pattern",
        category=ScamCategory.DIGITAL_ARREST,
        required_categories=["authority", "threat", "money_demand"],
        optional_categories=["urgency", "video_call"],
        min_required=2,  # Lowered from 3
        confidence_boost=0.45
    ),
    
    # Digital Arrest Pattern - Video Call Variant
    SemanticPattern(
        name="digital_arrest_video",
        category=ScamCategory.DIGITAL_ARREST,
        required_categories=["authority", "video_call"],
        optional_categories=["money_demand", "threat"],
        min_required=2,
        confidence_boost=0.4
    ),
    
    # UPI Click Fraud Pattern
    SemanticPattern(
        name="upi_collect_scam",
        category=ScamCategory.UPI_FRAUD,
        required_categories=["upi_action", "pin_request"],
        optional_categories=["receive_money", "urgency"],
        min_required=1,  # Lowered - even one is suspicious
        confidence_boost=0.4
    ),
    
    # UPI Refund/Cashback Scam Pattern
    SemanticPattern(
        name="upi_refund_scam",
        category=ScamCategory.UPI_FRAUD,
        required_categories=["receive_money", "upi_action"],
        optional_categories=["urgency", "pin_request"],
        min_required=2,
        confidence_boost=0.4
    ),
    
    # Voice Clone Emergency Pattern
    SemanticPattern(
        name="voice_clone_emergency",
        category=ScamCategory.AI_VOICE_CLONE,
        required_categories=["emergency", "family", "money_request", "secrecy"],
        optional_categories=["hospital", "accident"],
        min_required=3,
        confidence_boost=0.4
    ),
    
    # Task Scam Pattern
    SemanticPattern(
        name="task_job_scam",
        category=ScamCategory.TASK_JOB_SCAM,
        required_categories=["job_offer", "easy_money", "fee_required"],
        optional_categories=["telegram", "whatsapp"],
        min_required=2,
        confidence_boost=0.35
    ),
    
    # Task Scam Pattern - Telegram Variant
    SemanticPattern(
        name="task_telegram_scam",
        category=ScamCategory.TASK_JOB_SCAM,
        required_categories=["job_offer", "telegram", "fee_required"],
        optional_categories=["easy_money"],
        min_required=2,
        confidence_boost=0.35
    ),
    
    # Investment Fraud Pattern
    SemanticPattern(
        name="investment_fraud",
        category=ScamCategory.INVESTMENT_CRYPTO,
        required_categories=["investment", "guaranteed_returns"],
        optional_categories=["celebrity", "crypto", "urgency"],
        min_required=2,
        confidence_boost=0.35
    ),
    
    # Lottery/Prize Scam Pattern
    SemanticPattern(
        name="lottery_scam",
        category=ScamCategory.LOTTERY_REWARD,
        required_categories=["lottery", "fee_required"],
        optional_categories=["urgency"],
        min_required=2,
        confidence_boost=0.4
    ),
    
    # Courier/Parcel Scam Pattern
    SemanticPattern(
        name="courier_parcel_scam",
        category=ScamCategory.COURIER_PARCEL,
        required_categories=["courier", "threat"],
        optional_categories=["authority", "urgency"],
        min_required=2,
        confidence_boost=0.4
    ),
    
    # Bank Phishing Pattern
    SemanticPattern(
        name="bank_phishing_scam",
        category=ScamCategory.IMPERSONATION,
        required_categories=["bank", "urgency"],
        optional_categories=["click_action", "credential_request"],
        min_required=2,
        confidence_boost=0.4
    ),
    
    # Tech Support Scam Pattern
    SemanticPattern(
        name="tech_support_scam",
        category=ScamCategory.PHISHING,
        required_categories=["tech_support", "urgency"],
        optional_categories=["fee_required", "remote_access"],
        min_required=2,
        confidence_boost=0.4
    ),
]

# Category indicators for semantic matching
SEMANTIC_INDICATORS = {
    "authority": ["police", "cbi", "ed", "court", "rbi", "officer", "government", "ministry", "judge", "enforcement", "customs", "ncb", "narcotics"],
    "threat": ["arrest", "jail", "fir", "case", "warrant", "summons", "freeze", "frozen", "block", "legal action", "criminal", "suspended", "seized"],
    "money_demand": ["transfer", "send", "pay", "deposit", "amount", "rupees", "rs", "₹", "secure", "funds"],
    "urgency": ["immediately", "urgent", "now", "asap", "24 hours", "48 hours", "today", "hurry", "limited time", "within 2 hours"],
    "video_call": ["video call", "video verification", "stay on video", "don't disconnect", "do not disconnect", "verification required"],
    "upi_action": ["upi", "scan", "qr", "qr code", "collect", "request", "paytm", "phonepe", "gpay", "pin"],
    "pin_request": ["enter pin", "upi pin", "otp", "share otp", "6 digit", "your pin", "cvv", "expiry"],
    "receive_money": ["receive", "credit", "refund", "cashback", "receive money", "pending", "claim", "accept"],
    "emergency": ["emergency", "accident", "hospital", "urgent", "help needed", "critical"],
    "family": ["papa", "mummy", "dad", "mom", "son", "daughter", "brother", "sister", "uncle", "family"],
    "money_request": ["send money", "transfer", "need money", "help with money", "lend"],
    "secrecy": ["don't tell", "keep secret", "between us", "don't inform", "quietly"],
    "hospital": ["hospital", "admitted", "surgery", "treatment", "medical"],
    "accident": ["accident", "injured", "hurt", "crashed", "hit"],
    "job_offer": ["job", "work from home", "vacancy", "hiring", "recruitment", "offer", "task", "tasks", "rating"],
    "easy_money": ["earn", "daily income", "guaranteed", "easy money", "per month", "50000", "start earning"],
    "fee_required": ["registration fee", "deposit", "pay first", "joining fee", "activation", "fee to start", "processing fee"],
    "telegram": ["telegram", "channel", "group", "join telegram", "our channel", "on telegram"],
    "whatsapp": ["whatsapp", "wa.me", "message on whatsapp"],
    "investment": ["invest", "investment", "trading", "returns", "profit", "portfolio"],
    "guaranteed_returns": ["guaranteed", "100%", "fixed return", "assured", "no risk", "double"],
    "celebrity": ["elon musk", "ambani", "tata", "celebrity", "verified", "famous"],
    "crypto": ["bitcoin", "btc", "crypto", "blockchain", "nft", "ethereum"],
    "lottery": ["congratulations", "won", "winner", "prize", "lucky draw", "lottery", "lakh", "claim"],
    # New indicators for expanded scam types
    "courier": ["fedex", "dhl", "india post", "speed post", "parcel", "package", "delivery", "customs", "airport", "seized"],
    "bank": ["sbi", "hdfc", "icici", "axis", "pnb", "kotak", "bank", "account", "blocked", "kyc"],
    "click_action": ["click", "tap", "verify", "link", "update", "confirm"],
    "credential_request": ["otp", "pin", "cvv", "password", "card number", "expiry", "aadhaar"],
    "tech_support": ["microsoft", "windows", "computer", "virus", "hacked", "compromised", "support", "technician"],
    "remote_access": ["anydesk", "teamviewer", "remote", "connect", "access"],
}


# ============================================
# OPTION C: SCAM TEMPLATE DATABASE
# ============================================

@dataclass
class ScamTemplate:
    """Known scam message template."""
    id: str
    category: ScamCategory
    template: str  # Template with {placeholders}
    variables: Dict[str, List[str]]
    confidence: float  # How confident we are if this matches
    description: str


SCAM_TEMPLATES = [
    # Digital Arrest Templates
    ScamTemplate(
        id="DA001",
        category=ScamCategory.DIGITAL_ARREST,
        template="This is {authority} calling. Your {account_type} is linked to {crime}. You need to transfer {amount} to {destination} immediately or face {consequence}.",
        variables={
            "authority": ["CBI", "Cyber Cell", "ED Officer", "Police", "NCB"],
            "account_type": ["bank account", "Aadhaar", "PAN card", "mobile number"],
            "crime": ["money laundering", "drug trafficking", "terror funding", "hawala"],
            "amount": ["₹50000", "₹1 lakh", "₹25000", "Rs.50000"],
            "destination": ["RBI safe account", "verification account", "safe custody"],
            "consequence": ["arrest", "jail", "FIR", "court case", "passport seizure"]
        },
        confidence=0.95,
        description="Digital arrest impersonation demanding money transfer"
    ),
    
    ScamTemplate(
        id="DA002",
        category=ScamCategory.DIGITAL_ARREST,
        template="Your {id_type} has been misused in {crime}. Stay on this video call. Do not disconnect. Transfer amount to government safe account to avoid {consequence}.",
        variables={
            "id_type": ["Aadhaar", "PAN", "passport", "bank account"],
            "crime": ["illegal transactions", "money laundering", "drug case"],
            "consequence": ["immediate arrest", "7 years jail", "case filing"]
        },
        confidence=0.95,
        description="Video call digital arrest scam"
    ),
    
    # UPI Fraud Templates
    ScamTemplate(
        id="UPI001",
        category=ScamCategory.UPI_FRAUD,
        template="Your refund of {amount} is pending. Scan this QR code or enter your UPI PIN to receive the amount in your account.",
        variables={
            "amount": ["₹1500", "₹2999", "₹5000", "Rs.999"]
        },
        confidence=0.9,
        description="Fake refund QR scam"
    ),
    
    ScamTemplate(
        id="UPI002",
        category=ScamCategory.UPI_FRAUD,
        template="You have received a collect request of {amount}. Enter your UPI PIN to RECEIVE the money.",
        variables={
            "amount": ["₹5000", "₹10000", "₹15000"]
        },
        confidence=0.95,
        description="Reverse collect request scam"
    ),
    
    # Task/Job Scam Templates
    ScamTemplate(
        id="TASK001",
        category=ScamCategory.TASK_JOB_SCAM,
        template="Earn {amount} daily by doing simple {task_type}. No experience needed. Pay {fee} registration fee to start. Contact on {channel}.",
        variables={
            "amount": ["₹5000", "₹10000", "50000/month"],
            "task_type": ["rating tasks", "like and subscribe", "review posting", "data entry"],
            "fee": ["₹500", "₹1000", "₹2000"],
            "channel": ["Telegram", "WhatsApp", "this number"]
        },
        confidence=0.85,
        description="Task-based earning scam"
    ),
    
    # Investment Templates
    ScamTemplate(
        id="INV001",
        category=ScamCategory.INVESTMENT_CRYPTO,
        template="Double your {crypto} investment! Send {amount} to {wallet} and receive {return_amount} within 24 hours. Verified by {celebrity}.",
        variables={
            "crypto": ["Bitcoin", "Ethereum", "BTC", "ETH"],
            "amount": ["0.1 BTC", "1 ETH", "$500"],
            "wallet": ["wallet address", "this account"],
            "return_amount": ["0.2 BTC", "2 ETH", "$1000"],
            "celebrity": ["Elon Musk", "official team", "verified traders"]
        },
        confidence=0.9,
        description="Crypto doubling scam"
    ),
    
    # Lottery Templates
    ScamTemplate(
        id="LOT001",
        category=ScamCategory.LOTTERY_REWARD,
        template="Congratulations! Your {phone_brand} number won {prize} in {lottery}. Pay {fee} as processing charges to claim your prize.",
        variables={
            "phone_brand": ["Jio", "Airtel", "WhatsApp", "Amazon"],
            "prize": ["₹25 lakh", "iPhone 15", "₹50 lakh", "car"],
            "lottery": ["lucky draw", "mega prize", "annual lottery"],
            "fee": ["₹5000", "₹10000", "processing fee of ₹15000"]
        },
        confidence=0.9,
        description="Fake lottery/prize scam"
    ),
    
    # Voice Clone Templates
    ScamTemplate(
        id="VOICE001",
        category=ScamCategory.AI_VOICE_CLONE,
        template="Hello {relation}, {emergency_message}. I need {amount} urgently. Send to {destination}. Don't tell {other_family}. Battery dying.",
        variables={
            "relation": ["Papa", "Mummy", "Uncle", "Aunty"],
            "emergency_message": ["I had an accident", "I'm in hospital", "Police arrested me", "Phone stolen"],
            "amount": ["₹50000", "₹1 lakh", "₹25000"],
            "destination": ["this UPI", "this account", "friend's account"],
            "other_family": ["anyone", "Mummy", "Papa", "others"]
        },
        confidence=0.85,
        description="AI voice clone emergency scam"
    ),
    
    # Banking Phishing Templates
    ScamTemplate(
        id="BANK001",
        category=ScamCategory.IMPERSONATION,
        template="Dear Customer, Your {bank} account will be blocked in 24 hours due to {reason}. Click {link} to update your KYC immediately.",
        variables={
            "bank": ["SBI", "HDFC", "ICICI", "Axis", "Kotak"],
            "reason": ["incomplete KYC", "suspicious activity", "PAN not linked", "Aadhaar verification pending"],
            "link": ["here", "below", "this link"]
        },
        confidence=0.85,
        description="Bank KYC phishing scam"
    ),
]


# ============================================
# DETECTION ENGINE
# ============================================

class ScamDetectionEngine2025:
    """
    Comprehensive 2025 scam detection using:
    - Option A: Keyword matching
    - Option B: Semantic pattern matching
    - Option C: Template matching
    """
    
    def __init__(self):
        self.keywords = SCAM_KEYWORDS_2025
        self.semantic_patterns = SEMANTIC_PATTERNS
        self.templates = SCAM_TEMPLATES
        self.indicators = SEMANTIC_INDICATORS
    
    # Whitelist patterns for legitimate messages (reduce false positives)
    WHITELIST_PATTERNS = [
        r'\byour\s+order\s+(has\s+been\s+)?(shipped|delivered|confirmed)\b',
        r'\bthank\s+you\s+for\s+(shopping|ordering)\b',
        r'\barriv(e|ing|ed)\s+(tomorrow|today|soon)\b',
        r'\b(order|package|delivery)\s+(tracking|status|update)\b',
        r'\bappointment\s+(reminder|confirmed|scheduled)\b',
        r'\baccount\s+(credited|debited)\s+with\b',
        r'\bavailable\s+balance\s+is\b',
    ]
    
    def analyze(self, message: str) -> Dict[str, Any]:
        """
        Perform comprehensive scam analysis.
        
        Returns:
            Dict with detection results from all three methods
        """
        message_lower = message.lower()
        
        # WHITELIST CHECK: Reduce confidence for legitimate messages
        whitelist_reduction = 0.0
        for pattern in self.WHITELIST_PATTERNS:
            if re.search(pattern, message_lower, re.IGNORECASE):
                whitelist_reduction += 0.25  # Each whitelist match reduces confidence
        whitelist_reduction = min(whitelist_reduction, 0.6)  # Cap at 0.6 reduction
        
        # Option A: Keyword Analysis
        keyword_results = self._keyword_analysis(message_lower)
        
        # Option B: Semantic Pattern Analysis
        semantic_results = self._semantic_analysis(message_lower)
        
        # Option C: Template Matching
        template_results = self._template_analysis(message_lower)
        
        # Combine results
        combined_confidence = self._calculate_combined_confidence(
            keyword_results, semantic_results, template_results
        )
        
        # Apply whitelist reduction
        if whitelist_reduction > 0:
            combined_confidence = max(0, combined_confidence - whitelist_reduction)
        
        # Determine primary scam category
        primary_category = self._determine_primary_category(
            keyword_results, semantic_results, template_results
        )
        
        # If whitelist matched and confidence is low, mark as not scam
        is_scam = combined_confidence >= 0.4 and whitelist_reduction < 0.3
        
        return {
            "is_scam": is_scam,
            "confidence": combined_confidence,
            "category": primary_category if is_scam else None,
            "keyword_matches": keyword_results,
            "semantic_matches": semantic_results,
            "template_matches": template_results,
            "threat_level": self._calculate_threat_level(combined_confidence, primary_category) if is_scam else 1,
            "whitelist_reduction": whitelist_reduction
        }
    
    def _keyword_analysis(self, message: str) -> Dict[str, Any]:
        """Option A: Keyword matching analysis."""
        matches = {}
        total_matches = 0
        max_category_score = 0
        best_category = None
        
        for category, keywords in self.keywords.items():
            category_matches = []
            for keyword in keywords:
                if keyword in message:
                    category_matches.append(keyword)
            
            if category_matches:
                matches[category.value] = category_matches
                total_matches += len(category_matches)
                
                # Track best matching category
                if len(category_matches) > max_category_score:
                    max_category_score = len(category_matches)
                    best_category = category.value
        
        # Calculate confidence based on matches - IMPROVED scoring
        # Higher multiplier to catch more scams
        confidence = min(total_matches * 0.12, 0.7)  # Increased from 0.08 to 0.12
        
        return {
            "matches": matches,
            "total_matches": total_matches,
            "confidence": confidence,
            "best_category": best_category
        }
    
    def _semantic_analysis(self, message: str) -> Dict[str, Any]:
        """Option B: Semantic pattern matching."""
        matched_patterns = []
        total_confidence = 0.0
        
        # Check which indicator categories are present
        present_categories = {}
        for category, indicators in self.indicators.items():
            for indicator in indicators:
                if indicator in message:
                    present_categories[category] = present_categories.get(category, [])
                    present_categories[category].append(indicator)
        
        # Check semantic patterns
        for pattern in self.semantic_patterns:
            required_present = 0
            optional_present = 0
            
            for req in pattern.required_categories:
                if req in present_categories:
                    required_present += 1
            
            for opt in pattern.optional_categories:
                if opt in present_categories:
                    optional_present += 1
            
            # Check if pattern matches
            if required_present >= pattern.min_required:
                matched_patterns.append({
                    "pattern": pattern.name,
                    "category": pattern.category.value,
                    "required_matched": required_present,
                    "optional_matched": optional_present,
                    "confidence_boost": pattern.confidence_boost
                })
                total_confidence += pattern.confidence_boost
        
        return {
            "present_indicators": present_categories,
            "matched_patterns": matched_patterns,
            "confidence": min(total_confidence, 0.8)  # Cap at 0.8
        }
    
    def _template_analysis(self, message: str) -> Dict[str, Any]:
        """Option C: Template matching."""
        matched_templates = []
        best_match_confidence = 0.0
        
        for template in self.templates:
            # Simple similarity check - count variable matches
            match_score = 0
            total_vars = 0
            matched_vars = []
            
            for var_name, var_options in template.variables.items():
                total_vars += 1
                for option in var_options:
                    if option.lower() in message:
                        match_score += 1
                        matched_vars.append(f"{var_name}={option}")
                        break
            
            # Calculate match percentage
            if total_vars > 0:
                match_percentage = match_score / total_vars
                
                # If more than 40% of variables match, consider it a template match
                if match_percentage >= 0.4:
                    effective_confidence = template.confidence * match_percentage
                    matched_templates.append({
                        "template_id": template.id,
                        "category": template.category.value,
                        "description": template.description,
                        "match_percentage": match_percentage,
                        "matched_variables": matched_vars,
                        "confidence": effective_confidence
                    })
                    
                    if effective_confidence > best_match_confidence:
                        best_match_confidence = effective_confidence
        
        return {
            "matched_templates": matched_templates,
            "best_confidence": best_match_confidence,
            "confidence": best_match_confidence
        }
    
    def _calculate_combined_confidence(
        self, 
        keyword_results: Dict,
        semantic_results: Dict,
        template_results: Dict
    ) -> float:
        """Calculate combined confidence from all three methods."""
        # Weights for each method
        weights = {
            "keyword": 0.25,
            "semantic": 0.35,
            "template": 0.40
        }
        
        combined = (
            keyword_results["confidence"] * weights["keyword"] +
            semantic_results["confidence"] * weights["semantic"] +
            template_results["confidence"] * weights["template"]
        )
        
        # Bonus for multiple methods agreeing - LOWER thresholds
        methods_positive = 0
        if keyword_results["confidence"] > 0.1:  # Lowered from 0.2
            methods_positive += 1
        if semantic_results["confidence"] > 0.1:  # Lowered from 0.2
            methods_positive += 1
        if template_results["confidence"] > 0.1:  # Lowered from 0.2
            methods_positive += 1
        
        if methods_positive >= 3:
            combined = min(combined * 1.4, 1.0)  # 40% boost (was 30%)
        elif methods_positive >= 2:
            combined = min(combined * 1.25, 1.0)  # 25% boost (was 15%)
        elif methods_positive >= 1 and (keyword_results["total_matches"] >= 3 or template_results["matched_templates"]):
            combined = min(combined * 1.15, 1.0)  # 15% boost for strong single method
        
        return round(min(combined, 1.0), 3)
    
    def _determine_primary_category(
        self,
        keyword_results: Dict,
        semantic_results: Dict,
        template_results: Dict
    ) -> Optional[str]:
        """Determine the primary scam category."""
        # Priority: Template > Semantic > Keyword
        if template_results["matched_templates"]:
            return template_results["matched_templates"][0]["category"]
        
        if semantic_results["matched_patterns"]:
            return semantic_results["matched_patterns"][0]["category"]
        
        if keyword_results["best_category"]:
            return keyword_results["best_category"]
        
        return None
    
    def _calculate_threat_level(self, confidence: float, category: Optional[str]) -> int:
        """Calculate threat level (1-10)."""
        base_level = int(confidence * 10)
        
        # High-danger categories get a boost
        high_danger = ["digital_arrest", "ai_voice_clone", "investment_crypto"]
        if category in high_danger:
            base_level = min(base_level + 2, 10)
        
        return max(1, min(base_level, 10))


# Global instance
scam_engine_2025 = ScamDetectionEngine2025()
