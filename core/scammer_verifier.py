"""
Scammer Verification System.

Verifies if extracted UPI IDs, phone numbers, bank accounts are actually from scammers.

Features:
1. UPI ID pattern analysis (suspicious keywords, handle types)
2. Phone number verification (VOIP detection, known prefixes)
3. Bank account validation
4. Cross-reference with reported scammer database
5. Real-time risk scoring

Sources:
- Local reported scammer database (learned from conversations)
- Pattern-based detection (suspicious keywords)
- UPI handle type analysis
- Phone number prefix analysis
"""
import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of scammer verification."""
    identifier: str
    identifier_type: str  # "upi", "phone", "bank_account", "url"
    is_suspicious: bool
    risk_score: float  # 0.0 - 1.0
    risk_level: str  # "low", "medium", "high", "critical"
    reasons: List[str] = field(default_factory=list)
    reported_count: int = 0
    first_reported: Optional[str] = None
    last_reported: Optional[str] = None
    associated_scam_types: List[str] = field(default_factory=list)


# =============================================================================
# KNOWN SCAMMER PATTERNS (Research-based)
# =============================================================================

# Suspicious UPI handle keywords (scammers often use these)
SUSPICIOUS_UPI_KEYWORDS = [
    # Customer support impersonation
    "support", "customer", "care", "helpdesk", "service", "help",
    "complaint", "grievance", "feedback",
    # Refund/cashback scams
    "refund", "cashback", "reward", "bonus", "prize", "winner",
    "lottery", "lucky",
    # Official impersonation
    "official", "govt", "government", "rbi", "sbi", "hdfc", "icici",
    "axis", "pnb", "bank", "ministry", "cyber", "police",
    # Payment/verification scams
    "verify", "kyc", "update", "link", "secure", "payment",
    # Generic suspicious
    "admin", "manager", "officer", "agent", "executive",
]

# Suspicious UPI handle patterns (regex)
SUSPICIOUS_UPI_PATTERNS = [
    r"^[0-9]+@",  # Starts with numbers (often auto-generated scam accounts)
    r"support.*@",  # Support impersonation
    r".*refund.*@",  # Refund scam
    r".*customer.*@",  # Customer care impersonation
    r".*helpline.*@",  # Helpline impersonation
    r".*official.*@",  # Official impersonation
    r"^[a-z]{1,3}[0-9]{5,}@",  # Short prefix + long number (bot accounts)
]

# Legitimate UPI suffixes (PSP handles)
LEGITIMATE_UPI_SUFFIXES = [
    "@ybl",      # PhonePe (Yes Bank)
    "@paytm",    # Paytm
    "@okaxis",   # Google Pay (Axis)
    "@oksbi",    # Google Pay (SBI)
    "@okhdfcbank",  # Google Pay (HDFC)
    "@okicici",  # Google Pay (ICICI)
    "@apl",      # Amazon Pay
    "@ibl",      # PhonePe (ICICI)
    "@axl",      # PhonePe (Axis)
    "@upi",      # Generic UPI
    "@fbl",      # Freecharge
    "@ikwik",    # MobiKwik
]

# Suspicious phone prefixes
SUSPICIOUS_PHONE_PREFIXES = [
    # VOIP/Virtual numbers (commonly used by scammers)
    "+91 140",   # VOIP prefix
    "+91 120",   # Noida (high scam activity area)
    "+91 011",   # Delhi landline (often spoofed)
    # International (spoofed as "official" calls)
    "+1",        # US spoofed
    "+44",       # UK spoofed
    "+92",       # Pakistan
    "+86",       # China
    "+234",      # Nigeria (advance fee fraud)
    "+233",      # Ghana
]

# Valid Indian mobile prefixes
VALID_INDIAN_MOBILE_PREFIXES = [
    "6", "7", "8", "9"  # Indian mobile numbers start with these
]


class ScammerVerifier:
    """
    Verifies if identifiers belong to scammers.
    Uses pattern analysis + learned database.
    """
    
    def __init__(self, database_path: str = "scammer_database.json"):
        self.database_path = Path(database_path)
        self.database = self._load_database()
    
    def _load_database(self) -> Dict:
        """Load reported scammer database."""
        if self.database_path.exists():
            try:
                with open(self.database_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load scammer database: {e}")
        
        return {
            "upi_ids": {},
            "phone_numbers": {},
            "bank_accounts": {},
            "urls": {},
            "metadata": {
                "created": datetime.now().isoformat(),
                "total_reports": 0
            }
        }
    
    def _save_database(self):
        """Save database to disk."""
        try:
            with open(self.database_path, 'w') as f:
                json.dump(self.database, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save scammer database: {e}")
    
    # =========================================================================
    # MAIN VERIFICATION METHODS
    # =========================================================================
    
    def verify_upi(self, upi_id: str) -> VerificationResult:
        """
        Verify if a UPI ID is suspicious/belongs to scammer.
        
        Analysis includes:
        1. Keyword matching (support, refund, etc.)
        2. Pattern matching (bot-like handles)
        3. Handle suffix analysis
        4. Database lookup (previously reported)
        """
        upi_lower = upi_id.lower().strip()
        reasons = []
        risk_score = 0.0
        
        # 1. Check if in reported database
        db_entry = self.database["upi_ids"].get(self._hash_id(upi_id))
        if db_entry:
            risk_score += 0.4
            reasons.append(f"Previously reported {db_entry['report_count']} time(s)")
        
        # 2. Check for suspicious keywords
        keyword_matches = []
        for keyword in SUSPICIOUS_UPI_KEYWORDS:
            if keyword in upi_lower:
                keyword_matches.append(keyword)
        
        if keyword_matches:
            risk_score += min(len(keyword_matches) * 0.15, 0.4)
            reasons.append(f"Contains suspicious keywords: {', '.join(keyword_matches[:3])}")
        
        # 3. Check against suspicious patterns
        for pattern in SUSPICIOUS_UPI_PATTERNS:
            if re.match(pattern, upi_lower):
                risk_score += 0.2
                reasons.append(f"Matches suspicious pattern")
                break
        
        # 4. Check handle suffix
        suffix_found = False
        for suffix in LEGITIMATE_UPI_SUFFIXES:
            if upi_lower.endswith(suffix):
                suffix_found = True
                break
        
        if not suffix_found and "@" in upi_lower:
            risk_score += 0.1
            reasons.append("Unusual UPI handle suffix")
        
        # 5. Check for impersonation attempts
        official_names = ["sbi", "hdfc", "icici", "axis", "rbi", "paytm", "phonepe", "gpay"]
        for name in official_names:
            if name in upi_lower and not upi_lower.endswith(f"@{name}") and not upi_lower.endswith(f"@ok{name}"):
                risk_score += 0.25
                reasons.append(f"Possible impersonation of {name.upper()}")
                break
        
        # 6. Check for numeric-heavy handles (often scam accounts)
        handle_part = upi_lower.split("@")[0] if "@" in upi_lower else upi_lower
        digit_ratio = sum(c.isdigit() for c in handle_part) / len(handle_part) if handle_part else 0
        if digit_ratio > 0.6:
            risk_score += 0.15
            reasons.append("Handle is mostly numbers (possible bot account)")
        
        # Calculate final result
        risk_score = min(risk_score, 1.0)
        risk_level = self._get_risk_level(risk_score)
        
        return VerificationResult(
            identifier=upi_id,
            identifier_type="upi",
            is_suspicious=risk_score >= 0.3,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            reasons=reasons,
            reported_count=db_entry["report_count"] if db_entry else 0,
            first_reported=db_entry.get("first_reported") if db_entry else None,
            last_reported=db_entry.get("last_reported") if db_entry else None,
            associated_scam_types=db_entry.get("scam_types", []) if db_entry else []
        )
    
    def verify_phone(self, phone: str) -> VerificationResult:
        """
        Verify if a phone number is suspicious/belongs to scammer.
        
        Analysis includes:
        1. VOIP/virtual number detection
        2. International number check
        3. Known scam prefix detection
        4. Database lookup
        """
        # Normalize phone number
        phone_clean = re.sub(r'[\s\-\(\)]', '', phone)
        reasons = []
        risk_score = 0.0
        
        # 1. Check if in reported database
        db_entry = self.database["phone_numbers"].get(self._hash_id(phone_clean))
        if db_entry:
            risk_score += 0.5
            reasons.append(f"Previously reported {db_entry['report_count']} time(s)")
        
        # 2. Check for suspicious prefixes
        for prefix in SUSPICIOUS_PHONE_PREFIXES:
            prefix_clean = prefix.replace(" ", "")
            if phone_clean.startswith(prefix_clean):
                risk_score += 0.35
                reasons.append(f"Suspicious prefix: {prefix} (often used by scammers)")
                break
        
        # 3. Check if valid Indian mobile
        if phone_clean.startswith("+91") or phone_clean.startswith("91"):
            # Extract the main number
            main_num = phone_clean.replace("+91", "").replace("91", "", 1).lstrip("0")
            
            if len(main_num) == 10:
                first_digit = main_num[0]
                if first_digit not in VALID_INDIAN_MOBILE_PREFIXES:
                    risk_score += 0.2
                    reasons.append("Not a valid Indian mobile number format")
            else:
                risk_score += 0.15
                reasons.append("Invalid phone number length")
        
        # 4. Check for international numbers claiming to be Indian officials
        if not phone_clean.startswith("+91") and not phone_clean.startswith("91"):
            if phone_clean.startswith("+"):
                risk_score += 0.25
                reasons.append("International number (Indian officials don't call from abroad)")
        
        # 5. Check for toll-free impersonation
        toll_free_patterns = ["1800", "1860"]
        for pattern in toll_free_patterns:
            if pattern in phone_clean:
                # Real toll-free numbers are inbound only
                risk_score += 0.1
                reasons.append("Contains toll-free pattern (may be impersonation)")
        
        risk_score = min(risk_score, 1.0)
        risk_level = self._get_risk_level(risk_score)
        
        return VerificationResult(
            identifier=phone,
            identifier_type="phone",
            is_suspicious=risk_score >= 0.3,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            reasons=reasons,
            reported_count=db_entry["report_count"] if db_entry else 0,
            first_reported=db_entry.get("first_reported") if db_entry else None,
            last_reported=db_entry.get("last_reported") if db_entry else None,
            associated_scam_types=db_entry.get("scam_types", []) if db_entry else []
        )
    
    def verify_bank_account(self, account_number: str, ifsc: str = None) -> VerificationResult:
        """
        Verify if a bank account is suspicious.
        
        Note: Limited verification possible without API access.
        Uses pattern analysis and database lookup.
        """
        account_clean = re.sub(r'[\s\-]', '', account_number)
        reasons = []
        risk_score = 0.0
        
        # 1. Check if in reported database
        db_entry = self.database["bank_accounts"].get(self._hash_id(account_clean))
        if db_entry:
            risk_score += 0.6
            reasons.append(f"Previously reported {db_entry['report_count']} time(s) in scams")
        
        # 2. Basic validation
        if not account_clean.isdigit():
            risk_score += 0.2
            reasons.append("Invalid account number format")
        
        # 3. Length check (Indian accounts are typically 9-18 digits)
        if len(account_clean) < 9 or len(account_clean) > 18:
            risk_score += 0.15
            reasons.append("Unusual account number length")
        
        # 4. IFSC validation if provided
        if ifsc:
            ifsc_clean = ifsc.upper().strip()
            # IFSC format: 4 letters + 0 + 6 alphanumeric
            if not re.match(r'^[A-Z]{4}0[A-Z0-9]{6}$', ifsc_clean):
                risk_score += 0.2
                reasons.append("Invalid IFSC code format")
        
        # 5. Check for suspicious patterns (repeated digits often fake)
        if len(set(account_clean)) <= 3:
            risk_score += 0.25
            reasons.append("Account number has suspicious pattern (few unique digits)")
        
        risk_score = min(risk_score, 1.0)
        risk_level = self._get_risk_level(risk_score)
        
        return VerificationResult(
            identifier=account_number,
            identifier_type="bank_account",
            is_suspicious=risk_score >= 0.3,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            reasons=reasons,
            reported_count=db_entry["report_count"] if db_entry else 0,
            first_reported=db_entry.get("first_reported") if db_entry else None,
            last_reported=db_entry.get("last_reported") if db_entry else None,
            associated_scam_types=db_entry.get("scam_types", []) if db_entry else []
        )
    
    def verify_url(self, url: str) -> VerificationResult:
        """
        Verify if a URL is suspicious/phishing.
        
        Analysis includes:
        1. URL shortener detection
        2. Suspicious TLD check
        3. Brand impersonation detection
        4. Typosquatting detection
        """
        url_lower = url.lower().strip()
        reasons = []
        risk_score = 0.0
        
        # 1. Check if in reported database
        db_entry = self.database["urls"].get(self._hash_id(url_lower))
        if db_entry:
            risk_score += 0.5
            reasons.append(f"Previously reported as phishing")
        
        # 2. URL shorteners (hide real destination)
        shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly"]
        for shortener in shorteners:
            if shortener in url_lower:
                risk_score += 0.3
                reasons.append(f"Uses URL shortener ({shortener}) - hides real destination")
                break
        
        # 3. Suspicious TLDs
        suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".click"]
        for tld in suspicious_tlds:
            if url_lower.endswith(tld):
                risk_score += 0.25
                reasons.append(f"Suspicious domain extension ({tld})")
                break
        
        # 4. Brand impersonation
        brands = {
            "sbi": ["sbi", "statebank"],
            "hdfc": ["hdfc"],
            "icici": ["icici"],
            "axis": ["axis"],
            "paytm": ["paytm"],
            "phonepe": ["phonepe"],
            "gpay": ["googlepay", "gpay"],
            "amazon": ["amazon"],
            "flipkart": ["flipkart"],
        }
        
        for brand, keywords in brands.items():
            for kw in keywords:
                if kw in url_lower:
                    # Check if it's the real domain
                    real_domains = [f"{brand}.com", f"{brand}.in", f"{brand}.co.in"]
                    is_real = any(rd in url_lower for rd in real_domains)
                    if not is_real:
                        risk_score += 0.35
                        reasons.append(f"Possible {brand.upper()} impersonation")
                        break
        
        # 5. Login/verify/update in URL path (phishing indicators)
        phishing_paths = ["login", "verify", "update", "secure", "account", "confirm", "signin"]
        for path in phishing_paths:
            if path in url_lower:
                risk_score += 0.1
                reasons.append("Contains phishing-related path keywords")
                break
        
        # 6. IP address instead of domain
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            risk_score += 0.4
            reasons.append("Uses IP address instead of domain name")
        
        # 7. Excessive subdomains (often used to look legitimate)
        if url_lower.count('.') > 3:
            risk_score += 0.15
            reasons.append("Excessive subdomains (obfuscation technique)")
        
        risk_score = min(risk_score, 1.0)
        risk_level = self._get_risk_level(risk_score)
        
        return VerificationResult(
            identifier=url,
            identifier_type="url",
            is_suspicious=risk_score >= 0.3,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            reasons=reasons,
            reported_count=db_entry["report_count"] if db_entry else 0,
            first_reported=db_entry.get("first_reported") if db_entry else None,
            last_reported=db_entry.get("last_reported") if db_entry else None,
            associated_scam_types=db_entry.get("scam_types", []) if db_entry else []
        )
    
    # =========================================================================
    # BATCH VERIFICATION
    # =========================================================================
    
    def verify_all(self, intelligence: Dict) -> Dict[str, List[VerificationResult]]:
        """
        Verify all extracted intelligence at once.
        
        Args:
            intelligence: Dict with upi_ids, phone_numbers, bank_accounts, urls
            
        Returns:
            Dict with verification results for each type
        """
        results = {
            "upi_ids": [],
            "phone_numbers": [],
            "bank_accounts": [],
            "urls": [],
            "summary": {
                "total_checked": 0,
                "total_suspicious": 0,
                "highest_risk": "low",
                "critical_alerts": []
            }
        }
        
        highest_risk_score = 0.0
        
        # Verify UPI IDs
        for upi in intelligence.get("upi_ids", []):
            result = self.verify_upi(upi)
            results["upi_ids"].append(result)
            results["summary"]["total_checked"] += 1
            if result.is_suspicious:
                results["summary"]["total_suspicious"] += 1
            if result.risk_score > highest_risk_score:
                highest_risk_score = result.risk_score
            if result.risk_level in ["high", "critical"]:
                results["summary"]["critical_alerts"].append(
                    f"UPI {upi}: {result.risk_level.upper()} risk - {result.reasons[0] if result.reasons else 'suspicious'}"
                )
        
        # Verify phone numbers
        for phone in intelligence.get("phone_numbers", []):
            result = self.verify_phone(phone)
            results["phone_numbers"].append(result)
            results["summary"]["total_checked"] += 1
            if result.is_suspicious:
                results["summary"]["total_suspicious"] += 1
            if result.risk_score > highest_risk_score:
                highest_risk_score = result.risk_score
            if result.risk_level in ["high", "critical"]:
                results["summary"]["critical_alerts"].append(
                    f"Phone {phone}: {result.risk_level.upper()} risk - {result.reasons[0] if result.reasons else 'suspicious'}"
                )
        
        # Verify bank accounts
        for account in intelligence.get("bank_accounts", []):
            result = self.verify_bank_account(account)
            results["bank_accounts"].append(result)
            results["summary"]["total_checked"] += 1
            if result.is_suspicious:
                results["summary"]["total_suspicious"] += 1
            if result.risk_score > highest_risk_score:
                highest_risk_score = result.risk_score
        
        # Verify URLs
        for url in intelligence.get("urls", []):
            result = self.verify_url(url)
            results["urls"].append(result)
            results["summary"]["total_checked"] += 1
            if result.is_suspicious:
                results["summary"]["total_suspicious"] += 1
            if result.risk_score > highest_risk_score:
                highest_risk_score = result.risk_score
            if result.risk_level in ["high", "critical"]:
                results["summary"]["critical_alerts"].append(
                    f"URL: {result.risk_level.upper()} risk phishing link"
                )
        
        results["summary"]["highest_risk"] = self._get_risk_level(highest_risk_score)
        
        return results
    
    # =========================================================================
    # LEARNING / REPORTING
    # =========================================================================
    
    def report_scammer(
        self,
        identifier: str,
        identifier_type: str,
        scam_type: str,
        session_id: str = None
    ):
        """
        Report an identifier as belonging to a scammer.
        This helps build the local database for future detection.
        """
        now = datetime.now().isoformat()
        id_hash = self._hash_id(identifier)
        
        # Map identifier type to database key
        db_key_map = {
            "upi": "upi_ids",
            "phone": "phone_numbers",
            "bank_account": "bank_accounts",
            "url": "urls"
        }
        db_key = db_key_map.get(identifier_type, f"{identifier_type}s")
        
        if db_key not in self.database:
            self.database[db_key] = {}
        
        if id_hash not in self.database[db_key]:
            self.database[db_key][id_hash] = {
                "identifier_masked": self._mask_identifier(identifier, identifier_type),
                "report_count": 0,
                "first_reported": now,
                "last_reported": now,
                "scam_types": [],
                "session_ids": []
            }
        
        entry = self.database[db_key][id_hash]
        entry["report_count"] += 1
        entry["last_reported"] = now
        
        if scam_type and scam_type not in entry["scam_types"]:
            entry["scam_types"].append(scam_type)
        
        if session_id and session_id not in entry["session_ids"]:
            entry["session_ids"].append(session_id)
            # Keep only last 10 sessions
            entry["session_ids"] = entry["session_ids"][-10:]
        
        self.database["metadata"]["total_reports"] += 1
        self._save_database()
        
        logger.info(f"Reported scammer {identifier_type}: {self._mask_identifier(identifier, identifier_type)}")
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _hash_id(self, identifier: str) -> str:
        """Create hash of identifier for storage (privacy)."""
        return hashlib.sha256(identifier.lower().encode()).hexdigest()[:16]
    
    def _mask_identifier(self, identifier: str, id_type: str) -> str:
        """Mask identifier for logging (privacy)."""
        if id_type == "upi":
            parts = identifier.split("@")
            if len(parts) == 2:
                handle = parts[0]
                suffix = parts[1]
                masked = handle[:2] + "***" + handle[-1] if len(handle) > 3 else "***"
                return f"{masked}@{suffix}"
        elif id_type == "phone":
            clean = re.sub(r'[\s\-]', '', identifier)
            return clean[:4] + "****" + clean[-4:] if len(clean) > 8 else "****"
        elif id_type == "bank_account":
            return identifier[:4] + "****" + identifier[-4:] if len(identifier) > 8 else "****"
        elif id_type == "url":
            return identifier[:30] + "..." if len(identifier) > 30 else identifier
        return "***"
    
    def _get_risk_level(self, score: float) -> str:
        """Convert risk score to level."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.3:
            return "medium"
        return "low"
    
    def get_statistics(self) -> Dict:
        """Get database statistics."""
        return {
            "total_reports": self.database["metadata"]["total_reports"],
            "unique_upi_ids": len(self.database.get("upi_ids", {})),
            "unique_phones": len(self.database.get("phone_numbers", {})),
            "unique_accounts": len(self.database.get("bank_accounts", {})),
            "unique_urls": len(self.database.get("urls", {})),
        }


# Global instance
scammer_verifier = ScammerVerifier()
