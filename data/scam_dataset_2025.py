"""
Comprehensive Scam Message Dataset - 2025 Edition
Based on research from:
- Times of India cyber crime reports (Jan 2025-2026)
- NPCI UPI fraud awareness guidelines
- RBI banking fraud circulars
- Common scam patterns reported in India

This dataset includes real-world scam message templates used for training
and testing scam detection systems.
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class ScamType(str, Enum):
    """Scam type classification."""
    DIGITAL_ARREST = "digital_arrest"
    UPI_FRAUD = "upi_fraud"
    COURIER_PARCEL = "courier_parcel"
    AI_VOICE_CLONE = "ai_voice_clone"
    TASK_JOB = "task_job"
    INVESTMENT_CRYPTO = "investment_crypto"
    LOTTERY_REWARD = "lottery_reward"
    BANK_PHISHING = "bank_phishing"
    KYC_UPDATE = "kyc_update"
    TECH_SUPPORT = "tech_support"
    ROMANCE_SCAM = "romance_scam"
    SIM_SWAP = "sim_swap"
    TRAFFIC_CHALLAN = "traffic_challan"
    ATM_CARD = "atm_card"
    APK_MALWARE = "apk_malware"
    CSR_FUNDING = "csr_funding"
    FD_FRAUD = "fd_fraud"
    ONLINE_GAMBLING = "online_gambling"
    LEGITIMATE = "legitimate"


@dataclass
class ScamMessage:
    """A scam message sample with metadata."""
    id: str
    message: str
    scam_type: ScamType
    is_scam: bool
    severity: int  # 1-10
    source: str  # Where this pattern was observed
    keywords: List[str]
    language: str  # en, hi, hinglish


# ============================================
# DIGITAL ARREST SCAMS (₹2000+ Cr losses)
# Most dangerous scam type in India 2024-2025
# ============================================

DIGITAL_ARREST_MESSAGES = [
    ScamMessage(
        id="DA001",
        message="This is Officer Sharma from CBI Cyber Cell. Your Aadhaar number 8765-XXXX-4321 has been found linked to a money laundering case. A arrest warrant has been issued. Stay on this video call for identity verification. Transfer ₹50,000 to RBI safe custody account to clear your name.",
        scam_type=ScamType.DIGITAL_ARREST,
        is_scam=True,
        severity=10,
        source="TOI Kolkata Jan 2026 - 77yr old loses 35 lakh",
        keywords=["cbi", "aadhaar", "money laundering", "arrest warrant", "video call", "rbi safe custody"],
        language="en"
    ),
    ScamMessage(
        id="DA002",
        message="ED Enforcement Directorate has frozen your bank account due to suspicious hawala transactions detected. Video verification required immediately. Do not disconnect this call or you will be arrested. Transfer amount to government safe account to secure your funds.",
        scam_type=ScamType.DIGITAL_ARREST,
        is_scam=True,
        severity=10,
        source="TOI Kanpur Jan 2026 - Digital arrest fraud",
        keywords=["ed", "enforcement directorate", "frozen", "hawala", "video verification", "arrested"],
        language="en"
    ),
    ScamMessage(
        id="DA003",
        message="Main Mumbai Cyber Crime se Inspector Verma bol raha hoon. Aapka phone number drug trafficking case mein link mila hai. Abhi video call pe rehna, disconnect mat karna. NCB officer connect karenge. ₹1 lakh jama karo investigation ke liye.",
        scam_type=ScamType.DIGITAL_ARREST,
        is_scam=True,
        severity=10,
        source="Hindi digital arrest pattern",
        keywords=["cyber crime", "drug trafficking", "video call", "ncb", "investigation"],
        language="hinglish"
    ),
    ScamMessage(
        id="DA004",
        message="Supreme Court has issued non-bailable warrant against you. Your PAN card has been misused for ₹5 crore tax evasion. Stay on Skype/video call. Do not inform family or police will come to your house. Pay ₹2 lakh settlement amount now.",
        scam_type=ScamType.DIGITAL_ARREST,
        is_scam=True,
        severity=10,
        source="Common digital arrest variant",
        keywords=["supreme court", "warrant", "pan card", "tax evasion", "skype", "settlement"],
        language="en"
    ),
    ScamMessage(
        id="DA005",
        message="Narcotics Control Bureau calling. A parcel with drugs addressed to your name was intercepted at Mumbai Airport. You are under digital arrest. Do not leave your house. Video verification will take 6-8 hours. Cooperate or face 10 years imprisonment.",
        scam_type=ScamType.DIGITAL_ARREST,
        is_scam=True,
        severity=10,
        source="NCB impersonation variant",
        keywords=["narcotics", "ncb", "parcel", "drugs", "digital arrest", "video verification", "imprisonment"],
        language="en"
    ),
]

# ============================================
# COURIER/PARCEL SCAMS (Related to Digital Arrest)
# FedEx, DHL, India Post impersonation
# ============================================

COURIER_PARCEL_MESSAGES = [
    ScamMessage(
        id="CP001",
        message="FedEx Alert: Your parcel #FX7829301 containing illegal items has been seized by Customs. Your Aadhaar is linked. Call 1800-XXX-XXXX immediately to avoid arrest. Press 1 to speak to customs officer.",
        scam_type=ScamType.COURIER_PARCEL,
        is_scam=True,
        severity=9,
        source="FedEx impersonation scam",
        keywords=["fedex", "parcel", "illegal", "customs", "aadhaar", "arrest"],
        language="en"
    ),
    ScamMessage(
        id="CP002",
        message="DHL Delivery Failed: Package from China containing 5 fake passports addressed to you. Mumbai Police notified. Call customs helpline within 2 hours or face criminal charges. Reference: DHL98271634",
        scam_type=ScamType.COURIER_PARCEL,
        is_scam=True,
        severity=9,
        source="DHL courier scam",
        keywords=["dhl", "package", "china", "passports", "police", "criminal charges"],
        language="en"
    ),
    ScamMessage(
        id="CP003",
        message="India Post: Your speed post parcel was found containing banned drugs during scanning. FIR has been registered. Contact Central Investigation immediately: 011-XXXX-XXXX. Do not ignore or police will arrest you at home.",
        scam_type=ScamType.COURIER_PARCEL,
        is_scam=True,
        severity=9,
        source="India Post scam",
        keywords=["india post", "speed post", "drugs", "fir", "investigation", "arrest"],
        language="en"
    ),
]

# ============================================
# UPI FRAUD SCAMS (₹1087 Cr losses)
# QR code, PIN scams, collect requests
# ============================================

UPI_FRAUD_MESSAGES = [
    ScamMessage(
        id="UPI001",
        message="Your refund of ₹1,499 from Flipkart is pending. Enter your UPI PIN to receive the amount directly in your bank account. Click here to claim: bit.ly/refund-claim",
        scam_type=ScamType.UPI_FRAUD,
        is_scam=True,
        severity=8,
        source="Fake refund UPI scam",
        keywords=["refund", "upi pin", "receive", "click", "flipkart"],
        language="en"
    ),
    ScamMessage(
        id="UPI002",
        message="Scan this QR code to RECEIVE ₹5,000 cashback credited to your account. Limited time offer! Expires in 30 minutes. Scan now from Google Pay or PhonePe.",
        scam_type=ScamType.UPI_FRAUD,
        is_scam=True,
        severity=8,
        source="QR code receive scam",
        keywords=["scan", "qr code", "receive", "cashback", "limited time"],
        language="en"
    ),
    ScamMessage(
        id="UPI003",
        message="You have received a payment request of ₹1 from AMAZON-REFUND. Enter PIN to ACCEPT the payment of ₹15,000 bonus. [Accept] [Reject]",
        scam_type=ScamType.UPI_FRAUD,
        is_scam=True,
        severity=9,
        source="Collect request scam",
        keywords=["payment request", "enter pin", "accept", "amazon", "bonus"],
        language="en"
    ),
    ScamMessage(
        id="UPI004",
        message="Electricity Bill Overdue! Your connection will be disconnected in 2 hours. Pay immediately via UPI: electricityboard@ybl or call 9876543210. Bill Amount: ₹3,450",
        scam_type=ScamType.UPI_FRAUD,
        is_scam=True,
        severity=7,
        source="Fake electricity bill",
        keywords=["electricity", "bill", "disconnected", "pay", "upi"],
        language="en"
    ),
    ScamMessage(
        id="UPI005",
        message="OLX Buyer: Hi, I'm interested in your product. I've sent ₹10,000 advance via QR code. Please scan to receive. Send remaining amount after delivery. QR attached.",
        scam_type=ScamType.UPI_FRAUD,
        is_scam=True,
        severity=8,
        source="OLX buyer scam",
        keywords=["olx", "buyer", "qr code", "scan", "receive", "advance"],
        language="en"
    ),
]

# ============================================
# AI VOICE CLONE / FAMILY EMERGENCY SCAMS
# Using deepfake audio to impersonate relatives
# ============================================

AI_VOICE_CLONE_MESSAGES = [
    ScamMessage(
        id="AVC001",
        message="Papa maine accident kar diya hai. Hospital mein hoon. Mummy ko mat batana please. ₹50,000 turant bhejo is UPI pe. Battery khatam ho rahi hai. Jaldi karo please.",
        scam_type=ScamType.AI_VOICE_CLONE,
        is_scam=True,
        severity=9,
        source="Family emergency scam",
        keywords=["papa", "accident", "hospital", "mat batana", "turant", "battery"],
        language="hinglish"
    ),
    ScamMessage(
        id="AVC002",
        message="Dad, I'm stuck at airport. They arrested me for carrying extra cash. Need ₹1 lakh for bail. Please transfer to this account. Don't tell mom. Will explain later. Urgent!",
        scam_type=ScamType.AI_VOICE_CLONE,
        is_scam=True,
        severity=9,
        source="Airport arrest scam",
        keywords=["stuck", "airport", "arrested", "bail", "don't tell", "urgent"],
        language="en"
    ),
    ScamMessage(
        id="AVC003",
        message="Mummy, mere friend ka accident ho gaya. Uska operation ke liye ₹75,000 chahiye. Main hospital mein hoon. Papa ko call mat karna, wo pareshan ho jayenge. Jaldi transfer karo.",
        scam_type=ScamType.AI_VOICE_CLONE,
        is_scam=True,
        severity=9,
        source="Friend emergency scam",
        keywords=["friend", "accident", "operation", "hospital", "mat karna", "pareshan"],
        language="hinglish"
    ),
]

# ============================================
# TASK/JOB SCAMS (High Volume)
# Telegram tasks, YouTube likes, data entry
# ============================================

TASK_JOB_MESSAGES = [
    ScamMessage(
        id="TJ001",
        message="Earn ₹50,000 per month doing simple rating tasks on Telegram. No experience needed! Join our channel t.me/EasyEarnings. Pay ₹2,000 registration fee to start earning daily. 100% genuine opportunity!",
        scam_type=ScamType.TASK_JOB,
        is_scam=True,
        severity=7,
        source="TOI Jan 2026 Telegram job scam",
        keywords=["earn", "rating tasks", "telegram", "registration fee", "daily", "genuine"],
        language="en"
    ),
    ScamMessage(
        id="TJ002",
        message="AMAZON Work From Home! Data entry typing work. Guaranteed income ₹30,000/month. No interview, start immediately. Pay joining fee ₹5,000 only. WhatsApp: 9876543210",
        scam_type=ScamType.TASK_JOB,
        is_scam=True,
        severity=7,
        source="Amazon job scam",
        keywords=["amazon", "work from home", "data entry", "guaranteed", "joining fee", "whatsapp"],
        language="en"
    ),
    ScamMessage(
        id="TJ003",
        message="YouTube par video like karo aur ₹500 per like kamao! Roz 2 ghante kaam, ₹25,000 monthly pakka! Join karne ke liye ₹1,500 deposit do. Limited seats. Contact: 8765432109",
        scam_type=ScamType.TASK_JOB,
        is_scam=True,
        severity=6,
        source="YouTube like scam",
        keywords=["youtube", "like", "kamao", "deposit", "limited", "monthly"],
        language="hinglish"
    ),
    ScamMessage(
        id="TJ004",
        message="Part-time job for students! Review products on app and earn ₹1,000 daily. Initial investment ₹3,000 (refundable). 5 star rating task. Withdraw anytime. Join Telegram: @EarnDaily2025",
        scam_type=ScamType.TASK_JOB,
        is_scam=True,
        severity=6,
        source="Student job scam",
        keywords=["part-time", "students", "review", "investment", "refundable", "telegram"],
        language="en"
    ),
]

# ============================================
# INVESTMENT/CRYPTO SCAMS (₹500+ Cr)
# Stock tips, crypto doubling, trading apps
# ============================================

INVESTMENT_CRYPTO_MESSAGES = [
    ScamMessage(
        id="IC001",
        message="Double your Bitcoin in 24 hours! Send 0.1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and receive 0.2 BTC. Verified by Elon Musk. Guaranteed returns! Act now, limited offer!",
        scam_type=ScamType.INVESTMENT_CRYPTO,
        is_scam=True,
        severity=9,
        source="BTC doubler scam",
        keywords=["double", "bitcoin", "btc", "elon musk", "guaranteed", "limited"],
        language="en"
    ),
    ScamMessage(
        id="IC002",
        message="Exclusive stock tips from SEBI registered analyst! ₹10,000 investment = ₹1 lakh returns in 30 days. Join our premium group. Pay ₹15,000 subscription. 100% profit guaranteed.",
        scam_type=ScamType.INVESTMENT_CRYPTO,
        is_scam=True,
        severity=8,
        source="TOI Jan 2026 - 40L lost in investment scam",
        keywords=["stock tips", "sebi", "investment", "returns", "premium", "guaranteed"],
        language="en"
    ),
    ScamMessage(
        id="IC003",
        message="New crypto trading app with 500% monthly returns! Download now: cryptotrading.apk. Minimum investment ₹50,000. Withdraw profits anytime. Celebrity endorsed by Mukesh Ambani.",
        scam_type=ScamType.INVESTMENT_CRYPTO,
        is_scam=True,
        severity=9,
        source="Fake crypto app scam",
        keywords=["crypto", "trading", "500%", "returns", "apk", "ambani"],
        language="en"
    ),
    ScamMessage(
        id="IC004",
        message="URGENT: Forex trading opportunity! Earn $5,000 weekly with just $500 deposit. Expert signals provided. Binary options trading. VIP membership available. WhatsApp for details.",
        scam_type=ScamType.INVESTMENT_CRYPTO,
        is_scam=True,
        severity=8,
        source="Forex scam",
        keywords=["forex", "trading", "weekly", "deposit", "binary options", "vip"],
        language="en"
    ),
]

# ============================================
# LOTTERY/PRIZE SCAMS (Classic but persistent)
# Jio, Airtel, Amazon lucky draws
# ============================================

LOTTERY_REWARD_MESSAGES = [
    ScamMessage(
        id="LR001",
        message="Congratulations! Your Jio number 98765XXXXX has won ₹25 lakh in Jio Lucky Draw 2025! Pay ₹10,000 processing fee to claim your prize. Contact: 1800-XXX-XXXX. Reference: JIO2025WIN",
        scam_type=ScamType.LOTTERY_REWARD,
        is_scam=True,
        severity=6,
        source="Jio lottery scam",
        keywords=["congratulations", "jio", "won", "lakh", "lucky draw", "processing fee"],
        language="en"
    ),
    ScamMessage(
        id="LR002",
        message="Amazon Winner! You are selected for iPhone 15 Pro Max FREE! Your order #AMZ839201 won lucky draw. Pay ₹2,999 shipping + GST charges. Click: amzn.prize.win/claim",
        scam_type=ScamType.LOTTERY_REWARD,
        is_scam=True,
        severity=6,
        source="Amazon prize scam",
        keywords=["amazon", "winner", "iphone", "lucky draw", "shipping", "gst"],
        language="en"
    ),
    ScamMessage(
        id="LR003",
        message="WhatsApp Lottery Winner! You won $1,000,000 USD! Send name, address, and phone number. Pay $500 transfer fee via Western Union. Lottery Code: WA2025MEGA",
        scam_type=ScamType.LOTTERY_REWARD,
        is_scam=True,
        severity=6,
        source="WhatsApp lottery scam",
        keywords=["whatsapp", "lottery", "won", "usd", "transfer fee", "western union"],
        language="en"
    ),
]

# ============================================
# BANK PHISHING / KYC SCAMS
# SBI, HDFC, ICICI impersonation
# ============================================

BANK_PHISHING_MESSAGES = [
    ScamMessage(
        id="BP001",
        message="Dear Customer, Your SBI account will be blocked in 24 hours due to incomplete KYC. Click this link to update your Aadhaar: sbi-kyc-update.com. Ignore if done.",
        scam_type=ScamType.BANK_PHISHING,
        is_scam=True,
        severity=8,
        source="SBI KYC phishing",
        keywords=["sbi", "blocked", "24 hours", "kyc", "click", "aadhaar"],
        language="en"
    ),
    ScamMessage(
        id="BP002",
        message="HDFC Bank Alert: Unusual login detected from new device. If not you, call 1800-XXX-XXXX immediately. Share OTP sent to verify your identity. Your security is our priority.",
        scam_type=ScamType.BANK_PHISHING,
        is_scam=True,
        severity=8,
        source="HDFC OTP scam",
        keywords=["hdfc", "unusual login", "new device", "otp", "verify", "call"],
        language="en"
    ),
    ScamMessage(
        id="BP003",
        message="ICICI: Your credit card 4532-XXXX-XXXX-1234 has been temporarily blocked. Unblock now by verifying CVV and expiry date. Reply or call: 9876543210",
        scam_type=ScamType.BANK_PHISHING,
        is_scam=True,
        severity=9,
        source="Credit card scam",
        keywords=["icici", "credit card", "blocked", "cvv", "expiry", "verify"],
        language="en"
    ),
    ScamMessage(
        id="BP004",
        message="PNB: Your debit card is expiring soon. Link your Aadhaar to avoid service disruption. Update at: pnb-card-update.in. Time limit: 48 hours.",
        scam_type=ScamType.BANK_PHISHING,
        is_scam=True,
        severity=7,
        source="Debit card phishing",
        keywords=["pnb", "debit card", "expiring", "aadhaar", "update", "48 hours"],
        language="en"
    ),
]

# ============================================
# TECH SUPPORT SCAMS
# Microsoft, Apple, virus alerts
# ============================================

TECH_SUPPORT_MESSAGES = [
    ScamMessage(
        id="TS001",
        message="Microsoft Security Alert: Your computer has been compromised! Call Microsoft Support immediately: 1800-XXX-XXXX. Hackers may steal your bank details. Download security patch: microsoft-fix.exe",
        scam_type=ScamType.TECH_SUPPORT,
        is_scam=True,
        severity=7,
        source="Microsoft tech support scam",
        keywords=["microsoft", "security", "compromised", "hackers", "bank", "download"],
        language="en"
    ),
    ScamMessage(
        id="TS002",
        message="Your Windows license has expired. Your PC is at risk! Call toll-free: 1800-XXX-XXXX to renew. Pay ₹4,999 for lifetime license. Technician will connect via AnyDesk.",
        scam_type=ScamType.TECH_SUPPORT,
        is_scam=True,
        severity=7,
        source="Windows license scam",
        keywords=["windows", "license", "expired", "risk", "anydesk", "technician"],
        language="en"
    ),
]

# ============================================
# TRAFFIC CHALLAN SCAMS (New in 2025)
# Fake e-challan messages
# ============================================

TRAFFIC_CHALLAN_MESSAGES = [
    ScamMessage(
        id="TC001",
        message="Traffic Challan Alert! Vehicle MH02AB1234 violated signal on 25/01/2026. Fine: ₹2,000. Pay now to avoid court case: paytm.challan.pay/MH02AB1234. Due in 24 hrs.",
        scam_type=ScamType.TRAFFIC_CHALLAN,
        is_scam=True,
        severity=6,
        source="TOI Jan 2026 - Fake challan scam loses 11L",
        keywords=["traffic", "challan", "vehicle", "violated", "fine", "court"],
        language="en"
    ),
    ScamMessage(
        id="TC002",
        message="E-Challan Notice: Your vehicle was caught over-speeding. Penalty: ₹5,000. License may be suspended. Download challan: echallan-gov.in/pay. Verify with Aadhaar.",
        scam_type=ScamType.TRAFFIC_CHALLAN,
        is_scam=True,
        severity=6,
        source="E-challan phishing",
        keywords=["e-challan", "over-speeding", "penalty", "suspended", "download", "aadhaar"],
        language="en"
    ),
]

# ============================================
# APK MALWARE SCAMS (New in 2025)
# Fake apps that steal banking credentials
# ============================================

APK_MALWARE_MESSAGES = [
    ScamMessage(
        id="APK001",
        message="Income Tax Refund: Your refund of ₹23,450 is ready. Download official ITR app to claim: itr-refund.apk. Link Aadhaar and bank account. Refund within 24 hours.",
        scam_type=ScamType.APK_MALWARE,
        is_scam=True,
        severity=9,
        source="TOI Jan 2026 - APK scam arrests",
        keywords=["income tax", "refund", "download", "apk", "aadhaar", "bank account"],
        language="en"
    ),
    ScamMessage(
        id="APK002",
        message="PM Kisan Yojana: ₹6,000 credit pending. Download KisanPay app to receive: kisanpay.apk. Verify bank details. Government approved scheme.",
        scam_type=ScamType.APK_MALWARE,
        is_scam=True,
        severity=8,
        source="Government scheme APK scam",
        keywords=["pm kisan", "download", "apk", "bank details", "government", "scheme"],
        language="en"
    ),
]

# ============================================
# LEGITIMATE MESSAGES (For false positive testing)
# Real bank/service notifications
# ============================================

LEGITIMATE_MESSAGES = [
    ScamMessage(
        id="LEG001",
        message="Hi, this is a reminder for your doctor appointment tomorrow at 10 AM at Apollo Hospital. Please arrive 15 minutes early. Thank you.",
        scam_type=ScamType.LEGITIMATE,
        is_scam=False,
        severity=0,
        source="Doctor appointment reminder",
        keywords=["appointment", "doctor", "hospital"],
        language="en"
    ),
    ScamMessage(
        id="LEG002",
        message="Your Amazon order #402-8273891-2736281 has been shipped. Delivery expected by Jan 30. Track: amazon.in/track. Thank you for shopping!",
        scam_type=ScamType.LEGITIMATE,
        is_scam=False,
        severity=0,
        source="Amazon delivery notification",
        keywords=["amazon", "order", "shipped", "delivery", "track"],
        language="en"
    ),
    ScamMessage(
        id="LEG003",
        message="SBI: Your A/c XX7890 is credited with Rs.25,000.00 on 28-Jan-26. Avl Bal: Rs.1,23,456.78. If not done by you, call 1800112211.",
        scam_type=ScamType.LEGITIMATE,
        is_scam=False,
        severity=0,
        source="Bank credit notification",
        keywords=["sbi", "credited", "bal", "call"],
        language="en"
    ),
    ScamMessage(
        id="LEG004",
        message="Your Zomato order from Domino's Pizza is out for delivery. Delivery partner: Ravi. ETA: 20 mins. Track live on app.",
        scam_type=ScamType.LEGITIMATE,
        is_scam=False,
        severity=0,
        source="Food delivery notification",
        keywords=["zomato", "delivery", "eta", "track"],
        language="en"
    ),
    ScamMessage(
        id="LEG005",
        message="HDFC Bank: Your credit card statement for Jan 2026 is ready. Total Due: ₹15,234. Due Date: 15-Feb-26. Pay via NetBanking or HDFC app.",
        scam_type=ScamType.LEGITIMATE,
        is_scam=False,
        severity=0,
        source="Credit card statement",
        keywords=["hdfc", "credit card", "statement", "due", "pay"],
        language="en"
    ),
    ScamMessage(
        id="LEG006",
        message="Your Uber ride with driver Suresh (DL01AB1234) is arriving in 3 minutes. Share trip: uber.com/trip/abc123",
        scam_type=ScamType.LEGITIMATE,
        is_scam=False,
        severity=0,
        source="Uber ride notification",
        keywords=["uber", "ride", "driver", "arriving"],
        language="en"
    ),
    ScamMessage(
        id="LEG007",
        message="Reminder: Your TATA Play subscription expires on 05-Feb-26. Recharge now to continue enjoying entertainment. Visit tataplay.com",
        scam_type=ScamType.LEGITIMATE,
        is_scam=False,
        severity=0,
        source="Subscription reminder",
        keywords=["tata play", "subscription", "expires", "recharge"],
        language="en"
    ),
]

# ============================================
# SPECIAL SCAM PATTERNS (From recent news)
# CSR Funding, FD Fraud, Online Gambling
# ============================================

SPECIAL_SCAM_MESSAGES = [
    ScamMessage(
        id="CSR001",
        message="CSR Funding Available! Your NGO is eligible for ₹2 crore corporate funding. Pay ₹50,000 processing fee to Govt liaison officer. Documents required: Registration, PAN, Bank account.",
        scam_type=ScamType.CSR_FUNDING,
        is_scam=True,
        severity=8,
        source="TOI Jan 2026 - NGO loses 1.31 Cr",
        keywords=["csr", "funding", "ngo", "crore", "processing fee", "liaison"],
        language="en"
    ),
    ScamMessage(
        id="FD001",
        message="SBI Special FD Offer! 12% interest rate for senior citizens. Limited period scheme. Minimum deposit ₹1 lakh. Call our relationship manager: 9876543210 for doorstep service.",
        scam_type=ScamType.FD_FRAUD,
        is_scam=True,
        severity=8,
        source="TOI Jan 2026 - FD fraud arrests",
        keywords=["sbi", "fd", "12%", "senior citizens", "deposit", "doorstep"],
        language="en"
    ),
    ScamMessage(
        id="GAM001",
        message="Online Rummy Pro! Win ₹10 lakh daily. Download app: rummypro.apk. First deposit bonus 500%. Refer friends for extra ₹1000. Guaranteed winnings!",
        scam_type=ScamType.ONLINE_GAMBLING,
        is_scam=True,
        severity=7,
        source="TOI Jan 2026 - Couple loses 56L in gambling",
        keywords=["online", "rummy", "win", "lakh", "download", "deposit", "bonus"],
        language="en"
    ),
]


# ============================================
# AGGREGATED DATASET
# ============================================

ALL_SCAM_MESSAGES: List[ScamMessage] = (
    DIGITAL_ARREST_MESSAGES +
    COURIER_PARCEL_MESSAGES +
    UPI_FRAUD_MESSAGES +
    AI_VOICE_CLONE_MESSAGES +
    TASK_JOB_MESSAGES +
    INVESTMENT_CRYPTO_MESSAGES +
    LOTTERY_REWARD_MESSAGES +
    BANK_PHISHING_MESSAGES +
    TECH_SUPPORT_MESSAGES +
    TRAFFIC_CHALLAN_MESSAGES +
    APK_MALWARE_MESSAGES +
    SPECIAL_SCAM_MESSAGES +
    LEGITIMATE_MESSAGES
)

# Statistics
SCAM_MESSAGES = [m for m in ALL_SCAM_MESSAGES if m.is_scam]
LEGIT_MESSAGES = [m for m in ALL_SCAM_MESSAGES if not m.is_scam]


def get_messages_by_type(scam_type: ScamType) -> List[ScamMessage]:
    """Get all messages of a specific scam type."""
    return [m for m in ALL_SCAM_MESSAGES if m.scam_type == scam_type]


def get_all_keywords() -> List[str]:
    """Get all unique keywords from the dataset."""
    keywords = set()
    for msg in ALL_SCAM_MESSAGES:
        keywords.update(msg.keywords)
    return sorted(list(keywords))


def get_dataset_stats() -> Dict[str, Any]:
    """Get statistics about the dataset."""
    type_counts = {}
    for msg in ALL_SCAM_MESSAGES:
        type_counts[msg.scam_type.value] = type_counts.get(msg.scam_type.value, 0) + 1
    
    return {
        "total_messages": len(ALL_SCAM_MESSAGES),
        "scam_messages": len(SCAM_MESSAGES),
        "legitimate_messages": len(LEGIT_MESSAGES),
        "scam_types": len(set(m.scam_type for m in ALL_SCAM_MESSAGES)),
        "type_distribution": type_counts,
        "unique_keywords": len(get_all_keywords()),
        "high_severity_count": len([m for m in SCAM_MESSAGES if m.severity >= 8])
    }


# Print stats when imported
if __name__ == "__main__":
    stats = get_dataset_stats()
    print("=" * 50)
    print("SCAM DATASET 2025 - STATISTICS")
    print("=" * 50)
    print(f"Total Messages: {stats['total_messages']}")
    print(f"Scam Messages: {stats['scam_messages']}")
    print(f"Legitimate Messages: {stats['legitimate_messages']}")
    print(f"Scam Types: {stats['scam_types']}")
    print(f"Unique Keywords: {stats['unique_keywords']}")
    print(f"High Severity (8+): {stats['high_severity_count']}")
    print("\nType Distribution:")
    for scam_type, count in sorted(stats['type_distribution'].items()):
        print(f"  {scam_type}: {count}")
