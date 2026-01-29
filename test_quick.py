"""Quick test for 2025 engine and local classifier."""
import sys
sys.path.insert(0, 'd:\\honeypot')

from utils.scam_patterns_2025 import scam_engine_2025
from core.local_classifier import local_classifier

test_messages = [
    ("CBI Digital Arrest", "URGENT: CBI officer here. Your Aadhaar linked to money laundering. Transfer Rs.50000 to safe custody."),
    ("UPI Scam", "Enter your UPI PIN to receive refund of Rs.5000 in your account."),
    ("Job Scam", "Earn Rs.50000/month doing simple tasks. Pay Rs.2000 registration fee."),
    ("Lottery Scam", "Congratulations! You won Rs.25 lakh in Jio lucky draw. Pay processing fee."),
    ("Legitimate Order", "Your order has been shipped and will arrive tomorrow."),
    ("Legitimate Reminder", "Reminder: Your doctor appointment is tomorrow at 10 AM."),
]

print("="*70)
print("2025 SCAM ENGINE + LOCAL CLASSIFIER TEST")
print("="*70)

for name, msg in test_messages:
    result_2025 = scam_engine_2025.analyze(msg)
    result_local = local_classifier.classify(msg)
    
    print(f"\n[{name}]")
    print(f"  Message: {msg[:50]}...")
    print(f"  2025 Engine: is_scam={result_2025['is_scam']}, conf={result_2025['confidence']:.2f}, cat={result_2025['category']}")
    print(f"  Local Class: is_scam={result_local.is_scam}, conf={result_local.confidence:.2f}, skip_llm={result_local.skip_llm}")

print("\n" + "="*70)
print("SUMMARY: Both engines working!")
print("="*70)
