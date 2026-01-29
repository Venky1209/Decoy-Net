"""Test multiple scam scenarios with the enhanced detector."""
import asyncio
import sys
sys.path.insert(0, 'd:\\honeypot')

SCAM_SCENARIOS = [
    {
        "name": "Banking KYC Scam",
        "message": "URGENT: Your SBI bank account is BLOCKED. Transfer Rs.5000 to UPI scammer@upi immediately to avoid ARREST. Call 9876543210 now!",
        "expected": True
    },
    {
        "name": "Lottery Scam",
        "message": "Congratulations! You won Rs.50,00,000 in Amazon Lucky Draw! Click http://claim-prize.xyz to claim. Pay Rs.10,000 processing fee.",
        "expected": True
    },
    {
        "name": "Job Offer Scam",
        "message": "Work from home job! Earn Rs.50,000/month typing. No experience needed. Pay Rs.5000 registration fee to start. WhatsApp 9999888777",
        "expected": True
    },
    {
        "name": "OTP Scam",
        "message": "Your account will be blocked in 24 hours. Share OTP sent to your phone to verify. This is from HDFC Bank security team.",
        "expected": True
    },
    {
        "name": "Crypto Scam",
        "message": "Double your Bitcoin! Send 0.1 BTC to wallet abc123 and get 0.2 BTC back instantly. Verified by Elon Musk. Limited time offer!",
        "expected": True
    },
    {
        "name": "Impersonation Scam",
        "message": "This is RBI Governor. Your account has illegal funds linked to money laundering. Transfer Rs.25000 to avoid arrest. FIR will be filed.",
        "expected": True
    },
    {
        "name": "Legitimate Message",
        "message": "Hi, this is reminder for your doctor appointment tomorrow at 10 AM. Please arrive 15 minutes early. Thank you.",
        "expected": False
    },
    {
        "name": "Normal Bank SMS",
        "message": "Your SBI account ending 1234 has been credited with Rs.5000. Available balance is Rs.25000.",
        "expected": False
    }
]

async def run_tests():
    from core.enhanced_detector import EnhancedScamDetector
    
    detector = EnhancedScamDetector(use_llm=True, use_memory=False)
    
    print("="*70)
    print("SCAM DETECTION TEST SUITE")
    print("="*70)
    
    passed = 0
    failed = 0
    
    for scenario in SCAM_SCENARIOS:
        print(f"\n[TEST] {scenario['name']}")
        print(f"  Message: {scenario['message'][:60]}...")
        
        try:
            result = await detector.detect(scenario['message'], [], {})
            
            # Check if detection matches expected
            match = result.is_scam == scenario['expected']
            status = "PASS" if match else "FAIL"
            
            if match:
                passed += 1
            else:
                failed += 1
            
            print(f"  Expected: is_scam={scenario['expected']}")
            print(f"  Got:      is_scam={result.is_scam}, confidence={result.confidence:.2f}")
            print(f"  Status:   [{status}]")
            
        except Exception as e:
            failed += 1
            print(f"  ERROR: {e}")
    
    print("\n" + "="*70)
    print(f"RESULTS: {passed}/{len(SCAM_SCENARIOS)} passed, {failed} failed")
    print("="*70)

if __name__ == "__main__":
    asyncio.run(run_tests())
