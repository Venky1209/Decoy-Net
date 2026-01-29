"""
Comprehensive test suite for the enhanced scam detection system.
Tests: 2025 patterns, local classifier, rate limiting, full pipeline.
"""
import asyncio
import sys
sys.path.insert(0, 'd:\\honeypot')

# Test scenarios covering all 2025 scam types
TEST_SCENARIOS = [
    # ===== DIGITAL ARREST SCAMS =====
    {
        "name": "Digital Arrest - CBI Impersonation",
        "message": "This is CBI officer Sharma. Your Aadhaar is linked to money laundering case. Stay on video call. Transfer Rs.50000 to RBI safe custody account immediately or face arrest.",
        "expected_scam": True,
        "expected_category": "digital_arrest",
        "expected_min_confidence": 0.7
    },
    {
        "name": "Digital Arrest - ED Notice",
        "message": "ED has frozen your account due to suspicious hawala transactions. Video verification required. Do not disconnect call. Transfer amount to secure the funds.",
        "expected_scam": True,
        "expected_category": "digital_arrest",
        "expected_min_confidence": 0.6
    },
    
    # ===== UPI FRAUD =====
    {
        "name": "UPI Fraud - Enter PIN to Receive",
        "message": "Your refund of Rs.1500 is pending. Enter your UPI PIN to receive the amount in your bank account. Click here to claim.",
        "expected_scam": True,
        "expected_category": "upi_fraud",
        "expected_min_confidence": 0.7
    },
    {
        "name": "UPI Fraud - QR Scam",
        "message": "Scan this QR code to receive Rs.5000 cashback credited to your account. Limited time offer!",
        "expected_scam": True,
        "expected_category": "upi_fraud",
        "expected_min_confidence": 0.5
    },
    
    # ===== AI VOICE CLONE =====
    {
        "name": "AI Voice Clone - Family Emergency",
        "message": "Papa I had an accident and I'm in hospital. Don't tell mummy. Send Rs.50000 immediately to this UPI. Battery dying.",
        "expected_scam": True,
        "expected_category": "ai_voice_clone",
        "expected_min_confidence": 0.5
    },
    
    # ===== TASK/JOB SCAM =====
    {
        "name": "Task Scam - Telegram Job",
        "message": "Earn Rs.50000 per month doing simple rating tasks on Telegram. Join our channel. Pay Rs.2000 registration fee to start earning daily.",
        "expected_scam": True,
        "expected_category": "task_job_scam",
        "expected_min_confidence": 0.6
    },
    {
        "name": "Job Scam - Work From Home",
        "message": "Work from home job! No experience needed. Data entry typing work. Guaranteed income Rs.30000/month. Pay joining fee Rs.5000 on WhatsApp 9876543210",
        "expected_scam": True,
        "expected_category": "job_scam",
        "expected_min_confidence": 0.6
    },
    
    # ===== INVESTMENT/CRYPTO =====
    {
        "name": "Crypto Scam - BTC Doubler",
        "message": "Double your Bitcoin! Send 0.1 BTC and receive 0.2 BTC within 24 hours. Verified by Elon Musk. Guaranteed returns!",
        "expected_scam": True,
        "expected_category": "investment_crypto",
        "expected_min_confidence": 0.7
    },
    
    # ===== LOTTERY/REWARD =====
    {
        "name": "Lottery Scam - Jio Lucky Draw",
        "message": "Congratulations! Your Jio number won Rs.25 lakh in our lucky draw. Pay Rs.10000 processing fee to claim your prize. Contact now!",
        "expected_scam": True,
        "expected_category": "lottery",
        "expected_min_confidence": 0.7
    },
    
    # ===== BANKING PHISHING =====
    {
        "name": "Bank KYC Scam",
        "message": "Dear Customer, Your SBI account will be blocked in 24 hours due to incomplete KYC. Click this link to update your Aadhaar immediately.",
        "expected_scam": True,
        "expected_category": "impersonation",
        "expected_min_confidence": 0.5
    },
    
    # ===== LEGITIMATE MESSAGES (should NOT be flagged) =====
    {
        "name": "Legitimate - Doctor Appointment",
        "message": "Hi, this is a reminder for your doctor appointment tomorrow at 10 AM. Please arrive 15 minutes early. Thank you.",
        "expected_scam": False,
        "expected_category": None,
        "expected_max_confidence": 0.4
    },
    {
        "name": "Legitimate - Order Delivery",
        "message": "Your Flipkart order has been shipped and will arrive tomorrow. Track your order at flipkart.com/track/12345",
        "expected_scam": False,
        "expected_category": None,
        "expected_max_confidence": 0.4
    },
    {
        "name": "Legitimate - Bank Credit",
        "message": "Your SBI account ending 1234 has been credited with Rs.25000. Available balance is Rs.50000. Transaction ref: TXN123456",
        "expected_scam": False,
        "expected_category": None,
        "expected_max_confidence": 0.4
    },
]


async def test_2025_engine():
    """Test the 2025 scam detection engine directly."""
    from utils.scam_patterns_2025 import scam_engine_2025
    
    print("\n" + "="*70)
    print("TEST 1: 2025 SCAM ENGINE (Keywords + Semantic + Templates)")
    print("="*70)
    
    passed = 0
    failed = 0
    
    for scenario in TEST_SCENARIOS:
        result = scam_engine_2025.analyze(scenario["message"])
        
        is_correct = result["is_scam"] == scenario["expected_scam"]
        
        status = "PASS" if is_correct else "FAIL"
        if is_correct:
            passed += 1
        else:
            failed += 1
        
        print(f"\n[{status}] {scenario['name']}")
        print(f"  Expected: is_scam={scenario['expected_scam']}")
        print(f"  Got:      is_scam={result['is_scam']}, conf={result['confidence']:.2f}, cat={result['category']}")
    
    print(f"\n2025 Engine Results: {passed}/{len(TEST_SCENARIOS)} passed")
    return passed, len(TEST_SCENARIOS)


async def test_local_classifier():
    """Test the local classifier for LLM skip decisions."""
    from core.local_classifier import local_classifier
    
    print("\n" + "="*70)
    print("TEST 2: LOCAL CLASSIFIER (Fast Detection)")
    print("="*70)
    
    llm_skipped = 0
    llm_needed = 0
    
    for scenario in TEST_SCENARIOS:
        should_call_llm, result = local_classifier.should_call_llm(scenario["message"])
        
        if not should_call_llm:
            llm_skipped += 1
            status = "SKIP_LLM"
        else:
            llm_needed += 1
            status = "NEED_LLM"
        
        print(f"[{status}] {scenario['name'][:40]}... conf={result.confidence:.2f}")
    
    print(f"\nLocal Classifier: {llm_skipped} can skip LLM, {llm_needed} need LLM")
    return llm_skipped, llm_needed


async def test_full_pipeline():
    """Test the complete enhanced detector pipeline."""
    from core.enhanced_detector import EnhancedScamDetector
    
    print("\n" + "="*70)
    print("TEST 3: FULL PIPELINE (Enhanced Detector)")
    print("="*70)
    
    detector = EnhancedScamDetector(use_llm=True, use_memory=False)
    
    passed = 0
    failed = 0
    
    # Only test a few scenarios to avoid rate limiting
    test_subset = TEST_SCENARIOS[:5]  # First 5 scenarios
    
    for scenario in test_subset:
        try:
            result = await detector.detect(scenario["message"], [], {})
            
            is_correct = result.is_scam == scenario["expected_scam"]
            
            status = "PASS" if is_correct else "FAIL"
            if is_correct:
                passed += 1
            else:
                failed += 1
            
            print(f"\n[{status}] {scenario['name']}")
            print(f"  Expected: is_scam={scenario['expected_scam']}")
            print(f"  Got:      is_scam={result.is_scam}, conf={result.confidence:.2f}")
            
        except Exception as e:
            failed += 1
            print(f"\n[ERROR] {scenario['name']}: {e}")
    
    print(f"\nFull Pipeline Results: {passed}/{len(test_subset)} passed")
    return passed, len(test_subset)


async def main():
    print("\n" + "="*70)
    print("SCAM DETECTION SYSTEM - COMPREHENSIVE TEST SUITE")
    print("="*70)
    
    # Test 1: 2025 Engine
    engine_passed, engine_total = await test_2025_engine()
    
    # Test 2: Local Classifier
    skipped, needed = await test_local_classifier()
    
    # Test 3: Full Pipeline (limited to avoid rate limits)
    pipeline_passed, pipeline_total = await test_full_pipeline()
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"2025 Engine:      {engine_passed}/{engine_total} passed ({engine_passed/engine_total*100:.0f}%)")
    print(f"Local Classifier: {skipped} can skip LLM ({skipped/(skipped+needed)*100:.0f}% savings)")
    print(f"Full Pipeline:    {pipeline_passed}/{pipeline_total} passed")
    print("="*70)


if __name__ == "__main__":
    asyncio.run(main())
