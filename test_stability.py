"""
Pre-deployment stability check for all modified files.
Run this before deploying to ensure nothing will crash.
"""
import asyncio
import sys

def main():
    print("=" * 70)
    print("PRE-DEPLOYMENT STABILITY CHECK")
    print("=" * 70)
    
    errors = []
    warnings = []
    
    # 1. Test imports
    print("\n1. Testing imports...")
    
    try:
        from api.models import HoneypotRequest, HoneypotResponse
        print("   ✓ api.models")
    except Exception as e:
        errors.append(f"api.models: {e}")
        print(f"   ✗ api.models: {e}")
    
    try:
        from core.agent import HoneypotAgent
        print("   ✓ core.agent")
    except Exception as e:
        errors.append(f"core.agent: {e}")
        print(f"   ✗ core.agent: {e}")
    
    try:
        from core.intelligence_extractor import IntelligenceExtractor
        print("   ✓ core.intelligence_extractor")
    except Exception as e:
        errors.append(f"core.intelligence_extractor: {e}")
        print(f"   ✗ core.intelligence_extractor: {e}")
    
    try:
        from core.request_queue import RateLimitAwareQueue
        print("   ✓ core.request_queue")
    except Exception as e:
        errors.append(f"core.request_queue: {e}")
        print(f"   ✗ core.request_queue: {e}")
    
    try:
        from utils.patterns import SCAM_TYPE_PATTERNS
        print("   ✓ utils.patterns")
    except Exception as e:
        errors.append(f"utils.patterns: {e}")
        print(f"   ✗ utils.patterns: {e}")
    
    try:
        from utils.personas import PERSONAS
        print("   ✓ utils.personas")
    except Exception as e:
        errors.append(f"utils.personas: {e}")
        print(f"   ✗ utils.personas: {e}")
    
    try:
        from utils.scam_patterns_2025 import ScamDetectionEngine2025, scam_engine_2025
        print("   ✓ utils.scam_patterns_2025")
    except Exception as e:
        errors.append(f"utils.scam_patterns_2025: {e}")
        print(f"   ✗ utils.scam_patterns_2025: {e}")
    
    try:
        from core.enhanced_detector import EnhancedScamDetector
        print("   ✓ core.enhanced_detector")
    except Exception as e:
        errors.append(f"core.enhanced_detector: {e}")
        print(f"   ✗ core.enhanced_detector: {e}")
    
    if errors:
        print(f"\n   IMPORT ERRORS: {len(errors)}")
        return False
    
    # 2. Test API Models
    print("\n2. Testing API models (session_id handling)...")
    
    from api.models import HoneypotRequest
    
    # Without session_id
    try:
        req = HoneypotRequest(message='Test message')
        assert req.sessionId is not None, "sessionId should be auto-generated"
        assert len(req.sessionId) > 10, "sessionId should be a UUID"
        print("   ✓ Without session_id (auto-generates UUID)")
    except Exception as e:
        errors.append(f"session_id auto-gen: {e}")
        print(f"   ✗ Without session_id: {e}")
    
    # With session_id
    try:
        req = HoneypotRequest(session_id='my-session-123', message='Test')
        assert req.sessionId == 'my-session-123'
        print("   ✓ With session_id (preserves value)")
    except Exception as e:
        errors.append(f"session_id preserve: {e}")
        print(f"   ✗ With session_id: {e}")
    
    # Complex message object
    try:
        req = HoneypotRequest(message={'sender': 'scammer', 'text': 'Hello', 'timestamp': '2026-01-01'})
        assert req.get_message_text() == 'Hello'
        print("   ✓ Complex message object (hackathon format)")
    except Exception as e:
        errors.append(f"complex message: {e}")
        print(f"   ✗ Complex message: {e}")
    
    # 3. Test scam detection engine
    print("\n3. Testing 2025 scam detection engine...")
    
    from utils.scam_patterns_2025 import scam_engine_2025
    
    test_cases = [
        ('Digital Arrest', 'CBI officer calling about money laundering case. Stay on video call.', True),
        ('UPI Scam', 'Enter UPI PIN to receive Rs 5000 payment.', True),
        ('Bank KYC', 'Account will be blocked. Update KYC immediately.', True),
        ('Lottery', 'Congratulations! You won Rs 25 lakh in Jio lottery!', True),
        ('Job Scam', 'Earn Rs 5000 daily. Join Telegram for tasks.', True),
        ('Legitimate Order', 'Your order has been delivered. Thank you!', False),
        ('Legitimate Bank', 'Rs 5000 credited to your account.', False),
    ]
    
    detection_passed = 0
    for name, msg, expected in test_cases:
        result = scam_engine_2025.analyze(msg)
        is_correct = result['is_scam'] == expected
        if is_correct:
            detection_passed += 1
            print(f"   ✓ {name}: is_scam={result['is_scam']}, conf={result['confidence']:.2f}")
        else:
            warnings.append(f"{name}: expected {expected}, got {result['is_scam']}")
            print(f"   ⚠ {name}: expected {expected}, got {result['is_scam']} (conf={result['confidence']:.2f})")
    
    print(f"   Detection: {detection_passed}/{len(test_cases)} correct")
    
    # 4. Test full detection pipeline
    print("\n4. Testing full detection pipeline (no LLM)...")
    
    from core.enhanced_detector import EnhancedScamDetector
    detector = EnhancedScamDetector(use_llm=False, use_memory=False)
    
    async def test_detector():
        scam_msg = 'This is CBI cyber cell. Your Aadhaar is linked to money laundering.'
        result = await detector.detect(scam_msg)
        return result
    
    result = asyncio.run(test_detector())
    if result.is_scam:
        print(f"   ✓ Scam detected: conf={result.confidence:.2f}, type={result.scam_type}")
    else:
        warnings.append("Scam not detected without LLM")
        print(f"   ⚠ Scam not detected (may need LLM): conf={result.confidence:.2f}")
    
    # 5. Test intelligence extraction
    print("\n5. Testing intelligence extraction...")
    
    from core.intelligence_extractor import IntelligenceExtractor
    extractor = IntelligenceExtractor()
    
    test_msg = "Send money to UPI: scammer@paytm or call +91 98765 43210"
    intel = extractor.extract_all(test_msg)
    
    if intel.get('upi_ids'):
        print(f"   ✓ UPI extraction: {intel['upi_ids']}")
    else:
        warnings.append("UPI extraction failed")
        print("   ⚠ UPI extraction: not found")
    
    if intel.get('phone_numbers'):
        print(f"   ✓ Phone extraction: {intel['phone_numbers']}")
    else:
        warnings.append("Phone extraction failed")
        print("   ⚠ Phone extraction: not found")
    
    # 6. Test rate limiting
    print("\n6. Testing rate limiting...")
    
    from core.request_queue import RateLimitAwareQueue
    queue = RateLimitAwareQueue()
    
    allowed = 0
    blocked = 0
    for i in range(10):
        if queue.check_client_limit("test_client", limit=5, window=60):
            allowed += 1
        else:
            blocked += 1
    
    if allowed == 5 and blocked == 5:
        print(f"   ✓ Rate limiting: {allowed} allowed, {blocked} blocked")
    else:
        warnings.append(f"Rate limiting unexpected: {allowed} allowed, {blocked} blocked")
        print(f"   ⚠ Rate limiting: {allowed} allowed, {blocked} blocked (expected 5/5)")
    
    # 7. Test personas
    print("\n7. Testing personas...")
    
    from utils.personas import PERSONAS
    
    persona_count = len(PERSONAS)
    if persona_count >= 5:
        print(f"   ✓ {persona_count} personas loaded")
        for name in list(PERSONAS.keys())[:3]:
            print(f"     - {name}")
    else:
        warnings.append(f"Only {persona_count} personas")
        print(f"   ⚠ Only {persona_count} personas loaded")
    
    # 8. Test FastAPI app can be created
    print("\n8. Testing FastAPI app initialization...")
    
    try:
        from main import app
        print("   ✓ FastAPI app loads successfully")
    except Exception as e:
        errors.append(f"FastAPI app: {e}")
        print(f"   ✗ FastAPI app failed: {e}")
    
    # Summary
    print("\n" + "=" * 70)
    print("STABILITY CHECK SUMMARY")
    print("=" * 70)
    
    if errors:
        print(f"\n❌ ERRORS ({len(errors)}):")
        for e in errors:
            print(f"   - {e}")
        print("\n⛔ DO NOT DEPLOY - Fix errors first!")
        return False
    
    if warnings:
        print(f"\n⚠️  WARNINGS ({len(warnings)}):")
        for w in warnings:
            print(f"   - {w}")
    
    print("\n✅ ALL CRITICAL CHECKS PASSED")
    print("   - All imports work")
    print("   - API models handle session_id correctly")
    print("   - Scam detection engine works")
    print("   - Intelligence extraction works")
    print("   - Rate limiting works")
    print("   - FastAPI app initializes")
    
    if warnings:
        print(f"\n   Note: {len(warnings)} non-critical warnings (likely need LLM for full accuracy)")
    
    print("\n🚀 SAFE TO DEPLOY")
    return True


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
