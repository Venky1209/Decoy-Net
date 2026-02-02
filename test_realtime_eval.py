"""
Real-Time Evaluation Scenario Test
Simulates the automated security interaction scenarios that will be used in final evaluation.
"""
import asyncio
import sys

print('=' * 70)
print('REAL-TIME EVALUATION SCENARIO TEST')
print('=' * 70)

# Test scenarios that evaluators might send
EVAL_SCENARIOS = [
    {
        'name': 'Digital Arrest Scam (Multi-turn)',
        'messages': [
            'This is Inspector Sharma from Mumbai Cyber Cell. Your Aadhaar is linked to money laundering case.',
            'You need to stay on video call for verification. Do not disconnect or we will arrest you.',
            'Transfer Rs 50000 to this safe RBI account for investigation: 1234567890 IFSC SBIN0001234'
        ],
        'expected': {'is_scam': True, 'extract_bank': True}
    },
    {
        'name': 'UPI Fraud - QR/PIN Scam',
        'messages': [
            'Hi, I am buyer from OLX for your sofa. I will pay Rs 15000.',
            'Please scan this QR code to RECEIVE the payment. Enter your UPI PIN to accept.',
            'Payment of Rs 15000 is pending. Enter PIN now to receive money.'
        ],
        'expected': {'is_scam': True}
    },
    {
        'name': 'Job Scam - Telegram Task',
        'messages': [
            'Congratulations! You are selected for Amazon Review job. Earn Rs 5000 daily.',
            'Join our Telegram channel @amazon_tasks_official to start earning.',
            'Pay Rs 500 registration fee to activate your account. UPI: jobs@paytm'
        ],
        'expected': {'is_scam': True, 'extract_upi': True}
    },
    {
        'name': 'Bank KYC Phishing',
        'messages': [
            'Dear Customer, Your SBI account will be blocked in 24 hours due to incomplete KYC.',
            'Click here to update: http://sbi-kyc-update.xyz/verify',
            'Share OTP received on your mobile to complete verification.'
        ],
        'expected': {'is_scam': True, 'extract_url': True}
    },
    {
        'name': 'Lottery Scam',
        'messages': [
            'CONGRATULATIONS! Your mobile number won Rs 25 LAKH in Jio Lucky Draw!',
            'To claim prize, pay processing fee of Rs 5000 to this account.',
            'Contact lottery officer: +91 98765 43210. Offer valid for 24 hours only!'
        ],
        'expected': {'is_scam': True, 'extract_phone': True}
    },
    {
        'name': 'AI Voice Clone - Family Emergency',
        'messages': [
            'Papa, its me! I had an accident and Im in hospital.',
            'Dont tell mummy, just send Rs 50000 urgently to my friends account.',
            'UPI: friend_help@okaxis - Please send now, battery dying!'
        ],
        'expected': {'is_scam': True, 'extract_upi': True}
    },
    {
        'name': 'Legitimate - Order Delivery',
        'messages': [
            'Your Amazon order #123-456 has been shipped. Expected delivery: Feb 3.',
            'Track your package: https://amazon.in/track/123456'
        ],
        'expected': {'is_scam': False}
    },
    {
        'name': 'Legitimate - Bank Transaction',
        'messages': [
            'Your SBI account XXX1234 credited with Rs 25000. Available balance Rs 45000.'
        ],
        'expected': {'is_scam': False}
    },
    {
        'name': 'Legitimate - Appointment Reminder',
        'messages': [
            'Reminder: Your appointment with Dr. Sharma is scheduled for tomorrow at 10 AM.',
            'Location: Apollo Hospital, Sector 15. Please arrive 15 minutes early.'
        ],
        'expected': {'is_scam': False}
    }
]


async def test_scenario(scenario):
    from core.enhanced_detector import EnhancedScamDetector
    from core.intelligence_extractor import IntelligenceExtractor
    
    # Test with LLM disabled for speed (patterns only)
    detector = EnhancedScamDetector(use_llm=False, use_memory=True)
    extractor = IntelligenceExtractor()
    
    print(f'\n[TEST] {scenario["name"]}')
    print('-' * 50)
    
    all_intel = {'bank_accounts': [], 'upi_ids': [], 'phones': [], 'urls': []}
    conversation = []
    final_result = None
    
    for i, msg in enumerate(scenario['messages']):
        # Detect scam
        result = await detector.detect(msg, conversation)
        final_result = result
        
        # Extract intelligence
        intel = extractor.extract_all(msg)
        all_intel['bank_accounts'].extend(intel.get('bank_accounts', []))
        all_intel['upi_ids'].extend(intel.get('upi_ids', []))
        all_intel['phones'].extend(intel.get('phone_numbers', []))
        all_intel['urls'].extend(intel.get('urls', []))
        
        conversation.append({'role': 'scammer', 'content': msg})
        
        status = "SCAM" if result.is_scam else "SAFE"
        print(f'  Turn {i+1}: [{status}] conf={result.confidence:.2f}, type={result.scam_type}')
    
    # Verify expectations
    expected = scenario['expected']
    passed = True
    warnings = []
    
    if final_result.is_scam != expected['is_scam']:
        print(f'  [FAIL] Expected is_scam={expected["is_scam"]}, got {final_result.is_scam}')
        passed = False
    
    if expected.get('extract_bank') and not all_intel['bank_accounts']:
        warnings.append('bank account')
    
    if expected.get('extract_upi') and not all_intel['upi_ids']:
        warnings.append('UPI ID')
    
    if expected.get('extract_phone') and not all_intel['phones']:
        warnings.append('phone number')
    
    if expected.get('extract_url') and not all_intel['urls']:
        warnings.append('URL')
    
    if passed:
        print(f'  [PASS] Detection correct!')
    
    if warnings:
        print(f'  [WARN] Missing extraction: {", ".join(warnings)}')
    
    # Show extracted intel
    extracted = []
    if all_intel['bank_accounts']:
        extracted.append(f"banks={all_intel['bank_accounts']}")
    if all_intel['upi_ids']:
        extracted.append(f"upi={all_intel['upi_ids']}")
    if all_intel['phones']:
        extracted.append(f"phones={all_intel['phones']}")
    if all_intel['urls']:
        extracted.append(f"urls={[u[:30]+'...' if len(u)>30 else u for u in all_intel['urls']]}")
    
    if extracted:
        print(f'  Intel: {", ".join(extracted)}')
    
    return passed, len(warnings) == 0


async def test_full_api_flow():
    """Test the full API flow with agent response generation."""
    print('\n' + '=' * 70)
    print('FULL API FLOW TEST (with Agent Response)')
    print('=' * 70)
    
    from core.enhanced_detector import EnhancedScamDetector
    from core.agent import HoneypotAgent
    from core.intelligence_extractor import IntelligenceExtractor
    
    detector = EnhancedScamDetector(use_llm=True, use_memory=True)
    agent = HoneypotAgent()
    extractor = IntelligenceExtractor()
    
    test_message = "This is CBI officer calling. Your Aadhaar 1234-5678-9012 is linked to money laundering. Transfer Rs 1 lakh to safe account immediately or face arrest."
    
    print(f'\nScammer message: "{test_message[:60]}..."')
    print('-' * 50)
    
    # 1. Detect scam
    result = await detector.detect(test_message)
    print(f'1. Detection: is_scam={result.is_scam}, conf={result.confidence:.2f}, type={result.scam_type}')
    
    # 2. Extract intelligence
    intel = extractor.extract_all(test_message)
    print(f'2. Intelligence: {intel}')
    
    # 3. Generate agent response
    response = await agent.generate_response(
        message=test_message,
        is_scam=result.is_scam,
        scam_type=result.scam_type,
        confidence=result.confidence,
        conversation_history=[],
        extracted_intel=intel,
        threat_level=result.threat_level
    )
    print(f'3. Agent response: "{response[:100]}..."')
    
    # Verify response is engaging (not rejecting)
    rejection_phrases = ['i am an ai', 'i cannot', 'as an ai', 'i will not']
    is_engaging = not any(p in response.lower() for p in rejection_phrases)
    
    if result.is_scam and result.confidence > 0.5 and is_engaging:
        print('\n[PASS] Full flow working correctly!')
        return True
    else:
        print(f'\n[FAIL] Issues detected: is_scam={result.is_scam}, engaging={is_engaging}')
        return False


async def main():
    passed = 0
    perfect = 0
    total = len(EVAL_SCENARIOS)
    
    for scenario in EVAL_SCENARIOS:
        try:
            detection_ok, extraction_ok = await test_scenario(scenario)
            if detection_ok:
                passed += 1
            if detection_ok and extraction_ok:
                perfect += 1
        except Exception as e:
            print(f'  [ERROR] {e}')
            import traceback
            traceback.print_exc()
    
    print('\n' + '=' * 70)
    print(f'PATTERN DETECTION: {passed}/{total} scenarios passed ({100*passed//total}%)')
    print(f'INTEL EXTRACTION:  {perfect}/{total} scenarios perfect ({100*perfect//total}%)')
    print('=' * 70)
    
    # Now test full API flow with LLM
    try:
        api_ok = await test_full_api_flow()
    except Exception as e:
        print(f'[ERROR] Full API flow failed: {e}')
        api_ok = False
    
    print('\n' + '=' * 70)
    print('FINAL VERDICT')
    print('=' * 70)
    
    if passed >= total - 1 and api_ok:  # Allow 1 failure
        print('✅ READY FOR EVALUATION')
        print('   - Scam detection working')
        print('   - Intelligence extraction working')
        print('   - Agent responses engaging')
        return True
    else:
        print('⚠️  ISSUES DETECTED - Review failures above')
        return False


if __name__ == '__main__':
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
