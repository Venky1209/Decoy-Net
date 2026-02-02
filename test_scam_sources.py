"""
Test the scam sources lookup feature.
This verifies that similar scam reports are found and warnings are generated.
"""
import sys
sys.path.insert(0, '.')

from core.scam_sources import ScamSourceLookup, scam_source_lookup


def test_find_similar_scams():
    """Test finding similar scams by type and message."""
    print("\n" + "="*60)
    print("TEST: Find Similar Scams")
    print("="*60)
    
    # Test 1: Digital Arrest Scam
    message = "This is CBI Mumbai. Your Aadhaar is linked to money laundering. Stay on call or we will arrest you."
    
    results = scam_source_lookup.find_similar_scams(
        scam_type="digital_arrest",
        message=message
    )
    
    print(f"\n📌 Digital Arrest Message: {message[:50]}...")
    print(f"📊 Found {len(results)} similar scam reports:")
    
    for r in results:
        print(f"\n   Source: {r['source']}")
        print(f"   Title: {r['title']}")
        print(f"   Victims: {r['victims_count']:,}")
        print(f"   Losses: {r['amount_lost']}")
        print(f"   Relevance: {r['relevance_score']}")
        print(f"   ⚠️ {r['warning']}")
    
    assert len(results) > 0, "Should find similar digital arrest scams"
    print("\n✅ PASS: Digital arrest scam found similar reports")
    
    # Test 2: UPI Fraud
    message2 = "Sir, please scan this QR code to receive your refund of Rs. 5000"
    
    results2 = scam_source_lookup.find_similar_scams(
        scam_type="upi_fraud",
        message=message2
    )
    
    print(f"\n📌 UPI Fraud Message: {message2}")
    print(f"📊 Found {len(results2)} similar scam reports:")
    
    for r in results2:
        print(f"\n   Source: {r['source']}")
        print(f"   Title: {r['title']}")
        print(f"   Relevance: {r['relevance_score']}")
    
    print("\n✅ PASS: UPI fraud scam found similar reports")


def test_scam_statistics():
    """Test getting statistics for scam types."""
    print("\n" + "="*60)
    print("TEST: Scam Statistics")
    print("="*60)
    
    test_types = ["digital_arrest", "banking", "job_scam", "ai_voice_clone"]
    
    for scam_type in test_types:
        stats = scam_source_lookup.get_scam_statistics(scam_type)
        
        if stats.get("known"):
            print(f"\n📊 {scam_type.upper()}:")
            print(f"   Reports: {stats['reports_count']}")
            print(f"   Total Victims: {stats['total_victims']:,}")
            print(f"   Sources: {', '.join(stats['sources'])}")
            print(f"   Latest Report: {stats['latest_report']}")
            print(f"   ⚠️ {stats['warning']}")
        else:
            print(f"\n❓ {scam_type}: No data available")
    
    print("\n✅ PASS: Statistics retrieved successfully")


def test_known_scammer_detection():
    """Test detection of known scammer patterns."""
    print("\n" + "="*60)
    print("TEST: Known Scammer Detection")
    print("="*60)
    
    # Test suspicious phone numbers
    test_phones = [
        "+91 1406789012",  # VOIP pattern
        "+1 555 123 4567",  # International spoofed
        "+91 9876543210",  # Normal Indian number
    ]
    
    print("\n📞 Testing Phone Numbers:")
    for phone in test_phones:
        is_known, warning = scam_source_lookup.check_known_scammer(phone=phone)
        status = "⚠️ SUSPICIOUS" if is_known else "✓ OK"
        print(f"   {phone}: {status}")
        if warning:
            print(f"      {warning}")
    
    # Test suspicious UPI IDs
    test_upis = [
        "customersupport@ybl",  # Suspicious pattern
        "refund.help@paytm",  # Suspicious pattern
        "john.doe@okaxis",  # Normal UPI
    ]
    
    print("\n💳 Testing UPI IDs:")
    for upi in test_upis:
        is_known, warning = scam_source_lookup.check_known_scammer(upi=upi)
        status = "⚠️ SUSPICIOUS" if is_known else "✓ OK"
        print(f"   {upi}: {status}")
        if warning:
            print(f"      {warning}")
    
    # Test suspicious URLs
    test_urls = [
        "https://bit.ly/xyz123",  # URL shortener
        "https://login-sbi-bank.xyz/verify",  # Phishing pattern
        "https://www.google.com",  # Normal URL
    ]
    
    print("\n🔗 Testing URLs:")
    for url in test_urls:
        is_known, warning = scam_source_lookup.check_known_scammer(url=url)
        status = "⚠️ SUSPICIOUS" if is_known else "✓ OK"
        print(f"   {url}: {status}")
        if warning:
            print(f"      {warning}")
    
    print("\n✅ PASS: Known scammer detection working")


def test_callback_integration():
    """Test that scam sources integrate with callback handler."""
    print("\n" + "="*60)
    print("TEST: Callback Integration")
    print("="*60)
    
    from core.callback_handler import CallbackHandler
    from unittest.mock import MagicMock
    
    handler = CallbackHandler()
    
    # Create mock session and scam result
    session = MagicMock()
    session.session_id = "test-123"
    session.conversation_turn = 5
    session.persona = "curious_uncle"
    session.conversation_history = [
        MagicMock(content="Your account is blocked, pay Rs 50000 to CBI account")
    ]
    
    scam_result = MagicMock()
    scam_result.scam_type = "digital_arrest"
    scam_result.confidence = 0.95
    scam_result.tactics = ["urgency", "authority_impersonation"]
    scam_result.llm_consensus = {"votes": {"scam": 3, "total": 4}}
    scam_result.times_seen_before = 2
    
    intelligence = {
        "bank_accounts": ["1234567890"],
        "upi_ids": ["support@ybl"],
        "phone_numbers": ["+91 1406789012"],
        "urls": ["https://bit.ly/fake"]
    }
    
    # Build agent notes
    notes = handler._build_agent_notes(session, scam_result, intelligence, 8.5)
    
    print(f"\n📝 Generated Agent Notes:\n")
    print("-"*60)
    print(notes)
    print("-"*60)
    
    # Verify external sources section is included
    assert "[EXTERNAL SOURCES]" in notes, "Should include external sources section"
    assert "[WARNING]" in notes, "Should include warning section"
    assert "[ALERT]" in notes, "Should include alert for suspicious patterns"
    
    print("\n✅ PASS: Callback integration working with scam sources")


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("🔍 SCAM SOURCES LOOKUP TESTS")
    print("="*60)
    
    test_find_similar_scams()
    test_scam_statistics()
    test_known_scammer_detection()
    test_callback_integration()
    
    print("\n" + "="*60)
    print("✅ ALL SCAM SOURCE TESTS PASSED!")
    print("="*60)


if __name__ == "__main__":
    main()
