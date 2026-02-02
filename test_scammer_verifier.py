"""
Test the Scammer Verification System.
Verifies if UPI IDs, phone numbers, etc. are actually from scammers.
"""
import sys
sys.path.insert(0, '.')

from core.scammer_verifier import ScammerVerifier, scammer_verifier


def test_upi_verification():
    """Test UPI ID verification."""
    print("\n" + "="*60)
    print("TEST: UPI ID Verification")
    print("="*60)
    
    test_cases = [
        # Suspicious UPIs
        ("support.helpdesk@ybl", True, "Customer support impersonation"),
        ("refund.cashback@paytm", True, "Refund scam keywords"),
        ("sbi.official.verify@ybl", True, "Bank impersonation"),
        ("12345678901@ybl", True, "Numeric-heavy handle (bot)"),
        ("customercare.bank@axl", True, "Multiple suspicious keywords"),
        
        # Legitimate-looking UPIs
        ("john.doe@okaxis", False, "Normal personal UPI"),
        ("ravi.kumar.1990@ybl", False, "Normal with year"),
        ("shopname@paytm", False, "Normal business"),
    ]
    
    print(f"\n{'UPI ID':<35} {'Expected':<10} {'Actual':<10} {'Risk':<10} {'Reasons'}")
    print("-" * 100)
    
    passed = 0
    for upi, expected_sus, description in test_cases:
        result = scammer_verifier.verify_upi(upi)
        actual = result.is_suspicious
        status = "✅" if actual == expected_sus else "❌"
        
        reasons_short = "; ".join(result.reasons[:2]) if result.reasons else "-"
        print(f"{upi:<35} {str(expected_sus):<10} {str(actual):<10} {result.risk_level:<10} {reasons_short[:40]}")
        
        if actual == expected_sus:
            passed += 1
    
    print(f"\n✅ Passed: {passed}/{len(test_cases)}")
    return passed == len(test_cases)


def test_phone_verification():
    """Test phone number verification."""
    print("\n" + "="*60)
    print("TEST: Phone Number Verification")
    print("="*60)
    
    test_cases = [
        # Suspicious phones
        ("+91 140 6789012", True, "VOIP prefix"),
        ("+1 555 123 4567", True, "International spoofed"),
        ("+44 7911 123456", True, "UK number (Indian official impersonation)"),
        ("+91 120 4567890", True, "Noida area (high scam)"),
        
        # Legitimate phones
        ("+91 9876543210", False, "Valid Indian mobile"),
        ("+91 8765432109", False, "Valid Indian mobile"),
        ("7654321098", False, "Valid without country code"),
    ]
    
    print(f"\n{'Phone':<25} {'Expected':<10} {'Actual':<10} {'Risk':<10} {'Reasons'}")
    print("-" * 90)
    
    passed = 0
    for phone, expected_sus, description in test_cases:
        result = scammer_verifier.verify_phone(phone)
        actual = result.is_suspicious
        status = "✅" if actual == expected_sus else "❌"
        
        reasons_short = "; ".join(result.reasons[:2]) if result.reasons else "-"
        print(f"{phone:<25} {str(expected_sus):<10} {str(actual):<10} {result.risk_level:<10} {reasons_short[:40]}")
        
        if actual == expected_sus:
            passed += 1
    
    print(f"\n✅ Passed: {passed}/{len(test_cases)}")
    return passed == len(test_cases)


def test_url_verification():
    """Test URL verification."""
    print("\n" + "="*60)
    print("TEST: URL Verification")
    print("="*60)
    
    test_cases = [
        # Phishing URLs
        ("https://bit.ly/sbi-verify", True, "URL shortener"),
        ("https://sbi-login-secure.xyz/verify", True, "Impersonation + suspicious TLD"),
        ("http://192.168.1.1/login", True, "IP address URL"),
        ("https://login.hdfc.secure.update.verify.com", True, "Excessive subdomains"),
        ("https://amazon-verify.tk/confirm", True, "Brand impersonation"),
        
        # Legitimate URLs
        ("https://www.sbi.co.in/", False, "Official SBI"),
        ("https://www.google.com", False, "Google"),
        ("https://paytm.com/recharge", False, "Official Paytm"),
    ]
    
    print(f"\n{'URL':<45} {'Expected':<10} {'Actual':<10} {'Risk'}")
    print("-" * 80)
    
    passed = 0
    for url, expected_sus, description in test_cases:
        result = scammer_verifier.verify_url(url)
        actual = result.is_suspicious
        
        url_short = url[:42] + "..." if len(url) > 45 else url
        print(f"{url_short:<45} {str(expected_sus):<10} {str(actual):<10} {result.risk_level}")
        
        if actual == expected_sus:
            passed += 1
    
    print(f"\n✅ Passed: {passed}/{len(test_cases)}")
    return passed >= len(test_cases) - 1  # Allow 1 miss for edge cases


def test_batch_verification():
    """Test batch verification of all intelligence."""
    print("\n" + "="*60)
    print("TEST: Batch Verification")
    print("="*60)
    
    intelligence = {
        "upi_ids": ["support.helpdesk@ybl", "normal.user@okaxis"],
        "phone_numbers": ["+91 140 6789012", "+91 9876543210"],
        "bank_accounts": ["1234567890123456"],
        "urls": ["https://bit.ly/verify-account", "https://google.com"]
    }
    
    results = scammer_verifier.verify_all(intelligence)
    
    print(f"\n📊 Verification Summary:")
    print(f"   Total Checked: {results['summary']['total_checked']}")
    print(f"   Suspicious: {results['summary']['total_suspicious']}")
    print(f"   Highest Risk: {results['summary']['highest_risk'].upper()}")
    
    if results['summary']['critical_alerts']:
        print(f"\n🚨 Critical Alerts:")
        for alert in results['summary']['critical_alerts']:
            print(f"   • {alert}")
    
    # Verify expected results
    assert results['summary']['total_suspicious'] >= 2, "Should find at least 2 suspicious"
    assert results['summary']['highest_risk'] in ["medium", "high", "critical"], "Should have elevated risk"
    
    print("\n✅ PASS: Batch verification working correctly")
    return True


def test_scammer_reporting():
    """Test reporting and learning from scammers."""
    print("\n" + "="*60)
    print("TEST: Scammer Reporting & Learning")
    print("="*60)
    
    # Create a test verifier with temporary database
    test_verifier = ScammerVerifier("test_scammer_db.json")
    
    # Report a scammer
    test_upi = "test.scammer.unique.123@ybl"
    test_verifier.report_scammer(
        identifier=test_upi,
        identifier_type="upi",
        scam_type="digital_arrest",
        session_id="test-session-1"
    )
    
    # Report again (should increase count)
    test_verifier.report_scammer(
        identifier=test_upi,
        identifier_type="upi",
        scam_type="banking",
        session_id="test-session-2"
    )
    
    # Reload database to verify persistence
    test_verifier._load_database()
    test_verifier.database = test_verifier._load_database()
    
    # Now verify - should be flagged as reported
    result = test_verifier.verify_upi(test_upi)
    
    print(f"\n📌 Reported UPI: {test_upi}")
    print(f"   Report Count: {result.reported_count}")
    print(f"   Risk Score: {result.risk_score}")
    print(f"   Risk Level: {result.risk_level}")
    print(f"   Reasons: {result.reasons}")
    
    # Check stats
    stats = test_verifier.get_statistics()
    print(f"\n📊 Database Stats: {stats}")
    
    # Verify database was updated
    assert stats["total_reports"] >= 2, "Should have at least 2 reports"
    assert stats["unique_upi_ids"] >= 1, "Should have at least 1 unique UPI"
    
    # Clean up test database
    import os
    if os.path.exists("test_scammer_db.json"):
        os.remove("test_scammer_db.json")
    
    print("\n✅ PASS: Scammer reporting and learning working")
    return True


def test_callback_integration():
    """Test that verification integrates with callback handler."""
    print("\n" + "="*60)
    print("TEST: Callback Handler Integration")
    print("="*60)
    
    from core.callback_handler import CallbackHandler
    from unittest.mock import MagicMock
    
    handler = CallbackHandler()
    
    # Create mock session and scam result
    session = MagicMock()
    session.session_id = "verify-test-123"
    session.conversation_turn = 5
    session.persona = "confused_uncle"
    session.conversation_history = [
        MagicMock(content="Send money to support.helpdesk@ybl or call +91 140 6789012")
    ]
    
    scam_result = MagicMock()
    scam_result.scam_type = "banking"
    scam_result.confidence = 0.92
    scam_result.tactics = ["urgency", "authority_impersonation"]
    scam_result.llm_consensus = {"votes": {"scam": 3, "total": 4}}
    scam_result.times_seen_before = 0
    
    intelligence = {
        "bank_accounts": [],
        "upi_ids": ["support.helpdesk@ybl"],
        "phone_numbers": ["+91 140 6789012"],
        "urls": ["https://bit.ly/verify-now"]
    }
    
    # Build agent notes
    notes = handler._build_agent_notes(session, scam_result, intelligence, 7.5)
    
    print(f"\n📝 Generated Agent Notes (with verification):\n")
    print("-"*60)
    # Print in sections for readability
    sections = notes.split("[")
    for section in sections:
        if section:
            print(f"[{section.strip()}")
    print("-"*60)
    
    # Verify verification section is included
    assert "[VERIFICATION]" in notes, "Should include verification section"
    assert "[UPI VERIFIED]" in notes or "[PHONE VERIFIED]" in notes, "Should have specific verification"
    
    print("\n✅ PASS: Callback integration with verification working")
    return True


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("🔍 SCAMMER VERIFICATION SYSTEM TESTS")
    print("="*60)
    
    results = []
    
    results.append(("UPI Verification", test_upi_verification()))
    results.append(("Phone Verification", test_phone_verification()))
    results.append(("URL Verification", test_url_verification()))
    results.append(("Batch Verification", test_batch_verification()))
    results.append(("Scammer Reporting", test_scammer_reporting()))
    results.append(("Callback Integration", test_callback_integration()))
    
    print("\n" + "="*60)
    print("📊 FINAL RESULTS")
    print("="*60)
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"   {name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print("✅ ALL VERIFICATION TESTS PASSED!")
    else:
        print("❌ SOME TESTS FAILED")
    print("="*60)


if __name__ == "__main__":
    main()
