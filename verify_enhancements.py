import sys
import os
import asyncio
import time
sys.path.append(os.getcwd())

from utils.patterns import CRYPTO_KEYWORDS, CRYPTO_WALLET_PATTERNS
from utils.personas import PERSONAS
from core.intelligence_extractor import IntelligenceExtractor
from core.request_queue import RateLimitAwareQueue

async def test_enhancements():
    errors = []
    
    print("🔬 Verifying Honeypot Enhancements...\n")
    
    # 1. Verify Patterns
    print(f"1. Checking Scam Patterns...")
    if "bitcoin" in CRYPTO_KEYWORDS:
        print("   ✅ Crypto keywords present")
    else:
        errors.append("❌ Crypto keywords missing")
        
    if len(CRYPTO_WALLET_PATTERNS) >= 4:
        print(f"   ✅ Crypto wallet regexes present ({len(CRYPTO_WALLET_PATTERNS)})")
    else:
        errors.append("❌ Crypto wallet regexes missing/incomplete")

    # 2. Verify Personas
    print(f"\n2. Checking Persona Variations...")
    uncle = PERSONAS.get("elderly_uncle")
    if any("chashma" in p for p in uncle.common_phrases):
        print("   ✅ Elderly uncle has new phrases")
    else:
        errors.append("❌ Elderly uncle missing new phrases")
        
    student = PERSONAS.get("college_student")
    if any("wifi" in p for p in student.common_phrases):
        print("   ✅ Student has new phrases")
    else:
        errors.append("❌ Student missing new phrases")

    # 3. Verify Intel Extraction
    print(f"\n3. Checking Intelligence Extraction...")
    extractor = IntelligenceExtractor()
    text = "Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately"
    res = extractor.extract_all(text)
    wallets = res.get("crypto_wallets", [])
    if "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in wallets:
        print(f"   ✅ Extracted BTC wallet: {wallets[0]}")
    else:
        errors.append(f"❌ Failed to extract BTC wallet. Got: {wallets}")

    # 4. Verify Burst Handling logic
    print(f"\n4. Checking Burst Handling...")
    queue = RateLimitAwareQueue(max_concurrent=5)
    
    client_id = "spammer_session_123"
    allowed_count = 0
    blocked_count = 0
    
    # Simulate 10 requests
    for i in range(10):
        if queue.check_client_limit(client_id, limit=5, window=60):
            allowed_count += 1
        else:
            blocked_count += 1
            
    print(f"   Requests: 10 | Allowed: {allowed_count} | Blocked: {blocked_count}")
    
    if allowed_count == 5 and blocked_count == 5:
        print("   ✅ Burst protection working (5 allowed, 5 blocked)")
    else:
        errors.append(f"❌ Burst logic failed. Allowed: {allowed_count}, Blocked: {blocked_count}")

    print("\n" + "="*40)
    if not errors:
        print("🎉 ALL CHECKS PASSED!")
        return 0
    else:
        print("⚠️ ERRORS FOUND:")
        for e in errors:
            print(e)
        return 1

if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(test_enhancements()))
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
