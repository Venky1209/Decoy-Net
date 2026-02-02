"""
GUVI TESTER SIMULATION
=====================
This simulates what a senior GUVI tester would do to evaluate honeypot endpoints.
Tests designed to separate good honeypots from basic ones.

Run: python test_guvi_evaluation.py
"""
import httpx
import asyncio
import json
from datetime import datetime

# Your production endpoint - switch to local for testing
API_URL = "http://127.0.0.1:8001/analyze"  # Local testing
# API_URL = "https://web-production-2b14f.up.railway.app/analyze"  # Production
API_KEY = "decoynet_secret_key_2026"

HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

class GUVITester:
    """Simulates GUVI's evaluation criteria."""
    
    def __init__(self):
        self.results = []
        self.session_counter = 0
    
    def new_session(self):
        self.session_counter += 1
        return f"guvi_eval_{datetime.now().strftime('%H%M%S')}_{self.session_counter}"
    
    async def test_endpoint(self, name: str, payload: dict, expected: dict):
        """Test a single scenario."""
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.post(API_URL, headers=HEADERS, json=payload)
                data = resp.json() if resp.status_code == 200 else {"error": resp.text}
                
                result = {
                    "test": name,
                    "status": resp.status_code,
                    "passed": True,
                    "details": {}
                }
                
                # Check expectations
                if resp.status_code == 200:
                    for key, expected_val in expected.items():
                        actual = data.get(key)
                        if expected_val == "EXISTS":
                            passed = actual is not None
                        elif expected_val == "NOT_EMPTY":
                            passed = actual and len(str(actual)) > 0
                        elif isinstance(expected_val, bool):
                            passed = actual == expected_val
                        elif isinstance(expected_val, str) and expected_val.startswith(">="):
                            passed = actual >= float(expected_val[2:])
                        elif isinstance(expected_val, str) and expected_val.startswith("CONTAINS:"):
                            check_val = expected_val[9:]
                            passed = check_val in str(actual) if actual else False
                        else:
                            passed = actual == expected_val
                        
                        result["details"][key] = {"expected": expected_val, "actual": actual, "passed": passed}
                        if not passed:
                            result["passed"] = False
                else:
                    result["passed"] = False
                    result["details"]["error"] = data.get("error", "Unknown error")
                
                self.results.append(result)
                return result, data
                
            except Exception as e:
                result = {"test": name, "status": "ERROR", "passed": False, "details": str(e)}
                self.results.append(result)
                return result, None
    
    def print_summary(self):
        """Print evaluation summary."""
        print("\n" + "="*70)
        print("GUVI HONEYPOT EVALUATION RESULTS")
        print("="*70)
        
        passed = sum(1 for r in self.results if r["passed"])
        total = len(self.results)
        
        for r in self.results:
            icon = "✅" if r["passed"] else "❌"
            print(f"\n{icon} {r['test']}")
            if not r["passed"]:
                for key, detail in r.get("details", {}).items():
                    if isinstance(detail, dict) and not detail.get("passed"):
                        print(f"   ⚠️  {key}: expected {detail['expected']}, got {detail['actual']}")
        
        print("\n" + "="*70)
        print(f"SCORE: {passed}/{total} ({100*passed//total}%)")
        print("="*70)


async def run_guvi_evaluation():
    """Run complete GUVI-style evaluation."""
    tester = GUVITester()
    
    print("🔍 GUVI SENIOR TESTER EVALUATION")
    print("================================\n")
    
    # ============================================
    # TEST 1: Basic Functionality
    # ============================================
    print("📋 TEST 1: Basic Endpoint Functionality")
    session1 = tester.new_session()
    await tester.test_endpoint(
        name="1.1 Basic Request",
        payload={
            "sessionId": session1,
            "message": "Hello, who is this?"
        },
        expected={
            "sessionId": session1,
            "response": "NOT_EMPTY",
            "isScam": "EXISTS",
            "confidence": "EXISTS"
        }
    )
    
    # ============================================
    # TEST 2: Missing Session ID (Edge Case)
    # ============================================
    print("\n📋 TEST 2: Edge Case - Missing Session ID")
    await tester.test_endpoint(
        name="2.1 No Session ID (should auto-generate)",
        payload={
            "message": "Test message without session"
        },
        expected={
            "sessionId": "NOT_EMPTY",  # Should auto-generate UUID
            "response": "NOT_EMPTY"
        }
    )
    
    # ============================================
    # TEST 3: SCAM DETECTION ACCURACY
    # ============================================
    print("\n📋 TEST 3: Scam Detection Accuracy")
    
    # 3.1 Digital Arrest Scam (2025 trend)
    await tester.test_endpoint(
        name="3.1 Digital Arrest Detection",
        payload={
            "sessionId": tester.new_session(),
            "message": "This is CBI officer speaking. Your Aadhaar is linked to money laundering case. FIR registered. Stay on call or face arrest. Transfer 50000 for bail."
        },
        expected={
            "isScam": True,
            "confidence": ">=0.5"
        }
    )
    
    # 3.2 UPI Fraud
    await tester.test_endpoint(
        name="3.2 UPI Fraud Detection",
        payload={
            "sessionId": tester.new_session(),
            "message": "You won 10 lakh lottery! Send Rs 500 processing fee to scammer@paytm to claim your prize."
        },
        expected={
            "isScam": True,
            "confidence": ">=0.5"
        }
    )
    
    # 3.3 Legitimate Message (should NOT be scam)
    await tester.test_endpoint(
        name="3.3 Legitimate Message (False Positive Check)",
        payload={
            "sessionId": tester.new_session(),
            "message": "Hi, this is Swiggy delivery. Your order is arriving in 10 minutes. Please be available."
        },
        expected={
            "isScam": False
        }
    )
    
    # ============================================
    # TEST 4: INTELLIGENCE EXTRACTION
    # ============================================
    print("\n📋 TEST 4: Intelligence Extraction Quality")
    
    result, data = await tester.test_endpoint(
        name="4.1 Extract UPI ID",
        payload={
            "sessionId": tester.new_session(),
            "message": "Send money to fraudster@ybl for verification"
        },
        expected={
            "isScam": True
        }
    )
    if data and data.get("extractedIntelligence"):
        upi = data["extractedIntelligence"].get("upiIds", [])
        print(f"   📍 Extracted UPI: {upi}")
    
    result, data = await tester.test_endpoint(
        name="4.2 Extract Phone Number",
        payload={
            "sessionId": tester.new_session(),
            "message": "Call our officer at 9876543210 immediately for verification"
        },
        expected={
            "isScam": True
        }
    )
    if data and data.get("extractedIntelligence"):
        phones = data["extractedIntelligence"].get("phoneNumbers", [])
        print(f"   📍 Extracted Phones: {phones}")
    
    # ============================================
    # TEST 5: CONVERSATION CONTINUITY
    # ============================================
    print("\n📋 TEST 5: Conversation Continuity")
    
    conv_session = tester.new_session()
    
    # Turn 1
    result1, data1 = await tester.test_endpoint(
        name="5.1 Conversation Turn 1",
        payload={
            "sessionId": conv_session,
            "message": "Hello, I am from bank. Your account has problem.",
            "conversationHistory": []
        },
        expected={
            "conversationTurn": 1
        }
    )
    response1 = data1.get("response", "") if data1 else ""
    
    # Turn 2 - with history
    await tester.test_endpoint(
        name="5.2 Conversation Turn 2 (with history)",
        payload={
            "sessionId": conv_session,
            "message": "Yes, send me your OTP to fix the problem",
            "conversationHistory": [
                {"role": "user", "content": "Hello, I am from bank. Your account has problem."},
                {"role": "assistant", "content": response1}
            ]
        },
        expected={
            "conversationTurn": 2
        }
    )
    
    # ============================================
    # TEST 6: RESPONSE QUALITY & VARIATION
    # ============================================
    print("\n📋 TEST 6: Response Quality")
    
    # Same message twice - responses should differ
    same_msg = "You need to update KYC. Share your PAN card."
    
    result_a, data_a = await tester.test_endpoint(
        name="6.1 Response Variation Test A",
        payload={"sessionId": tester.new_session(), "message": same_msg},
        expected={"response": "NOT_EMPTY"}
    )
    
    result_b, data_b = await tester.test_endpoint(
        name="6.2 Response Variation Test B",
        payload={"sessionId": tester.new_session(), "message": same_msg},
        expected={"response": "NOT_EMPTY"}
    )
    
    if data_a and data_b:
        resp_a = data_a.get("response", "")
        resp_b = data_b.get("response", "")
        varied = resp_a != resp_b
        print(f"   📍 Response A: {resp_a[:50]}...")
        print(f"   📍 Response B: {resp_b[:50]}...")
        print(f"   {'✅' if varied else '⚠️'} Responses {'vary' if varied else 'are identical (bot-like)'}")
    
    # ============================================
    # TEST 7: RESPONSE REALISM (Human-like)
    # ============================================
    print("\n📋 TEST 7: Human-like Response Check")
    
    result, data = await tester.test_endpoint(
        name="7.1 Natural Response",
        payload={
            "sessionId": tester.new_session(),
            "message": "Sir your computer has virus. I am Microsoft support. Give me remote access."
        },
        expected={"response": "NOT_EMPTY"}
    )
    
    if data:
        response = data.get("response", "")
        # Check for human-like qualities
        checks = {
            "Has question/confusion": "?" in response,
            "Not too short (<10 chars)": len(response) > 10,
            "Not too long (>500 chars)": len(response) < 500,
            "Not robotic 'I am AI'": "i am" not in response.lower() or "ai" not in response.lower()
        }
        for check, passed in checks.items():
            print(f"   {'✅' if passed else '⚠️'} {check}")
    
    # ============================================
    # TEST 8: SCAMMER PROFILE GENERATION
    # ============================================
    print("\n📋 TEST 8: Scammer Profile Generation")
    
    result, data = await tester.test_endpoint(
        name="8.1 Scammer Profile Present",
        payload={
            "sessionId": tester.new_session(),
            "message": "This is Income Tax department. You have pending dues of Rs 5 lakh. Pay now via UPI to avoid penalty."
        },
        expected={
            "isScam": True,
            "scammerProfile": "EXISTS"
        }
    )
    
    if data and data.get("scammerProfile"):
        profile = data["scammerProfile"]
        print(f"   📍 Scam Type: {profile.get('scamType')}")
        print(f"   📍 Threat Level: {profile.get('threatLevel')}")
        print(f"   📍 Tactics: {profile.get('tacticsUsed', [])[:3]}...")
    
    # ============================================
    # FINAL SUMMARY
    # ============================================
    tester.print_summary()


if __name__ == "__main__":
    asyncio.run(run_guvi_evaluation())
