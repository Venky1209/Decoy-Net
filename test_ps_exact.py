"""
Test against EXACT Problem Statement examples.
This is what GUVI will send - we must handle it PERFECTLY.
"""
import httpx
import json
import asyncio

# Local test URL
BASE_URL = "http://127.0.0.1:8001"
API_KEY = "decoynet_secret_key_2026"
HEADERS = {"Content-Type": "application/json", "x-api-key": API_KEY}


async def test_ps_examples():
    """Test with EXACT examples from Problem Statement."""
    
    print("=" * 70)
    print("TESTING EXACT PROBLEM STATEMENT EXAMPLES")
    print("=" * 70)
    
    async with httpx.AsyncClient(timeout=60) as client:
        
        # ====================================================================
        # PS Section 6.1: First Message (Start of Conversation)
        # ====================================================================
        print("\n📋 TEST 1: PS Section 6.1 - First Message")
        first_message = {
            "sessionId": "wertyu-dfghj-ertyui",
            "message": {
                "sender": "scammer",
                "text": "Your bank account will be blocked today. Verify immediately.",
                "timestamp": "2026-01-21T10:15:30Z"
            },
            "conversationHistory": [],
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }
        
        resp = await client.post(f"{BASE_URL}/", headers=HEADERS, json=first_message)
        print(f"  Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Response: {json.dumps(data, indent=4)}")
            
            # Validate EXACT format from PS Section 8
            assert "status" in data, "Missing 'status' field"
            assert "reply" in data, "Missing 'reply' field"
            assert data["status"] == "success", f"Status should be 'success', got '{data['status']}'"
            assert len(data["reply"]) > 0, "Reply should not be empty"
            print("  ✅ PASS - Format matches PS Section 8")
        else:
            print(f"  ❌ FAIL - {resp.text}")
        
        # ====================================================================
        # PS Section 6.2: Second Message (Follow-Up)
        # ====================================================================
        print("\n📋 TEST 2: PS Section 6.2 - Second Message (with history)")
        second_message = {
            "sessionId": "wertyu-dfghj-ertyui",
            "message": {
                "sender": "scammer",
                "text": "Share your UPI ID to avoid account suspension.",
                "timestamp": "2026-01-21T10:17:10Z"
            },
            "conversationHistory": [
                {
                    "sender": "scammer",
                    "text": "Your bank account will be blocked today. Verify immediately.",
                    "timestamp": "2026-01-21T10:15:30Z"
                },
                {
                    "sender": "user",
                    "text": "Why will my account be blocked?",
                    "timestamp": "2026-01-21T10:16:10Z"
                }
            ],
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }
        
        resp = await client.post(f"{BASE_URL}/", headers=HEADERS, json=second_message)
        print(f"  Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Response: {json.dumps(data, indent=4)}")
            
            # Validate format
            assert data["status"] == "success"
            assert "upi" in data["reply"].lower() or "?" in data["reply"], "Should ask about UPI"
            print("  ✅ PASS - Handles follow-up with history")
        else:
            print(f"  ❌ FAIL - {resp.text}")
        
        # ====================================================================
        # TEST 3: No sessionId (should auto-generate)
        # ====================================================================
        print("\n📋 TEST 3: Missing sessionId (should auto-generate)")
        no_session = {
            "message": {
                "sender": "scammer",
                "text": "I am from RBI. Your account has suspicious activity.",
                "timestamp": "2026-01-21T10:20:00Z"
            }
        }
        
        resp = await client.post(f"{BASE_URL}/", headers=HEADERS, json=no_session)
        print(f"  Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Response: {json.dumps(data, indent=4)}")
            print("  ✅ PASS - Handles missing sessionId")
        else:
            print(f"  ❌ FAIL - {resp.text}")
        
        # ====================================================================
        # TEST 4: String message format (alternative)
        # ====================================================================
        print("\n📋 TEST 4: Simple string message format")
        simple_message = {
            "sessionId": "simple-test-123",
            "message": "Send Rs 5000 to avoid legal action."
        }
        
        resp = await client.post(f"{BASE_URL}/", headers=HEADERS, json=simple_message)
        print(f"  Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Response: {json.dumps(data, indent=4)}")
            print("  ✅ PASS - Handles string message format")
        else:
            print(f"  ❌ FAIL - {resp.text}")
        
        # ====================================================================
        # TEST 5: WhatsApp channel
        # ====================================================================
        print("\n📋 TEST 5: WhatsApp channel with Hindi")
        whatsapp_message = {
            "sessionId": "whatsapp-test-456",
            "message": {
                "sender": "scammer",
                "text": "Aapka KYC expire ho gaya hai. Abhi update karein.",
                "timestamp": "2026-01-21T11:00:00Z"
            },
            "metadata": {
                "channel": "WhatsApp",
                "language": "Hindi",
                "locale": "IN"
            }
        }
        
        resp = await client.post(f"{BASE_URL}/", headers=HEADERS, json=whatsapp_message)
        print(f"  Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Response: {json.dumps(data, indent=4)}")
            print("  ✅ PASS - Handles WhatsApp/Hindi")
        else:
            print(f"  ❌ FAIL - {resp.text}")
    
    print("\n" + "=" * 70)
    print("PS EXAMPLES TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_ps_examples())
