"""Quick local API test."""
import httpx
import asyncio

async def test():
    url = "http://127.0.0.1:8000/analyze"
    headers = {"Content-Type": "application/json", "x-api-key": "decoynet_secret_key_2026"}
    
    print("=" * 50)
    print("LOCAL API VERIFICATION TESTS")
    print("=" * 50)
    
    tests = [
        ("Scam (no session_id)", {"message": "Your SBI account blocked. Update KYC: http://sbi.xyz"}, True),
        ("Legitimate order", {"message": "Your order shipped. Track at amazon.in/track/123"}, False),
        ("With session_id", {"session_id": "test-123", "message": "You won Rs 25 lakh lottery!"}, True),
        ("Hackathon format", {"session_id": "hack", "message": {"sender": "scammer", "text": "Send to UPI: scam@axis", "timestamp": "2026"}}, True),
    ]
    
    async with httpx.AsyncClient(timeout=30) as client:
        for name, body, expected_scam in tests:
            try:
                resp = await client.post(url, headers=headers, json=body)
                data = resp.json()
                is_scam = data.get("isScam", False)
                conf = data.get("confidence", 0)
                session = data.get("sessionId", "")[:12]
                
                status = "✓" if is_scam == expected_scam else "✗"
                print(f"\n{status} {name}")
                print(f"   isScam={is_scam}, conf={conf:.2f}, session={session}...")
                
                # Check UPI extraction
                upi = data.get("extractedIntelligence", {}).get("upiIds", [])
                if upi:
                    print(f"   UPI extracted: {upi}")
                    
            except Exception as e:
                print(f"\n✗ {name}: ERROR - {e}")
    
    print("\n" + "=" * 50)
    print("LOCAL API TESTS COMPLETE")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(test())
