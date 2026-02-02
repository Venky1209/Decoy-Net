"""Test that LLM providers are working."""
import httpx
import time

time.sleep(1)

url = 'http://127.0.0.1:8001/analyze'
headers = {'Content-Type': 'application/json', 'x-api-key': 'decoynet_secret_key_2026'}

print("Testing LLM response quality...")
print("="*50)

# Send a scam message that requires LLM reasoning
resp = httpx.post(url, headers=headers, json={
    'sessionId': 'llm_test_001',
    'message': 'Hello sir, I am calling from Microsoft. Your computer has virus. Give me remote access to fix it.'
}, timeout=60)

if resp.status_code == 200:
    data = resp.json()
    response = data.get('response', '')
    confidence = data.get('confidence', 0)
    is_scam = data.get('isScam', False)
    notes = data.get('agentNotes', '')
    
    print(f"Status: {resp.status_code}")
    print(f"IsScam: {is_scam}")
    print(f"Confidence: {confidence}")
    print(f"Response: {response}")
    print(f"\nNotes: {notes[:200]}...")
    
    # Check if response is from LLM (longer, contextual) or fallback (short, generic)
    if len(response) > 20 and ('?' in response or 'what' in response.lower() or 'kya' in response.lower()):
        print("\n✅ Response appears to be from LLM (contextual, questioning)")
    else:
        print("\n⚠️ Response might be from fallback (check server logs)")
else:
    print(f"Error: {resp.status_code} - {resp.text[:200]}")
