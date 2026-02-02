"""Quick test for session_id auto-generation on local server."""
import httpx
import time

time.sleep(2)  # Wait for server to start

url = 'http://127.0.0.1:8001/analyze'
headers = {'Content-Type': 'application/json', 'x-api-key': 'decoynet_secret_key_2026'}

# Test 1: No session ID
print('Test 1: No session_id...')
try:
    resp = httpx.post(url, headers=headers, json={'message': 'Hello'}, timeout=30)
    print(f'  Status: {resp.status_code}')
    if resp.status_code == 200:
        data = resp.json()
        sid = data.get('sessionId', 'MISSING')
        print(f'  Session ID auto-generated: {sid}')
        print(f'  ✅ PASS' if sid != 'MISSING' and len(sid) > 10 else '  ❌ FAIL')
    else:
        print(f'  Error: {resp.text[:200]}')
        print(f'  ❌ FAIL')
except Exception as e:
    print(f'  Error: {e}')
    print(f'  ❌ FAIL (server may not be running)')

# Test 2: Session turn tracking
print('\nTest 2: Conversation turn tracking...')
try:
    session = 'test_turn_local'
    
    # Turn 1
    resp1 = httpx.post(url, headers=headers, json={'sessionId': session, 'message': 'Hello bank'}, timeout=30)
    turn1 = resp1.json().get('conversationTurn', 0) if resp1.status_code == 200 else 0
    print(f'  Turn 1: {turn1}')
    
    # Turn 2 - same session
    resp2 = httpx.post(url, headers=headers, json={'sessionId': session, 'message': 'What is my balance?'}, timeout=30)
    turn2 = resp2.json().get('conversationTurn', 0) if resp2.status_code == 200 else 0
    print(f'  Turn 2: {turn2}')
    
    if turn2 > turn1:
        print(f'  ✅ PASS - Turn incremented from {turn1} to {turn2}')
    else:
        print(f'  ❌ FAIL - Turn did not increment')
except Exception as e:
    print(f'  Error: {e}')
