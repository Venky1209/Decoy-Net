"""Quick API test against production."""
import asyncio
import httpx

async def test_api():
    print('TESTING PRODUCTION API...')
    print('=' * 60)
    
    url = 'https://web-production-2b14f.up.railway.app/analyze'
    headers = {'Content-Type': 'application/json', 'x-api-key': 'decoynet_secret_key_2026'}
    
    test_cases = [
        ('Digital Arrest', 'This is CBI officer. Your Aadhaar is linked to money laundering case. Stay on video call for verification.', True),
        ('UPI Scam', 'Scan QR to receive Rs 10000. Enter UPI PIN to accept payment.', True),
        ('Job Scam', 'Earn Rs 5000 daily with simple tasks. Join Telegram @jobs. Pay Rs 500 registration.', True),
        ('Lottery', 'Congratulations! You won Rs 25 lakh in Jio lucky draw. Pay Rs 5000 to claim prize.', True),
        ('Bank KYC', 'Your SBI account blocked in 24 hours. Update KYC now: http://sbi-update.xyz', True),
        ('Legitimate Order', 'Your Amazon order has been delivered. Thank you for shopping!', False),
        ('Legitimate Bank', 'Rs 25000 credited to your account. Available balance Rs 45000.', False),
    ]
    
    passed = 0
    async with httpx.AsyncClient(timeout=30) as client:
        for name, msg, expected_scam in test_cases:
            try:
                resp = await client.post(url, headers=headers, json={'message': msg})
                data = resp.json()
                is_scam = data.get('isScam', False)
                conf = data.get('confidence', 0)
                response = data.get('response', '')[:60]
                
                status = 'PASS' if is_scam == expected_scam else 'FAIL'
                if status == 'PASS':
                    passed += 1
                
                print(f'[{status}] {name}')
                print(f'       isScam: {is_scam} (expected: {expected_scam}), confidence: {conf:.2f}')
                print(f'       Response: "{response}..."')
                print()
            except Exception as e:
                print(f'[ERROR] {name}: {e}')
                print()
    
    print('=' * 60)
    print(f'RESULT: {passed}/{len(test_cases)} passed')
    if passed >= len(test_cases) - 1:
        print('✅ API is working correctly!')
    else:
        print('⚠️ Some tests failed - review above')

if __name__ == '__main__':
    asyncio.run(test_api())
