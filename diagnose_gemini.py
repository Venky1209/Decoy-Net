"""Deep diagnostic for Gemini response."""
import asyncio
import sys
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, 'd:\\honeypot')

async def test_gemini_deep():
    from config import settings
    import google.generativeai as genai
    
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel(settings.GEMINI_MODEL)
    
    message = "URGENT: Your SBI bank account is BLOCKED. Transfer Rs.5000 to UPI scammer@upi immediately to avoid ARREST. Call 9876543210 now!"
    
    prompt = f'''You are an expert fraud detection AI. Analyze this message and determine if it's a scam.

MESSAGE:
"{message}"

Analyze for:
1. Urgency tactics (immediate action required)
2. Authority impersonation (bank, govt, company)
3. Financial requests (money transfer, OTP, credentials)
4. Suspicious URLs or contact info
5. Emotional manipulation (fear, greed, emergency)
6. Too-good-to-be-true offers

Respond in this exact JSON format:
{{"is_scam": true/false, "confidence": 0.0-1.0, "scam_type": "banking/upi/phishing/lottery/job/impersonation/other/none", "reasoning": "brief explanation"}}

JSON Response:'''

    print(f"Model: {settings.GEMINI_MODEL}")
    print(f"Prompt length: {len(prompt)} chars")
    print("="*60)
    
    try:
        response = await asyncio.to_thread(
            model.generate_content,
            prompt,
            generation_config={"temperature": 0.1, "max_output_tokens": 300}
        )
        
        print("\n=== RAW GEMINI RESPONSE ===")
        print(response.text)
        print("\n=== END RAW RESPONSE ===")
        
        # Try parsing
        import json
        import re
        
        text = response.text.strip()
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        text = text.strip()
        
        print(f"\n=== CLEANED TEXT ===")
        print(text)
        
        try:
            parsed = json.loads(text)
            print(f"\n=== PARSED JSON ===")
            print(f"is_scam: {parsed.get('is_scam')}")
            print(f"confidence: {parsed.get('confidence')}")
            print(f"scam_type: {parsed.get('scam_type')}")
            print(f"reasoning: {parsed.get('reasoning')}")
        except Exception as e:
            print(f"\nJSON parse failed: {e}")
            
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_gemini_deep())
