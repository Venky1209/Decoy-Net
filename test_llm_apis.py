"""Test individual LLM APIs directly."""
import asyncio
import sys
sys.path.insert(0, 'd:\\honeypot')

from config import settings

async def test_groq():
    """Test Groq API directly."""
    print(f"\n=== Testing Groq API (model: {settings.GROQ_MODEL}) ===")
    try:
        from groq import Groq
        client = Groq(api_key=settings.GROQ_API_KEY)
        
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=settings.GROQ_MODEL,
            messages=[{"role": "user", "content": "Say 'Hello, I work!' and nothing else."}],
            temperature=0.1,
            max_tokens=50
        )
        
        result = response.choices[0].message.content
        print(f"SUCCESS: {result}")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        return False

async def test_gemini():
    """Test Gemini API directly."""
    print(f"\n=== Testing Gemini API (model: {settings.GEMINI_MODEL}) ===")
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
        
        model = genai.GenerativeModel(settings.GEMINI_MODEL)
        
        response = await asyncio.to_thread(
            model.generate_content,
            "Say 'Hello, I work!' and nothing else.",
            generation_config={"temperature": 0.1, "max_output_tokens": 50}
        )
        
        result = response.text
        print(f"SUCCESS: {result}")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    print("Testing LLM APIs...")
    print(f"Groq Key: {settings.GROQ_API_KEY[:8]}...")
    print(f"Gemini Key: {settings.GEMINI_API_KEY[:8]}...")
    
    groq_ok = await test_groq()
    gemini_ok = await test_gemini()
    
    print(f"\n=== Summary ===")
    print(f"Groq: {'OK' if groq_ok else 'FAILED'}")
    print(f"Gemini: {'OK' if gemini_ok else 'FAILED'}")

if __name__ == "__main__":
    asyncio.run(main())
