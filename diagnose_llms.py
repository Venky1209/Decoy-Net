"""Diagnose individual LLM responses for scam detection."""
import asyncio
import sys
import os

# Fix encoding for Windows
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, 'd:\\honeypot')

async def test_each_llm():
    from config import settings
    from core.multi_llm_detector import MultiLLMDetector, SCAM_DETECTION_PROMPT
    
    detector = MultiLLMDetector()
    
    message = "URGENT: Your SBI bank account is BLOCKED. Transfer Rs.5000 to UPI scammer@upi immediately to avoid ARREST. Call 9876543210 now!"
    
    print(f"Testing message: {message[:60]}...")
    print(f"\nGroq Model: {settings.GROQ_MODEL}")
    print(f"Gemini Model: {settings.GEMINI_MODEL}")
    print("="*60)
    
    # Test Groq individually
    print("\n[1] Testing GROQ...")
    try:
        groq_result = await detector._detect_groq(message)
        print(f"    Success: {groq_result.success}")
        print(f"    Is Scam: {groq_result.is_scam}")
        print(f"    Confidence: {groq_result.confidence}")
        print(f"    Scam Type: {groq_result.scam_type}")
        print(f"    Reasoning: {groq_result.reasoning[:100]}..." if groq_result.reasoning else "    No reasoning")
        if groq_result.error:
            print(f"    ERROR: {groq_result.error}")
    except Exception as e:
        print(f"    EXCEPTION: {e}")
    
    # Test Gemini individually
    print("\n[2] Testing GEMINI...")
    try:
        gemini_result = await detector._detect_gemini(message)
        print(f"    Success: {gemini_result.success}")
        print(f"    Is Scam: {gemini_result.is_scam}")
        print(f"    Confidence: {gemini_result.confidence}")
        print(f"    Scam Type: {gemini_result.scam_type}")
        print(f"    Reasoning: {gemini_result.reasoning[:100]}..." if gemini_result.reasoning else "    No reasoning")
        if gemini_result.error:
            print(f"    ERROR: {gemini_result.error}")
    except Exception as e:
        print(f"    EXCEPTION: {e}")
    
    # Test ensemble
    print("\n[3] Testing ENSEMBLE...")
    try:
        ensemble_result = await detector.detect_with_ensemble(message)
        print(f"    Is Scam: {ensemble_result.get('is_scam')}")
        print(f"    Confidence: {ensemble_result.get('ensemble_confidence')}")
        print(f"    Votes: {ensemble_result.get('votes')}")
        print(f"    Responses: {len(ensemble_result.get('responses', []))}")
        for r in ensemble_result.get('responses', []):
            print(f"      - {r['provider']}: is_scam={r['is_scam']}, conf={r['confidence']}")
    except Exception as e:
        print(f"    EXCEPTION: {e}")

if __name__ == "__main__":
    asyncio.run(test_each_llm())
