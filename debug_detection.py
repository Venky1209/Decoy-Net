"""Debug script for enhanced detector - bypasses circular imports."""
import asyncio
import logging
import sys

# Configure logging first
logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Direct imports to avoid circular dependency via core/__init__.py
sys.path.insert(0, 'd:\\honeypot')

async def test_detection():
    # Import inside function to control order
    from config import settings
    print(f"API Keys: Groq={settings.GROQ_API_KEY[:8]}... Gemini={settings.GEMINI_API_KEY[:8]}...")
    
    # Import detector directly (not from core package)
    from core.enhanced_detector import EnhancedScamDetector
    
    detector = EnhancedScamDetector(use_llm=True, use_memory=False)
    
    message = "URGENT: Your SBI bank account is BLOCKED. Click link immediately to update KYC or face police action."
    
    print(f"\n--- Testing Message ---")
    print(f"Message: {message[:80]}...")
    print()
    
    try:
        result = await detector.detect(message, conversation_history=[], intelligence={})
        
        print(f"=== RESULT ===")
        print(f"is_scam: {result.is_scam}")
        print(f"confidence: {result.confidence:.3f}")
        print(f"\nScore Breakdown:")
        print(f"  keyword_score: {result.keyword_score:.3f}")
        print(f"  pattern_score: {result.pattern_score:.3f}")
        print(f"  context_score: {result.context_score:.3f}")
        print(f"  memory_boost: {result.memory_boost:.3f}")
        print(f"  llm_confidence: {result.llm_confidence:.3f}")
        print(f"\nScam Type: {result.scam_type}")
        print(f"Threat Level: {result.threat_level}/10")
        print(f"Tactics: {result.tactics}")
        print(f"\nReasoning: {result.reasoning}")
        
        if result.llm_consensus:
            print(f"\nLLM Consensus: {result.llm_consensus}")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_detection())
