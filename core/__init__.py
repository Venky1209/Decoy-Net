"""
Core module for honeypot system.
Direct imports are preferred to avoid circular dependencies.

Usage:
    from core.scam_detector import ScamDetector
    from core.enhanced_detector import EnhancedScamDetector
    from core.agent import HoneypotAgent
    etc.
"""

# Intentionally minimal exports to avoid circular imports
# Import directly from submodules instead

__all__ = [
    "ScamDetector",
    "EnhancedScamDetector", 
    "HoneypotAgent",
    "SessionManager",
    "IntelligenceExtractor",
    "CallbackHandler",
    "PatternMemory",
    "MultiLLMDetector"
]

# Lazy imports - only load when accessed
def __getattr__(name):
    if name == "ScamDetector":
        from core.scam_detector import ScamDetector
        return ScamDetector
    elif name == "EnhancedScamDetector":
        from core.enhanced_detector import EnhancedScamDetector
        return EnhancedScamDetector
    elif name == "HoneypotAgent":
        from core.agent import HoneypotAgent
        return HoneypotAgent
    elif name == "SessionManager":
        from core.session_manager import SessionManager
        return SessionManager
    elif name == "IntelligenceExtractor":
        from core.intelligence_extractor import IntelligenceExtractor
        return IntelligenceExtractor
    elif name == "CallbackHandler":
        from core.callback_handler import CallbackHandler
        return CallbackHandler
    elif name == "PatternMemory":
        from core.pattern_memory import PatternMemory
        return PatternMemory
    elif name == "MultiLLMDetector":
        from core.multi_llm_detector import MultiLLMDetector
        return MultiLLMDetector
    raise AttributeError(f"module 'core' has no attribute '{name}'")
