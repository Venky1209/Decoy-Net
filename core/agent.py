"""
Honeypot AI Agent with LLM integration.
Manages persona, generates responses, and implements conversation strategies.
"""
import asyncio
import random
import json
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from api.models import ConversationState
from utils.personas import Persona, select_persona_for_scam, get_persona
from utils.prompts import get_agent_prompt, get_state_strategy, BREADCRUMB_STRATEGIES
from config import settings

logger = logging.getLogger(__name__)


@dataclass
class AgentResponse:
    """Response from the honeypot agent."""
    response: str
    state: ConversationState
    persona: str
    notes: str
    strategy_used: str
    breadcrumb_used: Optional[str] = None


class LLMClient:
    """
    Multi-model LLM client with fallback support.
    Primary: Groq (fast), Fallback: Gemini (reliable)
    """
    
    def __init__(self):
        self._groq_client = None
        self._gemini_model = None
        self._init_clients()
    
    def _init_clients(self):
        """Initialize LLM clients."""
        # Initialize Groq
        if settings.GROQ_API_KEY:
            try:
                from groq import Groq
                self._groq_client = Groq(api_key=settings.GROQ_API_KEY)
                logger.info("Groq client initialized")
            except ImportError:
                logger.warning("groq package not installed")
            except Exception as e:
                logger.warning(f"Failed to initialize Groq: {e}")
        
        # Initialize Gemini
        if settings.GEMINI_API_KEY:
            try:
                import google.generativeai as genai
                genai.configure(api_key=settings.GEMINI_API_KEY)
                self._gemini_model = genai.GenerativeModel('gemini-1.5-flash')
                logger.info("Gemini client initialized")
            except ImportError:
                logger.warning("google-generativeai package not installed")
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini: {e}")
    
    async def generate(self, prompt: str, max_tokens: int = 256) -> str:
        """
        Generate response using available LLM with fallback.
        """
        # Try Groq first (faster)
        if self._groq_client:
            try:
                response = await self._call_groq(prompt, max_tokens)
                if response:
                    return response
            except Exception as e:
                logger.warning(f"Groq failed, falling back to Gemini: {e}")
        
        # Fallback to Gemini
        if self._gemini_model:
            try:
                response = await self._call_gemini(prompt, max_tokens)
                if response:
                    return response
            except Exception as e:
                logger.error(f"Gemini also failed: {e}")
        
        # Final fallback - return a generic confused response
        return self._get_fallback_response()
    
    async def _call_groq(self, prompt: str, max_tokens: int) -> Optional[str]:
        """Call Groq API."""
        # Run in thread pool since groq is sync
        loop = asyncio.get_event_loop()
        
        def _sync_call():
            completion = self._groq_client.chat.completions.create(
                model="llama-3.1-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=0.7
            )
            return completion.choices[0].message.content
        
        return await loop.run_in_executor(None, _sync_call)
    
    async def _call_gemini(self, prompt: str, max_tokens: int) -> Optional[str]:
        """Call Gemini API."""
        loop = asyncio.get_event_loop()
        
        def _sync_call():
            response = self._gemini_model.generate_content(
                prompt,
                generation_config={
                    "max_output_tokens": max_tokens,
                    "temperature": 0.7
                }
            )
            return response.text
        
        return await loop.run_in_executor(None, _sync_call)
    
    def _get_fallback_response(self) -> str:
        """Return a generic confused response when LLMs fail."""
        fallbacks = [
            "Arey, samajh nahi aaya. Phir se bolo?",
            "What? I am not understanding...",
            "Sorry, can you explain again please?",
            "Haan ji, main sun raha hoon. Aap kya bole?",
            "My network is slow, please repeat."
        ]
        return random.choice(fallbacks)


class HoneypotAgent:
    """
    Main honeypot agent that manages personas and generates responses.
    """
    
    def __init__(self):
        self.llm = LLMClient()
        self._conversation_states: Dict[str, ConversationState] = {}
    
    async def generate_response(
        self,
        message: str,
        session: Any,
        scam_result: Any,
        intelligence: Dict[str, Any]
    ) -> AgentResponse:
        """
        Generate a response to the scammer.
        
        Args:
            message: Current scammer message
            session: Session object with conversation state
            scam_result: Detection result from ScamDetector
            intelligence: Extracted intelligence so far
            
        Returns:
            AgentResponse with persona response and metadata
        """
        # Select or continue with persona
        if not session.persona:
            persona = self._select_persona(scam_result.scam_type)
            session.persona = persona.name
        else:
            persona = get_persona(session.persona)
            if not persona:
                persona = self._select_persona(scam_result.scam_type)
        
        # Determine conversation state
        new_state = self._determine_state(
            current_state=session.state,
            scam_result=scam_result,
            intelligence=intelligence,
            turn=session.conversation_turn
        )
        
        # Get strategy for current state
        strategy = get_state_strategy(new_state.value)
        
        # Select breadcrumb strategy
        breadcrumb = self._select_breadcrumb(intelligence)
        
        # Build intelligence summary
        intel_summary = self._build_intel_summary(intelligence)
        
        # Build full prompt
        prompt = get_agent_prompt(
            persona_description=persona.system_prompt_extension,
            conversation_state=new_state.value,
            strategy=strategy,
            intelligence_summary=intel_summary,
            breadcrumb_strategy=breadcrumb or ""
        )
        
        # Add conversation context
        context = self._build_context(session.messages, message)
        full_prompt = f"{prompt}\n\n**CONVERSATION:**\n{context}\n\n**SCAMMER'S LATEST MESSAGE:**\n{message}\n\n**YOUR RESPONSE (as {persona.display_name}):**"
        
        # Generate response
        raw_response = await self.llm.generate(full_prompt)
        
        # Add human touches
        final_response = self._add_human_touches(raw_response, persona)
        
        # Build agent notes
        notes = self._build_agent_notes(
            persona=persona,
            state=new_state,
            scam_result=scam_result,
            strategy=strategy,
            breadcrumb=breadcrumb
        )
        
        return AgentResponse(
            response=final_response,
            state=new_state,
            persona=persona.name,
            notes=notes,
            strategy_used=strategy[:100],
            breadcrumb_used=breadcrumb
        )
    
    def _select_persona(self, scam_type: Optional[str]) -> Persona:
        """Select appropriate persona for the scam type."""
        return select_persona_for_scam(scam_type or "unknown")
    
    def _determine_state(
        self,
        current_state: ConversationState,
        scam_result: Any,
        intelligence: Dict[str, Any],
        turn: int
    ) -> ConversationState:
        """
        Determine the appropriate conversation state.
        
        State machine:
        PROBE -> ENGAGE -> EXTRACT -> VERIFY -> DEEPEN -> EXIT
        """
        if not current_state or current_state == ConversationState.PROBE:
            # First few turns - probe and understand
            if turn < 3:
                return ConversationState.PROBE
            else:
                return ConversationState.ENGAGE
        
        elif current_state == ConversationState.ENGAGE:
            # Move to extraction after building rapport
            if turn >= 4:
                return ConversationState.EXTRACT
            return ConversationState.ENGAGE
        
        elif current_state == ConversationState.EXTRACT:
            # Have we extracted enough?
            intel_count = self._count_intelligence(intelligence)
            if intel_count >= 2:
                return ConversationState.VERIFY
            elif turn >= 10:
                return ConversationState.VERIFY
            return ConversationState.EXTRACT
        
        elif current_state == ConversationState.VERIFY:
            # Move to deepen or exit
            if turn >= 15:
                return ConversationState.EXIT
            return ConversationState.DEEPEN
        
        elif current_state == ConversationState.DEEPEN:
            # Check exit conditions
            if turn >= 18:
                return ConversationState.EXIT
            intel_count = self._count_intelligence(intelligence)
            if intel_count >= 4:
                return ConversationState.EXIT
            return ConversationState.DEEPEN
        
        return ConversationState.EXIT
    
    def _count_intelligence(self, intelligence: Dict) -> int:
        """Count total intelligence items extracted."""
        count = 0
        for key in ["bank_accounts", "upi_ids", "phone_numbers", "urls", "emails"]:
            count += len(intelligence.get(key, []))
        return count
    
    def _select_breadcrumb(self, intelligence: Dict) -> Optional[str]:
        """Select breadcrumb strategy based on missing intelligence."""
        strategies = list(BREADCRUMB_STRATEGIES.values())
        
        # Prioritize based on what we're missing
        if not intelligence.get("bank_accounts"):
            return BREADCRUMB_STRATEGIES.get("confused_disclosure")
        elif not intelligence.get("upi_ids"):
            return BREADCRUMB_STRATEGIES.get("incomplete_action")
        elif not intelligence.get("phone_numbers"):
            return BREADCRUMB_STRATEGIES.get("verification_request")
        else:
            # Random strategy
            return random.choice(strategies) if random.random() > 0.5 else None
    
    def _build_intel_summary(self, intelligence: Dict) -> str:
        """Build summary of extracted intelligence."""
        parts = []
        
        if intelligence.get("bank_accounts"):
            parts.append(f"Bank accounts: {', '.join(intelligence['bank_accounts'])}")
        if intelligence.get("upi_ids"):
            parts.append(f"UPI IDs: {', '.join(intelligence['upi_ids'])}")
        if intelligence.get("phone_numbers"):
            parts.append(f"Phone numbers: {', '.join(intelligence['phone_numbers'])}")
        if intelligence.get("urls"):
            parts.append(f"URLs: {', '.join(intelligence['urls'][:3])}")
        if intelligence.get("keywords"):
            parts.append(f"Keywords: {', '.join(intelligence['keywords'][:5])}")
        
        if not parts:
            return "No intelligence extracted yet."
        
        return "\n".join(parts)
    
    def _build_context(self, messages: List, current_message: str) -> str:
        """Build conversation context string."""
        context_parts = []
        
        # Include last 5 messages for context
        recent = messages[-10:] if len(messages) > 10 else messages
        
        for msg in recent:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            prefix = "Scammer:" if role == "user" else "You:"
            context_parts.append(f"{prefix} {content}")
        
        return "\n".join(context_parts)
    
    def _add_human_touches(self, response: str, persona: Persona) -> str:
        """
        Add human-like imperfections to response.
        - Typos (with corrections)
        - Persona-specific vocabulary
        - Natural variations
        """
        if not settings.ENABLE_TYPOS:
            return response
        
        # Add occasional typo with correction (15% chance)
        if random.random() < 0.15 and len(response) > 20:
            response = self._add_typo_with_correction(response)
        
        # Add persona-specific starter phrase occasionally
        if random.random() < 0.2 and persona.common_phrases:
            phrase = random.choice(persona.common_phrases)
            if not response.startswith(phrase):
                response = f"{phrase} {response}"
        
        return response
    
    def _add_typo_with_correction(self, text: str) -> str:
        """Add a typo followed by correction."""
        words = text.split()
        if len(words) < 4:
            return text
        
        # Pick a word to typo
        idx = random.randint(1, min(5, len(words) - 1))
        word = words[idx]
        
        if len(word) > 3:
            # Create typo by swapping or duplicating letter
            typo = word[:2] + word[1] + word[2:]  # Duplicate a letter
            words.insert(idx, typo + "...")
            words[idx + 1] = "sorry, " + word
        
        return " ".join(words)
    
    def _build_agent_notes(
        self,
        persona: Persona,
        state: ConversationState,
        scam_result: Any,
        strategy: str,
        breadcrumb: Optional[str]
    ) -> str:
        """Build detailed agent notes for logging/review."""
        notes = {
            "persona_used": persona.display_name,
            "conversation_state": state.value,
            "scam_detected": scam_result.is_scam,
            "scam_type": scam_result.scam_type,
            "confidence": f"{scam_result.confidence:.2f}",
            "threat_level": scam_result.threat_level,
            "tactics_detected": scam_result.tactics,
            "strategy_summary": strategy[:100] + "..." if len(strategy) > 100 else strategy,
            "breadcrumb_strategy": breadcrumb
        }
        
        return json.dumps(notes, indent=2)
