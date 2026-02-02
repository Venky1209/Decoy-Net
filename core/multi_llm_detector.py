"""
Multi-LLM Ensemble Detection System.
Uses multiple LLMs for consensus-based scam detection with higher accuracy.

Supported FREE LLMs:
- Gemini (Google) - Primary
- Groq (Llama 3.1, Mixtral) - Fast inference
- Together AI - Free tier
- Cerebras - Ultra-fast
- Cohere - Command models
"""
import asyncio
import logging
import httpx
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from config import settings

logger = logging.getLogger(__name__)


class LLMProvider(str, Enum):
    POLLINATIONS = "pollinations"  # Priority 1 - No rate limits, new endpoint!
    CEREBRAS = "cerebras"          # Priority 2 - Llama 3.3 70B, GPT-OSS 120B
    GROQ = "groq"                  # Priority 3 - Fast inference
    GEMINI = "gemini"              # Priority 4 - Backup (high rate limits)
    TOGETHER = "together"
    COHERE = "cohere"


@dataclass
class LLMResponse:
    """Response from an LLM."""
    provider: LLMProvider
    is_scam: bool
    confidence: float
    scam_type: Optional[str]
    reasoning: str
    response_time_ms: int
    success: bool
    error: Optional[str] = None


SCAM_DETECTION_PROMPT = """You are an expert fraud detection AI. Analyze this message and determine if it's a scam.

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

JSON Response:"""


class MultiLLMDetector:
    """
    Multi-LLM ensemble for scam detection.
    Uses consensus from multiple models for higher accuracy.
    """
    
    def __init__(self):
        # API Keys - Priority Order: Pollinations → Cerebras → Groq → Gemini
        self.pollinations_key = getattr(settings, 'POLLINATIONS_API_KEY', None)
        self.cerebras_key = getattr(settings, 'CEREBRAS_API_KEY', None)
        self.groq_key = settings.GROQ_API_KEY
        self.gemini_key = settings.GEMINI_API_KEY
        self.together_key = getattr(settings, 'TOGETHER_API_KEY', None)
        self.cohere_key = getattr(settings, 'COHERE_API_KEY', None)
        
        self.timeout = 15.0
    
    async def detect_with_ensemble(
        self, 
        message: str,
        min_consensus: int = 2
    ) -> Dict[str, Any]:
        """
        Run scam detection across multiple LLMs and return consensus.
        
        Args:
            message: Message to analyze
            min_consensus: Minimum LLMs that must agree
            
        Returns:
            Ensemble result with consensus confidence
        """
        # Get available LLMs - Priority Order: Pollinations → Cerebras → Groq → Gemini
        tasks = []
        providers = []
        
        # Priority 1: Pollinations (No rate limits, new endpoint working!)
        if self.pollinations_key:
            tasks.append(self._detect_pollinations(message))
            providers.append(LLMProvider.POLLINATIONS)
        
        # Priority 2: Cerebras (Llama 3.3 70B - fast and reliable)
        if self.cerebras_key:
            tasks.append(self._detect_cerebras(message))
            providers.append(LLMProvider.CEREBRAS)
        
        # Priority 3: Groq (Fast inference)
        if self.groq_key:
            tasks.append(self._detect_groq(message))
            providers.append(LLMProvider.GROQ)
        
        # Priority 4: Gemini (High rate limit backup)
        if self.gemini_key:
            tasks.append(self._detect_gemini(message))
            providers.append(LLMProvider.GEMINI)
        
        # Optional: Together, Cohere
        if self.together_key:
            tasks.append(self._detect_together(message))
            providers.append(LLMProvider.TOGETHER)
        
        if self.cohere_key:
            tasks.append(self._detect_cohere(message))
            providers.append(LLMProvider.COHERE)
        
        if not tasks:
            return {
                "ensemble_confidence": 0.0,
                "is_scam": False,
                "consensus_reached": False,
                "responses": [],
                "error": "No LLM APIs configured"
            }
        
        # Run all detections in parallel
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful_responses = []
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.error(f"{providers[i]} failed: {response}")
            elif isinstance(response, LLMResponse) and response.success:
                successful_responses.append(response)
        
        if not successful_responses:
            return {
                "ensemble_confidence": 0.0,
                "is_scam": False,
                "consensus_reached": False,
                "responses": [],
                "error": "All LLM calls failed"
            }
        
        # Calculate consensus
        return self._calculate_consensus(successful_responses, min_consensus)
    
    def _calculate_consensus(
        self, 
        responses: List[LLMResponse],
        min_consensus: int
    ) -> Dict[str, Any]:
        """Calculate ensemble consensus from multiple LLM responses."""
        
        scam_votes = sum(1 for r in responses if r.is_scam)
        total_votes = len(responses)
        
        # Weighted average confidence
        total_confidence = sum(r.confidence for r in responses)
        avg_confidence = total_confidence / total_votes
        
        # Consensus reached if majority agrees (>= for tie-breaker in favor of scam detection)
        is_scam = scam_votes >= (total_votes / 2)
        consensus_strength = scam_votes / total_votes if is_scam else (total_votes - scam_votes) / total_votes
        
        # Boost confidence if strong consensus
        if consensus_strength >= 0.8:
            avg_confidence = min(avg_confidence * 1.2, 1.0)
        elif consensus_strength <= 0.6:
            avg_confidence = avg_confidence * 0.8
        
        # Get most common scam type
        scam_types = [r.scam_type for r in responses if r.scam_type and r.scam_type != "none"]
        most_common_type = max(set(scam_types), key=scam_types.count) if scam_types else None
        
        # Combine reasoning
        reasonings = [f"[{r.provider.value}] {r.reasoning}" for r in responses]
        
        return {
            "ensemble_confidence": round(avg_confidence, 3),
            "is_scam": is_scam,
            "consensus_reached": consensus_strength >= (min_consensus / total_votes),
            "consensus_strength": round(consensus_strength, 2),
            "scam_type": most_common_type,
            "votes": {
                "scam": scam_votes,
                "not_scam": total_votes - scam_votes,
                "total": total_votes
            },
            "responses": [
                {
                    "provider": r.provider.value,
                    "is_scam": r.is_scam,
                    "confidence": r.confidence,
                    "scam_type": r.scam_type,
                    "response_time_ms": r.response_time_ms
                }
                for r in responses
            ],
            "combined_reasoning": "\n".join(reasonings)
        }
    
    async def _detect_pollinations(self, message: str) -> LLMResponse:
        """Detect scam using Pollinations.ai - OpenAI-compatible endpoint."""
        import time
        start = time.time()
        
        try:
            # Build the prompt for scam detection
            prompt = SCAM_DETECTION_PROMPT.format(message=message)
            
            # Use POST to OpenAI-compatible endpoint (new gen.pollinations.ai API)
            url = "https://gen.pollinations.ai/v1/chat/completions"
            
            # Set up headers with Bearer token auth
            headers = {"Content-Type": "application/json"}
            if self.pollinations_key:
                headers["Authorization"] = f"Bearer {self.pollinations_key}"
            
            payload = {
                "model": "openai",  # OpenAI model via Pollinations
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 500
            }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                
                # Parse OpenAI-compatible response
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                result = self._parse_llm_response(content)
                elapsed = int((time.time() - start) * 1000)
                
                logger.info(f"Pollinations succeeded: is_scam={result.get('is_scam')}, conf={result.get('confidence')}, time={elapsed}ms")
                
                return LLMResponse(
                    provider=LLMProvider.POLLINATIONS,
                    is_scam=result.get("is_scam", False),
                    confidence=result.get("confidence", 0.5),
                    scam_type=result.get("scam_type"),
                    reasoning=result.get("reasoning", ""),
                    response_time_ms=elapsed,
                    success=True
                )
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            logger.error(f"Pollinations detection failed: {e}")
            return LLMResponse(
                provider=LLMProvider.POLLINATIONS,
                is_scam=False,
                confidence=0.0,
                scam_type=None,
                reasoning="",
                response_time_ms=elapsed,
                success=False,
                error=str(e)
            )
    
    async def _detect_gemini(self, message: str) -> LLMResponse:
        """Detect scam using Gemini (new google.genai package)."""
        import time
        start = time.time()
        
        try:
            from google import genai
            
            client = genai.Client(api_key=self.gemini_key)
            prompt = SCAM_DETECTION_PROMPT.format(message=message)
            
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=settings.GEMINI_MODEL,
                contents=prompt,
                config={
                    "temperature": 0.1,
                    "max_output_tokens": 500  # Increased to prevent truncation
                }
            )
            
            result = self._parse_llm_response(response.text)
            elapsed = int((time.time() - start) * 1000)
            
            return LLMResponse(
                provider=LLMProvider.GEMINI,
                is_scam=result.get("is_scam", False),
                confidence=result.get("confidence", 0.5),
                scam_type=result.get("scam_type"),
                reasoning=result.get("reasoning", ""),
                response_time_ms=elapsed,
                success=True
            )
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            logger.error(f"Gemini detection failed: {e}")
            return LLMResponse(
                provider=LLMProvider.GEMINI,
                is_scam=False,
                confidence=0.0,
                scam_type=None,
                reasoning="",
                response_time_ms=elapsed,
                success=False,
                error=str(e)
            )
    
    async def _detect_groq(self, message: str) -> LLMResponse:
        """Detect scam using Groq."""
        import time
        start = time.time()
        
        try:
            from groq import Groq
            client = Groq(api_key=self.groq_key)
            
            prompt = SCAM_DETECTION_PROMPT.format(message=message)
            
            response = await asyncio.to_thread(
                client.chat.completions.create,
                model=settings.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=200
            )
            
            result = self._parse_llm_response(response.choices[0].message.content)
            elapsed = int((time.time() - start) * 1000)
            
            return LLMResponse(
                provider=LLMProvider.GROQ,
                is_scam=result.get("is_scam", False),
                confidence=result.get("confidence", 0.5),
                scam_type=result.get("scam_type"),
                reasoning=result.get("reasoning", ""),
                response_time_ms=elapsed,
                success=True
            )
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            return LLMResponse(
                provider=LLMProvider.GROQ,
                is_scam=False,
                confidence=0.0,
                scam_type=None,
                reasoning="",
                response_time_ms=elapsed,
                success=False,
                error=str(e)
            )
    
    async def _detect_together(self, message: str) -> LLMResponse:
        """Detect scam using Together AI."""
        import time
        start = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    "https://api.together.xyz/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.together_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "meta-llama/Llama-3-70b-chat-hf",
                        "messages": [{"role": "user", "content": SCAM_DETECTION_PROMPT.format(message=message)}],
                        "temperature": 0.1,
                        "max_tokens": 200
                    }
                )
                response.raise_for_status()
                data = response.json()
                
                result = self._parse_llm_response(data["choices"][0]["message"]["content"])
                elapsed = int((time.time() - start) * 1000)
                
                return LLMResponse(
                    provider=LLMProvider.TOGETHER,
                    is_scam=result.get("is_scam", False),
                    confidence=result.get("confidence", 0.5),
                    scam_type=result.get("scam_type"),
                    reasoning=result.get("reasoning", ""),
                    response_time_ms=elapsed,
                    success=True
                )
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            return LLMResponse(
                provider=LLMProvider.TOGETHER,
                is_scam=False,
                confidence=0.0,
                scam_type=None,
                reasoning="",
                response_time_ms=elapsed,
                success=False,
                error=str(e)
            )
    
    async def _detect_cerebras(self, message: str) -> LLMResponse:
        """Detect scam using Cerebras (Llama 3.3 70B or GPT-OSS 120B)."""
        import time
        start = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    "https://api.cerebras.ai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.cerebras_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": settings.CEREBRAS_MODEL,  # llama-3.3-70b or gpt-oss-120b
                        "messages": [{"role": "user", "content": SCAM_DETECTION_PROMPT.format(message=message)}],
                        "temperature": 0.1,
                        "max_tokens": 200
                    }
                )
                response.raise_for_status()
                data = response.json()
                
                result = self._parse_llm_response(data["choices"][0]["message"]["content"])
                elapsed = int((time.time() - start) * 1000)
                
                return LLMResponse(
                    provider=LLMProvider.CEREBRAS,
                    is_scam=result.get("is_scam", False),
                    confidence=result.get("confidence", 0.5),
                    scam_type=result.get("scam_type"),
                    reasoning=result.get("reasoning", ""),
                    response_time_ms=elapsed,
                    success=True
                )
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            return LLMResponse(
                provider=LLMProvider.CEREBRAS,
                is_scam=False,
                confidence=0.0,
                scam_type=None,
                reasoning="",
                response_time_ms=elapsed,
                success=False,
                error=str(e)
            )
    
    async def _detect_cohere(self, message: str) -> LLMResponse:
        """Detect scam using Cohere."""
        import time
        start = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    "https://api.cohere.ai/v1/chat",
                    headers={
                        "Authorization": f"Bearer {self.cohere_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "command",
                        "message": SCAM_DETECTION_PROMPT.format(message=message),
                        "temperature": 0.1,
                        "max_tokens": 200
                    }
                )
                response.raise_for_status()
                data = response.json()
                
                result = self._parse_llm_response(data["text"])
                elapsed = int((time.time() - start) * 1000)
                
                return LLMResponse(
                    provider=LLMProvider.COHERE,
                    is_scam=result.get("is_scam", False),
                    confidence=result.get("confidence", 0.5),
                    scam_type=result.get("scam_type"),
                    reasoning=result.get("reasoning", ""),
                    response_time_ms=elapsed,
                    success=True
                )
        except Exception as e:
            elapsed = int((time.time() - start) * 1000)
            return LLMResponse(
                provider=LLMProvider.COHERE,
                is_scam=False,
                confidence=0.0,
                scam_type=None,
                reasoning="",
                response_time_ms=elapsed,
                success=False,
                error=str(e)
            )
    
    def _parse_llm_response(self, text: str) -> Dict[str, Any]:
        """Parse JSON response from LLM, handling various formats."""
        import json
        import re
        
        # Clean the text
        clean_text = text.strip()
        
        # Remove markdown code blocks if present
        clean_text = re.sub(r'^```(?:json)?\s*', '', clean_text)
        clean_text = re.sub(r'\s*```$', '', clean_text)
        clean_text = clean_text.strip()
        
        try:
            # Try direct JSON parse first
            if clean_text.startswith('{'):
                return json.loads(clean_text)
        except json.JSONDecodeError:
            pass
        
        try:
            # Try to find any JSON object (including nested)
            # Find the first { and last } to capture full object
            start = clean_text.find('{')
            end = clean_text.rfind('}')
            if start != -1 and end != -1 and end > start:
                json_str = clean_text[start:end+1]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback: parse manually by looking for key patterns
        text_lower = text.lower()
        
        # Detect is_scam
        is_scam = False
        if '"is_scam": true' in text_lower or '"is_scam":true' in text_lower:
            is_scam = True
        elif 'is_scam": false' not in text_lower and ('scam' in text_lower and 'not' not in text_lower.split('scam')[0][-20:]):
            is_scam = True
        
        # Extract confidence
        confidence = 0.5
        conf_patterns = [
            r'"confidence"\s*:\s*(\d+\.?\d*)',
            r'confidence[:\s]+(\d+\.?\d*)',
        ]
        for pattern in conf_patterns:
            match = re.search(pattern, text_lower)
            if match:
                try:
                    confidence = min(float(match.group(1)), 1.0)
                    break
                except ValueError:
                    continue
        
        # Extract scam_type
        scam_type = None
        type_match = re.search(r'"scam_type"\s*:\s*"([^"]+)"', text_lower)
        if type_match:
            scam_type = type_match.group(1)
        
        # Extract reasoning
        reasoning = ""
        reason_match = re.search(r'"reasoning"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
        if reason_match:
            reasoning = reason_match.group(1)
        else:
            reasoning = text[:200]
        
        return {
            "is_scam": is_scam,
            "confidence": confidence,
            "scam_type": scam_type,
            "reasoning": reasoning
        }


# Global instance
multi_llm_detector = MultiLLMDetector()
