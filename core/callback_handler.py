"""
Callback handler for sending results to GUVI endpoint.
"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from config import settings

logger = logging.getLogger(__name__)


class CallbackHandler:
    """
    Handles callbacks to GUVI evaluation endpoint.
    Implements retry logic with exponential backoff.
    """
    
    def __init__(self):
        self._callback_url = settings.GUVI_CALLBACK_URL
        self._timeout = 30.0
        self._max_retries = 3
    
    async def send_callback(
        self,
        session: Any,
        scam_result: Any,
        intelligence: Dict[str, Any],
        iqs: float
    ) -> bool:
        """
        Send final result callback to GUVI endpoint.
        
        Args:
            session: Session object with conversation data
            scam_result: Scam detection result
            intelligence: Extracted intelligence
            iqs: Intelligence Quality Score
            
        Returns:
            True if callback succeeded, False otherwise
        """
        # Build payload
        payload = self._build_payload(session, scam_result, intelligence, iqs)
        
        logger.info(f"Sending callback for session {session.session_id}")
        logger.debug(f"Callback payload: {json.dumps(payload, indent=2)}")
        
        # Attempt to send with retries
        try:
            success = await self._send_with_retry(payload)
            
            if success:
                session.callback_sent = True
                logger.info(f"Callback successful for session {session.session_id}")
            else:
                logger.error(f"Callback failed for session {session.session_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Callback error for session {session.session_id}: {e}")
            return False
    
    def _build_payload(
        self,
        session: Any,
        scam_result: Any,
        intelligence: Dict[str, Any],
        iqs: float
    ) -> Dict[str, Any]:
        """Build callback payload according to GUVI specification."""
        
        # Build scammer profile
        scammer_profile = {
            "scamType": scam_result.scam_type or "unknown",
            "scammerType": scam_result.scammer_type or "unknown",
            "threatLevel": scam_result.threat_level,
            "tacticsUsed": scam_result.tactics,
            "sophisticationLevel": "medium",
            "behavioralFingerprint": {
                "messagePatterns": "scripted",
                "urgencyLevel": "high" if "urgency" in scam_result.tactics else "low",
                "persistenceScore": min(session.conversation_turn / 10, 1.0)
            }
        }
        
        # Build intelligence data (using hackathon field names)
        extracted_intelligence = {
            "bankAccounts": intelligence.get("bank_accounts", []),
            "upiIds": intelligence.get("upi_ids", []),
            "phishingLinks": intelligence.get("urls", []),  # Hackathon spec uses phishingLinks
            "phoneNumbers": intelligence.get("phone_numbers", []),
            "suspiciousKeywords": intelligence.get("keywords", [])
        }
        
        # Build conversation summary
        summary = self._build_conversation_summary(session, scam_result)
        
        # Build agent notes (explainable AI)
        agent_notes = self._build_agent_notes(session, scam_result, intelligence, iqs)
        
        # Final payload
        payload = {
            "sessionId": session.session_id,
            "scamDetected": scam_result.is_scam,
            "confidence": round(scam_result.confidence, 3),
            "totalMessagesExchanged": session.conversation_turn,
            "extractedIntelligence": extracted_intelligence,
            "scammerProfile": scammer_profile,
            "conversationSummary": summary,
            "intelligenceQualityScore": round(iqs, 2),
            "agentNotes": agent_notes,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        return payload
    
    def _build_conversation_summary(self, session: Any, scam_result: Any) -> str:
        """Build a summary of the conversation."""
        parts = []
        
        parts.append(f"Conversation with {session.conversation_turn} exchanges.")
        
        if scam_result.is_scam:
            parts.append(f"Detected {scam_result.scam_type or 'unknown'} scam with {scam_result.confidence:.0%} confidence.")
        
        if scam_result.tactics:
            parts.append(f"Tactics used: {', '.join(scam_result.tactics)}.")
        
        if session.persona:
            parts.append(f"Engaged using {session.persona} persona.")
        
        intel_count = sum(
            len(session.intelligence.get(k, []))
            for k in ["bank_accounts", "upi_ids", "phone_numbers", "urls"]
        )
        if intel_count > 0:
            parts.append(f"Extracted {intel_count} intelligence items.")
        
        return " ".join(parts)
    
    def _build_agent_notes(
        self,
        session: Any,
        scam_result: Any,
        intelligence: Dict,
        iqs: float
    ) -> str:
        """Build agent notes as a simple string per hackathon spec."""
        parts = []
        
        # Scammer tactics
        if scam_result.tactics:
            parts.append(f"Scammer used {', '.join(scam_result.tactics)} tactics.")
        
        # Detection info
        parts.append(f"Detection confidence: {scam_result.confidence:.0%}.")
        
        # Scam type
        if scam_result.scam_type:
            parts.append(f"Scam type: {scam_result.scam_type}.")
        
        # Intelligence quality
        parts.append(f"Intelligence quality score: {iqs:.1f}/10.")
        
        # Persona used
        if session.persona:
            parts.append(f"Engaged using {session.persona} persona.")
        
        # Brief reasoning
        if scam_result.reasoning:
            reason_short = scam_result.reasoning[:150] + "..." if len(scam_result.reasoning) > 150 else scam_result.reasoning
            parts.append(f"Reasoning: {reason_short}")
        
        return " ".join(parts)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def _send_with_retry(self, payload: Dict) -> bool:
        """Send callback with retry logic."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                response = await client.post(
                    self._callback_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "HoneypotAgent/1.0"
                    }
                )
                
                if response.status_code == 200:
                    logger.info(f"Callback returned 200 OK")
                    return True
                else:
                    logger.warning(
                        f"Callback returned {response.status_code}: {response.text}"
                    )
                    # Don't retry for client errors
                    if 400 <= response.status_code < 500:
                        return False
                    raise Exception(f"Server error: {response.status_code}")
                    
            except httpx.TimeoutException:
                logger.warning("Callback timed out, will retry")
                raise
            except httpx.RequestError as e:
                logger.warning(f"Callback request error: {e}, will retry")
                raise
    
    async def validate_payload(self, payload: Dict) -> bool:
        """Validate payload before sending."""
        required_fields = [
            "sessionId",
            "scamDetected", 
            "totalMessagesExchanged",
            "extractedIntelligence"
        ]
        
        for field in required_fields:
            if field not in payload:
                logger.error(f"Missing required field: {field}")
                return False
        
        return True
