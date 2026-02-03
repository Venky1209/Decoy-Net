"""
API routes for the honeypot system.
Now using Enhanced Scam Detector with Pattern Memory and Multi-LLM Ensemble.

RESPONSE FORMAT (from PS Section 8):
    {"status": "success", "reply": "Why is my account being suspended?"}
"""
from fastapi import APIRouter, HTTPException, Header, Depends, BackgroundTasks, Request
from typing import Optional, Dict, Any
import logging

from api.models import (
    HoneypotRequest, 
    HoneypotResponse, 
    HealthResponse,
    ErrorResponse,
    ExtractedIntelligence,
    ScammerProfile,
    ConversationState,
    GUVISimpleResponse
)
from core.enhanced_detector import EnhancedScamDetector
from core.agent import HoneypotAgent
from core.session_manager import SessionManager
from core.intelligence_extractor import IntelligenceExtractor
from core.callback_handler import CallbackHandler
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize core components
# Using EnhancedScamDetector instead of basic ScamDetector
enhanced_detector = EnhancedScamDetector(use_llm=True, use_memory=True)
agent = HoneypotAgent()
session_manager = SessionManager()
intelligence_extractor = IntelligenceExtractor()
callback_handler = CallbackHandler()


async def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    """Dependency for API key validation."""
    if x_api_key != settings.API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key


@router.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint - basic health check."""
    return HealthResponse(status="healthy", version="1.0.0")


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="healthy", version="1.0.0")


# ============================================================================
# PRIMARY ENDPOINT - Returns EXACT format from PS Section 8
# {"status": "success", "reply": "..."}
# ============================================================================
@router.post(
    "/",
    response_model=GUVISimpleResponse,
    responses={
        403: {"model": ErrorResponse, "description": "Invalid API key"},
    }
)
async def guvi_honeypot(
    request: Request,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
) -> GUVISimpleResponse:
    """
    GUVI Hackathon Primary Endpoint.
    
    Returns the EXACT format from Problem Statement Section 8:
    {"status": "success", "reply": "Why is my account being suspended?"}
    
    Accepts ANY valid JSON body - extremely flexible for testing.
    """
    try:
        # Parse body flexibly - accept any JSON
        try:
            body = await request.json()
        except:
            body = {}
        
        # Extract fields with maximum flexibility
        session_id = body.get("sessionId") or body.get("session_id") or str(__import__("uuid").uuid4())
        
        # Handle message in multiple formats
        message = body.get("message") or body.get("text") or body.get("msg") or "Hello"
        if isinstance(message, dict):
            message = message.get("text") or message.get("content") or "Hello"
        
        # Handle conversation history
        history = body.get("conversationHistory") or body.get("conversation_history") or body.get("history") or []
        
        # Create proper request object
        honeypot_request = HoneypotRequest(
            sessionId=session_id,
            message=message,
            conversationHistory=history,
            metadata=body.get("metadata")
        )
        
        logger.info(f"[GUVI] Processing session: {honeypot_request.sessionId}")
        
        # 1. Get or create session
        session = session_manager.get_or_create_session(
            honeypot_request.sessionId,
            honeypot_request.conversationHistory
        )
        
        # Get message text (supports string or object format)
        message_text = honeypot_request.get_message_text()
        
        # Get metadata for context-aware responses
        metadata = honeypot_request.metadata
        language = metadata.language if metadata else "en"
        channel = metadata.channel if metadata else "unknown"
        
        # 2. Extract intelligence FIRST
        current_intelligence = intelligence_extractor.extract_all(
            message=message_text,
            conversation_history=honeypot_request.conversationHistory
        )
        session.update_intelligence(current_intelligence)
        
        # 3. Detect scam using Enhanced Detector
        scam_result = await enhanced_detector.detect(
            message=message_text,
            conversation_history=honeypot_request.conversationHistory,
            intelligence=session.intelligence
        )
        
        # 4. Calculate IQS (Intelligence Quality Score)
        iqs = intelligence_extractor.calculate_quality_score(session.intelligence)
        
        # 4.5 Report verified scammers to database (for future detection)
        if scam_result.is_scam and scam_result.confidence >= 0.7:
            try:
                from core.scammer_verifier import scammer_verifier
                
                # Report all extracted identifiers as belonging to scammers
                for upi in session.intelligence.get("upi_ids", []):
                    scammer_verifier.report_scammer(
                        identifier=upi,
                        identifier_type="upi",
                        scam_type=scam_result.scam_type or "unknown",
                        session_id=honeypot_request.sessionId
                    )
                
                for phone in session.intelligence.get("phone_numbers", []):
                    scammer_verifier.report_scammer(
                        identifier=phone,
                        identifier_type="phone",
                        scam_type=scam_result.scam_type or "unknown",
                        session_id=honeypot_request.sessionId
                    )
                
                for account in session.intelligence.get("bank_accounts", []):
                    scammer_verifier.report_scammer(
                        identifier=account,
                        identifier_type="bank_account",
                        scam_type=scam_result.scam_type or "unknown",
                        session_id=honeypot_request.sessionId
                    )
                
                logger.info(f"[SCAMMER DB] Reported identifiers for session {honeypot_request.sessionId}")
            except Exception as e:
                logger.debug(f"Scammer reporting error (non-critical): {e}")
        
        # 5. Generate AI Agent response
        agent_response = await agent.generate_response(
            message=message_text,
            session=session,
            scam_result=scam_result,
            intelligence=session.intelligence
        )
        
        # 6. Update session
        session.add_message("scammer", message_text)  # Use "scammer" as per PS
        session.add_message("user", agent_response.response)  # Our response
        session.conversation_turn += 1
        session.state = agent_response.state
        session_manager.update_session(session)
        
        # 7. Check if callback should be triggered
        should_callback = _should_trigger_callback(session, scam_result, iqs)
        
        if should_callback:
            logger.info(f"[GUVI] Triggering callback for session: {honeypot_request.sessionId}")
            background_tasks.add_task(
                callback_handler.send_callback,
                session=session,
                scam_result=scam_result,
                intelligence=session.intelligence,
                iqs=iqs
            )
        
        logger.info(
            f"[GUVI] Session {honeypot_request.sessionId}: "
            f"scam={scam_result.is_scam}, conf={scam_result.confidence:.2f}, "
            f"turn={session.conversation_turn}, IQS={iqs:.1f}"
        )
        
        # Return EXACT format from PS Section 8
        return GUVISimpleResponse(
            status="success",
            reply=agent_response.response
        )
        
    except Exception as e:
        logger.error(f"[GUVI] Error: {str(e)}", exc_info=True)
        # Even on error, try to return valid format
        return GUVISimpleResponse(
            status="error",
            reply="I'm having trouble understanding. Can you please repeat that?"
        )


@router.post(
    "/analyze",
    response_model=HoneypotResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Missing API key"},
        403: {"model": ErrorResponse, "description": "Invalid API key"},
        422: {"model": ErrorResponse, "description": "Validation error"}
    }
)
async def analyze_message(
    request: Request,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Main honeypot endpoint - analyzes incoming message and responds.
    
    Uses Advanced Detection Features:
    - Pattern Memory (Instant recognition)
    - Multi-LLM Ensemble (AI Consensus)
    - Context Analysis
    """
    try:
        # Parse body flexibly - accept any JSON
        try:
            body = await request.json()
        except:
            body = {}
        
        # Extract fields with maximum flexibility
        session_id = body.get("sessionId") or body.get("session_id") or str(__import__("uuid").uuid4())
        
        # Handle message in multiple formats
        message = body.get("message") or body.get("text") or body.get("msg") or "Hello"
        if isinstance(message, dict):
            message = message.get("text") or message.get("content") or "Hello"
        
        # Handle conversation history
        history = body.get("conversationHistory") or body.get("conversation_history") or body.get("history") or []
        
        # Create proper request object
        honeypot_request = HoneypotRequest(
            sessionId=session_id,
            message=message,
            conversationHistory=history,
            metadata=body.get("metadata")
        )
        
        logger.info(f"Processing message for session: {honeypot_request.sessionId}")
        
        # 1. Get or create session
        session = session_manager.get_or_create_session(
            honeypot_request.sessionId,
            honeypot_request.conversationHistory
        )
        
        # Get message text (supports both string and object format)
        message_text = honeypot_request.get_message_text()
        
        # 2. Extract intelligence FIRST (needed for pattern memory)
        current_intelligence = intelligence_extractor.extract_all(
            message=message_text,
            conversation_history=honeypot_request.conversationHistory
        )
        session.update_intelligence(current_intelligence)
        
        # 3. Detect scam using Enhanced Detector
        # Passes current intelligence to check against Pattern Memory
        scam_result = await enhanced_detector.detect(
            message=message_text,
            conversation_history=honeypot_request.conversationHistory,
            intelligence=session.intelligence
        )
        
        # 4. Calculate IQS
        iqs = intelligence_extractor.calculate_quality_score(session.intelligence)
        
        # 5. Generate agent response
        agent_response = await agent.generate_response(
            message=message_text,
            session=session,
            scam_result=scam_result,
            intelligence=session.intelligence
        )
        
        # 6. Update session state
        session.add_message("user", message_text)
        session.add_message("assistant", agent_response.response)
        session.conversation_turn += 1
        session.state = agent_response.state
        
        # 6.1 CRITICAL: Save session back to storage for persistence
        session_manager.update_session(session)
        
        # 7. Build rich scammer profile
        scammer_profile = ScammerProfile(
            scamType=scam_result.scam_type,
            scammerType=scam_result.scammer_type,
            threatLevel=scam_result.threat_level,
            tacticsUsed=scam_result.tactics,
            behavioralFingerprint={
                "times_seen": scam_result.times_seen_before,
                "pattern_matches": len(scam_result.pattern_matches),
                "llm_consensus": scam_result.llm_consensus.get("votes") if scam_result.llm_consensus else None
            }
        )
        
        # 8. Check callback trigger
        should_callback = _should_trigger_callback(
            session=session,
            scam_result=scam_result,
            intelligence_score=iqs
        )
        
        if should_callback:
            logger.info(f"Triggering callback for session: {honeypot_request.sessionId}")
            background_tasks.add_task(
                callback_handler.send_callback,
                session=session,
                scam_result=scam_result,
                intelligence=session.intelligence,
                iqs=iqs
            )
        
        # 9. Build response
        response = HoneypotResponse(
            sessionId=honeypot_request.sessionId,
            response=agent_response.response,
            isScam=scam_result.is_scam,
            confidence=scam_result.confidence,
            extractedIntelligence=ExtractedIntelligence(
                bankAccounts=session.intelligence.get("bank_accounts", []),
                upiIds=session.intelligence.get("upi_ids", []),
                phoneNumbers=session.intelligence.get("phone_numbers", []),
                suspiciousUrls=session.intelligence.get("urls", []),
                suspiciousKeywords=session.intelligence.get("keywords", []),
                emails=session.intelligence.get("emails", []),
                confidenceScores=session.intelligence.get("confidence_scores", {})
            ),
            scammerProfile=scammer_profile if scam_result.is_scam else None,
            agentNotes=f"{agent_response.notes} | Reasoning: {scam_result.reasoning}",
            shouldCallback=should_callback,
            conversationTurn=session.conversation_turn,
            intelligenceQualityScore=iqs
        )
        
        logger.info(
            f"Session {honeypot_request.sessionId}: "
            f"isScam={scam_result.is_scam}, "
            f"confidence={scam_result.confidence:.2f}, "
            f"IQS={iqs:.1f}, "
            f"MemoryMatches={len(scam_result.pattern_matches)}"
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def _should_trigger_callback(session, scam_result, intelligence_score: float) -> bool:
    """
    Determine if callback should be triggered.
    
    IMPORTANT: Callbacks are MANDATORY for scoring (PS Section 12).
    We trigger callbacks MORE aggressively to ensure GUVI receives data.
    """
    # Always callback if exiting conversation
    if session.state == ConversationState.EXIT:
        return True
    
    # Always callback after sufficient turns (engagement depth)
    if session.conversation_turn >= 3:
        return True
    
    # Callback if any scam detected with reasonable confidence
    if scam_result.is_scam and scam_result.confidence >= 0.5:
        return True
    
    # Callback if any intelligence extracted (shows capability)
    if intelligence_score >= 2.0:
        return True
    
    # Callback on high confidence even without intel
    if scam_result.confidence >= 0.7:
        return True
    
    return False


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, api_key: str = Depends(verify_api_key)):
    """Get session details."""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "sessionId": session_id,
        "state": session.state.value,
        "conversationTurn": session.conversation_turn,
        "intelligence": session.intelligence,
        "persona": session.persona,
        "createdAt": session.created_at.isoformat(),
        "lastActivity": session.last_activity.isoformat()
    }


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str, api_key: str = Depends(verify_api_key)):
    """Delete a session."""
    success = session_manager.delete_session(session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"message": f"Session {session_id} deleted"}


@router.get("/stats")
async def get_stats(api_key: str = Depends(verify_api_key)):
    """Get system statistics."""
    stats = session_manager.get_stats()
    return {
        "activeSessions": stats["active_sessions"],
        "totalProcessed": stats["total_processed"],
        "scamsDetected": stats["scams_detected"],
        "averageIQS": stats["average_iqs"]
    }


@router.post("/sessions/{session_id}/callback")
async def force_callback(
    session_id: str, 
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Force send callback for a session to GUVI endpoint.
    
    Use this to manually trigger the final result submission
    as required by PS Section 12.
    """
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Create a minimal scam result for callback
    from dataclasses import dataclass
    
    @dataclass
    class MinimalScamResult:
        is_scam: bool = True
        confidence: float = 0.8
        scam_type: str = "unknown"
        tactics: list = None
        llm_consensus: dict = None
        times_seen_before: int = 0
        
        def __post_init__(self):
            if self.tactics is None:
                self.tactics = []
    
    scam_result = MinimalScamResult(
        is_scam=session.scam_detected,
        confidence=session.scam_confidence,
        scam_type=session.scam_type or "unknown"
    )
    
    iqs = intelligence_extractor.calculate_quality_score(session.intelligence)
    
    background_tasks.add_task(
        callback_handler.send_callback,
        session=session,
        scam_result=scam_result,
        intelligence=session.intelligence,
        iqs=iqs
    )
    
    return {
        "message": f"Callback triggered for session {session_id}",
        "sessionId": session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.conversation_turn
    }
