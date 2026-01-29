"""
API routes for the honeypot system.
Now using Enhanced Scam Detector with Pattern Memory and Multi-LLM Ensemble.
"""
from fastapi import APIRouter, HTTPException, Header, Depends, BackgroundTasks
from typing import Optional
import logging

from api.models import (
    HoneypotRequest, 
    HoneypotResponse, 
    HealthResponse,
    ErrorResponse,
    ExtractedIntelligence,
    ScammerProfile,
    ConversationState
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
    request: HoneypotRequest,
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
        logger.info(f"Processing message for session: {request.sessionId}")
        
        # 1. Get or create session
        session = session_manager.get_or_create_session(
            request.sessionId,
            request.conversationHistory
        )
        
        # Get message text (supports both string and object format)
        message_text = request.get_message_text()
        
        # 2. Extract intelligence FIRST (needed for pattern memory)
        current_intelligence = intelligence_extractor.extract_all(
            message=message_text,
            conversation_history=request.conversationHistory
        )
        session.update_intelligence(current_intelligence)
        
        # 3. Detect scam using Enhanced Detector
        # Passes current intelligence to check against Pattern Memory
        scam_result = await enhanced_detector.detect(
            message=message_text,
            conversation_history=request.conversationHistory,
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
            logger.info(f"Triggering callback for session: {request.sessionId}")
            background_tasks.add_task(
                callback_handler.send_callback,
                session=session,
                scam_result=scam_result,
                intelligence=session.intelligence,
                iqs=iqs
            )
        
        # 9. Build response
        response = HoneypotResponse(
            sessionId=request.sessionId,
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
            f"Session {request.sessionId}: "
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
    """Determine if callback should be triggered."""
    if session.state == ConversationState.EXIT:
        return True
    
    if session.conversation_turn >= settings.MAX_CONVERSATION_TURNS:
        return True
    
    # Callback if high confidence scam with good intelligence
    if scam_result.is_scam and scam_result.confidence >= 0.8:
        if intelligence_score >= 5.0:
            return True
    
    if intelligence_score >= 8.0:
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
