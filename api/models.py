"""
Pydantic models for API request/response validation.
"""
from pydantic import BaseModel, Field, model_validator
from typing import Optional, List, Dict, Any, Union
from enum import Enum
from datetime import datetime


class MessageRole(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


class ConversationMessage(BaseModel):
    """Single message in conversation history."""
    role: MessageRole
    content: str
    timestamp: Optional[str] = None


class IncomingMessage(BaseModel):
    """Hackathon-format incoming message object."""
    sender: str  # "scammer" or "user"
    text: str
    timestamp: Optional[str] = None


class MessageMetadata(BaseModel):
    """Metadata about the incoming message."""
    source: Optional[str] = None
    timestamp: Optional[str] = None
    language: Optional[str] = "en"
    channel: Optional[str] = None
    locale: Optional[str] = None
    senderInfo: Optional[Dict[str, Any]] = None


class HoneypotRequest(BaseModel):
    """Main request model for honeypot API.
    
    Supports both formats:
    - Simple: {"message": "string"}
    - Hackathon: {"message": {"sender": "scammer", "text": "string", "timestamp": "..."}}
    """
    sessionId: str = Field(..., description="Unique session identifier")
    message: Union[str, IncomingMessage] = Field(..., description="Current message")
    conversationHistory: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Previous conversation messages"
    )
    metadata: Optional[MessageMetadata] = None
    
    def get_message_text(self) -> str:
        """Get message text regardless of format."""
        if isinstance(self.message, str):
            return self.message
        return self.message.text


class ExtractedIntelligence(BaseModel):
    """Intelligence extracted from conversation."""
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousUrls: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    confidenceScores: Optional[Dict[str, float]] = Field(default_factory=dict)


class ScammerProfile(BaseModel):
    """Profile built from analyzing scammer behavior."""
    scamType: Optional[str] = None
    scammerType: Optional[str] = None
    threatLevel: int = Field(default=1, ge=1, le=10)
    tacticsUsed: List[str] = Field(default_factory=list)
    behavioralFingerprint: Optional[Dict[str, Any]] = None


class ConversationState(str, Enum):
    """States in the conversation state machine."""
    PROBE = "probe"
    ENGAGE = "engage"
    EXTRACT = "extract"
    VERIFY = "verify"
    DEEPEN = "deepen"
    EXIT = "exit"


class HoneypotResponse(BaseModel):
    """Main response model for honeypot API."""
    sessionId: str
    response: str = Field(..., description="AI agent's response to the scammer")
    isScam: bool = Field(default=False, description="Whether message detected as scam")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    scammerProfile: Optional[ScammerProfile] = None
    agentNotes: Optional[str] = None
    shouldCallback: bool = Field(default=False)
    conversationTurn: int = Field(default=1)
    intelligenceQualityScore: float = Field(default=0.0, ge=0.0)


class CallbackPayload(BaseModel):
    """Payload sent to GUVI callback endpoint."""
    sessionId: str
    finalResponse: str
    isScamDetected: bool
    confidence: float
    extractedIntelligence: ExtractedIntelligence
    scammerProfile: Optional[ScammerProfile] = None
    conversationSummary: str
    totalTurns: int
    intelligenceQualityScore: float
    agentNotes: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "1.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None
