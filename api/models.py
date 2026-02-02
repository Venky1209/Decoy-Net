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
    SCAMMER = "scammer"  # Hackathon uses "scammer" as sender


class ConversationMessage(BaseModel):
    """Single message in conversation history.
    
    Supports both formats:
    - Our format: role, content
    - Hackathon format: sender, text
    """
    # Accept either format
    role: Optional[str] = None
    content: Optional[str] = None
    sender: Optional[str] = None
    text: Optional[str] = None
    timestamp: Optional[str] = None
    
    @model_validator(mode='before')
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        """Normalize sender/text to role/content format."""
        if isinstance(data, dict):
            # If sender is provided but not role, map it
            if 'sender' in data and 'role' not in data:
                data['role'] = data['sender']
            # If text is provided but not content, map it
            if 'text' in data and 'content' not in data:
                data['content'] = data['text']
        return data
    
    def get_content(self) -> str:
        """Get message content regardless of field name."""
        return self.content or self.text or ""
    
    def get_role(self) -> str:
        """Get message role/sender regardless of field name."""
        return self.role or self.sender or "user"


class IncomingMessage(BaseModel):
    """Hackathon-format incoming message object."""
    sender: str  # "scammer" or "user"
    text: str
    timestamp: Optional[Union[str, int]] = None  # Accept epoch ms (int) or ISO string


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
    
    Also accepts field name variations:
    - sessionId or session_id (optional - auto-generated if not provided)
    - message or text
    - conversationHistory, conversation_history, or history
    """
    sessionId: Optional[str] = Field(default=None, description="Unique session identifier", alias="session_id")
    message: Union[str, IncomingMessage] = Field(..., description="Current message")
    conversationHistory: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Previous conversation messages",
        alias="conversation_history"
    )
    metadata: Optional[MessageMetadata] = None
    
    model_config = {"populate_by_name": True}  # Accept both field name and alias
    
    @model_validator(mode='before')
    @classmethod
    def handle_field_variations(cls, data: Any) -> Any:
        """Handle various field name formats from different API clients."""
        if isinstance(data, dict):
            # Handle sessionId variations
            if 'session_id' in data and 'sessionId' not in data:
                data['sessionId'] = data.pop('session_id')
            
            # Auto-generate sessionId if not provided
            if not data.get('sessionId') and not data.get('session_id'):
                import uuid
                data['sessionId'] = str(uuid.uuid4())
            
            # Handle message variations (text field instead of message)
            if 'text' in data and 'message' not in data:
                data['message'] = data.pop('text')
            
            # Handle conversationHistory variations
            if 'conversation_history' in data and 'conversationHistory' not in data:
                data['conversationHistory'] = data.pop('conversation_history')
            elif 'history' in data and 'conversationHistory' not in data:
                data['conversationHistory'] = data.pop('history')
        return data
    
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


class GUVISimpleResponse(BaseModel):
    """EXACT response format from Problem Statement Section 8.
    
    The PS specifies: {"status": "success", "reply": "..."}
    """
    status: str = "success"
    reply: str = Field(..., description="AI Agent's human-like response")


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
