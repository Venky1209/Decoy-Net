"""
Session management for honeypot conversations.
"""
import json
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field

from api.models import ConversationState
from utils.storage import get_storage_backend, StorageBackend

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """Represents a conversation session."""
    session_id: str
    state: ConversationState = ConversationState.PROBE
    persona: Optional[str] = None
    conversation_turn: int = 0
    messages: List[Dict[str, str]] = field(default_factory=list)
    intelligence: Dict[str, List] = field(default_factory=lambda: {
        "bank_accounts": [],
        "upi_ids": [],
        "phone_numbers": [],
        "urls": [],
        "emails": [],
        "keywords": [],
        "confidence_scores": {}
    })
    scam_detected: bool = False
    scam_confidence: float = 0.0
    scam_type: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    callback_sent: bool = False
    
    def add_message(self, role: str, content: str):
        """Add a message to the conversation history."""
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        })
        self.last_activity = datetime.utcnow()
    
    def update_intelligence(self, new_intel: Dict[str, Any]):
        """Merge new intelligence with existing."""
        for key in ["bank_accounts", "upi_ids", "phone_numbers", "urls", "emails"]:
            existing = set(self.intelligence.get(key, []))
            new_items = new_intel.get(key, [])
            if isinstance(new_items, list):
                existing.update(new_items)
            self.intelligence[key] = list(existing)
        
        # Merge keywords
        keywords = set(self.intelligence.get("keywords", []))
        keywords.update(new_intel.get("keywords", []))
        self.intelligence["keywords"] = list(keywords)[:20]  # Limit keywords
        
        # Update confidence scores
        for key, conf in new_intel.get("confidence_scores", {}).items():
            existing_conf = self.intelligence["confidence_scores"].get(key, 0)
            self.intelligence["confidence_scores"][key] = max(existing_conf, conf)
    
    def to_dict(self) -> Dict:
        """Convert session to dictionary for storage."""
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "persona": self.persona,
            "conversation_turn": self.conversation_turn,
            "messages": self.messages,
            "intelligence": self.intelligence,
            "scam_detected": self.scam_detected,
            "scam_confidence": self.scam_confidence,
            "scam_type": self.scam_type,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "callback_sent": self.callback_sent
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "Session":
        """Create session from dictionary."""
        session = cls(session_id=data["session_id"])
        session.state = ConversationState(data.get("state", "probe"))
        session.persona = data.get("persona")
        session.conversation_turn = data.get("conversation_turn", 0)
        session.messages = data.get("messages", [])
        session.intelligence = data.get("intelligence", {
            "bank_accounts": [],
            "upi_ids": [],
            "phone_numbers": [],
            "urls": [],
            "emails": [],
            "keywords": [],
            "confidence_scores": {}
        })
        session.scam_detected = data.get("scam_detected", False)
        session.scam_confidence = data.get("scam_confidence", 0.0)
        session.scam_type = data.get("scam_type")
        session.callback_sent = data.get("callback_sent", False)
        
        if data.get("created_at"):
            session.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("last_activity"):
            session.last_activity = datetime.fromisoformat(data["last_activity"])
        
        return session


class SessionManager:
    """
    Manages conversation sessions with storage backend.
    """
    
    def __init__(self, use_redis: bool = False, redis_url: Optional[str] = None):
        self._storage: StorageBackend = get_storage_backend(use_redis, redis_url)
        self._prefix = "honeypot:session:"
        self._stats = {
            "total_processed": 0,
            "scams_detected": 0,
            "total_iqs": 0.0
        }
        logger.info("Session manager initialized")
    
    def _make_key(self, session_id: str) -> str:
        """Create storage key for session."""
        return f"{self._prefix}{session_id}"
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get existing session by ID."""
        key = self._make_key(session_id)
        data = self._storage.get(key)
        
        if not data:
            return None
        
        try:
            return Session.from_dict(json.loads(data))
        except Exception as e:
            logger.error(f"Error loading session {session_id}: {e}")
            return None
    
    def create_session(
        self,
        session_id: str,
        initial_history: Optional[List] = None
    ) -> Session:
        """Create a new session."""
        session = Session(session_id=session_id)
        
        # Add initial conversation history if provided
        if initial_history:
            for msg in initial_history:
                if hasattr(msg, 'role') and hasattr(msg, 'content'):
                    session.add_message(msg.role.value, msg.content)
                elif isinstance(msg, dict):
                    session.add_message(
                        msg.get("role", "user"),
                        msg.get("content", "")
                    )
        
        # Save to storage
        self._save_session(session)
        
        logger.info(f"Created new session: {session_id}")
        return session
    
    def get_or_create_session(
        self,
        session_id: str,
        initial_history: Optional[List] = None
    ) -> Session:
        """Get existing session or create new one."""
        session = self.get_session(session_id)
        
        if session:
            # Update history if provided and session is new
            if initial_history and session.conversation_turn == 0:
                for msg in initial_history:
                    if hasattr(msg, 'role') and hasattr(msg, 'content'):
                        session.add_message(msg.role.value, msg.content)
                    elif isinstance(msg, dict):
                        session.add_message(
                            msg.get("role", "user"),
                            msg.get("content", "")
                        )
            return session
        
        return self.create_session(session_id, initial_history)
    
    def update_session(self, session: Session) -> bool:
        """Update session in storage."""
        return self._save_session(session)
    
    def _save_session(self, session: Session) -> bool:
        """Save session to storage."""
        key = self._make_key(session.session_id)
        data = json.dumps(session.to_dict())
        
        # Set with 24-hour expiry
        return self._storage.set(key, data, expiry_seconds=86400)
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        key = self._make_key(session_id)
        return self._storage.delete(key)
    
    def should_exit(self, session: Session) -> bool:
        """
        Determine if session should exit.
        
        Exit conditions:
        - Max turns reached (20)
        - High intelligence quality achieved
        - Scammer disengaged (detected by patterns)
        - Session marked as EXIT state
        """
        from config import settings
        
        # Already in exit state
        if session.state == ConversationState.EXIT:
            return True
        
        # Max turns reached
        if session.conversation_turn >= settings.MAX_CONVERSATION_TURNS:
            logger.info(f"Session {session.session_id}: Max turns reached")
            return True
        
        # High intelligence score
        intel_count = sum(
            len(session.intelligence.get(k, []))
            for k in ["bank_accounts", "upi_ids", "phone_numbers", "urls"]
        )
        if intel_count >= 5:
            logger.info(f"Session {session.session_id}: Sufficient intelligence gathered")
            return True
        
        # Callback already sent
        if session.callback_sent:
            return True
        
        return False
    
    def get_active_sessions(self) -> List[str]:
        """Get list of active session IDs."""
        keys = self._storage.keys(f"{self._prefix}*")
        return [k.replace(self._prefix, "") for k in keys]
    
    def get_stats(self) -> Dict:
        """Get session statistics."""
        active_sessions = len(self.get_active_sessions())
        
        avg_iqs = 0.0
        if self._stats["total_processed"] > 0:
            avg_iqs = self._stats["total_iqs"] / self._stats["total_processed"]
        
        return {
            "active_sessions": active_sessions,
            "total_processed": self._stats["total_processed"],
            "scams_detected": self._stats["scams_detected"],
            "average_iqs": round(avg_iqs, 2)
        }
    
    def record_processing(self, scam_detected: bool, iqs: float):
        """Record processing statistics."""
        self._stats["total_processed"] += 1
        if scam_detected:
            self._stats["scams_detected"] += 1
        self._stats["total_iqs"] += iqs
