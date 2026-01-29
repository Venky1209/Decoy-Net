"""
DecoyNet Configuration
Manages environment variables and application settings
"""
import os
from typing import Literal
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Settings(BaseSettings):
    """Application configuration settings"""
    
    # API Configuration
    API_KEY: str = os.getenv("API_KEY", "decoynet_secret_key_2026")
    
    # LLM Configuration - Multi-Provider (Priority: Pollinations → Cerebras → Groq → Gemini)
    POLLINATIONS_API_KEY: str = os.getenv("POLLINATIONS_API_KEY", "")
    CEREBRAS_API_KEY: str = os.getenv("CEREBRAS_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # LLM Model Configuration
    PRIMARY_LLM: Literal["pollinations", "cerebras", "gemini", "groq"] = os.getenv("PRIMARY_LLM", "pollinations")
    FALLBACK_LLM: Literal["pollinations", "cerebras", "gemini", "groq"] = os.getenv("FALLBACK_LLM", "gemini")
    
    # Model Names
    POLLINATIONS_MODEL: str = os.getenv("POLLINATIONS_MODEL", "openai")  # Uses default model
    CEREBRAS_MODEL: str = os.getenv("CEREBRAS_MODEL", "llama-3.3-70b")  # or "gpt-oss-120b"
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    
    # Callback Configuration
    GUVI_CALLBACK_URL: str = os.getenv(
        "GUVI_CALLBACK_URL",
        "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    )
    
    # Application Settings
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    MAX_CONVERSATION_TURNS: int = int(os.getenv("MAX_CONVERSATION_TURNS", "20"))
    SCAM_CONFIDENCE_THRESHOLD: float = float(os.getenv("SCAM_CONFIDENCE_THRESHOLD", "0.7"))
    
    # Feature Flags
    ENABLE_TYPOS: bool = os.getenv("ENABLE_TYPOS", "true").lower() == "true"
    ENABLE_DELAYS: bool = os.getenv("ENABLE_DELAYS", "true").lower() == "true"
    
    # Intelligence Quality Thresholds
    IQS_HIGH_THRESHOLD: float = 50.0  # Consider session complete if IQS > 50
    IQS_EXIT_THRESHOLD: float = 70.0  # Force exit if IQS > 70
    
    # Session Settings
    SESSION_TIMEOUT_MINUTES: int = 30
    
    class Config:
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()


def validate_settings() -> bool:
    """Validate that all required settings are present"""
    # Only API_KEY is strictly required for startup. 
    # LLM keys are checked per-provider when needed.
    required = ["API_KEY"]
    missing = [key for key in required if not getattr(settings, key)]
    
    if missing:
        raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
    
    return True


# Validate on import
try:
    validate_settings()
    print("[OK] Configuration loaded successfully")
except ValueError as e:
    print(f"[WARN] Configuration warning: {e}")

