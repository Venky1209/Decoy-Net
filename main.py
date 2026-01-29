"""
AI Honeypot System - Main Application Entry Point

An AI-powered honeypot system that:
- Detects scam messages
- Engages scammers through multi-turn conversations
- Extracts intelligence (bank accounts, UPI IDs, phone numbers, URLs)
- Reports results to GUVI evaluation endpoint
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from api.middleware import APIKeyMiddleware, RequestLoggingMiddleware
from config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup
    logger.info("=" * 50)
    logger.info("🍯 AI Honeypot System Starting Up")
    logger.info("=" * 50)
    logger.info(f"Log Level: {settings.LOG_LEVEL}")
    logger.info(f"Max Conversation Turns: {settings.MAX_CONVERSATION_TURNS}")
    logger.info(f"Scam Confidence Threshold: {settings.SCAM_CONFIDENCE_THRESHOLD}")
    logger.info(f"Typos Enabled: {settings.ENABLE_TYPOS}")
    logger.info(f"Delays Enabled: {settings.ENABLE_DELAYS}")
    
    # Check LLM availability (Priority: Pollinations → Cerebras → Groq → Gemini)
    logger.info(f"Primary LLM: {getattr(settings, 'PRIMARY_LLM', 'pollinations')}")
    logger.info(f"Fallback LLM: {getattr(settings, 'FALLBACK_LLM', 'cerebras')}")
    
    if getattr(settings, 'POLLINATIONS_API_KEY', None):
        logger.info("✓ Pollinations API configured")
    else:
        logger.warning("✗ Pollinations API key not set")
    
    if getattr(settings, 'CEREBRAS_API_KEY', None):
        logger.info("✓ Cerebras API configured")
    else:
        logger.warning("✗ Cerebras API key not set")
    
    if settings.GROQ_API_KEY:
        logger.info("✓ Groq API configured")
    else:
        logger.warning("✗ Groq API key not set")
    
    if settings.GEMINI_API_KEY:
        logger.info("✓ Gemini API configured")
    else:
        logger.warning("✗ Gemini API key not set")
    
    logger.info("=" * 50)
    logger.info("🚀 Honeypot is ready to receive messages!")
    logger.info("=" * 50)
    
    yield
    
    # Shutdown
    logger.info("🛑 Honeypot shutting down...")


# Create FastAPI application
app = FastAPI(
    title="AI Honeypot System",
    description="""
    An AI-powered honeypot that engages with potential scammers 
    to extract intelligence and protect users.
    
    ## Features
    - 🔍 Multi-stage scam detection
    - 🎭 5+ dynamic victim personas
    - 🧠 LLM-powered conversation (Groq + Gemini)
    - 💎 Intelligence extraction with quality scoring
    - 📊 Scammer profiling and behavioral analysis
    - 🔗 Automatic callback to evaluation endpoint
    
    ## Authentication
    All endpoints require `x-api-key` header.
    """,
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middleware
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(APIKeyMiddleware)

# Include API routes
app.include_router(router)


# Add a simple root message for when middleware doesn't process
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "AI Honeypot System",
        "status": "running",
        "version": "1.0.0",
        "docs_url": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
