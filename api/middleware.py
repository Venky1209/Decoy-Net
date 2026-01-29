"""
API middleware for authentication and request processing.
"""
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import time
import logging
from config import settings

logger = logging.getLogger(__name__)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware for API key authentication.
    Validates x-api-key header against configured API key.
    """
    
    # Paths that don't require authentication
    EXEMPT_PATHS = {"/", "/health", "/docs", "/openapi.json", "/redoc"}
    
    async def dispatch(self, request: Request, call_next):
        # Skip auth for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)
        
        # Get API key from header
        api_key = request.headers.get("x-api-key")
        
        if not api_key:
            logger.warning(f"Missing API key for request to {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Missing API key", "detail": "x-api-key header required"}
            )
        
        if api_key != settings.API_KEY:
            logger.warning(f"Invalid API key attempt for {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Invalid API key", "detail": "API key validation failed"}
            )
        
        return await call_next(request)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging requests and response times.
    """
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Log incoming request
        logger.info(f"Request: {request.method} {request.url.path}")
        
        # Process request
        response = await call_next(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Log response
        logger.info(
            f"Response: {request.method} {request.url.path} "
            f"status={response.status_code} time={process_time:.3f}s"
        )
        
        # Add processing time header
        response.headers["X-Process-Time"] = f"{process_time:.3f}"
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiting middleware.
    Limits requests per session/IP.
    """
    
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.request_counts: dict = {}  # IP -> (count, window_start)
    
    async def dispatch(self, request: Request, call_next):
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()
        
        # Check rate limit
        if client_ip in self.request_counts:
            count, window_start = self.request_counts[client_ip]
            
            # Reset window if minute passed
            if current_time - window_start > 60:
                self.request_counts[client_ip] = (1, current_time)
            elif count >= self.requests_per_minute:
                logger.warning(f"Rate limit exceeded for {client_ip}")
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "Rate limit exceeded",
                        "detail": f"Maximum {self.requests_per_minute} requests per minute"
                    }
                )
            else:
                self.request_counts[client_ip] = (count + 1, window_start)
        else:
            self.request_counts[client_ip] = (1, current_time)
        
        return await call_next(request)


def validate_api_key(api_key: str) -> bool:
    """
    Validate API key against configured value.
    
    Args:
        api_key: The API key to validate
        
    Returns:
        True if valid, False otherwise
    """
    return api_key == settings.API_KEY
