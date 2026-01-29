"""
API endpoint tests.
"""
import pytest
from fastapi.testclient import TestClient

# Add parent directory to path for imports
import sys
sys.path.insert(0, 'd:/honeypot')

from main import app
from config import settings


client = TestClient(app)


class TestHealthEndpoints:
    """Test health check endpoints."""
    
    def test_root_endpoint(self):
        """Test root endpoint returns status."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
    
    def test_health_endpoint(self):
        """Test /health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestAuthentication:
    """Test API key authentication."""
    
    def test_missing_api_key(self):
        """Test request without API key returns 401."""
        response = client.post(
            "/analyze",
            json={
                "sessionId": "test123",
                "message": "Hello"
            }
        )
        assert response.status_code == 401
    
    def test_invalid_api_key(self):
        """Test request with invalid API key returns 403."""
        response = client.post(
            "/analyze",
            json={
                "sessionId": "test123",
                "message": "Hello"
            },
            headers={"x-api-key": "wrong_key"}
        )
        assert response.status_code == 403
    
    def test_valid_api_key(self):
        """Test request with valid API key succeeds."""
        response = client.post(
            "/analyze",
            json={
                "sessionId": "test123",
                "message": "Hello, this is a test message."
            },
            headers={"x-api-key": settings.API_KEY}
        )
        # Should return 200 (might be scam or not, but auth passes)
        assert response.status_code == 200


class TestAnalyzeEndpoint:
    """Test /analyze endpoint."""
    
    def test_basic_scam_detection(self):
        """Test detection of obvious scam message."""
        response = client.post(
            "/analyze",
            json={
                "sessionId": "test_scam_001",
                "message": "Your bank account is blocked! Send OTP immediately to unblock.",
                "conversationHistory": []
            },
            headers={"x-api-key": settings.API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["sessionId"] == "test_scam_001"
        assert "response" in data
        assert "isScam" in data
        assert "confidence" in data
        assert "extractedIntelligence" in data
    
    def test_legitimate_message(self):
        """Test that legitimate messages have low confidence."""
        response = client.post(
            "/analyze",
            json={
                "sessionId": "test_legit_001",
                "message": "Hello, I am calling to check on my order status.",
                "conversationHistory": []
            },
            headers={"x-api-key": settings.API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Legitimate message should have low scam confidence
        assert data["confidence"] < 0.7
    
    def test_response_format(self):
        """Test that response has all required fields."""
        response = client.post(
            "/analyze",
            json={
                "sessionId": "test_format_001",
                "message": "Test message"
            },
            headers={"x-api-key": settings.API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check required fields
        required_fields = [
            "sessionId",
            "response",
            "isScam",
            "confidence",
            "extractedIntelligence",
            "conversationTurn",
            "intelligenceQualityScore"
        ]
        
        for field in required_fields:
            assert field in data, f"Missing field: {field}"
    
    def test_intelligence_extraction(self):
        """Test that intelligence is extracted correctly."""
        response = client.post(
            "/analyze",
            json={
                "sessionId": "test_intel_001",
                "message": "Send money to 9876543210 or transfer to scammer@ybl",
                "conversationHistory": []
            },
            headers={"x-api-key": settings.API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        intel = data["extractedIntelligence"]
        
        # Should extract phone and UPI
        assert "phoneNumbers" in intel
        assert "upiIds" in intel


class TestSessionManagement:
    """Test session-related endpoints."""
    
    def test_get_nonexistent_session(self):
        """Test getting a session that doesn't exist."""
        response = client.get(
            "/sessions/nonexistent_session_xyz",
            headers={"x-api-key": settings.API_KEY}
        )
        assert response.status_code == 404
    
    def test_stats_endpoint(self):
        """Test stats endpoint returns data."""
        response = client.get(
            "/stats",
            headers={"x-api-key": settings.API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "activeSessions" in data
        assert "totalProcessed" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
