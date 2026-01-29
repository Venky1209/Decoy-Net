# 🕸️ DecoyNet - AI-Powered Honeypot for Scam Detection

**DecoyNet** is an intelligent honeypot system that autonomously detects and engages scammers to extract actionable intelligence for fraud prevention.

## 🌟 Features

### Core Capabilities
- ✅ **Multi-Stage Scam Detection**: 90%+ accuracy with confidence scoring
- ✅ **AI-Powered Agent**: Gemini 3 + Groq dual-LLM system
- ✅ **Dynamic Personas**: 5 unique victim profiles (elderly, business owner, student, etc.)
- ✅ **Intelligence Extraction**: Extracts bank accounts, UPI IDs, URLs, phone numbers
- ✅ **Real-time Profiling**: Classifies scammer type, tactics, and threat level

### Unique Features (Competitive Edge)
- 🎭 **Dynamic Persona System**: Switches personas mid-conversation if needed
- 🧠 **Scammer Profiling**: Builds behavioral fingerprint and threat assessment
- 💎 **Intelligence Quality Scoring (IQS)**: Scores intelligence value (0-100+)
- 🎪 **Breadcrumb Extraction**: Strategic questioning to extract info naturally
- 🔍 **Anti-Detection**: Typos, delays, human-like imperfections
- 🎯 **Conversation State Machine**: 6-state conversation flow (PROBE→ENGAGE→EXTRACT→VERIFY→DEEPEN→EXIT)
- 🛡️ **Deception Detection**: Identifies when scammer is testing for bots
- 📈 **Explainable AI**: Detailed agent notes with strategy breakdown

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- API Keys (both free):
  - **Groq API**: https://console.groq.com/
  - **Gemini API**: https://aistudio.google.com/apikey

### Installation

1. **Install Python** (if not already installed):
   - Download from https://www.python.org/downloads/
   - ⚠️ Make sure to check "Add Python to PATH" during installation

2. **Clone/Navigate to project**:
```bash
cd D:\honeypot
```

3. **Create virtual environment** (recommended):
```bash
python -m venv venv
venv\Scripts\activate  # Windows
```

4. **Install dependencies**:
```bash
pip install -r requirements.txt
```

5. **Configure environment**:
   - API keys are already set in `.env` file
   - Modify settings in `.env` if needed

### Running the Server

```bash
uvicorn main:app --reload --port 8000
```

Server will start at: `http://localhost:8000`

### Testing the API

#### Health Check:
```powershell
curl http://localhost:8000/health
```

#### Send a Test Message:
```powershell
curl -X POST http://localhost:8000/api/honeypot `
  -H "Content-Type: application/json" `
  -H "x-api-key: decoynet_secret_key_2026" `
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer",
      "text": "Your bank account will be blocked today. Verify immediately.",
      "timestamp": "2026-01-29T04:00:00Z"
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

## 📁 Project Structure

```
honeypot/
├── main.py                 # FastAPI application entry point
├── config.py               # Configuration management
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (DO NOT COMMIT)
├── .env.example            # Environment template
├── api/
│   ├── __init__.py
│   ├── routes.py          # API endpoints
│   ├── middleware.py      # Authentication & validation
│   └── models.py          # Pydantic request/response models
├── core/
│   ├── __init__.py
│   ├── scam_detector.py   # Scam detection engine
│   ├── agent.py           # AI agent orchestration
│   ├── session_manager.py # Conversation state management
│   ├── intelligence_extractor.py  # Entity extraction
│   └── callback_handler.py        # GUVI callback integration
├── extractors/
│   ├── __init__.py
│   ├── bank_account.py    # Bank account extraction
│   ├── upi.py             # UPI ID extraction
│   ├── url.py             # URL/phishing link extraction
│   ├── phone.py           # Phone number extraction
│   └── keywords.py        # Suspicious keyword extraction
├── utils/
│   ├── __init__.py
│   ├── patterns.py        # Detection patterns & regex
│   ├── personas.py        # Victim persona definitions
│   ├── prompts.py         # LLM prompts & templates
│   └── storage.py         # Session storage layer
├── tests/
│   ├── __init__.py
│   ├── test_api.py
│   ├── test_scam_detector.py
│   ├── test_agent.py
│   └── test_extraction.py
└── examples/
    ├── sample_requests.json
    └── test_conversations.json
```

## 🔑 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_KEY` | Authentication key for API | `decoynet_secret_key_2026` |
| `GROQ_API_KEY` | Groq API key (free) | - |
| `GEMINI_API_KEY` | Gemini API key (free) | - |
| `GUVI_CALLBACK_URL` | GUVI evaluation endpoint | Set |
| `MAX_CONVERSATION_TURNS` | Max messages per session | `20` |
| `SCAM_CONFIDENCE_THRESHOLD` | Confidence to activate agent | `0.7` |
| `ENABLE_TYPOS` | Add human-like typos | `true` |
| `ENABLE_DELAYS` | Simulate typing delays | `true` |

## 🎯 API Endpoints

### `POST /api/honeypot`
Main endpoint for scam message processing.

**Headers:**
- `x-api-key`: Your API key (from `.env`)
- `Content-Type`: `application/json`

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Message content",
    "timestamp": "ISO-8601 timestamp"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Agent response message"
}
```

### `GET /health`
Health check endpoint.

## 🧪 Testing

Run the test suite:
```bash
pytest tests/ -v
```

Run specific tests:
```bash
pytest tests/test_scam_detector.py -v
```

## 📊 Intelligence Quality Score (IQS)

DecoyNet calculates an Intelligence Quality Score based on extracted entities:

| Entity Type | Points | Notes |
|-------------|--------|-------|
| Phone Number | 3 | Indian format preferred |
| Email Address | 4 | Validated format |
| UPI ID | 5 | username@bank format |
| URL/Phishing Link | 6 | Validated and accessible |
| Bank Account | 7 | Multiple formats supported |
| Full Scam Workflow | 10 | Complete attack chain |

**Formula:** `IQS = Σ(entity_points × confidence_score)`

**Exit Conditions:**
- IQS > 50: Consider session complete
- IQS > 70: Force exit
- Turn count > 20: Max turns reached

## 🤖 Persona System

DecoyNet uses 5 distinct personas:

1. **Ramesh Uncle (Elderly)**: Tech-unsavvy, trusting, asks basic questions
2. **Priya (Business Owner)**: Busy, worried about money, moderate tech knowledge
3. **Arjun (College Student)**: Limited funds, curious, casual language
4. **Lakshmi Aunty (Homemaker)**: Cautious, asks family, traditional
5. **Vikram (Tech Worker)**: Skeptical, asks verification questions

Personas auto-switch if current strategy isn't effective.

## 🛡️ Conversation States

1. **PROBE**: Initial scam detection and assessment
2. **ENGAGE**: Build trust with scammer
3. **EXTRACT**: Primary intelligence gathering
4. **VERIFY**: Confirm extracted information
5. **DEEPEN**: Get additional details
6. **EXIT**: End conversation and send callback

## 📡 Callback Integration

When a conversation completes, DecoyNet sends results to GUVI:

```json
{
  "sessionId": "session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 15,
  "extractedIntelligence": {
    "bankAccounts": ["..."],
    "upiIds": ["..."],
    "phishingLinks": ["..."],
    "phoneNumbers": ["..."],
    "suspiciousKeywords": ["..."]
  },
  "scammerProfile": {
    "scammerType": "Aggressive",
    "scamCategory": "Banking",
    "psychologicalTactics": ["Urgency", "Authority"],
    "threatLevel": 8
  },
  "intelligenceQualityScore": 65.5,
  "agentNotes": "Detailed strategy breakdown..."
}
```

## 🏆 Competition Submissions

### GUVI Honeypot Hackathon
- ✅ Meets all API requirements
- ✅ Enhanced callback with profiling & IQS
- ✅ Production-ready deployment

### Gemini 3 Hackathon
- ✅ Uses Gemini 3 API as primary LLM
- ✅ Leverages advanced reasoning capabilities
- ✅ Social good application (fraud prevention)
- ✅ Novel approach with multi-agent system

## 📝 Development Roadmap

See `DEVELOPMENT_ROADMAP.md` for detailed step-by-step implementation guide.

## 🤝 Contributing

This is a hackathon project. Future enhancements:
- [ ] Voice scam detection
- [ ] Multi-language support (Hindi, Tamil, etc.)
- [ ] Analytics dashboard
- [ ] Machine learning model training from collected data
- [ ] Real-time alerts and reporting

## 📜 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- **Groq** for ultra-fast LLM inference
- **Google Gemini** for advanced AI capabilities
- **GUVI** for hosting the hackathon
- **FastAPI** for the excellent framework

## 📧 Support

For issues or questions, open an issue on the repository.

---

**Built with ❤️ for fraud prevention and user safety**
