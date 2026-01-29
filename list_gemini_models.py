"""List available Gemini models."""
import sys
sys.path.insert(0, 'd:\\honeypot')

from config import settings
from google import genai

client = genai.Client(api_key=settings.GEMINI_API_KEY)

print("Listing available Gemini models...")
print("="*60)

try:
    for model in client.models.list():
        if hasattr(model, 'name'):
            print(f"  - {model.name}")
except Exception as e:
    print(f"Error listing models: {e}")
