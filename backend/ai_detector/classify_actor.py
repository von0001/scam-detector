# backend/ai_detector/classify_actor.py

"""
Lightweight AI vs Human Detector using Groq API.
"""

from __future__ import annotations
from typing import Dict, Any
import os
from groq import Groq

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_MSG = """
You are an AI-human text classifier.
Return:
- ai_probability (0-100)
- actor_type ("AI-generated text", "Human", or "Hybrid")
- confidence (0-1)
- signals: specific reasons for classification
Respond ONLY in JSON.
"""

def analyze_actor(text: str) -> Dict[str, Any]:
    if not text.strip():
        return {
            "actor_type": "Unknown",
            "confidence": 0.0,
            "ai_probability": 0,
            "signals": ["No text provided."],
        }

    prompt = f"""
Classify the following text:

{text}

Return JSON with:
{{
  "ai_probability": number (0-100),
  "actor_type": string,
  "confidence": number,
  "signals": [string]
}}
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_MSG},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )

    try:
        import json
        out = json.loads(response.choices[0].message.content)
        return out
    except Exception:
        # fallback if non-JSON
        return {
            "actor_type": "Unknown",
            "confidence": 0.0,
            "ai_probability": 0,
            "signals": ["Model returned invalid format."]
        }