# backend/ai_detector/classify_actor.py

"""
Lightweight AI vs Human Detector using Groq API.
Fast, small, Railway-safe.
"""

from __future__ import annotations
from typing import Dict, Any
import os
from groq import Groq
import json

# ❗ DO NOT INITIALIZE AT IMPORT TIME
_groq_client = None


def get_client():
    """Load the Groq client lazily (Railway-safe)."""
    global _groq_client
    if _groq_client is None:
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set on server.")
        _groq_client = Groq(api_key=key)
    return _groq_client


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
    text = text.strip()
    if not text:
        return {
            "actor_type": "Unknown",
            "confidence": 0.0,
            "ai_probability": 0,
            "signals": ["No text provided."],
        }

    client = get_client()  # ← LOAD CLIENT HERE, AND ONLY HERE

    prompt = f"""
Classify the following text:

{text}

Return JSON with:
{{
  "ai_probability": number,
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
        return json.loads(response.choices[0].message.content)
    except:
        return {
            "actor_type": "Unknown",
            "confidence": 0.0,
            "ai_probability": 0,
            "signals": ["Model returned invalid format."]
        }