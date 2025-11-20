# backend/manipulation/ai_manipulation_classifier.py

from __future__ import annotations
from typing import Dict, Any
import os
import json
from groq import Groq

_groq_client = None

def get_groq():
    global _groq_client
    if _groq_client is None:
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set.")
        _groq_client = Groq(api_key=key)
    return _groq_client


SYSTEM_MSG = """
You are an emotional manipulation detector.

Analyze the user's message and return ONLY a JSON dict:
{
  "manipulation_type": "...",
  "manipulation_score": 0-100,
  "tactics": ["list", "of", "detected", "tactics"],
  "explanation": "short human readable explanation"
}

manipulation_type should be one of:
"none", "gaslighting", "coercion", "guilt_tripping", 
"love_bombing", "financial_grooming", 
"emotional_leverage", "boundary_violation",
"passive_threats", "authority_pressure",
"romance_scam", "money_scam", "other"

Be strict. Score reflects severity.
"""


def ai_detect_manipulation(text: str) -> Dict[str, Any]:
    client = get_groq()

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            temperature=0,
            messages=[
                {"role": "system", "content": SYSTEM_MSG},
                {"role": "user", "content": text},
            ],
        )

        raw = response.choices[0].message.content
        data = json.loads(raw)

        # safety sanitization
        return {
            "manipulation_type": data.get("manipulation_type", "none"),
            "manipulation_score": int(data.get("manipulation_score", 0)),
            "tactics": data.get("tactics", []),
            "explanation": data.get("explanation", ""),
        }

    except Exception:
        return {
            "manipulation_type": "none",
            "manipulation_score": 0,
            "tactics": [],
            "explanation": "AI detector failed.",
        }