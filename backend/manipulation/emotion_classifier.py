# backend/manipulation/emotion_classifier.py

from __future__ import annotations
from typing import List, Dict, Any
import os
import json
from groq import Groq

# ==========================================================
# Lazy Groq client loader (SAFE FOR RAILWAY)
# ==========================================================
_groq_client = None

def get_groq():
    """Initialize Groq client ONLY when needed (not at import)."""
    global _groq_client
    if _groq_client is None:
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set.")
        _groq_client = Groq(api_key=key)
    return _groq_client


# ==========================================================
# System Prompt for Emotion Classification
# ==========================================================
SYSTEM_MSG = """
You are an emotion classifier.
For each sentence, return ONLY a JSON list.

Each item:
{
  "sentence": "...",
  "top_label": "joy|sadness|anger|fear|disgust|neutral",
  "top_score": 0-1 float
}

Be strict, deterministic, and consistent.
"""


# ==========================================================
# Main Emotion Classifier
# ==========================================================
def classify_emotions(sentences: List[str]) -> List[Dict[str, Any]]:
    """
    Calls Groq LLM to classify emotion per sentence.
    Falls back to neutral if anything goes wrong.
    """
    if not sentences:
        return []

    client = get_groq()

    joined = "\n".join(f"- {s}" for s in sentences)

    user_prompt = f"""
Analyze the emotion of each of the following sentences.
Respond ONLY with a JSON list.

{joined}
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_MSG},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.05
        )

        parsed = json.loads(response.choices[0].message.content)

        # Safety: ensure ALL returned objects have the necessary keys
        cleaned = []
        for s, row in zip(sentences, parsed):
            cleaned.append({
                "sentence": s,
                "top_label": row.get("top_label", "neutral"),
                "top_score": float(row.get("top_score", 0.0)),
            })
        return cleaned

    except Exception:
        # Fallback
        return [{
            "sentence": s,
            "top_label": "neutral",
            "top_score": 0.0
        } for s in sentences]