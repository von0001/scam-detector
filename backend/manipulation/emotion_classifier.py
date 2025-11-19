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


SYSTEM_MSG = """
You are an emotion classifier.
For each sentence, return:
- top_label: one of [joy, sadness, anger, fear, disgust, neutral]
- top_score: 0-1
Respond ONLY in JSON.
"""


# ==========================================================
# Main Emotion Classifier
# ==========================================================
def classify_emotions(sentences: List[str]) -> List[Dict[str, Any]]:
    if not sentences:
        return []

    client = get_groq()  # SAFE

    joined = "\n".join(f"- {s}" for s in sentences)

    prompt = f"""
Analyze the emotion of each of the following sentences:

{joined}

Return JSON list like:
[
  {{"sentence": "...", "top_label": "...", "top_score": 0.52}},
  ...
]
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_MSG},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1
    )

    try:
        return json.loads(response.choices[0].message.content)
    except Exception:
        # fallback: neutral for each
        return [
            {
                "sentence": s,
                "top_label": "neutral",
                "top_score": 0.0
            } 
            for s in sentences
        ]