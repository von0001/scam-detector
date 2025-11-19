# backend/manipulation/emotion_classifier.py

from __future__ import annotations
from typing import List, Dict, Any
import os
from groq import Groq
import json

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_MSG = """
You are an emotion classifier.
For each sentence, return:
- top_label: one of [joy, sadness, anger, fear, disgust, neutral]
- top_score: 0-1
Respond ONLY in JSON.
"""

def classify_emotions(sentences: List[str]) -> List[Dict[str, Any]]:
    if not sentences:
        return []

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
        return [
            {
                "sentence": s,
                "top_label": "neutral",
                "top_score": 0.0
            } for s in sentences
        ]