# backend/ai_detector/classify_actor.py

"""
AI vs Human Chat Detector (Groq Embedding Version)

Features:
1. Style-based linguistic analysis
2. Groq embedding similarities to AI-like vs human-like sample texts

This file is fully deployment-safe:
- No model loads at import time
- Groq client and embeddings load ONLY when needed
"""

from __future__ import annotations

import os
from typing import Dict, Any, List

import numpy as np
from groq import Groq

from .feature_extractors import compute_style_features, style_features_to_dict


# ============================================================
# Lazy Groq Client Loader (IMPORTANT)
# ============================================================
_groq_client = None


def get_groq():
    """Create the Groq client ONLY when needed."""
    global _groq_client
    if _groq_client is None:
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set.")
        _groq_client = Groq(api_key=key)
    return _groq_client


# ============================================================
# Example Corpora (AI-like vs Human-like)
# ============================================================
AI_EXAMPLES = [
    "As an AI language model, I do not have personal feelings.",
    "Sure! Here is a step-by-step explanation of how this works.",
    "I understand your concern. Let me break this down.",
    "Here are several options you can consider.",
]

HUMAN_EXAMPLES = [
    "idk man this seems weird.",
    "bro that message feels off.",
    "ngl that might be a scam tbh.",
    "hey, just checking in. how are you doing?",
]


# ============================================================
# Text → Embedding via Groq
# ============================================================
def embed(texts: List[str]) -> np.ndarray:
    """
    Return embeddings for a list of strings using Groq.
    """
    client = get_groq()
    response = client.embeddings.create(
        model="text-embedding-3-small",
        input=texts,
    )

    vectors = [item.embedding for item in response.data]
    return np.array(vectors, dtype=float)


# Cached embeddings (for speed)
_ai_embs = None
_human_embs = None


def embedding_similarity(text: str) -> Dict[str, float]:
    """
    Convert text to embedding, compare to cached AI/HUMAN embeddings.
    """
    global _ai_embs, _human_embs

    # Input embedding
    emb = embed([text])[0]

    # Cache example embeddings
    if _ai_embs is None:
        _ai_embs = embed(AI_EXAMPLES)
    if _human_embs is None:
        _human_embs = embed(HUMAN_EXAMPLES)

    # Cosine similarities
    def cos(a, b):
        a = a / (np.linalg.norm(a) + 1e-9)
        b = b / (np.linalg.norm(b) + 1e-9)
        return float(np.dot(a, b))

    ai_sim = max(cos(emb, e) for e in _ai_embs)
    human_sim = max(cos(emb, e) for e in _human_embs)

    # Normalize [-1, 1] → [0, 1]
    ai_norm = (ai_sim + 1) / 2
    human_norm = (human_sim + 1) / 2

    return {
        "ai_similarity": ai_norm,
        "human_similarity": human_norm,
    }


# ============================================================
# Scoring Logic
# ============================================================
def score_from_features(style, sims) -> Dict[str, Any]:
    signals = []

    ai_sim = sims["ai_similarity"]
    human_sim = sims["human_similarity"]

    # baseline
    base_ai = ai_sim - human_sim
    ai_score = 50 + base_ai * 40

    # AI-like signals
    if style.burstiness < 5 and style.word_count > 40:
        ai_score += 8
        signals.append("Very consistent sentence lengths → AI-like.")

    if style.emoji_ratio < 0.001 and style.word_count > 20:
        ai_score += 4
        signals.append("Almost no emojis → AI-like.")

    if style.grammar_error_rate < 0.02 and style.word_count > 25:
        ai_score += 6
        signals.append("Low grammar error rate → AI-like.")

    if style.type_token_ratio > 0.6 and style.word_count > 40:
        ai_score += 3
        signals.append("High lexical diversity → AI-like.")

    # Human-like signals
    if style.burstiness > 20:
        ai_score -= 10
        signals.append("High burstiness → Human.")

    if style.emoji_ratio > 0.005:
        ai_score -= 6
        signals.append("Frequent emojis → Human.")

    if style.grammar_error_rate > 0.05:
        ai_score -= 8
        signals.append("Grammar inconsistency → Human.")

    if style.all_caps_ratio > 0.03:
        ai_score -= 4
        signals.append("All CAPS emotional emphasis → Human.")

    # clamp
    ai_score = max(0, min(100, int(round(ai_score))))

    # classification
    if ai_score >= 70:
        actor = "AI-generated text"
        conf = (ai_score - 70) / 30
    elif ai_score <= 30:
        actor = "Human"
        conf = (30 - ai_score) / 30
    else:
        actor = "Hybrid / Mixed"
        conf = 1.0 - abs(ai_score - 50) / 20
        conf = max(0, min(conf, 1))

    return {
        "ai_probability": ai_score,
        "actor_type": actor,
        "confidence": round(conf, 3),
        "signals": signals,
    }


# ============================================================
# Public entry point
# ============================================================
def analyze_actor(chat_text: str) -> Dict[str, Any]:
    text = chat_text.strip()
    if not text:
        return {
            "actor_type": "Unknown",
            "confidence": 0.0,
            "ai_probability": 0,
            "signals": ["No text provided."],
            "style_features": {},
            "similarity": {"ai_similarity": 0.0, "human_similarity": 0.0},
        }

    style = compute_style_features(text)
    sims = embedding_similarity(text)
    scored = score_from_features(style, sims)

    return {
        "actor_type": scored["actor_type"],
        "confidence": scored["confidence"],
        "ai_probability": scored["ai_probability"],
        "signals": scored["signals"],
        "style_features": style_features_to_dict(style),
        "similarity": sims,
    }
