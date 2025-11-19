# backend/ai_detector/classify_actor.py

"""
AI vs Human Chat Detector.

This combines:
1. Style-based linguistic features
2. SBERT embedding similarity to known AI vs human examples
"""

from __future__ import annotations

from typing import Dict, Any, List

import numpy as np

from sentence_transformers import SentenceTransformer
from sentence_transformers.util import cos_sim  # type: ignore

from .feature_extractors import compute_style_features, style_features_to_dict


# ===============================================
# GLOBAL SBERT MODEL (LOAD ONCE)
# ===============================================
_SBERT_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
_sbert_model: SentenceTransformer | None = None

# Cached embeddings so we don't recompute them every request
_ai_example_embs = None
_human_example_embs = None


def _get_sbert() -> SentenceTransformer:
    """Load SBERT only once."""
    global _sbert_model
    if _sbert_model is None:
        _sbert_model = SentenceTransformer(_SBERT_MODEL_NAME)
    return _sbert_model


# ===============================================
# Example Corpora
# ===============================================
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


# ===============================================
# Embedding Similarity (with caching)
# ===============================================
def _embedding_similarity_score(text: str) -> Dict[str, float]:
    global _ai_example_embs, _human_example_embs

    model = _get_sbert()

    # Encode input
    input_emb = model.encode(text, convert_to_tensor=True)

    # Cache AI example embeddings
    if _ai_example_embs is None:
        _ai_example_embs = model.encode(AI_EXAMPLES, convert_to_tensor=True)
    if _human_example_embs is None:
        _human_example_embs = model.encode(HUMAN_EXAMPLES, convert_to_tensor=True)

    # Similarity scores
    ai_sim = float(cos_sim(input_emb, _ai_example_embs).max().item())
    human_sim = float(cos_sim(input_emb, _human_example_embs).max().item())

    # Normalize [-1, 1] → [0, 1]
    ai_norm = (ai_sim + 1) / 2
    human_norm = (human_sim + 1) / 2

    return {
        "ai_similarity": ai_norm,
        "human_similarity": human_norm,
    }


# ===============================================
# Scoring Engine
# ===============================================
def _score_from_features(style, sims) -> Dict[str, Any]:
    signals: List[str] = []

    ai_sim = sims["ai_similarity"]
    human_sim = sims["human_similarity"]

    # Baseline score from similarity difference
    base_ai = ai_sim - human_sim  # >0 = closer to AI
    ai_score = 50 + base_ai * 40  # center=50, range=±40

    # -----------------------------------------------
    # AI-like indicators
    # -----------------------------------------------
    if style.burstiness < 5 and style.word_count > 40:
        ai_score += 8
        signals.append("Very consistent sentence lengths → AI-like.")

    if style.emoji_ratio < 0.001 and style.word_count > 20:
        ai_score += 4
        signals.append("Almost no emojis → AI-like pattern.")

    if style.grammar_error_rate < 0.02 and style.word_count > 25:
        ai_score += 6
        signals.append("Very low grammar error rate → AI signal.")

    if style.type_token_ratio > 0.6 and style.word_count > 40:
        ai_score += 3
        signals.append("High lexical diversity + clean structure → AI-like.")

    # -----------------------------------------------
    # Human-like indicators
    # -----------------------------------------------
    if style.burstiness > 20:
        ai_score -= 10
        signals.append("High burstiness → human typing.")

    if style.emoji_ratio > 0.005:
        ai_score -= 6
        signals.append("Frequent emojis → human behavior.")

    if style.grammar_error_rate > 0.05:
        ai_score -= 8
        signals.append("Grammar inconsistencies → human-like.")

    if style.all_caps_ratio > 0.03:
        ai_score -= 4
        signals.append("ALL CAPS emphasis → human emotional pattern.")

    # Clamp score 0–100
    ai_score = max(0, min(100, int(round(ai_score))))

    # Determine label
    if ai_score >= 70:
        label = "AI-generated text"
        conf = (ai_score - 70) / 30
    elif ai_score <= 30:
        label = "Human"
        conf = (30 - ai_score) / 30
    else:
        label = "Hybrid / Mixed"
        conf = 1.0 - (abs(ai_score - 50) / 20)
        conf = max(0.0, min(conf, 1.0))

    return {
        "ai_probability": ai_score,
        "actor_type": label,
        "confidence": float(round(conf, 3)),
        "signals": signals,
    }


# ===============================================
# PUBLIC ENTRY POINT
# ===============================================
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
    sims = _embedding_similarity_score(text)
    scored = _score_from_features(style, sims)

    return {
        "actor_type": scored["actor_type"],
        "confidence": scored["confidence"],
        "ai_probability": scored["ai_probability"],
        "signals": scored["signals"],
        "style_features": style_features_to_dict(style),
        "similarity": sims,
    }