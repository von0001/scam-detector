# backend/manipulation/emotion_classifier.py

"""
Sentence-level emotion classification wrapper.

Uses a HuggingFace transformer model. You can swap `MODEL_NAME`
to any local / downloaded emotion model you prefer.
"""

from __future__ import annotations

from typing import List, Dict, Any

from transformers import pipeline


_MODEL_NAME = "j-hartmann/emotion-english-distilroberta-base"
_emotion_pipe: pipeline | None = None


def _get_emotion_pipe() -> pipeline:
    global _emotion_pipe
    if _emotion_pipe is None:
        _emotion_pipe = pipeline(
            "text-classification",
            model=_MODEL_NAME,
            return_all_scores=True,
        )
    return _emotion_pipe


def classify_emotions(sentences: List[str]) -> List[Dict[str, Any]]:
    """
    Returns list of:
    {
      "sentence": str,
      "top_label": str,
      "top_score": float,
      "all_scores": [{"label": str, "score": float}, ...]
    }
    """
    if not sentences:
        return []

    pipe = _get_emotion_pipe()
    outputs = pipe(sentences)

    results: List[Dict[str, Any]] = []
    for sent, scores in zip(sentences, outputs):
        if not scores:
            results.append(
                {
                    "sentence": sent,
                    "top_label": "neutral",
                    "top_score": 0.0,
                    "all_scores": [],
                }
            )
            continue

        best = max(scores, key=lambda x: x["score"])
        results.append(
            {
                "sentence": sent,
                "top_label": best["label"],
                "top_score": float(best["score"]),
                "all_scores": [
                    {"label": s["label"], "score": float(s["score"])} for s in scores
                ],
            }
        )
    return results