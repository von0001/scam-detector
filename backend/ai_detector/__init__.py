# backend/ai_detector/__init__.py

"""
AI vs Human Chat Detector.

Exposes:
    analyze_actor(chat_text: str) -> dict
"""

from .classify_actor import analyze_actor