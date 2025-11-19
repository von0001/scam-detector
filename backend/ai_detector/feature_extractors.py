# backend/ai_detector/feature_extractors.py

"""
Feature extraction utilities for AI vs Human detection.

We compute:
- basic token/word/sentence stats
- lexical diversity
- punctuation / emoji usage
- capitalization patterns
- simple "burstiness" proxy
- grammar quality (optional, if language_tool_python available)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any

import math
import re

import textstat

try:
    import language_tool_python  # optional, heavy
    _LT_TOOL = language_tool_python.LanguageTool("en-US")
except Exception:
    _LT_TOOL = None


EMOJI_RE = re.compile(
    r"[\U0001F600-\U0001F64F"
    r"\U0001F300-\U0001F5FF"
    r"\U0001F680-\U0001F6FF"
    r"\U0001F1E0-\U0001F1FF]"
)


@dataclass
class StyleFeatures:
    word_count: int
    sentence_count: int
    avg_sentence_len: float
    type_token_ratio: float
    punctuation_ratio: float
    emoji_ratio: float
    all_caps_ratio: float
    question_ratio: float
    exclamation_ratio: float
    flesch_reading_ease: float
    grammar_error_rate: float  # 0–1
    burstiness: float          # variance of sentence lengths


def compute_style_features(text: str) -> StyleFeatures:
    raw = text.strip()
    if not raw:
        return StyleFeatures(
            word_count=0,
            sentence_count=0,
            avg_sentence_len=0.0,
            type_token_ratio=0.0,
            punctuation_ratio=0.0,
            emoji_ratio=0.0,
            all_caps_ratio=0.0,
            question_ratio=0.0,
            exclamation_ratio=0.0,
            flesch_reading_ease=0.0,
            grammar_error_rate=0.0,
            burstiness=0.0,
        )

    # Basic tokens
    tokens = re.findall(r"\w+", raw)
    words = [t.lower() for t in tokens]
    word_count = len(words)

    # Sentences
    sentences = re.split(r"[.!?]+", raw)
    sentences = [s.strip() for s in sentences if s.strip()]
    sentence_count = max(len(sentences), 1)

    lengths = [len(s.split()) for s in sentences]
    avg_sentence_len = sum(lengths) / sentence_count
    if len(lengths) > 1:
        mean_len = avg_sentence_len
        burstiness = sum((l - mean_len) ** 2 for l in lengths) / (len(lengths) - 1)
    else:
        burstiness = 0.0

    # Lexical diversity
    unique_words = len(set(words)) or 1
    type_token_ratio = unique_words / max(word_count, 1)

    # Punctuation / emojis
    total_chars = len(raw) or 1
    punct_count = len(re.findall(r"[.,!?;:]", raw))
    punctuation_ratio = punct_count / total_chars

    emojis = EMOJI_RE.findall(raw)
    emoji_ratio = len(emojis) / total_chars

    # ALL CAPS words (but not single-letter like I / A)
    all_caps_words = [w for w in re.findall(r"\b[A-Z]{2,}\b", raw)]
    all_caps_ratio = len(all_caps_words) / max(word_count, 1)

    # Question / exclamation
    question_ratio = raw.count("?") / max(sentence_count, 1)
    exclamation_ratio = raw.count("!") / max(sentence_count, 1)

    # Readability and grammar
    try:
        fre = textstat.flesch_reading_ease(raw)
    except Exception:
        fre = 0.0

    grammar_error_rate = 0.0
    if _LT_TOOL is not None:
        try:
            matches = _LT_TOOL.check(raw)
            grammar_error_rate = len(matches) / max(word_count, 1)
        except Exception:
            grammar_error_rate = 0.0

    return StyleFeatures(
        word_count=word_count,
        sentence_count=sentence_count,
        avg_sentence_len=avg_sentence_len,
        type_token_ratio=type_token_ratio,
        punctuation_ratio=punctuation_ratio,
        emoji_ratio=emoji_ratio,
        all_caps_ratio=all_caps_ratio,
        question_ratio=question_ratio,
        exclamation_ratio=exclamation_ratio,
        flesch_reading_ease=fre,
        grammar_error_rate=grammar_error_rate,
        burstiness=burstiness,
    )


def style_features_to_dict(sf: StyleFeatures) -> Dict[str, Any]:
    return sf.__dict__