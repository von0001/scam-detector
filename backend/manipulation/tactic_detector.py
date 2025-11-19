# backend/manipulation/tactic_detector.py

"""
Rule-based pattern detector for scam manipulation tactics.

Tactics:
- urgency
- fear / threat
- authority_impersonation
- secrecy / isolation
- love_bombing / romance
- reward / prize
- financial_grooming
"""

from __future__ import annotations

from typing import List, Dict, Any
import re


TACTIC_KEYWORDS = {
    "urgency": [
        r"\bright now\b",
        r"\bimmediately\b",
        r"\blast warning\b",
        r"\bfinal notice\b",
        r"\bact fast\b",
        r"\btime[-\s]?sensitive\b",
        r"\bwithin\s+\d+\s+(minutes?|hours?)\b",
    ],
    "fear": [
        r"\baccount (?:will be|has been) (?:closed|suspended|locked)\b",
        r"\bpolice\b",
        r"\bcharges?\b",
        r"\blegal action\b",
        r"\bfraud department\b",
        r"\bsecurity alert\b",
    ],
    "authority_impersonation": [
        r"\birs\b",
        r"\brevenue service\b",
        r"\bbank\b",
        r"\bpaypal\b",
        r"\bsecurity team\b",
        r"\bofficial notice\b",
    ],
    "secrecy": [
        r"\bdon't tell\b",
        r"\bkeep this between us\b",
        r"\bno one else can know\b",
        r"\bdo not share\b",
    ],
    "love_bombing": [
        r"\bmy (?:love|angel|dear|princess|king)\b",
        r"\bi can't stop thinking about you\b",
        r"\byou are the only one\b",
        r"\bwe were meant to be\b",
    ],
    "reward": [
        r"\byou (?:have )?won\b",
        r"\bcongratulations\b",
        r"\bprize\b",
        r"\bjackpot\b",
        r"\bclaim your reward\b",
        r"\bselected randomly\b",
    ],
    "financial_grooming": [
        r"\binvestment opportunity\b",
        r"\bflip your money\b",
        r"\bguaranteed returns\b",
        r"\bdouble your funds\b",
        r"\bprofit\b",
        r"\bwire transfer\b",
        r"\bgift card\b",
        r"\bcrypto\b",
    ],
}


def detect_tactics(sentence: str) -> List[str]:
    """
    Return list of tactic keys triggered by this sentence.
    """
    lower = sentence.lower()
    hits = []

    for tactic, patterns in TACTIC_KEYWORDS.items():
        for pat in patterns:
            if re.search(pat, lower):
                hits.append(tactic)
                break

    return hits


def sentence_risk_level(tactics: List[str]) -> str:
    """
    Map tactics → color-coded level.
    """
    if not tactics:
        return "neutral"

    if any(t in tactics for t in ("urgency", "fear", "authority_impersonation", "financial_grooming")):
        return "red"

    if any(t in tactics for t in ("reward", "love_bombing", "secrecy")):
        return "yellow"

    return "yellow"