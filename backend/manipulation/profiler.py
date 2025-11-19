# backend/manipulation/profiler.py

"""
High-level Emotional Manipulation Profiler.

Pipeline:
1. Split into sentences
2. Run emotion classifier
3. Run tactic detector
4. Compute per-sentence and global risk scores
5. Generate "what happens next" scenario based on patterns
"""

from __future__ import annotations

from typing import Dict, Any, List
import re

from .emotion_classifier import classify_emotions
from .tactic_detector import detect_tactics, sentence_risk_level


def _split_sentences(text: str) -> List[str]:
    # Light-weight splitter (no NLTK dependency)
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [p.strip() for p in parts if p.strip()]


def _estimate_global_risk(sentence_rows: List[Dict[str, Any]]) -> int:
    """
    Combine tactics + emotions into a 0–100 risk number.
    """
    score = 0
    for row in sentence_rows:
        tactics = row["tactics"]
        color = row["risk_color"]
        emotion = row["emotion"]["top_label"]

        if color == "red":
            score += 12
        elif color == "yellow":
            score += 7

        if emotion.lower() in ("fear", "anger", "disgust"):
            score += 5

        if "secrecy" in tactics or "financial_grooming" in tactics:
            score += 6

    return max(0, min(100, score))


def _guess_scam_profile(tactic_counts: Dict[str, int]) -> str:
    """
    Rough text label for scam type based on tactic composition.
    """
    if tactic_counts.get("love_bombing", 0) >= 2 and tactic_counts.get("secrecy", 0):
        return "romance_scam"

    if tactic_counts.get("financial_grooming", 0) >= 2:
        return "investment_or_money_flip"

    if tactic_counts.get("authority_impersonation", 0) and tactic_counts.get("urgency", 0):
        return "account_or_authority_phishing"

    if tactic_counts.get("reward", 0) >= 2:
        return "lottery_or_prize"

    return "unclear"


def _simulate_next_steps(profile: str) -> List[str]:
    """
    No external LLM here: carefully hand-crafted simulation scripts
    so it works offline by default.
    """
    if profile == "romance_scam":
        return [
            "Scammer continues emotional validation and constant affection.",
            "They introduce a sudden emergency or financial problem.",
            "They ask for money, crypto, or gift cards to 'solve' the issue.",
            "If paid, they escalate the amounts or invent new crises.",
            "Eventually they disappear once financial extraction slows down.",
        ]
    if profile == "investment_or_money_flip":
        return [
            "Scammer pitchs 'risk-free' investment or money flip with huge returns.",
            "They push you to deposit funds into a wallet, broker, or platform they control.",
            "They may show fake dashboards or screenshots of other 'clients' profits.",
            "If you try to withdraw, they block you or demand extra 'unlock' fees.",
            "They abandon the account once they max out what they can extract.",
        ]
    if profile == "account_or_authority_phishing":
        return [
            "Scammer sends a link or attachment for 'verification' or 'resolution'.",
            "They capture login, card, or identity data from the fake page.",
            "They may immediately attempt logins or card charges.",
            "They might contact again pretending to be fraud support.",
            "Identity theft or account takeover can follow.",
        ]
    if profile == "lottery_or_prize":
        return [
            "Scammer congratulates you for winning a prize or lottery you never entered.",
            "They ask for processing fees, taxes, or delivery charges up front.",
            "They delay or deny payout with new excuses and more fee requests.",
            "No actual prize is ever delivered.",
        ]
    return [
        "Scammer continues probing for personal details and financial information.",
        "They adapt the script based on how you respond.",
        "They eventually transition into either asking for money, credentials, or documents.",
        "Once they collect enough, they disappear or move you to another platform.",
    ]


def analyze_manipulation(text: str) -> Dict[str, Any]:
    """
    Public entry point.

    Returns:
    {
      "primary_tactics": [...],
      "risk_score": int,
      "highlights": [
        {"sentence": "...", "tactics": [...], "risk_color": "red|yellow|neutral"},
      ],
      "tactic_counts": {...},
      "scam_profile": str,
      "scenario_simulation": [...],
    }
    """
    cleaned = text.strip()
    if not cleaned:
        return {
            "primary_tactics": [],
            "risk_score": 0,
            "highlights": [],
            "tactic_counts": {},
            "scam_profile": "none",
            "scenario_simulation": [],
        }

    sentences = _split_sentences(cleaned)
    emo_rows = classify_emotions(sentences)

    rows: List[Dict[str, Any]] = []
    tactic_counts: Dict[str, int] = {}

    for emo in emo_rows:
        sent = emo["sentence"]
        tactics = detect_tactics(sent)
        for t in tactics:
            tactic_counts[t] = tactic_counts.get(t, 0) + 1

        color = sentence_risk_level(tactics)

        rows.append(
            {
                "sentence": sent,
                "emotion": {"top_label": emo["top_label"], "top_score": emo["top_score"]},
                "tactics": tactics,
                "risk_color": color,
            }
        )

    risk_score = _estimate_global_risk(rows)
    primary_tactics = sorted(
        tactic_counts.keys(), key=lambda t: tactic_counts[t], reverse=True
    )
    scam_profile = _guess_scam_profile(tactic_counts)
    scenario_simulation = _simulate_next_steps(scam_profile)

    return {
        "primary_tactics": primary_tactics,
        "risk_score": risk_score,
        "highlights": rows,
        "tactic_counts": tactic_counts,
        "scam_profile": scam_profile,
        "scenario_simulation": scenario_simulation,
    }