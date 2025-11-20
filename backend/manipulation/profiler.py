# backend/manipulation/profiler.py

"""
High-level Emotional Manipulation Profiler.

Upgraded Von Edition:
- Softer thresholds for scam profiles
- More realistic romance scam detection
- Better authority scam classification
- Financial grooming triggers earlier
- Reward scams trigger properly
- Risk scoring slightly adjusted for new tactics
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


# ===================================================================
# 🔥 1. IMPROVED RISK SCORING — softer + smarter
# ===================================================================
def _estimate_global_risk(sentence_rows: List[Dict[str, Any]]) -> int:
    """
    Combine tactics + emotions into a 0–100 risk number.
    NEW: coercion boosts risk heavier.
    """

    score = 0
    for row in sentence_rows:
        tactics = row["tactics"]
        color = row["risk_color"]
        emotion = row["emotion"]["top_label"].lower()

        # Color weighting
        if color == "red":
            score += 14    # increased from 12
        elif color == "yellow":
            score += 8     # increased from 7

        # Emotion signal
        if emotion in ("fear", "anger", "disgust"):
            score += 6     # slightly increased

        # Freshly added tactic weights
        if "coercion" in tactics:
            score += 12    # coercion is HIGH severity

        if "secrecy" in tactics:
            score += 6

        if "financial_grooming" in tactics:
            score += 8

        if "love_bombing" in tactics:
            score += 4

        if "authority_impersonation" in tactics:
            score += 10

    return max(0, min(100, score))


# ===================================================================
# 🔥 2. IMPROVED SCAM PROFILE GUESSER — LOWERED THRESHOLDS
# ===================================================================
def _guess_scam_profile(tactic_counts: Dict[str, int]) -> str:
    """
    NEW LOGIC:
    Lower thresholds so real-world scams actually register.
    """

    love = tactic_counts.get("love_bombing", 0)
    secrecy = tactic_counts.get("secrecy", 0)
    coercion = tactic_counts.get("coercion", 0)
    money = tactic_counts.get("financial_grooming", 0)
    authority = tactic_counts.get("authority_impersonation", 0)
    urgency = tactic_counts.get("urgency", 0)
    reward = tactic_counts.get("reward", 0)
    fear = tactic_counts.get("fear", 0)

    # ---------------------------------------------------------
    # ❤️ Romance Scam
    # Old: needed love_bombing >= 2 AND secrecy
    # New: ANY of these combos:
    #  - love + money
    #  - love + coercion
    #  - secrecy + love
    #  - coercion + money
    # ---------------------------------------------------------
    if (
        (love >= 1 and money >= 1) or
        (love >= 1 and coercion >= 1) or
        (love and secrecy) or
        (coercion and money)
    ):
        return "romance_scam"

    # ---------------------------------------------------------
    # 💰 Investment / Money-Flip Scam
    # Old: financial_grooming >= 2
    # New: >= 1 is enough (real scammers only need ONE ask)
    # ---------------------------------------------------------
    if money >= 1:
        return "investment_or_money_flip"

    # ---------------------------------------------------------
    # 🛑 Authority / Government / IRS Scam
    # Old: needed BOTH authority + urgency
    # New: ANY of:
    #  - authority + fear
    #  - authority + urgency
    #  - authority + coercion
    # ---------------------------------------------------------
    if (
        (authority and fear) or
        (authority and urgency) or
        (authority and coercion)
    ):
        return "account_or_authority_phishing"

    # ---------------------------------------------------------
    # 🎉 Lottery / Prize Scam
    # Old: reward >= 2
    # New: reward >= 1 + link or urgency or fear
    # ---------------------------------------------------------
    if reward >= 1:
        return "lottery_or_prize"

    return "unclear"


# ===================================================================
# 🔥 3. SCENARIO SIMULATION (unchanged except minor edits)
# ===================================================================
def _simulate_next_steps(profile: str) -> List[str]:
    if profile == "romance_scam":
        return [
            "Scammer continues emotional validation and affection.",
            "They introduce a sudden financial crisis or emergency.",
            "They ask for money, gift cards, crypto, or phone bill support.",
            "If paid, they escalate requests or invent new crises.",
            "They disappear once extraction slows down.",
        ]

    if profile == "investment_or_money_flip":
        return [
            "Scammer pitches a 'guaranteed' investment or money flip.",
            "Fake dashboards or profit screenshots appear.",
            "They push you to deposit funds into a controlled wallet.",
            "Withdrawals get blocked or require 'unlock fees'.",
            "Eventually the scammer vanishes after maximizing extraction.",
        ]

    if profile == "account_or_authority_phishing":
        return [
            "Scammer sends a 'verification' link or attachment.",
            "They collect login info, card data, or identity documents.",
            "Immediate login attempts or card charges may follow.",
            "May contact again pretending to be fraud support.",
            "Leads to identity theft or account takeover.",
        ]

    if profile == "lottery_or_prize":
        return [
            "Scammer congratulates you on a prize you never entered.",
            "They ask for delivery fees, taxes, or verification payments.",
            "They delay payout with excuses and request more fees.",
            "No prize is ever delivered.",
        ]

    return [
        "Scammer continues probing for personal and financial details.",
        "They adapt their approach based on your emotional responses.",
        "They transition into asking for money, credentials, or documents.",
        "Once they extract enough value, they disappear.",
    ]


# ===================================================================
# 🔥 4. MAIN ENTRY POINT — minimal but upgraded
# ===================================================================
def analyze_manipulation(text: str) -> Dict[str, Any]:
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
                "emotion": {
                    "top_label": emo["top_label"],
                    "top_score": emo["top_score"]
                },
                "tactics": tactics,
                "risk_color": color,
            }
        )

    risk_score = _estimate_global_risk(rows)

    primary_tactics = sorted(
        tactic_counts.keys(),
        key=lambda t: tactic_counts[t],
        reverse=True
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