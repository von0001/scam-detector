# backend/manipulation/profiler.py

"""
Von Ultra Emotional Manipulation Profiler
Massively upgraded — detects scams AND emotional abuse patterns.
"""

from __future__ import annotations
from typing import Dict, Any, List
import re

from .emotion_classifier import classify_emotions
from .tactic_detector import detect_tactics, sentence_risk_level
from .ai_manipulation_classifier import ai_detect_manipulation


# ==========================================================
# Sentence splitter (robust, zero imports)
# ==========================================================
def _split_sentences(text: str) -> List[str]:
    raw = re.split(r"(?<=[.!?])\s+", text.strip())
    cleaned = []
    for part in raw:
        if part.strip():
            cleaned.append(part.strip())
    return cleaned


# ==========================================================
# RISK SCORING (ULTRA MODE)
# ==========================================================
def _estimate_global_risk(sentence_rows: List[Dict[str, Any]]) -> int:
    score = 0

    for row in sentence_rows:
        tactics = row["tactics"]
        color = row["risk_color"]
        emotion = row["emotion"]["top_label"].lower()

        # Color weight
        if color == "red":
            score += 14
        elif color == "yellow":
            score += 8

        # Emotion weight
        if emotion in ("fear", "anger", "disgust"):
            score += 6

        # Tactical weights
        weights = {
            "coercion": 12,
            "secrecy": 6,
            "financial_grooming": 8,
            "love_bombing": 4,
            "authority_impersonation": 10,
            "guilt_tripping": 10,
            "gaslighting": 12,
            "emotional_leverage": 8,
            "conditional_affection": 7,
            "passive_threats": 10,
            "boundary_disrespect": 10,
        }

        for t in tactics:
            if t in weights:
                score += weights[t]

    return max(0, min(100, score))


# ==========================================================
# SCAM / MANIPULATION PROFILE GUESSER
# ==========================================================
def _guess_scam_profile(tactic_counts: Dict[str, int]) -> str:
    love = tactic_counts.get("love_bombing", 0)
    secrecy = tactic_counts.get("secrecy", 0)
    coercion = tactic_counts.get("coercion", 0)
    money = tactic_counts.get("financial_grooming", 0)
    authority = tactic_counts.get("authority_impersonation", 0)
    urgency = tactic_counts.get("urgency", 0)
    reward = tactic_counts.get("reward", 0)
    fear = tactic_counts.get("fear", 0)

    # Emotional abuse profile
    if any([
        tactic_counts.get("guilt_tripping", 0),
        tactic_counts.get("gaslighting", 0),
        tactic_counts.get("emotional_leverage", 0),
        tactic_counts.get("conditional_affection", 0),
        tactic_counts.get("passive_threats", 0),
        tactic_counts.get("boundary_disrespect", 0),
    ]):
        return "emotional_manipulation"

    # Romance scam
    if (
        (love >= 1 and money >= 1) or
        (love >= 1 and coercion >= 1) or
        (love and secrecy) or
        (coercion and money)
    ):
        return "romance_scam"

    # Investment scam
    if money >= 1:
        return "investment_or_money_flip"

    # Authority scams
    if (
        (authority and fear) or
        (authority and urgency) or
        (authority and coercion)
    ):
        return "account_or_authority_phishing"

    # Lottery
    if reward >= 1:
        return "lottery_or_prize"

    return "unclear"


# ==========================================================
# SIMULATION ENGINE
# ==========================================================
def _simulate_next_steps(profile: str) -> List[str]:
    if profile == "emotional_manipulation":
        return [
            "Manipulator escalates guilt tripping and emotional pressure.",
            "Gaslighting increases to destabilize your confidence.",
            "They ignore or violate boundaries to regain control.",
            "Conditional affection becomes leverage to force compliance.",
            "They apply subtle threats or emotional withdrawal cycles."
        ]

    if profile == "romance_scam":
        return [
            "They increase affection to deepen emotional dependency.",
            "They stage a sudden financial emergency.",
            "They request money via gift cards, crypto, or urgent transfers.",
            "If you send money, they escalate to larger requests.",
            "They disappear after maximizing extraction."
        ]

    if profile == "investment_or_money_flip":
        return [
            "They introduce a 'guaranteed' flip opportunity.",
            "They show fake profits or screenshots.",
            "They push you to deposit into a controlled wallet.",
            "Withdrawals get blocked behind new fees.",
            "Scammer vanishes once extraction peaks."
        ]

    if profile == "account_or_authority_phishing":
        return [
            "They send verification links or attachments.",
            "They request credentials or identity documents.",
            "Fraudulent login attempts happen immediately.",
            "They may call back pretending to be fraud support.",
            "Possible identity theft or account takeover."
        ]

    if profile == "lottery_or_prize":
        return [
            "They congratulate you for a prize you never entered.",
            "They ask for delivery or verification fees.",
            "They invent delays requiring more payments.",
            "No prize is ever delivered."
        ]

    return [
        "Manipulator continues probing for vulnerability points.",
        "They adapt based on your emotional responses.",
        "They escalate into boundary violations or financial asks.",
        "Interaction ends once they extract enough value."
    ]


# ==========================================================
# MAIN ENTRY
# ==========================================================
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

    rows = []
    tactic_counts = {}

    for emo in emo_rows:
        sent = emo["sentence"]
        tactics = detect_tactics(sent)
        for t in tactics:
            tactic_counts[t] = tactic_counts.get(t, 0) + 1

        rows.append({
            "sentence": sent,
            "emotion": {
                "top_label": emo["top_label"],
                "top_score": emo["top_score"],
            },
            "tactics": tactics,
            "risk_color": sentence_risk_level(tactics),
        })

    # Keyword-based score
    risk_score = _estimate_global_risk(rows)
    keyword_score = risk_score  # <- Save original for comparison

    # =====================================================
    # AI SEMANTIC MANIPULATION DETECTOR (LLM-BASED)
    # =====================================================
    ai_row = ai_detect_manipulation(cleaned)

    # If AI finds something stronger, override
    if ai_row["manipulation_score"] > keyword_score:
        risk_score = ai_row["manipulation_score"]
        primary_tactics = ai_row.get("tactics", [])
        scam_profile = ai_row.get("manipulation_type", "none")
        explanation = ai_row.get("explanation", "")
        scenario_simulation = _simulate_next_steps(scam_profile)

    else:
        # Keyword fallback
        if risk_score == 0:
            explanation = "No manipulation detected."
        else:
            explanation = "Emotional manipulation patterns detected."

        primary_tactics = sorted(
            tactic_counts.keys(),
            key=lambda x: tactic_counts[x],
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