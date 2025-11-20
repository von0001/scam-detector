# backend/manipulation/tactic_detector.py

"""
Von Ultra Edition Manipulation Tactic Detector

Detects:
- urgency
- fear
- authority_impersonation
- secrecy
- love_bombing
- reward
- financial_grooming
- coercion
- guilt_tripping
- gaslighting
- emotional_leverage
- conditional_affection
- passive_threats
- boundary_disrespect
"""

from __future__ import annotations
from typing import List
import re


# ==========================================================
# VON ULTRA PATTERN LIBRARY
# (MAXIMUM POWER — NO IMPORTS ADDED)
# ==========================================================
TACTIC_KEYWORDS = {

    # ------------------------------------------------------
    # URGENCY
    # ------------------------------------------------------
    "urgency": [
        r"\bright now\b",
        r"\bimmediately\b",
        r"\brespond now\b",
        r"\burgent\b",
        r"\blast warning\b",
        r"\bfinal notice\b",
        r"\bact fast\b",
        r"\bdeadline\b",
        r"\btime[-\s]?sensitive\b",
        r"\bwithin\s+\d+\s+(minutes?|hours?)\b",
        r"\burgent action required\b",
    ],

    # ------------------------------------------------------
    # FEAR / THREAT
    # ------------------------------------------------------
    "fear": [
        r"\bpolice\b",
        r"\bcharges?\b",
        r"\blegal action\b",
        r"\bfraud department\b",
        r"\bsecurity alert\b",
        r"\bwarrant\b",
        r"\barrest\b",
        r"\blegal consequences\b",
        r"\bor else\b",
        r"\bwe will take action\b",
        r"\bmy life depends on\b",
    ],

    # ------------------------------------------------------
    # AUTHORITY IMPERSONATION
    # ------------------------------------------------------
    "authority_impersonation": [
        r"\birs\b",
        r"\bbank\b",
        r"\bpaypal\b",
        r"\bsecurity team\b",
        r"\bofficial notice\b",
        r"\bfederal\b",
        r"\blaw enforcement\b",
        r"\bofficer\b",
        r"\bagent\b",
        r"\bssa\b",
        r"\bsocial security\b",
        r"\bfbi\b",
    ],

    # ------------------------------------------------------
    # SECRECY
    # ------------------------------------------------------
    "secrecy": [
        r"\bdon't tell\b",
        r"\bkeep this between us\b",
        r"\bno one else can know\b",
        r"\bkeep this private\b",
        r"\bjust between you and me\b",
        r"\bdo not share\b",
        r"\bbetween us only\b",
        r"\bplease don't tell anyone\b",
    ],

    # ------------------------------------------------------
    # LOVE BOMBING
    # ------------------------------------------------------
    "love_bombing": [
        r"\bmy (?:love|angel|dear|princess|king)\b",
        r"\bi can't stop thinking about you\b",
        r"\byou are the only one\b",
        r"\bwe were meant to be\b",
        r"\bmy soulmate\b",
        r"\bbaby\b",
        r"\bbabe\b",
        r"\bi need you\b",
        r"\bi miss you so much\b",
        r"\bno one else understands me\b",
    ],

    # ------------------------------------------------------
    # REWARD
    # ------------------------------------------------------
    "reward": [
        r"\byou (?:have )?won\b",
        r"\bcongratulations\b",
        r"\bprize\b",
        r"\bjackpot\b",
        r"\bclaim your reward\b",
        r"\bselected randomly\b",
        r"\bpayout\b",
    ],

    # ------------------------------------------------------
    # FINANCIAL GROOMING
    # ------------------------------------------------------
    "financial_grooming": [
        r"\binvestment opportunity\b",
        r"\bflip your money\b",
        r"\bguaranteed returns\b",
        r"\bdouble your funds\b",
        r"\bprofit\b",
        r"\bwire transfer\b",
        r"\bgift card\b",
        r"\bcrypto\b",
        r"\bwallet\b",
        r"\bsend.*\$(\d+)",
        r"\b(zelle|cashapp|apple pay|paypal)\b",
        r"\bonboarding fee\b",
        r"\bprocessing fee\b",
        r"\bcan you send me\b",
        r"\bhelp me pay\b",
        r"\bcover my (?:bill|rent|phone|medical)\b",
        r"\bi just need\b",
        r"\bsmall favor\b",
    ],

    # ======================================================
    # NEW MANIPULATION TACTICS (VON ULTRA)
    # ======================================================

    # GUILT TRIPPING
    "guilt_tripping": [
        r"\bi thought you cared\b",
        r"\bguess i mean nothing\b",
        r"\byou don't care about me\b",
        r"\bi can't believe you'd do this\b",
        r"\byou're letting me down\b",
        r"\bafter everything i've done\b",
    ],

    # GASLIGHTING
    "gaslighting": [
        r"\byou're imagining things\b",
        r"\byou're overreacting\b",
        r"\bthat never happened\b",
        r"\byou always twist things\b",
        r"\bstop being dramatic\b",
        r"\bwhy are you acting crazy\b",
        r"\byou're too sensitive\b",
    ],

    # EMOTIONAL LEVERAGE
    "emotional_leverage": [
        r"\bonly you understand\b",
        r"\bi need you or i can't\b",
        r"\bwithout you i'm nothing\b",
        r"\byou're the only one i have\b",
        r"\bif you leave me\b",
    ],

    # CONDITIONAL AFFECTION
    "conditional_affection": [
        r"\bif you loved me\b",
        r"\bprove you love me\b",
        r"\bi'll care if you\b",
        r"\bdo this for me and i'll\b",
        r"\blove you only if\b",
    ],

    # PASSIVE THREATS
    "passive_threats": [
        r"\bi guess i'll just disappear\b",
        r"\bi'll remember this\b",
        r"\byou'll regret this\b",
        r"\bdon't make me do something\b",
        r"\bi might do something stupid\b",
        r"\bthings will get worse\b",
    ],

    # BOUNDARY DISRESPECT
    "boundary_disrespect": [
        r"\bstop ignoring me\b",
        r"\bi said answer me\b",
        r"\bi don't care what you want\b",
        r"\byou're not allowed to\b",
        r"\bi don't accept that\b",
        r"\bwhy are you saying no\b",
    ],

    # COERCION (boosted)
    "coercion": [
        r"\bif you don't\b",
        r"\bi'll block you\b",
        r"\bi'll leave\b",
        r"\bi'll never speak to you\b",
        r"\byou'll lose me\b",
        r"\byou promised\b",
        r"\bdon't abandon me\b",
        r"\bonly you can help me\b",
        r"\bprove you care\b",
    ],
}


# ==========================================================
# DETECTOR
# ==========================================================
def detect_tactics(sentence: str) -> List[str]:
    """Return list of triggered tactics."""
    lower = sentence.lower()
    found = []

    for tactic, patterns in TACTIC_KEYWORDS.items():
        for pat in patterns:
            if re.search(pat, lower):
                found.append(tactic)
                break

    return found


# ==========================================================
# RISK COLOR
# ==========================================================
def sentence_risk_level(tactics: List[str]) -> str:
    if not tactics:
        return "neutral"

    red_triggers = (
        "urgency",
        "fear",
        "authority_impersonation",
        "financial_grooming",
        "coercion",
        "guilt_tripping",
        "gaslighting",
        "passive_threats",
        "boundary_disrespect",
    )

    if any(t in tactics for t in red_triggers):
        return "red"

    yellow_triggers = (
        "reward",
        "love_bombing",
        "secrecy",
        "emotional_leverage",
        "conditional_affection",
    )

    if any(t in tactics for t in yellow_triggers):
        return "yellow"

    return "yellow"