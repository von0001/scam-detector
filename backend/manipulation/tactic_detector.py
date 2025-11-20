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
- coercion / guilt / pressure  ← NEW (Von Edition)
"""

from __future__ import annotations

from typing import List, Dict, Any
import re

# ==========================================================
# UPGRADED TACTIC KEYWORDS (Von Ultra Edition)
# ==========================================================

TACTIC_KEYWORDS = {
    "urgency": [
        r"\bright now\b",
        r"\bimmediately\b",
        r"\blast warning\b",
        r"\bfinal notice\b",
        r"\bact fast\b",
        r"\btime[-\s]?sensitive\b",
        r"\bwithin\s+\d+\s+(minutes?|hours?)\b",
        r"\burgent action required\b",
        r"\brespond now\b",
        r"\bdeadline\b",
    ],

    "fear": [
        r"\baccount (?:will be|has been) (?:closed|suspended|locked)\b",
        r"\bpolice\b",
        r"\bcharges?\b",
        r"\blegal action\b",
        r"\bfraud department\b",
        r"\bsecurity alert\b",
        r"\bmy (?:child|daughter|son).*(hospital|sick|dying)\b",
        r"\bmy life depends on\b",
        r"\bdon't abandon me\b",
        # NEW:
        r"\bwarrant\b",
        r"\barrest\b",
        r"\blegal consequences\b",
        r"\bwe will take action\b",
        r"\bor else\b",
    ],

    "authority_impersonation": [
        r"\birs\b",
        r"\brevenue service\b",
        r"\bbank\b",
        r"\bpaypal\b",
        r"\bsecurity team\b",
        r"\bofficial notice\b",
        r"\bfrom the government\b",
        r"\bstate department\b",
        r"\bfederal\b",
        # NEW:
        r"\bfbi\b",
        r"\bssa\b",
        r"\bsocial security\b",
        r"\blaw enforcement\b",
        r"\bofficer\b",
        r"\bagent\b",
    ],

    "secrecy": [
        r"\bdon't tell\b",
        r"\bkeep this between us\b",
        r"\bno one else can know\b",
        r"\bdo not share\b",
        r"\bkeep this private\b",
        r"\bjust between you and me\b",
        r"\bbetween us only\b",
        # NEW:
        r"\bplease don't tell anyone\b",
    ],

    "love_bombing": [
        r"\bmy (?:love|angel|dear|princess|king)\b",
        r"\bi can't stop thinking about you\b",
        r"\byou are the only one\b",
        r"\bwe were meant to be\b",
        r"\bmy soulmate\b",
        # NEW:
        r"\bbaby\b",
        r"\bbabe\b",
        r"\bi need you\b",
        r"\bi miss you so much\b",
        r"\bno one else understands me\b",
        r"\bif you loved me\b",
        r"\bprove you love me\b",
    ],

    "reward": [
        r"\byou (?:have )?won\b",
        r"\bcongratulations\b",
        r"\bprize\b",
        r"\bjackpot\b",
        r"\bclaim your reward\b",
        r"\bselected randomly\b",
        r"\byou have been selected\b",
        r"\bpayout\b",
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
        r"\bwallet\b",
        r"\bsend.*\$(\d+)",
        r"\b(zelle|cashapp|cash app|apple pay|paypal)\b",
        r"\bonboarding fee\b",
        r"\bprocessing fee\b",
        # NEW:
        r"\bcan you send me\b",
        r"\bhelp me pay\b",
        r"\bcover my (?:bill|rent|phone|medical)\b",
        r"\bi just need\b",
        r"\bsmall favor\b",
    ],

    # ======================================================
    # NEW: Coercion / Guilt / Pressure (Von Ultra Upgrade)
    # ======================================================
    "coercion": [
        r"\bif you don't\b",
        r"\bif you do not\b",
        r"\bi'll block you\b",
        r"\bi will block you\b",
        r"\bi'll leave\b",
        r"\bi'll never speak to you\b",
        r"\byou'll lose me\b",
        r"\byou don't care about me\b",
        r"\bi thought you cared\b",
        r"\bi guess i mean nothing to you\b",
        r"\bprove you care\b",
        r"\bwhy won't you help me\b",
        r"\bwhy aren't you helping\b",
        r"\byou owe me\b",
        r"\bdon't abandon me\b",
        r"\bonly you can help me\b",
        r"\byou promised\b",
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

    if any(t in tactics for t in (
        "urgency",
        "fear",
        "authority_impersonation",
        "financial_grooming",
        "coercion"            # ← NEW: coercion automatically RED
    )):
        return "red"

    if any(t in tactics for t in (
        "reward",
        "love_bombing",
        "secrecy"
    )):
        return "yellow"

    return "yellow"