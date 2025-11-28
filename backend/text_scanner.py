# backend/text_scanner.py

"""
AI-based Text Scam & Manipulation Detector (Von Ultra Edition)

Replaces the old rule-based text_scanner with an AI-first pipeline
using the Groq API. It keeps the SAME public interface:

    analyze_text(text: str) -> {
        "score": number,
        "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
        "explanation": str,
        "reasons": [str],
        "details": {
            "text_length": int,
            "links_detected": [str],
            "emoji_count": int,
        }
    }

So the frontend / AUTO mode can keep working without changes.
"""

from __future__ import annotations
from typing import Dict, Any, List
import os
import json
import re
from urllib.parse import urlparse
from groq import Groq

# ---------------------------------------------------------------------
# 1. CONSTANTS (regex + defaults)
# ---------------------------------------------------------------------

EMOJI_REGEX = r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF]"
URL_REGEX = r"https?://\S+|www\.\S+"

# Lazy Groq client (Railway-safe, same pattern as classify_actor.py)
_groq_client: Groq | None = None


def get_client() -> Groq:
    """Lazily initialize Groq client to avoid import-time failures."""
    global _groq_client
    if _groq_client is None:
        key = os.getenv("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set on server.")
        _groq_client = Groq(api_key=key)
    return _groq_client


SYSTEM_MSG = """
You are a scam and manipulation detector for text messages.

Your job:
- Look at emails, texts, and DMs.
- Spot scam messages that try to steal money or account access.
- Notice fear, rushing, money pressure, fake links, or fake company messages.

Very important style rules:
- Imagine you are talking to someone's grandma.
- Use ONLY simple, everyday words.
- Do NOT use technical words like: "phishing", "domain", "URL", "infrastructure",
  "vector", "credential", "authentication", "TLD", "spoof".
- Instead, say things like:
  - "scam message" instead of "phishing"
  - "website address" instead of "domain" or "URL"
  - "password or bank info" instead of "credentials"
  - "link that looks like the real bank but is not" instead of "spoofed domain"
- Keep the explanation 1-2 SHORT sentences.
- In "reasons", each item must:
  - be one short phrase,
  - use simple language,
  - avoid any technical words,
  - be easy for a teenager or grandparent to understand.

You MUST respond ONLY with a valid JSON object using this EXACT schema:

{
  "score": number,              // 0 to 10, higher = more dangerous
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "explanation": string,        // 1-2 sentence summary in simple words
  "reasons": [string]           // bullet-point style reasons (3-8 items ideal)
}

Guidelines:
- "SAFE": looks like a normal message with no clear scam behavior.
- "SUSPICIOUS": some red flags, but not clearly a scam.
- "DANGEROUS": strong signs of a scam or someone trying to trick the person.
- Give concrete reasons like:
  - "tries to scare you by saying your account will be closed"
  - "pushes you to click a link to fix a problem"
  - "asks for money or gift cards"
  - "asks for your password or bank info"
  - "uses a link that looks like a real company but is not"

Never include explanations or commentary outside the JSON.
"""


# ---------------------------------------------------------------------
# 2. JSON extraction (for when the model gets chatty)
# ---------------------------------------------------------------------

def _extract_json_block(text: str) -> str | None:
    """
    Extract the FIRST JSON object from the model output.
    Same pattern as classify_actor.py.
    """
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return match.group(0)
    return None


def _merge_reasons(primary: List[str], extras: List[str]) -> List[str]:
    """
    Merge and deduplicate reasons while preserving readable order.
    """
    merged: List[str] = []
    seen = set()
    for reason in list(primary or []) + list(extras or []):
        reason_str = str(reason).strip()
        if not reason_str:
            continue
        key = reason_str.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(reason_str)
    return merged


# ---------------------------------------------------------------------
# 2b. RULE-BASED FALLBACK (no network)
# ---------------------------------------------------------------------

_PATTERNS = [
    (r"\burgent\b|\burgently\b|\bimmediately\b", "Creates urgency or pressure.", 2),
    (r"\bverify\b|\bconfirm\b|\breset\b", "Asks you to verify or reset something.", 2),
    (r"\bpassword\b|\blogin\b|\bcredential", "Requests your password or login info.", 3),
    (r"\bwire\b|\btransfer\b|\bgift card\b", "Pushes money transfer or gift cards.", 3),
    (r"\bbank\b|\baccount\b|\bsecurity\b", "Mentions bank or account security.", 1),
    (r"\bprize\b|\blottery\b|\bwinner\b", "Promises a prize or winnings.", 2),
    (r"\bcrypto\b|\bbitcoin\b|\beth\b", "References crypto for payment.", 2),
    (r"click\s+here|tinyurl|bit\.ly|shorturl", "Uses shortened or vague links.", 2),
]

# ---------------------------------------------------------------------
# 2c. BEHAVIORAL / BRAND / MANIPULATION SIGNALS
# ---------------------------------------------------------------------

UNREQUESTED_ACTION_PATTERNS = [
    r"\bwe sent you a code\b",
    r"\byour email (?:has|was) changed\b",
    r"\byour (?:subscription|plan) has been (?:modified|changed|updated)\b",
    r"\breset your account (?:now|immediately)\b",
    r"\bpassword (?:has been )?reset\b",
    r"\bsecurity code (?:has been )?sent\b",
]

CORPORATE_VAGUE_PHRASES = [
    "security protocol update",
    "generic browser detected",
    "account policy change",
    "final notice",
    "compliance requirement",
]

URGENCY_WORDS = {
    "act now",
    "immediately",
    "today only",
    "right away",
    "asap",
    "within 24 hours",
    "immediate action required",
    "act immediately",
}

CONSEQUENCE_WORDS = {
    "suspend",
    "suspension",
    "offline",
    "terminate",
    "deactivate",
    "loss",
    "penalty",
    "closure",
    "lose access",
    "locked out",
}

EMOTIONAL_KEYWORDS = {
    "fear-based": ["scare", "fear", "threat", "arrest", "penalty", "lawsuit", "fraud", "compromised"],
    "authority-based": [
        "compliance",
        "official notice",
        "legal action",
        "authority",
        "enforcement",
        "regulation",
    ],
    "scarcity-based": ["limited time", "only today", "spots left", "expires soon", "last chance"],
    "urgency-based": list(URGENCY_WORDS),
    "trust-exploitation": ["trusted partner", "as a valued customer", "loyal customer", "verified sender"],
}

BRAND_BEHAVIOR_RULES = [
    {
        "name": "Amazon",
        "keywords": ["amazon"],
        "violations": [
            {
                "pattern": r"\bclick\b|\blogin\b|\bsign in\b|\breset\b|\bverify\b",
                "requires_link": True,
                "message": "Amazon directs you to use the official app, not a direct login link.",
                "weight": 2.0,
            }
        ],
    },
    {
        "name": "PayPal",
        "keywords": ["paypal"],
        "violations": [
            {
                "pattern": r"\bdear customer\b|\bvalued user\b|\baccount user\b",
                "requires_link": False,
                "message": "PayPal uses your full name instead of generic greetings.",
                "weight": 1.5,
            },
            {
                "pattern": r"\bclick\b|\bresolve\b|\breset\b|\bverify\b",
                "requires_link": True,
                "message": "Unusual clickable reset or login link claiming to be PayPal.",
                "weight": 2.0,
            },
        ],
    },
    {
        "name": "Bank",
        "keywords": ["bank", "boa", "wells fargo", "chase", "citibank", "citi"],
        "violations": [
            {
                "pattern": r"\breset\b|\bverify\b|\bunlock\b|\bclick here\b",
                "requires_link": True,
                "message": "Banks rarely send clickable reset links; they direct you to the secure app or site.",
                "weight": 2.0,
            }
        ],
    },
]


def _detect_behavioral_signals(text: str, urls: List[str]) -> Dict[str, Any]:
    """
    Behavioral, psychological, and brand-aware overlays to enrich the core scan.
    Returns score adjustments plus human-readable tags for transparency.
    """
    lowered = text.lower()
    flags: List[dict] = []
    reasons: List[str] = []
    brand_violations: List[str] = []
    emotional_tags: List[str] = []
    score_boost = 0.0
    risk_multiplier = 1.0

    # 1) Unrequested action triggers
    for pattern in UNREQUESTED_ACTION_PATTERNS:
        if re.search(pattern, lowered):
            flags.append(
                {
                    "tag": "Unsolicited Security Action",
                    "explanation": "This message attempts to initiate an action you did not request - a common scam tactic.",
                    "severity": "high",
                }
            )
            reasons.append(
                "Unsolicited Security Action: This message attempts to initiate an action you did not request - a common scam tactic."
            )
            score_boost += 2.5
            risk_multiplier = max(risk_multiplier, 1.2)
            break

    # 2) Synthetic corporate language
    for phrase in CORPORATE_VAGUE_PHRASES:
        if phrase in lowered:
            flags.append(
                {
                    "tag": "Synthetic Corporate Language",
                    "explanation": "Uses corporate-sounding but vague language to appear official.",
                    "severity": "medium",
                }
            )
            reasons.append("Synthetic Corporate Language: Corporate tone with vague technical wording.")
            score_boost += 1.0
            break

    # 3) Urgency + consequence combo
    has_urgency = any(term in lowered for term in URGENCY_WORDS)
    has_consequence = any(term in lowered for term in CONSEQUENCE_WORDS)
    if has_urgency and has_consequence:
        flags.append(
            {
                "tag": "Pressure-Based Threat",
                "explanation": "Combines time pressure with a loss threat to force quick action.",
                "severity": "high",
            }
        )
        reasons.append("Pressure-Based Threat: Urgency plus threat of loss is a classic scam tactic.")
        score_boost += 2.0
        risk_multiplier = max(risk_multiplier, 1.2)

    # 4) Brand behavior mismatch
    for rule in BRAND_BEHAVIOR_RULES:
        if any(key in lowered for key in rule["keywords"]):
            for violation in rule["violations"]:
                if violation.get("requires_link") and not urls:
                    continue
                if re.search(violation["pattern"], lowered):
                    msg = f"This message does not match verified behavior patterns of {rule['name']}."
                    brand_violations.append(msg)
                    reasons.append(f"{msg} {violation['message']}")
                    flags.append(
                        {
                            "tag": "Brand Behavior Violation",
                            "explanation": msg,
                            "severity": "high",
                            "brand": rule["name"],
                        }
                    )
                    score_boost += violation.get("weight", 1.5)
                    risk_multiplier = max(risk_multiplier, 1.15)
                    break

    # 5) Emotional manipulation tags
    for label, keywords in EMOTIONAL_KEYWORDS.items():
        for kw in keywords:
            if kw in lowered:
                emotional_tags.append(label)
                break
    emotional_tags = sorted(set(emotional_tags))
    if emotional_tags:
        flags.append(
            {
                "tag": "Emotional Manipulation",
                "explanation": f"Emotional levers detected: {', '.join(emotional_tags)}.",
                "severity": "medium",
            }
        )
        reasons.append(f"Emotional cues detected: {', '.join(emotional_tags)}.")
        score_boost += min(len(emotional_tags) * 0.6, 2.0)

    # Mild boost when corporate tone pairs with urgency
    if has_urgency and any(f["tag"] == "Synthetic Corporate Language" for f in flags):
        score_boost += 0.5
        risk_multiplier = max(risk_multiplier, 1.1)

    return {
        "score_boost": score_boost,
        "risk_multiplier": risk_multiplier,
        "flags": flags,
        "reasons": reasons,
        "brand_violations": brand_violations,
        "emotional_tags": emotional_tags,
    }


def _rule_based(text: str, urls: List[str], emojis: List[str]) -> Dict[str, Any]:
    """
    Offline heuristic fallback so scans keep working if AI is unavailable.
    """
    score = 0
    reasons: List[str] = []
    lowered = text.lower()

    if urls:
        score += 1
        reasons.append("Includes a link that should be treated carefully.")

    if len(emojis) > 3:
        score += 1
        reasons.append("Uses a lot of emojis to get attention.")

    for pattern, reason, weight in _PATTERNS:
        if re.search(pattern, lowered):
            score += weight
            if reason not in reasons:
                reasons.append(reason)

    score = min(max(score, 0), 10)
    behavioral = _detect_behavioral_signals(text, urls)
    score = min(10, (score + behavioral["score_boost"]) * behavioral["risk_multiplier"])
    reasons = _merge_reasons(reasons, behavioral["reasons"])

    if score >= 7:
        verdict = "DANGEROUS"
        explanation = "This message has strong signs of a scam."
    elif score >= 3:
        verdict = "SUSPICIOUS"
        explanation = "This message shows some warning signs. Be careful."
    else:
        verdict = "SAFE"
        explanation = "Offline fallback used. No clear scam signs found by basic checks."

    if not reasons:
        reasons.append("No major red flags detected by offline checks.")

    return {
        "score": score,
        "verdict": verdict,
        "explanation": explanation,
        "reasons": reasons,
        "details": {
            "text_length": len(text),
            "links_detected": urls,
            "emoji_count": len(emojis),
            "mode": "fallback",
            "behavior_flags": behavioral["flags"],
            "emotional_tags": behavioral["emotional_tags"],
            "brand_violations": behavioral["brand_violations"],
            "behavior_score_boost": behavioral["score_boost"],
            "behavior_risk_multiplier": behavioral["risk_multiplier"],
        },
        "ai_used": False,
    }


# ---------------------------------------------------------------------
# 3. MAIN PUBLIC FUNCTION
# ---------------------------------------------------------------------

def analyze_text(text: str) -> Dict[str, Any]:
    """
    Main AI-based text scanner.

    Returns a dict with:
      - score (0-10 by design, but kept generic)
      - verdict ("SAFE" | "SUSPICIOUS" | "DANGEROUS")
      - explanation (short, user-facing)
      - reasons (list of strings)
      - details (meta info: text_length, links_detected, emoji_count)
    """
    t = text.strip()

    # Basic meta details (even if we fail over later)
    urls: List[str] = re.findall(URL_REGEX, t) if t else []
    emojis: List[str] = re.findall(EMOJI_REGEX, t) if t else []

    if not t:
        # Empty input: keep structure consistent
        return {
            "score": 0,
            "verdict": "SAFE",
            "explanation": "No text provided to analyze.",
            "reasons": ["The message is empty."],
            "details": {
                "text_length": 0,
                "links_detected": [],
                "emoji_count": 0,
            },
        }

    # -----------------------------------------------------------------
    # Call Groq AI
    # -----------------------------------------------------------------
    try:
        client = get_client()

        user_prompt = f"""
Analyze the following message for scam / manipulation risk and explain it
in very simple everyday words:

{text}

Remember: respond ONLY with JSON matching the schema described earlier.
"""

        messages = [
            {"role": "system", "content": SYSTEM_MSG},
            {"role": "user", "content": user_prompt},
        ]

        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.0,
        )

        raw_output = resp.choices[0].message.content if resp.choices else ""

        try:
            parsed = json.loads(raw_output)
        except Exception:
            parsed = {
                "score": 0,
                "verdict": "SAFE",
                "explanation": (raw_output or "").strip(),
                "reasons": [],
                "details": {"ai_raw_output": raw_output},
            }

        # Score normalization
        raw_score = parsed.get("score", 0)
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            score = 0.0

        score = max(0, min(10, score))

        verdict_raw = str(parsed.get("verdict", "SAFE")).upper()
        if verdict_raw not in {"SAFE", "SUSPICIOUS", "DANGEROUS"}:
            if score <= 2:
                verdict_raw = "SAFE"
            elif score <= 5:
                verdict_raw = "SUSPICIOUS"
            else:
                verdict_raw = "DANGEROUS"

        explanation = parsed.get("explanation") or ""
        if not isinstance(explanation, str) or not explanation.strip():
            if verdict_raw == "SAFE":
                explanation = "Analyzed using AI. No scam patterns detected in this message."
            elif verdict_raw == "SUSPICIOUS":
                explanation = "Analyzed using AI. Some warning signs detected. Review carefully."
            else:
                explanation = "Analyzed using AI. Strong signs of a scam. Do not engage."

        reasons = parsed.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        reasons = [str(r).strip() for r in reasons if str(r).strip()]
        if not reasons:
            reasons.append("The message looks risky based on its words and tone.")
        reasons = _merge_reasons(reasons, [])

        details = parsed.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        details.update(
            {
                "text_length": len(t),
                "links_detected": urls,
                "emoji_count": len(emojis),
            }
        )

        behavioral = _detect_behavioral_signals(t, urls)
        score = min(10, (score + behavioral["score_boost"]) * behavioral["risk_multiplier"])
        reasons = _merge_reasons(reasons, behavioral["reasons"])
        details.update(
            {
                "behavior_flags": behavioral["flags"],
                "emotional_tags": behavioral["emotional_tags"],
                "brand_violations": behavioral["brand_violations"],
                "behavior_score_boost": behavioral["score_boost"],
                "behavior_risk_multiplier": behavioral["risk_multiplier"],
            }
        )

        verdict_from_score = "DANGEROUS" if score >= 7 else "SUSPICIOUS" if score >= 3 else "SAFE"
        severity_rank = {"SAFE": 0, "SUSPICIOUS": 1, "DANGEROUS": 2}
        if severity_rank.get(verdict_from_score, 0) > severity_rank.get(verdict_raw, 0):
            verdict_raw = verdict_from_score

        return {
            "score": score * 10,
            "verdict": verdict_raw,
            "explanation": explanation,
            "reasons": reasons,
            "details": details,
            "ai_used": True,
        }

    except Exception as exc:
        try:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            print(f"[analyze_text] AI call failed: {exc} status={status}")
        except Exception:
            pass
        return _rule_based(t, urls, emojis)
