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
- Keep the explanation 1–2 SHORT sentences.
- In "reasons", each item must:
  - be one short phrase,
  - use simple language,
  - avoid any technical words,
  - be easy for a teenager or grandparent to understand.

You MUST respond ONLY with a valid JSON object using this EXACT schema:

{
  "score": number,              // 0 to 10, higher = more dangerous
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "explanation": string,        // 1–2 sentence summary in simple words
  "reasons": [string]           // bullet-point style reasons (3–8 items ideal)
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


# ---------------------------------------------------------------------
# 3. MAIN PUBLIC FUNCTION
# ---------------------------------------------------------------------

def analyze_text(text: str) -> Dict[str, Any]:
    """
    Main AI-based text scanner.

    Returns a dict with:
      - score (0–10 by design, but kept generic)
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

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_MSG},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )

        raw_output = response.choices[0].message.content or ""
        json_text = _extract_json_block(raw_output)

        parsed: Dict[str, Any] | None = None
        if json_text:
            try:
                parsed = json.loads(json_text)
            except Exception:
                parsed = None

        # -----------------------------------------------------------------
        # Normalize / validate AI output
        # -----------------------------------------------------------------
        if not isinstance(parsed, dict):
            raise ValueError("Model returned invalid or non-JSON output.")

        # Score normalization
        raw_score = parsed.get("score", 0)
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            score = 0.0

        # Clamp to 0–10 just to keep it sane
        if score < 0:
            score = 0.0
        if score > 10:
            score = 10.0

        # Verdict normalization
        verdict_raw = str(parsed.get("verdict", "SAFE")).upper()
        if verdict_raw not in {"SAFE", "SUSPICIOUS", "DANGEROUS"}:
            # Fallback from score if verdict is weird
            if score <= 2:
                verdict_raw = "SAFE"
            elif score <= 5:
                verdict_raw = "SUSPICIOUS"
            else:
                verdict_raw = "DANGEROUS"

        explanation = parsed.get("explanation") or ""
        if not isinstance(explanation, str) or not explanation.strip():
            if verdict_raw == "SAFE":
                explanation = "We did not see clear signs of a scam in this message."
            elif verdict_raw == "SUSPICIOUS":
                explanation = "This message has some warning signs and could be a scam."
            else:
                explanation = "This message has strong signs of a scam or someone trying to trick you."

        reasons = parsed.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        # Ensure all reasons are strings
        reasons = [str(r).strip() for r in reasons if str(r).strip()]

        # If AI didn't provide any reasons, at least give one generic one
        if not reasons:
            reasons.append("The message looks risky based on its words and tone.")

        return {
            "score": score,
            "verdict": verdict_raw,
            "explanation": explanation,
            "reasons": reasons,
            "details": {
                "text_length": len(t),
                "links_detected": urls,
                "emoji_count": len(emojis),
            },
        }

    except Exception as e:
        # 🚨 Fail-safe: never crash the app – fall back to conservative "SUSPICIOUS"
        # but explain it's a system issue, not the user's fault.
        return {
            "score": 0,
            "verdict": "SUSPICIOUS",
            "explanation": "We could not finish the scan because of a system problem.",
            "reasons": [
                "The AI engine hit an error (network, key, or model issue).",
                f"Internal error: {type(e).__name__}.",
            ],
            "details": {
                "text_length": len(t),
                "links_detected": urls,
                "emoji_count": len(emojis),
            },
        }