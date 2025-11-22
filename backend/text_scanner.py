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
You are a scam, phishing, and manipulation detector for text messages.

Your job:
- Analyze emails, SMS, DMs, and chat messages.
- Detect scams, phishing, fraud, financial manipulation, or attempts to steal credentials.
- Consider urgency, threats, romance pressure, money requests, login links, and identity theft.

You MUST respond ONLY with a valid JSON object using this EXACT schema:

{
  "score": number,              // 0 to 10, higher = more dangerous
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "explanation": string,        // 1–2 sentence summary for a regular user
  "reasons": [string]           // bullet-point style reasons (3–8 items ideal)
}

Guidelines:
- "SAFE": clearly normal conversation, support message, or content with no apparent scam intent.
- "SUSPICIOUS": some red flags, but not clearly confirmed scam.
- "DANGEROUS": strong evidence of phishing, fraud, coercion, or credential theft.
- Include concrete reasons like: "Threatens account suspension", "Asks for login via link",
  "Requests money urgently", "Romantic pressure plus money request", etc.

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
Analyze the following message for scam / phishing / manipulation risk:

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
                explanation = "No major scam or manipulation patterns detected."
            elif verdict_raw == "SUSPICIOUS":
                explanation = "Some potential scam or manipulation patterns detected."
            else:
                explanation = "Strong indicators of scam, phishing, or manipulation detected."

        reasons = parsed.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        # Ensure all reasons are strings
        reasons = [str(r).strip() for r in reasons if str(r).strip()]

        # If AI didn't provide any reasons, at least give one generic one
        if not reasons:
            reasons.append("AI model did not provide specific reasons, only an overall risk assessment.")

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
            "explanation": "We couldn't run the AI scan due to an internal error.",
            "reasons": [
                "AI engine failed (network, key, or model issue).",
                f"Internal error detail: {type(e).__name__}",
            ],
            "details": {
                "text_length": len(t),
                "links_detected": urls,
                "emoji_count": len(emojis),
            },
        }