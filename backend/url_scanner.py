# backend/url_scanner.py
# ---------------------------------------------------------
# URL Scanner v4 — Von Hybrid Edition (Rules + AI, Simple Language)
# ---------------------------------------------------------

import re
import math
import json
import idna
import tldextract
import unicodedata
from urllib.parse import urlparse
from typing import Dict, List, Any

from .ai.groq_client import groq_chat  # uses your existing Groq helper


# ---------------------------------------------------------
# TRUST LISTS
# ---------------------------------------------------------

HARD_TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "gstatic.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "amazon.com", "aws.amazon.com", "apple.com", "icloud.com",
    "zoom.us", "slack.com", "github.com", "dropbox.com",
    "stripe.com", "linkedin.com", "docusign.net"
}

SOFT_TRUSTED_DOMAINS = {
    "amazonaws.com", "sharepoint.com", "googleusercontent.com",
    "cloudfront.net", "firebaseapp.com", "githubusercontent.com"
}

URL_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "cutt.ly",
    "is.gd", "v.gd", "ow.ly", "shorturl.at"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "link", "click", "info", "work", "biz",
    "gq", "tk", "ml", "cf", "ga", "ru", "cn", "rest", "monster", "zip"
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "update", "secure", "security", "confirm",
    "reset", "account", "unlock", "auth", "password", "credentials"
}

BRAND_KEYWORDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "facebook": {"facebook.com", "fb.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "boa": {"bankofamerica.com"}
}


# ---------------------------------------------------------
# HOMOGLYPH NORMALIZATION
# ---------------------------------------------------------

HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "ɑ": "a", "ά": "a", "ạ": "a", "ą": "a",
    "е": "e", "℮": "e",
    "ο": "o", "σ": "o",
    "р": "p", "ρ": "p",
    "с": "c",
    "ԁ": "d",
    "κ": "k",
    "һ": "h",
    "ӏ": "l",
    "Ꭵ": "i",
    "ɡ": "g"
})


def normalize_homoglyphs(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    return text.translate(HOMOGLYPH_MAP)


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in freq)


def _is_ip(host: str) -> bool:
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return False
    return all(0 <= int(part) <= 255 for part in host.split("."))


def extract_root(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()


# ---------------------------------------------------------
# UNICODE / HOMOGLYPH SPOOF DETECTION
# ---------------------------------------------------------

def detect_unicode_spoof(host: str, root: str) -> List[str]:
    reasons: List[str] = []

    # Unicode present
    if any(ord(c) > 127 for c in host):
        reasons.append("Website address uses unusual characters.")

    # Punycode check
    try:
        decoded = idna.decode(host)
        if decoded != host:
            reasons.append("Website address is written in a tricky encoded way.")
    except Exception:
        reasons.append("Website address looks broken or fake.")

    # Homoglyph mimic detection
    normalized = normalize_homoglyphs(host)
    normalized_root = normalize_homoglyphs(root)

    for brand, legit_set in BRAND_KEYWORDS.items():
        for legit in legit_set:
            if normalized_root == normalize_homoglyphs(legit) and root != legit:
                reasons.append(
                    f"Website address tries to look like '{legit}' but is not the real one."
                )
                return reasons

    return reasons


# ---------------------------------------------------------
# AI HELPER (HYBRID LAYER)
# ---------------------------------------------------------

AI_SYSTEM = """
You are a link scam/scam-website risk classifier.

You will receive:
- The link
- The hostname and root website address
- A numeric score from a rule-based engine (higher = more risky)
- A list of rule-based reasons

Your job:
- Double-check the rule-based evaluation.
- Decide if the link looks SAFE, SUSPICIOUS, or DANGEROUS.
- Explain everything in VERY SIMPLE everyday words.

Style rules:
- Imagine you are talking to someone's grandma.
- Use ONLY simple words.
- Do NOT use technical terms like: "phishing", "domain", "TLD", "IP address",
  "infrastructure", "vector", "credentials", "spoof", "URL".
- Instead, say things like:
  - "link" or "website address"
  - "password or bank info"
  - "scam message" or "scam link"
  - "link that looks like a real company but is not"
- Keep "explanation" as 1–2 short sentences.
- In "extra_reasons", each item must be a short phrase that is easy to read.

Respond ONLY with valid JSON in this EXACT shape:

{
  "ai_verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "explanation": "short human explanation",
  "extra_reasons": ["reason 1", "reason 2"]
}
"""


def _extract_json_block(text: str) -> str | None:
    """Extract the first JSON object from any AI output."""
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return match.group(0)
    return None


def _ai_assess_url(
    url: str,
    host: str,
    root: str,
    score: int,
    reasons: List[str]
) -> Dict[str, Any] | None:
    """
    Call Groq to get an AI verdict for the URL.

    Returns:
        dict with keys: ai_verdict, explanation, extra_reasons
        or None if anything fails.
    """
    try:
        reasons_bullets = "\n".join(f"- {r}" for r in reasons) or "- (no reasons)"

        user_prompt = f"""
Link: {url}
Hostname: {host}
Root website: {root}
Rule-based score: {score}
Rule-based reasons:
{reasons_bullets}

Using this information, classify the link risk.

Remember: explain it in very simple words and respond ONLY with JSON.
"""

        raw = groq_chat(
            [
                {"role": "system", "content": AI_SYSTEM},
                {"role": "user", "content": user_prompt},
            ],
            model="llama-3.3-70b-versatile",
        )

        json_text = _extract_json_block(raw)
        if not json_text:
            return None

        data = json.loads(json_text)

        if not isinstance(data, dict):
            return None

        # Basic normalization
        ai_verdict = str(data.get("ai_verdict", "")).upper()
        if ai_verdict not in {"SAFE", "SUSPICIOUS", "DANGEROUS"}:
            ai_verdict = "UNKNOWN"

        explanation = data.get("explanation") or ""
        if not isinstance(explanation, str):
            explanation = str(explanation)

        extra_reasons = data.get("extra_reasons") or []
        if not isinstance(extra_reasons, list):
            extra_reasons = [str(extra_reasons)]
        extra_reasons = [str(r).strip() for r in extra_reasons if str(r).strip()]

        return {
            "ai_verdict": ai_verdict,
            "explanation": explanation.strip(),
            "extra_reasons": extra_reasons,
        }

    except Exception:
        # Fail silently; hybrid still works with rules only
        return None


# ---------------------------------------------------------
# MAIN SCANNER ENGINE (RULES + AI HYBRID)
# ---------------------------------------------------------

def analyze_url(url_raw: str) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0

    url_raw = url_raw.strip()

    # Ensure scheme
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_raw):
        url_raw = "http://" + url_raw
        reasons.append("Link was missing http/https, so we added it to check it.")
        score += 1

    parsed = urlparse(url_raw)
    host = parsed.hostname or ""
    root = extract_root(url_raw)

    if not host:
        return {
            "score": 10,
            "verdict": "DANGEROUS",
            "rule_verdict": "DANGEROUS",
            "ai_verdict": "Unknown",
            "explanation": "We could not read this link as a normal website address.",
            "reasons": ["The website address looks invalid or broken."],
            "details": {
                "url": url_raw,
                "host": host,
                "root": root,
            },
        }

    host_lower = host.lower()

    # -------------------------
    # Unicode Spoof Detection
    # -------------------------
    unicode_hits = detect_unicode_spoof(host_lower, root)
    if unicode_hits:
        score += 10
        reasons.extend(unicode_hits)

    # -------------------------
    # Trusted Domains (hard)
    # -------------------------
    if root in HARD_TRUSTED_DOMAINS:
        ent = _entropy(parsed.path + parsed.query)
        if ent > 4.5:
            reasons.append("The link path looks random, which is common on big trusted sites.")

        rule_verdict = "SAFE"
        final = {
            "score": score,
            "verdict": rule_verdict,
            "rule_verdict": rule_verdict,
            "ai_verdict": "Unknown",
            "explanation": "This is a well-known trusted website.",
            "reasons": reasons,
            "details": {
                "url": url_raw,
                "host": host,
                "root": root,
            },
        }
        return final

    # -------------------------
    # Shorteners
    # -------------------------
    if root in URL_SHORTENERS:
        score += 5
        reasons.append("The link is shortened, which scammers often use to hide the real website.")

    # -------------------------
    # HTTPS
    # -------------------------
    if parsed.scheme != "https":
        score += 3
        reasons.append("The link does not use https, so it is less secure.")

    # -------------------------
    # Soft Trusted
    # -------------------------
    if root in SOFT_TRUSTED_DOMAINS:
        ent = _entropy(parsed.path + parsed.query)
        if ent > 5:
            reasons.append("The link path looks random, which is normal for stored files.")

        rule_verdict = "SUSPICIOUS" if score > 0 else "SAFE"
        return {
            "score": score,
            "verdict": rule_verdict,
            "rule_verdict": rule_verdict,
            "ai_verdict": "Unknown",
            "explanation": "This looks like a storage or cloud link. Safety depends on who sent it.",
            "reasons": reasons,
            "details": {
                "url": url_raw,
                "host": host,
                "root": root,
            },
        }

    # -------------------------
    # IP Address
    # -------------------------
    if _is_ip(host_lower):
        score += 6
        reasons.append("The link uses only numbers instead of a normal website name, which scammers often do.")

    # -------------------------
    # Suspicious TLD
    # -------------------------
    tld = root.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 8
        reasons.append(f"The website ends with '.{tld}', which is often used in scams.")

    # -------------------------
    # Subdomain Abuse
    # -------------------------
    if host_lower.count(".") > 3:
        score += 6
        reasons.append("The website name has many dots, which is common on scam sites.")

    # -------------------------
    # Hyphen overload
    # -------------------------
    if host_lower.count("-") >= 3:
        score += 5
        reasons.append("The website name has many dashes, often used to copy real brands.")

    # -------------------------
    # Entropy
    # -------------------------
    combo = parsed.path + parsed.query
    if combo:
        ent = _entropy(combo)
        if len(combo) > 80 and ent > 4.5:
            score += 3
            reasons.append("The link after the main website is very long and looks random.")
        elif ent > 5:
            score += 1
            reasons.append("The link includes random-looking characters.")

    # -------------------------
    # Suspicious Keywords
    # -------------------------
    lower_path = combo.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower_path:
            score += 6
            reasons.append(
                f"The link talks about '{kw}', which scammers often use to steal accounts."
            )
            break

    # -------------------------
    # Brand impersonation
    # -------------------------
    for brand, legit_domains in BRAND_KEYWORDS.items():
        if brand in host_lower:
            if root not in legit_domains:
                score += 10
                reasons.append(
                    f"The website name tries to look like {brand} but is not the real site."
                )
            break

    # -------------------------
    # Length
    # -------------------------
    if len(url_raw) > 150:
        score += 2
        reasons.append("The link is extremely long, which is common in scam links.")

    # -------------------------
    # RULE-BASED VERDICT
    # -------------------------
    if score == 0:
        rule_verdict = "SAFE"
    elif score <= 5:
        rule_verdict = "SUSPICIOUS"
    else:
        rule_verdict = "DANGEROUS"

    # -------------------------
    # AI HYBRID LAYER
    # -------------------------
    ai_data = _ai_assess_url(url_raw, host, root, score, reasons)

    if ai_data is not None:
        ai_verdict = ai_data.get("ai_verdict", "UNKNOWN")
        ai_explanation = ai_data.get("explanation", "").strip()
        extra_reasons = ai_data.get("extra_reasons", [])

        # Merge reasons (tag AI reasons so it's clear if you ever inspect raw JSON)
        for r in extra_reasons:
            reasons.append(f"AI: {r}")

        # Combine verdicts — choose the more severe of rule vs AI
        severity_rank = {"SAFE": 0, "SUSPICIOUS": 1, "DANGEROUS": 2}
        rule_lvl = severity_rank.get(rule_verdict, 0)
        ai_lvl = severity_rank.get(ai_verdict, rule_lvl)
        final_lvl = max(rule_lvl, ai_lvl)

        final_verdict = {v: k for k, v in severity_rank.items()}[final_lvl]

        if ai_explanation:
            explanation = ai_explanation
        else:
            if final_verdict == "SAFE":
                explanation = "We did not see clear signs that this link is a scam."
            elif final_verdict == "SUSPICIOUS":
                explanation = "This link has some warning signs and could be a scam."
            else:
                explanation = "This link has strong signs of being a scam or fake website."

        return {
            "score": score,
            "verdict": final_verdict,
            "rule_verdict": rule_verdict,
            "ai_verdict": ai_verdict,
            "explanation": explanation,
            "reasons": reasons,
            "details": {
                "url": url_raw,
                "host": host,
                "root": root,
            },
        }

    # -------------------------
    # NO AI (fallback to rules only)
    # -------------------------
    if rule_verdict == "SAFE":
        explanation = "We did not see clear signs that this link is a scam."
    elif rule_verdict == "SUSPICIOUS":
        explanation = "This link has some warning signs and could be a scam."
    else:
        explanation = "This link has strong signs of being a scam or fake website."

    return {
        "score": score,
        "verdict": rule_verdict,
        "rule_verdict": rule_verdict,
        "ai_verdict": "Unknown",
        "explanation": explanation,
        "reasons": reasons,
        "details": {
            "url": url_raw,
            "host": host,
            "root": root,
        },
    }