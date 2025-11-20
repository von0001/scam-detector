# text_scanner_v2.py — Fully Upgraded (Von Ultra Edition)

import re
from typing import Dict, List

# ——————————————————————————————————————————
# 1. SCAM PHRASE DATABASE (SMARTER TIERS)
# ——————————————————————————————————————————

HIGH_SEVERITY = [
    # Account/login threats
    ("your account is locked", 6, "Claims your account is locked."),
    ("account suspended", 6, "Threatens account suspension."),
    ("account deactivated", 6, "Threatens account deactivation."),
    ("verify your identity", 5, "Requests identity verification."),
    ("reset your password", 5, "Password reset threat."),
    ("security alert", 5, "Fake security alert."),
    ("legal action", 5, "Threat of legal action."),
    ("warrant", 5, "Threat of warrant/arrest."),
    ("arrest", 5, "Threat of arrest."),
    ("your ssn has been suspended", 6, "Claims your Social Security number is suspended."),

    # Direct money request (romance scam trigger)
    ("can you send me", 6, "Direct money request."),
    ("i just need", 5, "Manipulative money request."),
    ("help me pay", 5, "Financial pressure."),
    ("cover my", 5, "Financial emergency request."),
    ("my phone bill", 5, "Suspicious financial request."),
    ("my rent", 5, "Financial crisis trigger."),
    ("emergency", 5, "Emergency pressure."),

    # Job scam
    ("onboarding fee", 6, "Job scam: asks for onboarding fee."),
    ("training fee", 6, "Job scam: asks for training fee."),
    ("application fee", 6, "Job scam: asks for application fee."),

    # Payment/funds transfer
    ("wire transfer", 6, "Requests wire transfer."),
    ("routing number", 6, "Requests routing number."),
]

MEDIUM_SEVERITY = [
    ("verify your account", 4, "Asks you to verify your account."),
    ("update your information", 3, "Requests personal info update."),
    ("unusual activity", 3, "Claims unusual activity."),
    ("someone tried to", 3, "Suspicious login attempt claim."),
    ("urgent", 3, "Uses urgency."),
    ("immediately", 3, "Immediate pressure."),
    ("last chance", 3, "Last chance pressure."),
    ("you have been selected", 4, "Prize-selection scam."),
    ("claim your reward", 4, "Reward/lottery scam."),
    ("prize", 3, "Claims reward."),
    ("congratulations", 3, "Prize/lottery scam."),
]

LOW_SEVERITY = [
    ("support team", 2, "Generic 'support team'."),
    ("customer service", 2, "Generic customer service."),
    ("it department", 2, "Fake IT department."),
    ("technical support", 2, "Tech support impersonation."),
    ("gift card", 2, "Gift card scam keyword."),
    ("shipping address", 2, "Shipment scam."),
    ("click here", 2, "Pushes you to click a link."),
    ("click the link", 2, "Pushes link interaction."),
    ("open the link", 2, "Pushes link access."),
    ("login here", 3, "Requests login."),
]

SENSITIVE_INFO = [
    "password", "passcode", "pin", "ssn",
    "social security", "cvv", "verification code",
    "access code", "banking details", "card number",
]

# Romance/Manipulation indicators (not score-based — verbal cues)
ROMANCE_INDICATORS = [
    "baby", "babe", "my love", "my darling",
    "i need you", "i miss you", "you mean everything to me",
]

# Threat/coercion indicators
COERCION_PHRASES = [
    "if you don't", "if you do not",
    "i'll block you", "i will block you",
    "you don't care about me", "i thought you cared",
    "guess i mean nothing to you", "prove you care",
]

EMOJI_REGEX = r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF]"
URL_REGEX = r"https?://\S+|www\.\S+"


# ——————————————————————————————————————————
# 2. HELPERS
# ——————————————————————————————————————————

def _split_sentences(text: str) -> List[str]:
    return re.split(r"[.!?]+", text)

def _detect_tone(text: str) -> int:
    score = 0
    lower = text.lower()

    if any(w in lower for w in ["warning", "danger", "risk", "alert", "issue detected"]):
        score += 2

    if any(w in lower for w in ["now", "immediately", "asap", "right away"]):
        score += 2

    if any(w in lower for w in ["official", "government", "irs", "administrator"]):
        score += 3

    return score


# ——————————————————————————————————————————
# 3. MAIN ANALYZER (with ENHANCED scam detection)
# ——————————————————————————————————————————

def analyze_text(text: str) -> Dict[str, object]:
    reasons = []
    score = 0

    t = text.strip()
    lower = t.lower()

    # — HIGH severity patterns
    for phrase, weight, reason in HIGH_SEVERITY:
        if phrase in lower:
            score += weight
            reasons.append(reason)

    # — MEDIUM severity patterns
    for phrase, weight, reason in MEDIUM_SEVERITY:
        if phrase in lower:
            score += weight
            reasons.append(reason)

    # — LOW severity patterns
    for phrase, weight, reason in LOW_SEVERITY:
        if phrase in lower:
            score += weight
            reasons.append(reason)

    # — Sensitive info
    for w in SENSITIVE_INFO:
        if w in lower:
            score += 4
            reasons.append(f"Requests sensitive info: '{w}'.")
            break

    # — Direct coercion
    for c in COERCION_PHRASES:
        if c in lower:
            score += 5
            reasons.append("Coercive or guilt-driven pressure detected.")
            break

    # — Romance scam cues + money request combo
    if any(r in lower for r in ROMANCE_INDICATORS) and ("$" in lower or "send" in lower):
        score += 6
        reasons.append("Romance-style emotional + money request pattern.")

    # — Links
    urls = re.findall(URL_REGEX, lower)
    if urls:
        count = len(urls)
        score += min(count * 2, 6)
        reasons.append(f"Contains {count} link(s).")

    # — Phone numbers
    phone_matches = re.findall(r"\b(\+?\d{1,3})?[-.\s]??\(?\d{3}\)?[-.\s]??\d{3}[-.\s]??\d{4}\b", t)
    if phone_matches:
        score += 2
        reasons.append("Contains phone number(s).")

    # — Email
    if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[A-Za-z0-9-.]+", t):
        score += 2
        reasons.append("Contains email address.")

    # — OTP
    if re.search(r"\b\d{6}\b", lower):
        score += 3
        reasons.append("Contains a 6-digit OTP code.")

    # — Emoji spam
    emojis = re.findall(EMOJI_REGEX, t)
    if len(emojis) >= 4:
        score += 1
        reasons.append("Contains many emojis (manipulative style).")

    # — ALL CAPS
    letters_only = re.sub(r"[^A-Za-z]", "", t)
    if len(letters_only) >= 10 and letters_only.isupper():
        score += 2
        reasons.append("Uses excessive ALL CAPS.")

    # — Exclamation spam
    if t.count("!") >= 3:
        score += 2
        reasons.append("Spammy exclamation marks.")

    # — Tone detection
    tone_score = _detect_tone(t)
    if tone_score > 0:
        score += tone_score
        reasons.append("Manipulative or warning tone detected.")

    # — Short message
    if len(t) < 12:
        score += 1
        reasons.append("Message extremely short (scam-like).")

    # ——————————————————————————
    # FINAL OUTPUT
    # ——————————————————————————

    if score == 0:
        verdict = "SAFE"
        explanation = "No major scam patterns detected."
    elif score <= 5:
        verdict = "SUSPICIOUS"
        explanation = "Some mild scam patterns detected."
    else:
        verdict = "DANGEROUS"
        explanation = "Multiple strong scam indicators detected."

    return {
        "score": score,
        "verdict": verdict,
        "explanation": explanation,
        "reasons": reasons,
        "details": {
            "text_length": len(t),
            "links_detected": urls,
            "emoji_count": len(emojis),
        }
    }