# text_scanner_v2.py — Fully Upgraded (Von Edition)

import re
from typing import Dict, List

# ——————————————————————————————————————————
# 1. SCAM PHRASE DATABASE (SMARTER TIERS)
# ——————————————————————————————————————————

# High-power scam signals (heavy weight)
HIGH_SEVERITY = [
    ("your account is locked", 6, "Claims your account is locked."),
    ("account suspended", 6, "Threatens account suspension."),
    ("account deactivated", 6, "Threatens account deactivation."),
    ("verify your identity", 5, "Requests identity verification."),
    ("final notice", 5, "Threatening 'final notice'."),
    ("reset your password", 5, "Password reset threat."),
    ("payment required", 5, "Demands payment."),
    ("routing number", 5, "Requests routing number."),
    ("wire transfer", 5, "Requests wire transfer."),
]

# Medium-power scam signals (moderate weight)
MEDIUM_SEVERITY = [
    ("verify your account", 4, "Asks you to verify your account."),
    ("update your information", 3, "Requests personal info update."),
    ("security alert", 3, "Fake security alert."),
    ("unusual activity", 3, "Scare tactic: unusual activity."),
    ("someone tried to", 3, "Suspicious activity claim."),
    ("urgent", 3, "Uses urgency."),
    ("immediately", 3, "Immediate pressure."),
    ("last chance", 3, "Last chance pressure."),
    ("you have been selected", 4, "Prize-selection scam."),
    ("claim your reward", 4, "Claims of reward/lottery."),
]

# Low-level indicators that *strengthen suspicion* (light weight)
LOW_SEVERITY = [
    ("support team", 2, "Generic 'support team'."),
    ("customer service", 2, "Generic customer service."),
    ("it department", 2, "Fake IT department."),
    ("technical support", 2, "Tech support impersonation."),
    ("gift card", 2, "Gift card scam pattern."),
    ("shipping address", 2, "Shipment scam."),
    ("click here", 2, "Pushes you to click a link."),
    ("click the link", 2, "Pushes link interaction."),
    ("open the link", 2, "Pushes link access."),
    ("login here", 3, "Requests login."),
]

# Sensitive personal information requests
SENSITIVE_INFO = [
    "password", "passcode", "pin", "ssn", 
    "social security", "cvv", "verification code",
    "access code", "banking details", "card number"
]

# Emoji ranges for manipulation detection
EMOJI_REGEX = r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF]"

# URL regex
URL_REGEX = r"https?://\S+|www\.\S+"


# ——————————————————————————————————————————
# 2. SMARTER SENTENCE ANALYZER
# ——————————————————————————————————————————

def _split_sentences(text: str) -> List[str]:
    """Split text into sentences for better analysis."""
    return re.split(r"[.!?]+", text)


def _detect_tone(text: str) -> int:
    """Detect manipulative writing tone (fear, urgency, commands)."""
    score = 0
    lower = text.lower()

    # Fear / threat tone
    if any(word in lower for word in ["warning", "danger", "risk", "alert", "issue detected"]):
        score += 2

    # Pressure tone
    if any(word in lower for word in ["now", "immediately", "asap", "right away"]):
        score += 2

    # Authority impersonation
    if any(word in lower for word in ["official", "government", "irs", "administrator"]):
        score += 3

    return score


# ——————————————————————————————————————————
# 3. MAIN TEXT ANALYZER (V2)
# ——————————————————————————————————————————

def analyze_text(text: str) -> Dict[str, object]:
    reasons = []
    score = 0

    t = text.strip()
    lower = t.lower()

    # ————————————————————————
    # 1. Phrase Detection (multi-tier)
    # ————————————————————————

    for phrase, weight, reason in HIGH_SEVERITY:
        if phrase in lower:
            score += weight
            reasons.append(reason)

    for phrase, weight, reason in MEDIUM_SEVERITY:
        if phrase in lower:
            score += weight
            reasons.append(reason)

    for phrase, weight, reason in LOW_SEVERITY:
        if phrase in lower:
            score += weight
            reasons.append(reason)

    # ————————————————————————
    # 2. Sensitive Info
    # ————————————————————————
    for w in SENSITIVE_INFO:
        if w in lower:
            score += 4
            reasons.append(f"Requests sensitive info: '{w}'.")
            break

    # ————————————————————————
    # 3. Link Detection (smarter)
    # ————————————————————————
    urls = re.findall(URL_REGEX, lower)
    if urls:
        count = len(urls)
        score += min(count * 2, 6)  # cap link penalty
        reasons.append(f"Contains {count} link(s).")

    # ————————————————————————
    # 4. Phone Numbers
    # ————————————————————————
    phone_matches = re.findall(r"\b(\+?\d{1,3})?[-.\s]??\(?\d{3}\)?[-.\s]??\d{3}[-.\s]??\d{4}\b", t)
    if phone_matches:
        score += 2
        reasons.append("Contains phone number(s).")

    # ————————————————————————
    # 5. Emails
    # ————————————————————————
    if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[A-Za-z0-9-.]+", t):
        score += 2
        reasons.append("Contains email address.")

    # ————————————————————————
    # 6. OTP Code Detection
    # ————————————————————————
    if re.search(r"\b\d{6}\b", lower):
        score += 3
        reasons.append("Contains a 6-digit OTP code.")

    # ————————————————————————
    # 7. Emoji manipulation
    # ————————————————————————
    emojis = re.findall(EMOJI_REGEX, t)
    if len(emojis) >= 4:
        score += 1
        reasons.append("Contains many emojis (manipulative style).")

    # ————————————————————————
    # 8. ALL CAPS Detection
    # ————————————————————————
    letters_only = re.sub(r"[^A-Za-z]", "", t)
    if len(letters_only) >= 10 and letters_only.isupper():
        score += 2
        reasons.append("Uses excessive ALL CAPS.")

    # ————————————————————————
    # 9. Exclamation Spam
    # ————————————————————————
    if t.count("!") >= 3:
        score += 2
        reasons.append("Spammy exclamation marks.")

    # ————————————————————————
    # 10. Tone Analysis (NEW)
    # ————————————————————————
    tone_score = _detect_tone(t)
    if tone_score > 0:
        score += tone_score
        reasons.append("Manipulative tone detected.")

    # ————————————————————————
    # 11. Short / Low-effort Messages (refined)
    # ————————————————————————
    if len(t) < 12:
        score += 1
        reasons.append("Message extremely short (scam-like).")

    return {"score": score, "reasons": reasons}