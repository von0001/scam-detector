import re
from typing import Dict, List

# Scam-like phrase patterns with weights + explanations
PHRASE_PATTERNS = [
    ("your account is locked", 3, "Claims your account is locked."),
    ("verify your account", 3, "Asks you to verify your account."),
    ("verify your identity", 3, "Requests identity verification."),
    ("act now", 2, "Uses urgency language ('act now')."),
    ("urgent", 2, "Marks message as urgent."),
    ("immediately", 2, "Pushes immediate action."),
    ("click here", 2, "Asks you to click an unspecified link."),
    ("click the link", 2, "Tells you to click a provided link."),
    ("reset your password", 3, "Requests password reset via text."),
    ("confirm your password", 4, "Asks for password confirmation."),
    ("you have won", 3, "States you won a prize — classic scam."),
    ("congratulations, you have been selected", 3, "Fake reward selection."),
    ("delivery attempt failed", 3, "Fake delivery failure alert."),
    ("package is on hold", 2, "Package held until you act — scam pattern."),
    ("bank account", 2, "Mentions bank accounts."),
    ("wire transfer", 3, "Mentions wire transfers — common scam angle."),
    ("crypto", 2, "Mentions crypto in a suspicious context."),
]

def analyze_text(text: str) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0

    t = text.strip()
    lower = t.lower()

    # Phrase patterns
    for phrase, weight, reason in PHRASE_PATTERNS:
        if phrase in lower:
            reasons.append(reason)
            score += weight

    # URLs inside text
    urls = re.findall(r"https?://\S+|www\.\S+", lower)
    if urls:
        reasons.append(f"Contains {len(urls)} link(s).")
        score += min(2, len(urls))  # cap the score increase

    # Possible OTP codes (6 digits)
    if re.search(r"\b\d{6}\b", lower):
        reasons.append("Contains a 6-digit code (OTP-like).")
        score += 1

    # ALL CAPS detection
    stripped_letters = re.sub(r"[^A-Z]", "", t)
    if stripped_letters and stripped_letters.isupper() and len(stripped_letters) >= 10:
        reasons.append("Contains excessive ALL CAPS, indicating pressure.")
        score += 2

    # Too many exclamation marks
    if t.count("!") >= 3:
        reasons.append("Uses many exclamation marks for urgency.")
        score += 2

    # Sensitive info requests
    sensitive_words = [
        "password", "pin", "ssn", "social security",
        "routing number", "card number", "cvv"
    ]
    for w in sensitive_words:
        if w in lower:
            reasons.append(f"Mentions sensitive info ('{w}').")
            score += 3
            break

    return {"score": score, "reasons": reasons}
