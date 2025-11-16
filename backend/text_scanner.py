import re
from typing import Dict, List


# HIGH-POWER scam phrase patterns:
PHRASE_PATTERNS = [
    # Account / identity threats
    ("your account is locked", 5, "Claims your account is locked."),
    ("account suspended", 5, "Threatens account suspension."),
    ("account deactivated", 5, "Threatens account deactivation."),
    ("verify your account", 4, "Asks you to verify your account."),
    ("verify your identity", 4, "Requests identity verification."),
    ("update your information", 3, "Asks for personal info update."),
    ("unusual activity", 3, "Mentions unusual activity for fear."),
    ("someone tried to", 3, "Claims suspicious activity."),
    ("security alert", 3, "Fake security alert."),

    # Urgency / fear triggers
    ("act now", 3, "Urgency phrase: 'act now'."),
    ("immediately", 3, "Uses immediate time pressure."),
    ("urgent", 3, "Marks the message as urgent."),
    ("final notice", 4, "Threatening 'final notice'."),
    ("last chance", 3, "'Last chance' pressure."),
    ("within 24 hours", 3, "Artificial time window."),

    # Tech support/authority impersonation
    ("support team", 2, "Mentions generic 'support team'."),
    ("customer service", 2, "Mentions customer service generically."),
    ("it department", 3, "Fake IT department."),
    ("technical support", 3, "Tech support impersonation."),
    ("we detected", 3, "Claims detection of an issue."),
    ("official notice", 3, "Fake official notice."),

    # Money/reward scams
    ("you have won", 4, "Fake winning message."),
    ("congratulations", 3, "Fake congratulatory reward."),
    ("you have been selected", 4, "Fake selection scam."),
    ("claim your reward", 4, "Reward-claim scam line."),
    ("gift card", 3, "Mentions gift card — scam classic."),
    ("wire transfer", 4, "Mentions wire transfer."),
    ("crypto", 3, "Crypto in suspicious context."),
    ("bitcoin", 3, "Bitcoin in suspicious context."),
    ("payment required", 4, "Fake payment request."),
    ("final payment", 4, "Pressures for final payment."),
    ("bank account", 3, "Mentions bank account."),
    ("routing number", 4, "Requests routing number."),

    # Delivery scams
    ("delivery attempt failed", 4, "Fake delivery failure alert."),
    ("package is on hold", 3, "Package hold scam."),
    ("shipping address", 2, "Requests shipping address."),

    # Links
    ("click here", 3, "Asks to click an unspecified link."),
    ("click the link", 3, "Pushes a link click."),
    ("open the link", 3, "Pushes link interaction."),
    ("login here", 4, "Requests login through link."),
    ("reset your password", 4, "Password reset scam."),
]


# Sensitive data captures
SENSITIVE_INFO = [
    "password", "passcode", "pin", "ssn",
    "social security", "routing number",
    "card number", "cvv", "verification code",
    "banking details", "access code"
]


def analyze_text(text: str) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0

    t = text.strip()
    lower = t.lower()

    # 1. PHRASE PATTERNS
    for phrase, weight, reason in PHRASE_PATTERNS:
        if phrase in lower:
            reasons.append(reason)
            score += weight

    # 2. URL DETECTION
    urls = re.findall(r"https?://\S+|www\.\S+", lower)
    if urls:
        reasons.append(f"Contains {len(urls)} link(s).")
        score += min(3, len(urls))

    # 3. PHONE NUMBER DETECTION
    phone_matches = re.findall(r"\b(\+?\d{1,3})?[-.\s]??\(?\d{3}\)?[-.\s]??\d{3}[-.\s]??\d{4}\b", t)
    if phone_matches:
        reasons.append("Contains phone number(s). Could be bait for calling scammers.")
        score += 2

    # 4. EMAIL DETECTION
    if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", t):
        reasons.append("Contains email address.")
        score += 2

    # 5. OTP CODE DETECTION
    if re.search(r"\b\d{6}\b", lower):
        reasons.append("Contains a 6-digit OTP-like code.")
        score += 2

    # 6. ALL CAPS DETECTION
    letters_only = re.sub(r"[^A-Za-z]", "", t)
    if letters_only.isupper() and len(letters_only) >= 10:
        reasons.append("Contains excessive ALL CAPS.")
        score += 2

    # 7. EXCLAMATION SPAM
    if t.count("!") >= 3:
        reasons.append("Uses many exclamation marks for pressure.")
        score += 2

    # 8. SENSITIVE INFO REQUESTS
    for w in SENSITIVE_INFO:
        if w in lower:
            reasons.append(f"Mentions sensitive info: '{w}'.")
            score += 4
            break

    # 9. EMOJI MANIPULATION
    emoji_count = len(re.findall(r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF]", t))
    if emoji_count >= 4:
        reasons.append("Contains many emojis used manipulatively.")
        score += 1

    # 10. TOO SHORT (often scammy)
    if len(t) < 15:
        reasons.append("Message is unusually short; scammers often send low-effort texts.")
        score += 1

    return {
        "score": score,
        "reasons": reasons
    }