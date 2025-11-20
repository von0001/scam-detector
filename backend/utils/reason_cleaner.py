# backend/utils/reason_cleaner.py

"""
Universal plain-English translator for scanner reasons.
Makes fully human-friendly explanations for URLs, texts, QR codes,
and manipulation tactics.
"""

import re

FRIENDLY_MAP = [

    # ------------------ URL reasons ------------------
    (r"Suspicious TLD '(\.\w+)'", lambda m:
        f"The website ends with '{m.group(1)}', a domain commonly used by scammers."
    ),
    (r"Not using HTTPS", lambda m:
        "The website does not use secure HTTPS encryption."
    ),
    (r"URL shortener", lambda m:
        "The link uses a URL shortener, which hides the real destination."
    ),
    (r"Excessive hyphens", lambda m:
        "The website name contains many hyphens — unusual for legitimate companies."
    ),
    (r"Deep subdomain chain", lambda m:
        "This domain has multiple subdomains — a trick scammers use to mimic trusted sites."
    ),
    (r"Domain impersonates brand '(.+)'", lambda m:
        f"This website appears to imitate the brand '{m.group(1)}'."
    ),
    (r"Phishing keyword detected: '(.+)'", lambda m:
        f"The link contains the keyword '{m.group(1)}', commonly used in phishing attacks."
    ),

    # ------------------ TEXT reasons ------------------
    (r"Requests sensitive info", lambda m:
        "The message requests private information (passwords, codes). Legit companies never do this."
    ),
    (r"Manipulative tone detected", lambda m:
        "The message uses pressure, fear, or guilt — common manipulation tactics."
    ),
    (r"Contains (\d+) link", lambda m:
        f"The message contains {m.group(1)} link(s) — scammers often use links to steal data."
    ),
    (r"Spammy exclamation marks", lambda m:
        "The message uses excessive exclamation marks to create urgency."
    ),
    (r"Contains many emojis", lambda m:
        "The message uses many emojis — often seen in manipulative or scam attempts."
    ),
    (r"Message extremely short", lambda m:
        "The message is extremely short — common in low-effort scam attempts."
    ),

    # ------------------ QR reasons ------------------
    (r"WiFi QR", lambda m:
        "This QR code attempts to connect your device to a WiFi network."
    ),
    (r"Crypto payment QR", lambda m:
        "Crypto payment QR codes are often used in scams because transactions cannot be reversed."
    ),
    (r"Payment QR code could be fraudulent", lambda m:
        "This QR code appears to request money — a common scam pattern."
    ),

    # ------------------ MANIPULATION TACTICS ------------------
    (r"urgency", lambda m:
        "The message tries to pressure you with urgency."
    ),
    (r"fear", lambda m:
        "The message attempts to scare you or create fear-based pressure."
    ),
    (r"authority_impersonation", lambda m:
        "The sender appears to impersonate an authority figure (bank, IRS, government, security team)."
    ),
    (r"secrecy", lambda m:
        "The sender asks you to keep the conversation secret — a classic manipulation tactic."
    ),
    (r"love_bombing", lambda m:
        "The sender uses excessive affection or emotional praise to gain trust."
    ),
    (r"reward", lambda m:
        "The message promises rewards, prizes, or winnings to lure you in."
    ),
    (r"financial_grooming", lambda m:
        "The message tries to influence or extract money, often through investment or payment schemes."
    ),
]


def clean_reason(reason: str) -> str:
    """Return a human-friendly explanation for a single raw reason."""
    for pattern, handler in FRIENDLY_MAP:
        match = re.fullmatch(pattern, reason, flags=re.IGNORECASE)
        if match:
            try:
                return handler(match)
            except:
                pass

    # fallback: return unchanged if no pattern matches
    return reason


def clean_reasons(reasons):
    """Clean entire list of reasons."""
    cleaned = []
    for r in reasons:
        cleaned.append(clean_reason(r))
    return cleaned