# backend/utils/reason_cleaner.py

"""
Universal plain-English translator for scanner reasons.
Turns raw scanner messages into human-friendly explanations.
"""

import re

FRIENDLY_MAP = [

    # ------------------ URL reasons ------------------
    (r"Suspicious TLD '(\.\w+)'", lambda m:
        f"The website ends with '{m.group(1)}', a domain that scammers often use because it’s cheap and unregulated."
    ),

    (r"Not using HTTPS", lambda m:
        "The website is not using a secure HTTPS connection."
    ),

    (r"URL shortener", lambda m:
        "This link uses a URL shortener — a common way scammers hide real destinations."
    ),

    (r"Excessive hyphens", lambda m:
        "This website name has many hyphens, which is unusual for real companies."
    ),

    (r"Deep subdomain chain", lambda m:
        "This domain contains many subdomains — a trick used to mimic trusted websites."
    ),

    (r"Domain impersonates brand '(.+)'", lambda m:
        f"This website appears to imitate the brand '{m.group(1)}'."
    ),

    (r"Phishing keyword detected: '(.+)'", lambda m:
        f"The URL contains the keyword '{m.group(1)}', commonly found in phishing attacks."
    ),

    (r"URL missing scheme", lambda m:
        "The link is missing 'http://' or 'https://', which is suspicious."
    ),

    (r"Uses raw IP address", lambda m:
        "The link goes directly to an IP address, a common phishing indicator."
    ),

    # ------------------ TEXT reasons ------------------
    (r"Requests sensitive info", lambda m:
        "The message asks for private information, which legitimate companies do not request like this."
    ),

    (r"Manipulative tone detected", lambda m:
        "The message uses pressure, fear, or urgency — a manipulation tactic."
    ),

    (r"Contains (\d+) link", lambda m:
        f"The message contains {m.group(1)} link(s), which scammers often use to steal information."
    ),

    (r"Spammy exclamation marks", lambda m:
        "The message uses excessive exclamation marks to add fake urgency."
    ),

    (r"Contains many emojis", lambda m:
        "The message uses many emojis — a common tactic in manipulative writing."
    ),

    (r"Message extremely short", lambda m:
        "The message is extremely short — common in low-effort scam attempts."
    ),

    # ------------------ QR reasons ------------------
    (r"WiFi QR", lambda m:
        "This QR code tries to connect you to WiFi, which could expose your device."
    ),

    (r"Crypto payment QR", lambda m:
        "Crypto payment QR codes are often used in scams because payments cannot be reversed."
    ),

    (r"Payment QR code could be fraudulent", lambda m:
        "This QR code appears to request payment, which is a common scam pattern."
    ),
]

def clean_reason(reason: str) -> str:
    """Return a human-friendly explanation for a single raw reason."""
    for pattern, handler in FRIENDLY_MAP:
        match = re.search(pattern, reason, flags=re.IGNORECASE)
        if match:
            try:
                return handler(match)
            except:
                pass
    return reason  # fallback if nothing matches

def clean_reasons(reasons):
    """Clean an entire list of reasons."""
    return [clean_reason(r) for r in reasons]