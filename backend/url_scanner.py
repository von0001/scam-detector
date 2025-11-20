# ---------------------------------------------------------
# URL Scanner v3 — Von Edition (Full Rewrite)
# ---------------------------------------------------------

import re
import math
import idna
import tldextract
import unicodedata
from urllib.parse import urlparse
from typing import Dict, List


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
        return 0
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
    reasons = []

    # Unicode present
    if any(ord(c) > 127 for c in host):
        reasons.append("Hostname contains Unicode characters.")

    # Punycode check
    try:
        decoded = idna.decode(host)
        if decoded != host:
            reasons.append("Punycode detected (possible Unicode spoof).")
    except Exception:
        reasons.append("Invalid IDNA encoding in hostname (spoof attempt).")

    # Homoglyph mimic detection
    normalized = normalize_homoglyphs(host)
    normalized_root = normalize_homoglyphs(root)

    for brand, legit_set in BRAND_KEYWORDS.items():
        for legit in legit_set:
            if normalized_root == normalize_homoglyphs(legit) and root != legit:
                reasons.append(f"Unicode/homoglyph spoof detected: mimics '{legit}'.")
                return reasons

    return reasons


# ---------------------------------------------------------
# MAIN SCANNER ENGINE
# ---------------------------------------------------------

def analyze_url(url_raw: str) -> Dict[str, object]:
    reasons = []
    score = 0

    url_raw = url_raw.strip()

    # Ensure scheme
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url_raw):
        url_raw = "http://" + url_raw
        reasons.append("URL missing scheme — added http://")
        score += 1

    parsed = urlparse(url_raw)
    host = parsed.hostname or ""
    root = extract_root(url_raw)

    if not host:
        return {"score": 10, "reasons": ["Invalid or unparseable hostname."]}

    host_lower = host.lower()

    # -------------------------
    # Unicode Spoof Detection
    # -------------------------
    unicode_hits = detect_unicode_spoof(host_lower, root)
    if unicode_hits:
        score += 10
        reasons.extend(unicode_hits)

    # -------------------------
    # Trusted Domains
    # -------------------------
    if root in HARD_TRUSTED_DOMAINS:
        ent = _entropy(parsed.path + parsed.query)
        if ent > 4.5:
            reasons.append("High randomness in path (normal for trusted sites).")
        return {"score": score, "reasons": reasons}

    # -------------------------
    # Shorteners
    # -------------------------
    if root in URL_SHORTENERS:
        score += 5
        reasons.append("URL shortener used — high phishing risk.")

    # -------------------------
    # HTTPS
    # -------------------------
    if parsed.scheme != "https":
        score += 3
        reasons.append("Not using HTTPS.")

    # -------------------------
    # Soft Trusted
    # -------------------------
    if root in SOFT_TRUSTED_DOMAINS:
        ent = _entropy(parsed.path + parsed.query)
        if ent > 5:
            reasons.append("High randomness (normal for cloud storage URLs).")
        return {"score": score, "reasons": reasons}

    # -------------------------
    # IP Address
    # -------------------------
    if _is_ip(host_lower):
        score += 6
        reasons.append("Uses raw IP address — common in phishing.")

    # -------------------------
    # Suspicious TLD
    # -------------------------
    tld = root.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 8
        reasons.append(f"Suspicious TLD '.{tld}' used heavily in scams.")

    # -------------------------
    # Subdomain Abuse
    # -------------------------
    if host_lower.count(".") > 3:
        score += 6
        reasons.append("Deep subdomain chain — common in scam hosting.")

    # -------------------------
    # Hyphen overload
    # -------------------------
    if host_lower.count("-") >= 3:
        score += 5
        reasons.append("Excessive hyphens used to mimic legit domains.")

    # -------------------------
    # Entropy
    # -------------------------
    combo = parsed.path + parsed.query
    if combo:
        ent = _entropy(combo)
        if len(combo) > 80 and ent > 4.5:
            score += 3
            reasons.append("Long, random-looking URL path.")
        elif ent > 5:
            score += 1
            reasons.append("Some randomness in URL.")

    # -------------------------
    # Suspicious Keywords
    # -------------------------
    lower_path = combo.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower_path:
            score += 6
            reasons.append(f"Phishing keyword detected: '{kw}'.")
            break

    # -------------------------
    # Brand impersonation
    # -------------------------
    for brand, legit_domains in BRAND_KEYWORDS.items():
        if brand in host_lower:
            if root not in legit_domains:
                score += 10
                reasons.append(f"Brand impersonation attempt: '{brand}'.")
            break

    # -------------------------
    # Length
    # -------------------------
    if len(url_raw) > 150:
        score += 2
        reasons.append("URL extremely long.")

    return {"score": score, "reasons": reasons}