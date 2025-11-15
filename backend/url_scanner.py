import re
from urllib.parse import urlparse
from typing import Dict, List

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "link", "click", "info", "work",
    "gq", "tk", "ml", "cf", "ga", "ru", "cn"
}

BRAND_KEYWORDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "accounts.google.com"},
    "facebook": {"facebook.com", "fb.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "boa": {"bankofamerica.com"},
}

def _is_ip_address(host: str) -> bool:
    # Detect IPv4-style addresses
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def analyze_url(raw_url: str) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0

    url = raw_url.strip()

    # Add scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
        reasons.append("URL missing scheme (http/https). Assuming http.")
        score += 1

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if not host:
        reasons.append("Could not parse a valid domain.")
        score += 4
        return {"score": score, "reasons": reasons}

    # Unsafe (non-HTTPS)
    if parsed.scheme != "https":
        reasons.append("Connection is not HTTPS.")
        score += 2

    # IP address domains
    if _is_ip_address(host):
        reasons.append("Uses a raw IP address instead of a normal domain.")
        score += 3

    # Long domain
    if len(host) > 35:
        reasons.append("Domain name is unusually long.")
        score += 2

    # Many subdomains
    if host.count(".") >= 3:
        reasons.append("Domain contains many subdomains.")
        score += 2

    # Hyphens look phishy
    if host.count("-") >= 3:
        reasons.append("Domain has many hyphens.")
        score += 2

    # Punycode
    if "xn--" in host:
        reasons.append("Contains punycode, used for fake lookalike domains.")
        score += 2

    # Suspicious TLDs
    tld = host.split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Top-level domain .{tld} is commonly used in scams.")
        score += 2

    # @ trick
    if "@" in parsed.netloc or "@" in parsed.path:
        reasons.append("URL contains '@', which can hide the real destination.")
        score += 3

    # Long/complex path
    if len(parsed.path + parsed.query) > 120:
        reasons.append("URL path or query is very long.")
        score += 2

    # Suspicious keywords
    key_words = ["login", "verify", "reset", "bank", "update", "unlock", "secure"]
    combined = (parsed.path + parsed.query).lower()

    for word in key_words:
        if word in combined:
            reasons.append(f"Contains sensitive keyword '{word}'.")
            score += 2
            break

    # Brand impersonation
    host_lower = host.lower()
    for brand, legit in BRAND_KEYWORDS.items():
        if brand in host_lower:
            if host_lower not in {d.lower() for d in legit}:
                reasons.append(f"Domain impersonates brand '{brand}'.")
                score += 4
                break

    return {"score": score, "reasons": reasons}
