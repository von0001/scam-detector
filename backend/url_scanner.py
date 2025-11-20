# url_scanner_v2.py — Fully Upgraded Engine (Von Edition + Enhanced)

import re
import math
import tldextract
from urllib.parse import urlparse
from typing import Dict, List

# ---------------------------------------------------------
# TRUST LISTS
# ---------------------------------------------------------

HARD_TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "gstatic.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "sharepoint.com",
    "aws.amazon.com", "amazon.com", "apple.com", "icloud.com",
    "slack.com", "zoom.us", "dropbox.com", "github.com",
    "stripe.com", "box.com", "docusign.net", "adobesign.com",
    "linkedin.com"
}

SOFT_TRUSTED_DOMAINS = {
    "safelinks.protection.outlook.com",
    "amazonaws.com",
    "azureedge.net",
    "sharepoint.com",
    "githubusercontent.com",
    "googleusercontent.com",
    "cloudfront.net",
    "firebaseapp.com"
}

URL_SHORTENERS = {
    "t.co", "bit.ly", "tinyurl.com", "goo.gl", "cutt.ly",
    "buff.ly", "is.gd", "v.gd", "ow.ly", "shorturl.at"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "link", "click", "info", "work",
    "gq", "tk", "ml", "cf", "ga", "ru", "cn", "rest", "monster", "zip",
    "biz", "ws"
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "reset", "unlock", "update",
    "secure", "security", "confirm", "account",
    "support", "recover", "validation", "auth",
    "password", "credentials", "signin"
}

BRAND_KEYWORDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com"},
    "facebook": {"facebook.com", "fb.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "amazon": {"amazon.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "boa": {"bankofamerica.com"},
}

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def _is_ip_address(host: str) -> bool:
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return all(0 <= int(p) <= 255 for p in host.split("."))
    return False

def _entropy(string: str) -> float:
    if len(string) == 0:
        return 0
    probabilities = [string.count(c) / len(string) for c in set(string)]
    return -sum(p * math.log2(p) for p in probabilities)

def extract_root_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()

# ---------------------------------------------------------
# MAIN ENGINE
# ---------------------------------------------------------

def analyze_url(raw_url: str) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0

    url = raw_url.strip()

    # Scheme
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "http://" + url
        reasons.append("URL missing scheme. Assuming http://")
        score += 1

    parsed = urlparse(url)
    host = parsed.hostname or ""
    root_domain = extract_root_domain(url)

    if not host:
        return {"score": 10, "reasons": ["Could not parse any valid domain."]}

    host_lower = host.lower()

    # Trusted domains
    if root_domain in HARD_TRUSTED_DOMAINS:
        path_entropy = _entropy(parsed.path + parsed.query)
        if path_entropy > 4.5:
            score += 1
            reasons.append("Contains randomness (normal for trusted service).")
        return {"score": score, "reasons": reasons}

    # URL shorteners
    if root_domain in URL_SHORTENERS:
        score += 5
        reasons.append("URL shortener used (high phishing risk).")

    # HTTPS
    if parsed.scheme != "https":
        score += 3
        reasons.append("Not using HTTPS (unsafe).")

    # Soft trusted (AWS, GCS)
    if root_domain in SOFT_TRUSTED_DOMAINS:
        ent = _entropy(parsed.path + parsed.query)
        if ent > 5.2:
            score += 1
            reasons.append("Contains high randomness (normal for cloud).")
        return {"score": score, "reasons": reasons}

    # IP address
    if _is_ip_address(host_lower):
        score += 6
        reasons.append("Uses raw IP address (phishing indicator).")

    # Suspicious TLD
    tld = root_domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 8
        reasons.append(f"Suspicious TLD '.{tld}' frequently used in scams.")

    # Subdomain abuse
    subparts = host_lower.split(".")[:-2]
    if len(subparts) >= 3:
        score += 6
        reasons.append("Deep subdomain chain often used in phishing.")

    # Hyphen overload
    if host_lower.count("-") >= 3:
        score += 5
        reasons.append("Excessive hyphens mimic legit domains.")

    # Entropy
    combined = parsed.path + parsed.query
    if combined:
        ent = _entropy(combined)
        if len(combined) > 80 and ent > 4.5:
            score += 3
            reasons.append("High-entropy long URL segment.")
        elif ent > 5.0:
            score += 1
            reasons.append("Some randomness detected.")

    # Sensitive keywords
    lower_path = combined.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower_path:
            score += 6
            reasons.append(f"Phishing keyword detected: '{kw}'.")
            break

    # Brand impersonation
    for brand, legit_domains in BRAND_KEYWORDS.items():
        if brand in host_lower:
            if root_domain not in legit_domains:
                score += 10
                reasons.append(f"Domain impersonates brand '{brand}'.")
            break

    # Long URL
    if len(url) > 150:
        score += 2
        reasons.append("URL unusually long.")

    return {"score": score, "reasons": reasons}