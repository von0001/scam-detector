# url_scanner_v2.py — Fully Upgraded Engine (Von Edition)

import re
import math
import tldextract
from urllib.parse import urlparse
from typing import Dict, List

# ——————————————————————————————————————————
# 1. DOMAIN TRUST SYSTEM (NEW)
# ——————————————————————————————————————————

# Hard-trusted roots (NEVER treated as scams unless extreme evidence)
HARD_TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "gstatic.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "sharepoint.com",
    "aws.amazon.com", "amazon.com", "apple.com", "icloud.com",
    "slack.com", "zoom.us", "dropbox.com", "github.com",
    "stripe.com", "box.com", "docusign.net", "adobesign.com",
    "linkedin.com"
}

# Soft-trusted domains (allowed to contain randomness, tokens, IDs)
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

# HIGH-RISK SHORTENER DOMAINS (your ONLY blind spot)
URL_SHORTENERS = {
    "t.co", "bit.ly", "tinyurl.com", "goo.gl", "cutt.ly",
    "buff.ly", "is.gd", "v.gd", "ow.ly", "shorturl.at"
}

# TLDs commonly abused
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "link", "click", "info", "work",
    "gq", "tk", "ml", "cf", "ga", "ru", "cn", "rest", "monster", "zip"
}

# Suspicious keywords
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "reset", "unlock", "update",
    "secure", "security", "confirm", "account",
    "support", "recover", "validation", "auth"
}

# Brand roots
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

# ——————————————————————————————————————————
# HELPER FUNCTIONS
# ——————————————————————————————————————————

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

# ——————————————————————————————————————————
# MAIN URL ANALYSIS ENGINE (V2)
# ——————————————————————————————————————————

def analyze_url(raw_url: str) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0

    url = raw_url.strip()

    # Missing scheme check
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

    # ————————————————————————
    # 1. Hard-trusted domains → ignore MOST red flags
    # ————————————————————————
    if root_domain in HARD_TRUSTED_DOMAINS:
        # Mild checks only, never heavy penalties
        path_entropy = _entropy(parsed.path + parsed.query)
        if path_entropy > 4.5:
            score += 1
            reasons.append("Contains randomness (normal for trusted service).")
        return {"score": score, "reasons": reasons}

    # ————————————————————————
    # 2. URL Shorteners (fixed your t.co weakness)
    # ————————————————————————
    if root_domain in URL_SHORTENERS:
        score += 4
        reasons.append("URL shortener used (high phishing risk).")

    # ————————————————————————
    # 3. HTTPS check
    # ————————————————————————
    if parsed.scheme != "https":
        score += 2
        reasons.append("Not using HTTPS (unsafe).")

    # ————————————————————————
    # 4. Soft-trusted domains (AWS, GCS, Azure)
    # ————————————————————————
    if root_domain in SOFT_TRUSTED_DOMAINS:
        # Allow randomness, but still check for extreme sketchiness
        path_entropy = _entropy(parsed.path + parsed.query)
        if path_entropy > 5.2:
            score += 1
            reasons.append("Contains high randomness (normal for cloud).")
        return {"score": score, "reasons": reasons}

    # ————————————————————————
    # 5. IP address usage
    # ————————————————————————
    if _is_ip_address(host_lower):
        score += 4
        reasons.append("Uses raw IP (high phishing indicator).")

    # ————————————————————————
    # 6. Suspicious TLD
    # ————————————————————————
    tld = root_domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 3
        reasons.append(f"Suspicious TLD '.{tld}' used frequently in scams.")

    # ————————————————————————
    # 7. Subdomain overload
    # ————————————————————————
    subparts = host_lower.split(".")[:-2]
    if len(subparts) >= 3:  # (Made less sensitive)
        score += 2
        reasons.append("Unusually deep subdomain chain.")

    # ————————————————————————
    # 8. Excessive hyphens
    # ————————————————————————
    if host_lower.count("-") >= 3:  # Also less sensitive
        score += 2
        reasons.append("Domain contains many hyphens (phishing pattern).")

    # ————————————————————————
    # 9. Entropy detection (Smarter now)
    #    Allows enterprise randomness without over-penalizing
    # ————————————————————————
    combined_path = parsed.path + parsed.query
    if combined_path:
        ent = _entropy(combined_path)
        # Dynamic entropy threshold based on length
        if len(combined_path) > 80 and ent > 4.5:
            score += 2
            reasons.append("High entropy in long URL segment.")
        elif ent > 5.0:
            score += 1
            reasons.append("Some randomness detected.")

    # ————————————————————————
    # 10. Suspicious keywords (weight lowered)
    # ————————————————————————
    lower_path = combined_path.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower_path and root_domain not in HARD_TRUSTED_DOMAINS:
            score += 2  # reduced from +3
            reasons.append(f"Contains sensitive keyword: '{kw}'.")
            break

    # ————————————————————————
    # 11. Brand impersonation detection (SMARTER)
    # ————————————————————————
    for brand, legit_domains in BRAND_KEYWORDS.items():
        legit_domains = {d.lower() for d in legit_domains}

        # If brand appears anywhere
        if brand in host_lower:
            if root_domain in legit_domains:
                # OK
                pass
            else:
                # ONLY penalize heavy if domain is REALLY off
                score += 4
                reasons.append(f"Domain appears to impersonate brand '{brand}'.")
            break

    # ————————————————————————
    # 12. Very long URL (light penalty)
    # ————————————————————————
    if len(url) > 150:
        score += 1
        reasons.append("URL is unusually long.")

    return {"score": score, "reasons": reasons}