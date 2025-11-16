import re
import math
import tldextract
from urllib.parse import urlparse
from typing import Dict, List

# Highly abused TLDs in phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "link", "click", "info", "work",
    "gq", "tk", "ml", "cf", "ga", "ru", "cn", "rest", "monster", "zip"
}

# Major brands and their legit domains
BRAND_KEYWORDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "accounts.google.com"},
    "facebook": {"facebook.com", "fb.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "amazon": {"amazon.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "boa": {"bankofamerica.com"},
}

# Phishing words commonly found in scam links
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "reset", "unlock", "update",
    "secure", "security", "confirm", "account",
    "support", "recover", "validation"
}

def _is_ip_address(host: str) -> bool:
    """Detect IPv4 IP addresses."""
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return all(0 <= int(p) <= 255 for p in host.split("."))
    return False

def _entropy(string: str) -> float:
    """Calculate Shannon entropy. High entropy = suspicious."""
    probabilities = [string.count(c) / len(string) for c in set(string)]
    return -sum(p * math.log2(p) for p in probabilities)

def extract_root_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()

def analyze_url(raw_url: str) -> Dict[str, object]:
    reasons: List[str] = []
    score = 0

    url = raw_url.strip()

    # Add scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "http://" + url
        reasons.append("URL missing scheme. Assuming http://")
        score += 1

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if not host:
        return {
            "score": 10,
            "reasons": ["Could not parse domain at all (broken URL)."]
        }

    host_lower = host.lower()
    root_domain = extract_root_domain(url)

    # 1. HTTPS Check
    if parsed.scheme != "https":
        reasons.append("Not using HTTPS (unsafe connection).")
        score += 2

    # 2. IP Address Check
    if _is_ip_address(host):
        reasons.append("Using raw IP address instead of domain.")
        score += 4

    # 3. Suspicious TLD Check
    tld = root_domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Top-level domain '.{tld}' frequently used in scams.")
        score += 3

    # 4. Subdomain Checks
    subdomain_parts = host_lower.split(".")[:-2]

    if len(subdomain_parts) >= 2:
        reasons.append("Excessive subdomains (common in phishing).")
        score += 3

    # 5. Hyphen Abuse
    if host_lower.count("-") >= 2:
        reasons.append("Domain has unusual amount of hyphens.")
        score += 2

    # 6. Punycode (IDN Homograph attacks)
    if "xn--" in host_lower:
        reasons.append("Contains punycode (possible IDN homograph attack).")
        score += 4

    # 7. High Entropy Path (random strings)
    path_entropy = _entropy(parsed.path + parsed.query) if (parsed.path + parsed.query) else 0
    if path_entropy > 4.0:
        reasons.append("URL contains high-entropy/randomized characters.")
        score += 2

    # 8. Phishing Keywords
    combined = (parsed.path + parsed.query).lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined:
            reasons.append(f"Contains sensitive keyword: '{kw}'.")
            score += 3
            break

    # 9. Brand Impersonation Detection
    for brand, legit_set in BRAND_KEYWORDS.items():
        legit_set = {d.lower() for d in legit_set}

        if brand in root_domain:
            if root_domain not in legit_set:
                reasons.append(f"Domain impersonates brand '{brand}'.")
                score += 7
            break

        # brand inside SUBDOMAIN is highly suspicious
        if any(brand in part for part in subdomain_parts):
            reasons.append(f"Brand '{brand}' appears in subdomain (impersonation).")
            score += 6
            break

    # 10. URL Length
    total_len = len(url)
    if total_len > 120:
        reasons.append("Very long URL length (common obfuscation technique).")
        score += 2

    return {
        "score": score,
        "reasons": reasons
    }