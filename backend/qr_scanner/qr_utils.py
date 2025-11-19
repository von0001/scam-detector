# backend/qr_scanner/qr_utils.py

"""
Utility helpers for QR decoding + content classification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Literal, Dict, Any

import io

import cv2
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode as decode_zbar
import tldextract
import validators

from ..url_scanner import analyze_url
from ..text_scanner import analyze_text


QRType = Literal[
    "url",
    "wifi",
    "payment",
    "crypto",
    "vcard",
    "text",
    "unknown",
]


@dataclass
class QRContent:
    raw_data: str
    qr_type: QRType
    normalized: Optional[str] = None   # e.g. normalized URL, address, etc.


def pil_to_cv2(img: Image.Image) -> np.ndarray:
    """Convert a PIL image to an OpenCV BGR ndarray."""
    if img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGB")

    arr = np.array(img)

    if img.mode == "RGBA":
        arr = cv2.cvtColor(arr, cv2.COLOR_RGBA2BGR)
    elif img.mode == "RGB":
        arr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
    elif img.mode == "L":
        arr = cv2.cvtColor(arr, cv2.COLOR_GRAY2BGR)

    return arr


def load_image_bytes(image_bytes: bytes) -> Image.Image:
    """Robust loader from raw bytes → PIL image."""
    bio = io.BytesIO(image_bytes)
    img = Image.open(bio)
    img.load()
    return img


def decode_qr_codes(img_bgr: np.ndarray) -> List[Dict[str, Any]]:
    """
    Run pyzbar on an OpenCV BGR image.

    Returns a list of dicts:
    {
        "data": str,
        "polygon": List[(x, y)],
        "rect": {"x": int, "y": int, "w": int, "h": int},
    }
    """
    results = []
    decoded = decode_zbar(img_bgr)

    for obj in decoded:
        try:
            raw = obj.data.decode("utf-8", errors="replace").strip()
        except Exception:
            raw = ""

        # polygon points
        polygon = [(p.x, p.y) for p in obj.polygon]

        # bounding rect
        r = obj.rect
        rect = {"x": r.left, "y": r.top, "w": r.width, "h": r.height}

        results.append(
            {
                "data": raw,
                "polygon": polygon,
                "rect": rect,
            }
        )

    return results


# -------------------------------------------------------------------
# QR DATA TYPE CLASSIFICATION
# -------------------------------------------------------------------

def _looks_like_url(text: str) -> bool:
    if validators.url(text):
        return True
    # allow bare domains like "example.com"
    ext = tldextract.extract(text)
    if ext.domain and ext.suffix:
        return True
    return False


def classify_qr_data(raw: str) -> QRContent:
    """
    Classify QR payload into high-level types.
    """
    s = raw.strip()
    lower = s.lower()

    # URL
    if _looks_like_url(s):
        # normalize URL
        if not lower.startswith(("http://", "https://")):
            normalized = "https://" + s
        else:
            normalized = s
        return QRContent(raw_data=s, qr_type="url", normalized=normalized)

    # WiFi QR: WIFI:S:<ssid>;T:<WPA|WEP|nopass>;P:<password>;;
    if lower.startswith("wifi:"):
        return QRContent(raw_data=s, qr_type="wifi")

    # Very rough crypto detection
    if lower.startswith(("btc:", "bitcoin:")):
        return QRContent(raw_data=s, qr_type="crypto", normalized=s[4:])
    if lower.startswith(("eth:", "ethereum:")):
        return QRContent(raw_data=s, qr_type="crypto", normalized=s[4:])
    if lower.startswith(("usdt:", "ltc:", "xrp:", "doge:")):
        return QRContent(raw_data=s, qr_type="crypto")

    # Payments: CashApp, PayPal.me, Venmo-style
    if "$" in s and ("cash.app" in lower or "cashapp" in lower):
        return QRContent(raw_data=s, qr_type="payment")
    if "paypal.me" in lower or "venmo.com" in lower:
        return QRContent(raw_data=s, qr_type="payment")

    # vCard
    if lower.startswith("begin:vcard"):
        return QRContent(raw_data=s, qr_type="vcard")

    # Fallback: if it contains spaces or full sentences, treat as text
    if " " in s or len(s.splitlines()) > 1:
        return QRContent(raw_data=s, qr_type="text")

    # Unknown data
    return QRContent(raw_data=s, qr_type="unknown")


# -------------------------------------------------------------------
# CONTENT RISK ANALYSIS (RE-USE EXISTING ENGINES)
# -------------------------------------------------------------------

def analyze_qr_payload(content: QRContent) -> Dict[str, Any]:
    """
    Feed decoded QR payload into the right existing scanner (URL / text).
    Returns a normalized dict:

    {
        "qr_type": "url" | "wifi" | ...,
        "raw_data": "...",
        "normalized": "...",
        "content_score": int,
        "content_verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "UNKNOWN",
        "content_reasons": [...],
        "content_category": "url" | "text" | "none"
    }
    """
    base = {
        "qr_type": content.qr_type,
        "raw_data": content.raw_data,
        "normalized": content.normalized,
        "content_score": 0,
        "content_verdict": "UNKNOWN",
        "content_reasons": [],
        "content_category": "none",
    }

    if content.qr_type == "url" and content.normalized:
        raw = analyze_url(content.normalized)
        score = int(raw.get("score", 0))
        verdict = "SAFE"
        if score >= 30:
            verdict = "DANGEROUS"
        elif score >= 10:
            verdict = "SUSPICIOUS"

        base.update(
            {
                "content_score": score,
                "content_verdict": verdict,
                "content_reasons": raw.get("reasons", []),
                "content_category": "url",
            }
        )

    elif content.qr_type in ("text", "payment", "crypto", "wifi"):
        # You could specialise later; for now treat as text.
        raw = analyze_text(content.raw_data)
        score = int(raw.get("score", 0))
        verdict = "SAFE"
        if score >= 30:
            verdict = "DANGEROUS"
        elif score >= 10:
            verdict = "SUSPICIOUS"

        base.update(
            {
                "content_score": score,
                "content_verdict": verdict,
                "content_reasons": raw.get("reasons", []),
                "content_category": "text",
            }
        )

    return base