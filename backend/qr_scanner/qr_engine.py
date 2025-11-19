import cv2
import numpy as np
from typing import Dict, List, Any

from ..url_scanner import analyze_url
from ..text_scanner import analyze_text
from .tamper_detect import analyze_tampering


# ---------------------------------------------------------
# QR DECODING (OpenCV ONLY)
# ---------------------------------------------------------
def decode_qr_opencv(img: np.ndarray) -> List[Dict[str, Any]]:
    detector = cv2.QRCodeDetector()

    results = []

    # ---- Try Multi QR first ----
    try:
        data, points, _ = detector.detectAndDecodeMulti(img)
    except:
        data, points = None, None

    # If Multi works, use it
    if points is not None and data:
        for i, txt in enumerate(data):
            if not txt:
                continue
            pts = points[i].astype(int).tolist()
            results.append({
                "data": txt.strip(),
                "polygon": pts
            })
        if results:
            return results

    # ---- FALLBACK: Single QR detection ----
    try:
        txt, pts, _ = detector.detectAndDecode(img)
        if txt:
            polygon = pts.astype(int).tolist() if pts is not None else []
            results.append({
                "data": txt.strip(),
                "polygon": polygon
            })
    except:
        pass

    return results


# ---------------------------------------------------------
# CLASSIFICATION
# ---------------------------------------------------------
def classify_qr_content(raw: str) -> Dict[str, Any]:
    raw_lower = raw.lower()

    # ---- URL ----
    if raw_lower.startswith(("http://", "https://", "www.")):
        url = raw if raw.startswith("http") else "https://" + raw
        result = analyze_url(url)

        score = int(result.get("score", 0))
        verdict = (
            "DANGEROUS" if score >= 30 else
            "SUSPICIOUS" if score >= 10 else
            "SAFE"
        )

        return {
            "qr_type": "url",
            "content": url,
            "score": score,
            "verdict": verdict,
            "reasons": result.get("reasons", []),
            "analysis_type": "url",
        }

    # ---- WiFi ----
    if raw_lower.startswith("wifi:"):
        return {
            "qr_type": "wifi",
            "content": raw,
            "score": 20,
            "verdict": "SUSPICIOUS",
            "reasons": ["WiFi QR codes may attempt network hijacking."],
            "analysis_type": "text",
        }

    # ---- Crypto ----
    if any(raw_lower.startswith(prefix) for prefix in ["btc:", "eth:", "usdt:", "xmr:"]):
        return {
            "qr_type": "crypto",
            "content": raw,
            "score": 40,
            "verdict": "DANGEROUS",
            "reasons": ["Crypto payment QR common in scams."],
            "analysis_type": "text",
        }

    # ---- Payment ----
    if "$" in raw or "cash.app" in raw_lower or "paypal.me" in raw_lower:
        return {
            "qr_type": "payment",
            "content": raw,
            "score": 30,
            "verdict": "SUSPICIOUS",
            "reasons": ["Payment QR code could be fraudulent."],
            "analysis_type": "text",
        }

    # ---- vCard ----
    if raw_lower.startswith("begin:vcard"):
        return {
            "qr_type": "vcard",
            "content": raw,
            "score": 10,
            "verdict": "SAFE",
            "reasons": ["vCard contact QR detected."],
            "analysis_type": "text",
        }

    # ---- Fallback = text ----
    result = analyze_text(raw)
    score = int(result.get("score", 0))
    verdict = (
        "DANGEROUS" if score >= 30 else
        "SUSPICIOUS" if score >= 10 else
        "SAFE"
    )

    return {
        "qr_type": "text",
        "content": raw,
        "score": score,
        "verdict": verdict,
        "reasons": result.get("reasons", []),
        "analysis_type": "text",
    }


# ---------------------------------------------------------
# MAIN ENTRY — EXACT NAME REQUIRED BY main.py
# ---------------------------------------------------------
def process_qr_image(image_bytes: bytes) -> Dict[str, Any]:
    np_arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    if img is None:
        return {"qr_found": False, "error": "Could not decode image."}

    # 1. Decode
    qrs = decode_qr_opencv(img)
    if not qrs:
        return {"qr_found": False, "count": 0, "items": []}

    # 2. Tampering analysis
    tamper = analyze_tampering(img, qrs)

    # 3. Analyze results
    items = []
    for qr in qrs:
        raw = qr["data"]
        classified = classify_qr_content(raw)
        classified["polygon"] = qr["polygon"]
        items.append(classified)

    return {
        "qr_found": True,
        "count": len(items),
        "items": items,
        "tampering": tamper,
    }