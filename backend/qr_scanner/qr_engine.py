import cv2
import numpy as np
from typing import Dict, List, Any

from ..url_scanner import analyze_url
from ..text_scanner import analyze_text
from .tamper_detect import analyze_tampering


# ---------------------------------------------------------
# QR DECODING
# ---------------------------------------------------------
def decode_qr_opencv(img: np.ndarray) -> List[Dict[str, Any]]:
    detector = cv2.QRCodeDetector()
    results = []

    # ---- Try Multi QR (correct unpack) ----
    try:
        ret, data, points, _ = detector.detectAndDecodeMulti(img)
    except Exception:
        ret, data, points = False, None, None

    if ret and data and points is not None:
        for i, txt in enumerate(data):
            if not txt:
                continue
            pts = points[i].astype(int).tolist()
            results.append({
                "data": txt.strip(),
                "points": pts
            })
        if results:
            return results

    # ---- Single QR Fallback ----
    try:
        txt, pts, _ = detector.detectAndDecode(img)
        if txt:
            polygon = pts.astype(int).tolist() if pts is not None else []
            results.append({
                "data": txt.strip(),
                "points": polygon
            })
    except Exception:
        pass

    return results


# ---------------------------------------------------------
# CLASSIFICATION
# ---------------------------------------------------------
def classify_qr_content(raw: str) -> Dict[str, Any]:
    raw_lower = raw.lower()

    # URL
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
        }

    # WiFi
    if raw_lower.startswith("wifi:"):
        return {
            "qr_type": "wifi",
            "content": raw,
            "score": 20,
            "verdict": "SUSPICIOUS",
            "reasons": ["WiFi QR codes may attempt network hijacking."],
        }

    # Crypto
    if any(raw_lower.startswith(prefix) for prefix in ["btc:", "eth:", "usdt:", "xmr:"]):
        return {
            "qr_type": "crypto",
            "content": raw,
            "score": 40,
            "verdict": "DANGEROUS",
            "reasons": ["Crypto payment QR common in scams."],
        }

    # Payment
    if "$" in raw_lower or "cash.app" in raw_lower or "paypal.me" in raw_lower:
        return {
            "qr_type": "payment",
            "content": raw,
            "score": 30,
            "verdict": "SUSPICIOUS",
            "reasons": ["Payment QR code could be fraudulent."],
        }

    # vCard
    if raw_lower.startswith("begin:vcard"):
        return {
            "qr_type": "vcard",
            "content": raw,
            "score": 10,
            "verdict": "SAFE",
            "reasons": ["vCard contact QR detected."],
        }

    # Fallback to text analysis
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
    }


# ---------------------------------------------------------
# MAIN ENTRY
# ---------------------------------------------------------
def process_qr_image(image_bytes: bytes) -> Dict[str, Any]:
    np_arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    if img is None:
        return {
            "qr_found": False,
            "count": 0,
            "items": [],
            "tampering": {},
            "overall": {
                "combined_risk_score": 0,
                "combined_verdict": "SAFE",
            }
        }

    # 1. Decode
    qrs = decode_qr_opencv(img)
    if not qrs:
        return {
            "qr_found": False,
            "count": 0,
            "items": [],
            "tampering": {},
            "overall": {
                "combined_risk_score": 0,
                "combined_verdict": "SAFE",
            }
        }

    # 2. Tampering analysis
    tamper = analyze_tampering(img, qrs)

    # 3. Analyze content
    items = []
    scores = []
    for qr in qrs:
        raw = qr["data"]
        classified = classify_qr_content(raw)
        classified["points"] = qr["points"]
        items.append(classified)
        scores.append(classified["score"])

    # 4. Combined risk
    avg_score = sum(scores) / len(scores)

    overall_verdict = (
        "DANGEROUS" if avg_score >= 30 else
        "SUSPICIOUS" if avg_score >= 10 else
        "SAFE"
    )

    return {
        "qr_found": True,
        "count": len(items),
        "items": items,
        "tampering": tamper,
        "overall": {
            "combined_risk_score": int(avg_score),
            "combined_verdict": overall_verdict,
        }
    }