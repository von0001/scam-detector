# backend/qr_scanner/qr_engine.py

import cv2
import json
import numpy as np
from typing import Dict, List, Any, Tuple

from ..url_scanner import analyze_url
from ..text_scanner import analyze_text
from .tamper_detect import analyze_tampering
from backend.utils.reason_cleaner import clean_reasons


# ---------------------------------------------------------
# QR DECODING
# ---------------------------------------------------------
def decode_qr_opencv(img: np.ndarray) -> List[Dict[str, Any]]:
    detector = cv2.QRCodeDetector()
    results = []

    # Try Multi QR
    try:
        ret, data, points, _ = detector.detectAndDecodeMulti(img)
    except Exception:
        ret, data, points = False, None, None

    if ret and data and points is not None:
        for i, txt in enumerate(data):
            if not txt:
                continue
            pts = points[i].astype(int).tolist()
            results.append({"data": txt.strip(), "points": pts})

        if results:
            return results

    # Single fallback
    try:
        txt, pts, _ = detector.detectAndDecode(img)
        if txt:
            polygon = pts.astype(int).tolist() if pts is not None else []
            results.append({"data": txt.strip(), "points": polygon})
    except Exception:
        pass

    return results


# ---------------------------------------------------------
# CLASSIFICATION
# ---------------------------------------------------------
def classify_qr_content(raw: str) -> Dict[str, Any]:
    raw_lower = raw.lower()
    routed_mode = "qr_internal"

    def log_item(payload: Dict[str, Any]) -> Dict[str, Any]:
        meta = {
            "qr_type": payload.get("qr_type"),
            "routed_mode": payload.get("routed_mode", routed_mode),
            "score": payload.get("score"),
            "verdict": payload.get("verdict"),
            "content_preview": (payload.get("content") or "")[:140],
        }
        try:
            print("[qr_classification]", json.dumps(meta))
        except Exception:
            pass
        return payload

    def base_score_to_verdict(score: int) -> str:
        return "DANGEROUS" if score >= 30 else "SUSPICIOUS" if score >= 10 else "SAFE"

    def combine_with_url_engine(url: str) -> Tuple[int, str, list]:
        url_result = analyze_url(url)
        url_score = int(url_result.get("score", 0))
        url_verdict = base_score_to_verdict(url_score)
        reasons = clean_reasons(url_result.get("reasons", []))
        reasons.insert(0, "QR-derived URL detected and analyzed using URL Security Engine.")
        return url_score, url_verdict, reasons

    # URL QR
    if raw_lower.startswith(("http://", "https://", "www.")):
        url = raw if raw.startswith("http") else "https://" + raw
        score, verdict, reasons = combine_with_url_engine(url)
        classification = {
            "qr_type": "url",
            "routed_mode": "url_scan",
            "content": url,
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
        }
        return log_item(classification)

    # App download / deep link
    app_indicators = [
        ".apk",
        "itms-services://",
        "apps.apple.com/",
        "play.google.com/",
        "app.link",
        "deeplink=",
    ]
    if any(ind in raw_lower for ind in app_indicators):
        score = 25
        classification = {
            "qr_type": "app_download",
            "routed_mode": "qr_internal",
            "content": raw,
            "score": score,
            "verdict": base_score_to_verdict(score),
            "reasons": clean_reasons(["App download / deep link detected from QR."]),
        }
        return log_item(classification)

    # WiFi QR
    if raw_lower.startswith("wifi:"):
        classification = {
            "qr_type": "wifi",
            "routed_mode": "qr_internal",
            "content": raw,
            "score": 20,
            "verdict": "SUSPICIOUS",
            "reasons": clean_reasons(["WiFi QR"]),
        }
        return log_item(classification)

    # Crypto
    if any(raw_lower.startswith(prefix) for prefix in ["btc:", "eth:", "usdt:", "xmr:"]):
        classification = {
            "qr_type": "crypto",
            "routed_mode": "qr_internal",
            "content": raw,
            "score": 40,
            "verdict": "DANGEROUS",
            "reasons": clean_reasons(["Crypto payment QR"]),
        }
        return log_item(classification)

    # Payment style
    if "$" in raw_lower or "cash.app" in raw_lower or "paypal.me" in raw_lower:
        classification = {
            "qr_type": "payment",
            "routed_mode": "qr_internal",
            "content": raw,
            "score": 30,
            "verdict": "SUSPICIOUS",
            "reasons": clean_reasons(["Payment QR code could be fraudulent"]),
        }
        return log_item(classification)

    # vCard
    if raw_lower.startswith("begin:vcard"):
        classification = {
            "qr_type": "vcard",
            "routed_mode": "qr_internal",
            "content": raw,
            "score": 10,
            "verdict": "SAFE",
            "reasons": clean_reasons(["vCard contact QR detected."]),
        }
        return log_item(classification)

    # Fallback – treat as text
    result = analyze_text(raw)
    score = int(result.get("score", 0))
    verdict = base_score_to_verdict(score)
    reasons = clean_reasons(result.get("reasons", []))
    if "http" in raw_lower or "www." in raw_lower:
        reasons.insert(0, "Text QR contains URL-like patterns. Treat with caution.")

    classification = {
        "qr_type": "text",
        "routed_mode": "qr_internal",
        "content": raw,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }
    return log_item(classification)


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
            "overall": {"combined_risk_score": 0, "combined_verdict": "SAFE"},
        }

    qrs = decode_qr_opencv(img)
    if not qrs:
        return {
            "qr_found": False,
            "count": 0,
            "items": [],
            "tampering": {},
            "overall": {"combined_risk_score": 0, "combined_verdict": "SAFE"},
        }

    tamper = analyze_tampering(img, qrs)

    items = []
    scores = []
    logs = []
    for qr in qrs:
        classified = classify_qr_content(qr["data"])
        classified["points"] = qr["points"]
        items.append(classified)
        scores.append(classified["score"])
        try:
            logs.append(
                {
                    "qr_type": classified.get("qr_type"),
                    "routed_mode": classified.get("routed_mode"),
                    "score": classified.get("score"),
                    "verdict": classified.get("verdict"),
                    "content_preview": (classified.get("content") or "")[:120],
                }
            )
        except Exception:
            pass

    avg_score = sum(scores) / len(scores)
    verdict = "DANGEROUS" if avg_score >= 30 else "SUSPICIOUS" if avg_score >= 10 else "SAFE"

    try:
        print(
            "[qr_gateway_log]",
            json.dumps({"items": logs, "combined_score": avg_score, "combined_verdict": verdict}),
        )
    except Exception:
        pass

    return {
        "qr_found": True,
        "count": len(items),
        "items": items,
        "tampering": tamper,
        "overall": {
            "combined_risk_score": int(avg_score),
            "combined_verdict": verdict,
        },
    }
