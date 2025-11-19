# backend/qr_scanner/tamper_detect.py

"""
Computer-vision heuristics to detect visually tampered QR codes.
"""

from __future__ import annotations
from typing import Dict, List, Any

import cv2
import numpy as np


def _clip_rect(img: np.ndarray, rect: Dict[str, int], pad: int = 6) -> np.ndarray:
    h, w = img.shape[:2]
    x = max(rect["x"] - pad, 0)
    y = max(rect["y"] - pad, 0)
    x2 = min(rect["x"] + rect["w"] + pad, w)
    y2 = min(rect["y"] + rect["h"] + pad, h)
    return img[y:y2, x:x2]


def _edge_density(gray: np.ndarray) -> float:
    edges = cv2.Canny(gray, 60, 150)
    return float(np.count_nonzero(edges)) / float(gray.size + 1e-9)


def _laplacian_blur(gray: np.ndarray) -> float:
    return float(cv2.Laplacian(gray, cv2.CV_64F).var())


def analyze_single_qr_tamper(
    img_bgr: np.ndarray,
    rect: Dict[str, int],
) -> Dict[str, Any]:

    flags: List[str] = []
    score = 0

    if img_bgr.size == 0:
        return {"tamper_score": 0, "flags": ["Invalid image for tamper detection."]}

    region = _clip_rect(img_bgr, rect, pad=8)
    if region.size == 0:
        return {"tamper_score": 0, "flags": ["QR region out of bounds."]}

    gray = cv2.cvtColor(region, cv2.COLOR_BGR2GRAY)

    # 1. Edge density
    edges = cv2.Canny(gray, 80, 200)
    inner_density = np.count_nonzero(edges) / (edges.size + 1e-9)

    context_rect = {
        "x": max(rect["x"] - 20, 0),
        "y": max(rect["y"] - 20, 0),
        "w": rect["w"] + 40,
        "h": rect["h"] + 40,
    }

    context = _clip_rect(img_bgr, context_rect, pad=0)
    context_gray = cv2.cvtColor(context, cv2.COLOR_BGR2GRAY)
    context_edges = cv2.Canny(context_gray, 80, 200)
    context_density = np.count_nonzero(context_edges) / (context_edges.size + 1e-9)

    if inner_density > context_density * 2.2:
        score += 15
        flags.append("QR edge density much higher than surroundings.")

    # 2. Brightness difference
    delta_brightness = abs(float(gray.mean()) - float(context_gray.mean()))
    if delta_brightness > 35:
        score += 15
        flags.append("QR brightness differs sharply from background.")

    # 3. Blur mismatch
    qr_blur = _laplacian_blur(gray)
    ctx_blur = _laplacian_blur(context_gray)

    if ctx_blur < 20 and qr_blur > 45:
        score += 10
        flags.append("QR is much sharper than background.")
    elif ctx_blur > 45 and qr_blur < 20:
        score += 8
        flags.append("QR is blurrier than environment.")

    # 4. Border detection
    lines = cv2.HoughLinesP(
        edges,
        rho=1,
        theta=np.pi / 180,
        threshold=40,
        minLineLength=min(rect["w"], rect["h"]) * 0.7,
        maxLineGap=8,
    )
    if lines is not None and len(lines) >= 4:
        score += 10
        flags.append("Rectangular border detected around QR.")

    score = int(max(0, min(score, 100)))
    return {"tamper_score": score, "flags": flags}


def aggregate_tamper_scores(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not results:
        return {"overall_tamper_score": 0, "overall_verdict": "SAFE"}

    scores = [r.get("tamper_score", 0) for r in results]
    avg = float(sum(scores)) / max(len(scores), 1)

    if avg >= 60:
        verdict = "HIGH"
    elif avg >= 30:
        verdict = "MEDIUM"
        verdict = "LOW"

    return {
        "overall_tamper_score": int(avg),
        "overall_verdict": verdict,
    }


def analyze_tampering(img_bgr: np.ndarray, qrs: List[Dict[str, Any]]) -> Dict[str, Any]:
    per_qr = []

    for qr in qrs:
        pts = qr.get("points")
        if pts and len(pts) == 4:
            xs = [p[0] for p in pts]
            ys = [p[1] for p in pts]

            rect = {
                "x": min(xs),
                "y": min(ys),
                "w": max(xs) - min(xs),
                "h": max(ys) - min(ys),
            }

            per_qr.append(analyze_single_qr_tamper(img_bgr, rect))
        else:
            per_qr.append({"tamper_score": 0, "flags": ["No bounding box detected."]})

    summary = aggregate_tamper_scores(per_qr)

    return {"per_qr": per_qr, "summary": summary}