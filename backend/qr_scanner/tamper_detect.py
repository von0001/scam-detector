# backend/qr_scanner/tamper_detect.py

"""
Computer-vision heuristics to detect visually tampered QR codes.

We look for:
- Hard rectangular boundaries with sharp contrast vs surrounding region
- Edge-density spikes around the QR border (indicates sticker edges)
- Blur / shadow mismatch between QR patch and background

Outputs:
- tamper_score: 0–100
- flags: list of human-readable signals
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import cv2
import numpy as np
from typing import Any


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
) -> Dict[str, object]:
    """
    Analyze a single QR bounding box for tampering.

    Returns:
    {
        "tamper_score": int (0–100),
        "flags": [str, ...]
    }
    """
    flags: List[str] = []
    score = 0

    if img_bgr.size == 0:
        return {"tamper_score": 0, "flags": ["Invalid image for tamper detection."]}

    region = _clip_rect(img_bgr, rect, pad=8)
    if region.size == 0:
        return {"tamper_score": 0, "flags": ["QR region out of bounds."]}

    gray = cv2.cvtColor(region, cv2.COLOR_BGR2GRAY)

    # --- 1. Edge-density vs immediate surround -----------------
    edges = cv2.Canny(gray, 80, 200)
    inner_density = np.count_nonzero(edges) / (edges.size + 1e-9)

    # Build slightly larger context window
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
        flags.append("QR edge density much higher than surroundings (sticker edge pattern).")

    # --- 2. Contrast / brightness jump -------------------------
    qr_mean = float(gray.mean())
    ctx_mean = float(context_gray.mean())
    delta_brightness = abs(qr_mean - ctx_mean)

    if delta_brightness > 35:
        score += 15
        flags.append("QR brightness/contrast sharply different from background (overlay suspicion).")

    # --- 3. Blur mismatch (printed sticker on glossy surface) --
    qr_blur = _laplacian_blur(gray)
    ctx_blur = _laplacian_blur(context_gray)

    if ctx_blur < 20 and qr_blur > 45:
        # Background soft, QR very sharp
        score += 10
        flags.append("QR is much sharper than background (possible sticker).")
    elif ctx_blur > 45 and qr_blur < 20:
        # Background sharp, QR soft / smudged
        score += 8
        flags.append("QR is blurrier than environment (low-quality sticker).")

    # --- 4. Hard rectangular border line detection -------------
    # Look for strong straight lines around region perimeter
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
        flags.append("Strong rectangular border detected around QR (sticker border).")

    # Clamp and map to 0–100
    score = int(max(0, min(score, 100)))
    return {"tamper_score": score, "flags": flags}


def aggregate_tamper_scores(results: List[Dict[str, object]]) -> Dict[str, object]:
    """
    Compute an overall tampering verdict for all QR codes in an image.
    """
    if not results:
        return {"overall_tamper_score": 0, "overall_verdict": "SAFE"}

    scores = [r.get("tamper_score", 0) for r in results]
    avg = float(sum(scores)) / max(len(scores), 1)

    if avg >= 60:
        verdict = "HIGH"
    elif avg >= 30:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return {
        "overall_tamper_score": int(avg),
        "overall_verdict": verdict,
    }

def analyze_tampering(img_bgr: np.ndarray, qrs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Entry point used by qr_engine.py.

    Runs tamper detection on every QR bounding box and aggregates results.
    """
    per_qr = []

    for qr in qrs:
        # qr from OpenCV has "points", NOT rect. We convert points → rect box.
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

    return {
        "per_qr": per_qr,
        "summary": summary
    }