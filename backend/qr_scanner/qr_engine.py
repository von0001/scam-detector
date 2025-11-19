# backend/qr_scanner/qr_engine.py

"""
High-level engine for the QR Trap Scanner.

Entry point:
    analyze_qr_image(image_bytes: bytes) -> dict

This will be called from your FastAPI endpoint (/qr).
"""

from __future__ import annotations

from typing import Dict, Any, List

import numpy as np
import cv2

from .qr_utils import (
    load_image_bytes,
    pil_to_cv2,
    decode_qr_codes,
    classify_qr_data,
    analyze_qr_payload,
)
from .tamper_detect import analyze_single_qr_tamper, aggregate_tamper_scores


def analyze_qr_image(image_bytes: bytes) -> Dict[str, Any]:
    """
    Full pipeline:
    - Load bytes
    - Detect one or multiple QR codes
    - Decode + classify payloads
    - Analyze content risk (URL/text engines)
    - Analyze visual tampering
    - Return structured JSON

    Returns shape:

    {
      "qr_found": bool,
      "qr_count": int,
      "items": [
        {
          "index": 0,
          "raw_data": "...",
          "qr_type": "url",
          "normalized": "...",
          "content_score": int,
          "content_verdict": "...",
          "content_reasons": [...],
          "tamper_score": int,
          "tamper_flags": [...],
        },
        ...
      ],
      "overall": {
        "max_content_score": int,
        "max_tamper_score": int,
        "combined_risk_score": int,  # 0–100
        "combined_verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
      },
      "tampering_summary": {
        "overall_tamper_score": int,
        "overall_verdict": "LOW" | "MEDIUM" | "HIGH",
      },
    }
    """
    pil_img = load_image_bytes(image_bytes)
    img_bgr = pil_to_cv2(pil_img)

    qr_objs = decode_qr_codes(img_bgr)

    if not qr_objs:
        return {
            "qr_found": False,
            "qr_count": 0,
            "items": [],
            "overall": {
                "max_content_score": 0,
                "max_tamper_score": 0,
                "combined_risk_score": 0,
                "combined_verdict": "SAFE",
            },
            "tampering_summary": {
                "overall_tamper_score": 0,
                "overall_verdict": "SAFE",
            },
        }

    items: List[Dict[str, Any]] = []
    tamper_results: List[Dict[str, Any]] = []

    for idx, obj in enumerate(qr_objs):
        raw_data = obj["data"]
        rect = obj["rect"]

        classified = classify_qr_data(raw_data)
        content_analysis = analyze_qr_payload(classified)

        tamper = analyze_single_qr_tamper(img_bgr, rect)
        tamper_results.append(tamper)

        item = {
            "index": idx,
            "raw_data": raw_data,
            "qr_type": content_analysis["qr_type"],
            "normalized": content_analysis["normalized"],
            "content_score": content_analysis["content_score"],
            "content_verdict": content_analysis["content_verdict"],
            "content_reasons": content_analysis["content_reasons"],
            "content_category": content_analysis["content_category"],
            "tamper_score": tamper["tamper_score"],
            "tamper_flags": tamper["flags"],
            "rect": rect,
        }
        items.append(item)

    # Overall stats
    max_content_score = max(i["content_score"] for i in items)
    max_tamper_score = max(i["tamper_score"] for i in items)

    # Combine risk: 70% content risk, 30% tamper risk
    combined = int(
        min(
            100,
            (max_content_score / 40.0) * 70 + (max_tamper_score / 100.0) * 30,
        )
    )

    if combined >= 70:
        combined_verdict = "DANGEROUS"
    elif combined >= 30:
        combined_verdict = "SUSPICIOUS"
    else:
        combined_verdict = "SAFE"

    tampering_summary = aggregate_tamper_scores(tamper_results)

    return {
        "qr_found": True,
        "qr_count": len(items),
        "items": items,
        "overall": {
            "max_content_score": max_content_score,
            "max_tamper_score": max_tamper_score,
            "combined_risk_score": combined,
            "combined_verdict": combined_verdict,
        },
        "tampering_summary": tampering_summary,
    }