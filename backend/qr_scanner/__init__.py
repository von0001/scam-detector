# backend/qr_scanner/__init__.py

"""
QR Trap Scanner package.

Exposes a high-level function:

    analyze_qr_image(image_bytes: bytes) -> dict

which:
- Detects one or more QR codes in an image
- Decodes contents (URL, WiFi, payment, vCard, raw text)
- Runs URL contents through your existing URL scanner
- Performs visual tampering checks around each QR region
- Returns a rich JSON structure with scores & reasoning
"""

from .qr_engine import analyze_qr_image