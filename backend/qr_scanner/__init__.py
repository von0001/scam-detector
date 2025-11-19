# backend/qr_scanner/__init__.py

"""
QR Trap Scanner package.

Exposes:
    process_qr_image(image_bytes: bytes) -> dict
"""

from .qr_engine import process_qr_image