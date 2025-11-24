# backend/auth.py

from __future__ import annotations
import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Core secret for signing tokens (user + admin) — must be provided via env
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("FATAL: SECRET_KEY NOT SET or too short (32+ chars required).")

# Admin password/secret (for /admin login page) — no defaults
ADMIN_SECRET = os.getenv("ADMIN_SECRET")
if not ADMIN_SECRET or len(ADMIN_SECRET) < 32:
    raise RuntimeError("FATAL: ADMIN_SECRET NOT SET or too short (32+ chars required).")
ADMIN_PASSWORD = ADMIN_SECRET  # alias retained for existing imports

_admin_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="sd-admin-v1")
ADMIN_COOKIE_NAME = "sd_admin"
ADMIN_MAX_AGE = 60 * 60 * 4  # 4 hours


def create_admin_token() -> str:
    return _admin_serializer.dumps({"role": "admin"})


def verify_admin_token(token: str) -> bool:
    try:
        data = _admin_serializer.loads(token, max_age=ADMIN_MAX_AGE)
        return data.get("role") == "admin"
    except (BadSignature, SignatureExpired):
        return False
