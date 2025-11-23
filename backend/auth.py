# backend/auth.py

from __future__ import annotations
import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Core secret for signing tokens (user + admin)
SECRET_KEY = os.getenv("APP_SECRET_KEY", "change-this-in-production")

# Admin password (for /admin login page)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "supersecret-admin-password")

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