# backend/auth.py

"""
Railway-Safe Authentication System
- No bcrypt (Railway can't compile it)
- Uses SHA256 hashing (secure + lightweight)
- Uses itsdangerous for signed session cookies
- Drop-in replacement for your old auth system
"""

import hashlib
import os
from itsdangerous import URLSafeTimedSerializer

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "super_secret_key_change_me_123456789!!!!"
)

COOKIE_NAME = "admin_session"

# Admin password (plaintext in env variable)
PLAINTEXT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")


# ---------------------------------------------------------
# HASHING
# ---------------------------------------------------------

def _hash_password(pw: str) -> str:
    """Generate a SHA256 hash for the password."""
    return hashlib.sha256(pw.encode()).hexdigest()


ADMIN_PASSWORD_HASH = _hash_password(PLAINTEXT_ADMIN_PASSWORD)


# ---------------------------------------------------------
# COOKIE SIGNER
# ---------------------------------------------------------

serializer = URLSafeTimedSerializer(SECRET_KEY)


# ---------------------------------------------------------
# AUTH FUNCTIONS
# ---------------------------------------------------------

def verify_password(password: str) -> bool:
    """Check a plaintext password against the stored SHA256 hash."""
    return _hash_password(password) == ADMIN_PASSWORD_HASH


def create_session() -> str:
    """Create a new signed session cookie."""
    return serializer.dumps({"user": "admin"})


def verify_session(cookie_value: str) -> bool:
    """Verify signed cookie and expiration."""
    try:
        data = serializer.loads(cookie_value, max_age=86400)  # 24 hours
        return data.get("user") == "admin"
    except Exception:
        return False