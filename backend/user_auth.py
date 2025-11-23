# backend/user_auth.py

from __future__ import annotations
from typing import Optional, Dict, Any
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from backend.auth import SECRET_KEY

USER_ACCESS_COOKIE = "sd_access"
USER_REFRESH_COOKIE = "sd_refresh"

ACCESS_TOKEN_MAX_AGE = 60 * 60           # 1 hour
REFRESH_TOKEN_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

_access_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="user-access-v1")
_refresh_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="user-refresh-v1")


def create_access_token(user: Dict[str, Any]) -> str:
    return _access_serializer.dumps(
        {
            "uid": user["id"],
            "plan": user.get("plan", "free"),
        }
    )


def create_refresh_token(user: Dict[str, Any]) -> str:
    return _refresh_serializer.dumps({"uid": user["id"]})


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return _access_serializer.loads(token, max_age=ACCESS_TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return _refresh_serializer.loads(token, max_age=REFRESH_TOKEN_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None