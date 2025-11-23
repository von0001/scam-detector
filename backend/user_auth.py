# backend/user_auth.py

from __future__ import annotations

import datetime as _dt
from typing import Optional, Dict, Any

import jwt

from backend.auth import SECRET_KEY

USER_ACCESS_COOKIE = "sd_access"
USER_REFRESH_COOKIE = "sd_refresh"

ACCESS_TOKEN_MAX_AGE = 60 * 60  # 1 hour
REFRESH_TOKEN_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

_ALGORITHM = "HS256"


def _expiry(seconds: int) -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc) + _dt.timedelta(seconds=seconds)


def create_access_token(user: Dict[str, Any]) -> str:
    payload = {
        "uid": user["id"],
        "type": "access",
        "exp": _expiry(ACCESS_TOKEN_MAX_AGE),
        "iat": _dt.datetime.now(tz=_dt.timezone.utc),
    }
    # Include plan for convenience, but it is never trusted for authorization.
    payload["plan"] = user.get("plan", "free")
    payload["admin"] = bool(user.get("is_admin"))
    return jwt.encode(payload, SECRET_KEY, algorithm=_ALGORITHM)


def create_refresh_token(user: Dict[str, Any]) -> str:
    payload = {
        "uid": user["id"],
        "type": "refresh",
        "exp": _expiry(REFRESH_TOKEN_MAX_AGE),
        "iat": _dt.datetime.now(tz=_dt.timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=_ALGORITHM)


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[_ALGORITHM])
        if data.get("type") != "access":
            return None
        return data
    except jwt.PyJWTError:
        return None


def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[_ALGORITHM])
        if data.get("type") != "refresh":
            return None
        return data
    except jwt.PyJWTError:
        return None
