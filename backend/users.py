# backend/users.py

from __future__ import annotations
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import json
import time
import secrets
import hashlib

USERS_FILE = Path("analytics/users.json")
SCAN_LOG_FILE = Path("analytics/scan_logs.json")

DEFAULT_FREE_DAILY_LIMIT = 8  # tweakable


# -------------------------------------------------------------------
# JSON helpers
# -------------------------------------------------------------------
def _ensure_files():
    if not USERS_FILE.exists():
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        USERS_FILE.write_text("[]")
    if not SCAN_LOG_FILE.exists():
        SCAN_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        SCAN_LOG_FILE.write_text("[]")


def _load_users() -> List[Dict[str, Any]]:
    _ensure_files()
    return json.loads(USERS_FILE.read_text() or "[]")


def _save_users(users: List[Dict[str, Any]]) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=4))


def _load_logs() -> List[Dict[str, Any]]:
    _ensure_files()
    return json.loads(SCAN_LOG_FILE.read_text() or "[]")


def _save_logs(logs: List[Dict[str, Any]]) -> None:
    SCAN_LOG_FILE.write_text(json.dumps(logs, indent=4))


# -------------------------------------------------------------------
# Password hashing (PBKDF2-SHA256)
# -------------------------------------------------------------------
def _hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    )
    return dk.hex()


def _strip_sensitive(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user["id"],
        "email": user["email"],
        "plan": user.get("plan", "free"),
        "created_at": user.get("created_at"),
        "last_login": user.get("last_login"),
        "daily_scan_date": user.get("daily_scan_date", ""),
        "daily_scan_count": user.get("daily_scan_count", 0),
        "daily_limit": user.get("daily_limit", DEFAULT_FREE_DAILY_LIMIT),
    }


# -------------------------------------------------------------------
# User CRUD
# -------------------------------------------------------------------
def find_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    users = _load_users()
    email_lower = email.lower()
    for u in users:
        if u["email"].lower() == email_lower:
            return _strip_sensitive(u)
    return None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    users = _load_users()
    for u in users:
        if u["id"] == user_id:
            return _strip_sensitive(u)
    return None


def create_user(email: str, password: str) -> Dict[str, Any]:
    users = _load_users()
    email_lower = email.lower()

    if any(u["email"].lower() == email_lower for u in users):
        raise ValueError("Email already registered.")

    now = int(time.time())
    user_id = secrets.token_hex(12)
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)

    user = {
        "id": user_id,
        "email": email_lower,
        "password_hash": pw_hash,
        "salt": salt,
        "plan": "free",
        "created_at": now,
        "last_login": now,
        "daily_scan_date": "",
        "daily_scan_count": 0,
        "daily_limit": DEFAULT_FREE_DAILY_LIMIT,
    }

    users.append(user)
    _save_users(users)
    return _strip_sensitive(user)


def verify_user_credentials(email: str, password: str) -> Optional[Dict[str, Any]]:
    users = _load_users()
    email_lower = email.lower()
    changed = False
    user_out: Optional[Dict[str, Any]] = None

    for u in users:
        if u["email"].lower() == email_lower:
            candidate_hash = _hash_password(password, u["salt"])
            if candidate_hash != u["password_hash"]:
                return None
            u["last_login"] = int(time.time())
            changed = True
            user_out = _strip_sensitive(u)
            break

    if changed:
        _save_users(users)

    return user_out


def update_user_plan_by_email(email: str, plan: str) -> Optional[Dict[str, Any]]:
    users = _load_users()
    email_lower = email.lower()
    changed = False
    updated_user: Optional[Dict[str, Any]] = None

    for u in users:
        if u["email"].lower() == email_lower:
            u["plan"] = plan
            if plan == "premium":
                u["daily_limit"] = 999999
            else:
                u["daily_limit"] = DEFAULT_FREE_DAILY_LIMIT
            changed = True
            updated_user = _strip_sensitive(u)
            break

    if changed:
        _save_users(users)

    return updated_user


# -------------------------------------------------------------------
# Scan limits
# -------------------------------------------------------------------
def register_scan_attempt(user_id: str) -> Tuple[bool, int, int]:
    """
    Increment today's scan counter.

    Returns (allowed, remaining, limit).
    For premium: remaining/limit = -1.
    """
    users = _load_users()
    today = time.strftime("%Y-%m-%d")
    changed = False
    allowed = False
    remaining = 0
    limit = DEFAULT_FREE_DAILY_LIMIT

    for u in users:
        if u["id"] != user_id:
            continue

        if u.get("daily_scan_date") != today:
            u["daily_scan_date"] = today
            u["daily_scan_count"] = 0
            changed = True

        plan = u.get("plan", "free")
        limit = u.get("daily_limit", DEFAULT_FREE_DAILY_LIMIT)

        # Premium unlimited
        if plan == "premium":
            u["daily_scan_count"] = u.get("daily_scan_count", 0) + 1
            allowed = True
            remaining = -1
            limit = -1
            changed = True
            break

        used = u.get("daily_scan_count", 0)
        if used >= limit:
            allowed = False
            remaining = 0
            break

        u["daily_scan_count"] = used + 1
        remaining = max(limit - u["daily_scan_count"], 0)
        allowed = True
        changed = True
        break

    if changed:
        _save_users(users)

    return allowed, remaining, limit


# -------------------------------------------------------------------
# Scan history
# -------------------------------------------------------------------
def add_scan_log(
    user_id: Optional[str],
    category: str,
    mode: str,
    verdict: str,
    score: int,
    content_snippet: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    logs = _load_logs()
    logs.append(
        {
            "id": secrets.token_hex(10),
            "user_id": user_id,
            "timestamp": int(time.time()),
            "category": category,
            "mode": mode,
            "verdict": verdict,
            "score": int(score),
            "snippet": content_snippet[:280],
            "details": details or {},
        }
    )
    _save_logs(logs)


def get_scan_history_for_user(user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    logs = _load_logs()
    user_logs = [l for l in logs if l.get("user_id") == user_id]
    user_logs.sort(key=lambda x: x["timestamp"], reverse=True)
    return user_logs[:limit]