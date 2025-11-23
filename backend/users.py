# backend/users.py

from __future__ import annotations
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter
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
    raw = USERS_FILE.read_text() or "[]"
    return json.loads(raw)


def _save_users(users: List[Dict[str, Any]]) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=4))


def _load_logs() -> List[Dict[str, Any]]:
    _ensure_files()
    raw = SCAN_LOG_FILE.read_text() or "[]"
    return json.loads(raw)


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
        "auth_method": user.get("auth_method", "password"),
        "created_at": user.get("created_at"),
        "last_login": user.get("last_login"),
        "daily_scan_date": user.get("daily_scan_date", ""),
        "daily_scan_count": user.get("daily_scan_count", 0),
        "daily_limit": user.get("daily_limit", DEFAULT_FREE_DAILY_LIMIT),
        "billing_cycle": user.get("billing_cycle", "none"),
        "subscription_status": user.get("subscription_status", "inactive"),
        "last_plan_change": user.get("last_plan_change"),
        "subscription_renewal": user.get("subscription_renewal"),
    }


# -------------------------------------------------------------------
# User lookups
# -------------------------------------------------------------------
def find_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    users = _load_users()
    email_lower = email.lower()
    for u in users:
        if u["email"].lower() == email_lower:
            return _strip_sensitive(u)
    return None


def _find_user_record_by_email(email: str) -> Optional[Dict[str, Any]]:
    users = _load_users()
    email_lower = email.lower()
    for u in users:
        if u["email"].lower() == email_lower:
            return u
    return None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    users = _load_users()
    for u in users:
        if u["id"] == user_id:
            return _strip_sensitive(u)
    return None


# -------------------------------------------------------------------
# User creation
# -------------------------------------------------------------------
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
        "auth_method": "password",  # password | google | mixed
        "created_at": now,
        "last_login": now,
        "daily_scan_date": "",
        "daily_scan_count": 0,
        "daily_limit": DEFAULT_FREE_DAILY_LIMIT,
        "billing_cycle": "none",  # monthly | yearly | none
        "subscription_status": "inactive",  # active | canceled | inactive
        "subscription_renewal": None,
        "last_plan_change": now,
        "stripe_customer_id": None,
        "stripe_subscription_id": None,
    }

    users.append(user)
    _save_users(users)
    return _strip_sensitive(user)


def get_or_create_google_user(email: str, google_sub: str) -> Dict[str, Any]:
    """
    Used by Google Sign-In.
    If a user with this email exists:
      - if they were password-only, mark as 'mixed'
      - if they were google-only, reuse
    Otherwise create a new google-only account.
    """
    users = _load_users()
    email_lower = email.lower()
    now = int(time.time())

    # First try to match by google_sub
    for u in users:
        if u.get("google_sub") == google_sub:
            u["last_login"] = now
            if not u.get("plan"):
                u["plan"] = "free"
            if not u.get("auth_method"):
                u["auth_method"] = "google"
            if "billing_cycle" not in u:
                u["billing_cycle"] = "none"
            if "subscription_status" not in u:
                u["subscription_status"] = "inactive"
            if "subscription_renewal" not in u:
                u["subscription_renewal"] = None
            if "last_plan_change" not in u:
                u["last_plan_change"] = now
            _save_users(users)
            return _strip_sensitive(u)

    # Then by email
    for u in users:
        if u["email"].lower() == email_lower:
            # Existing account: upgrade auth_method
            method = u.get("auth_method") or "password"
            if method == "password":
                u["auth_method"] = "mixed"
            else:
                u["auth_method"] = method
            u["google_sub"] = google_sub
            u["last_login"] = now
            if not u.get("plan"):
                u["plan"] = "free"
            if "daily_limit" not in u:
                u["daily_limit"] = DEFAULT_FREE_DAILY_LIMIT
            if "billing_cycle" not in u:
                u["billing_cycle"] = "none"
            if "subscription_status" not in u:
                u["subscription_status"] = "inactive"
            if "subscription_renewal" not in u:
                u["subscription_renewal"] = None
            u["last_plan_change"] = now
            _save_users(users)
            return _strip_sensitive(u)

    # Brand new google-only account
    user_id = secrets.token_hex(12)
    user = {
        "id": user_id,
        "email": email_lower,
        "plan": "free",
        "auth_method": "google",
        "google_sub": google_sub,
        "created_at": now,
        "last_login": now,
        "daily_scan_date": "",
        "daily_scan_count": 0,
        "daily_limit": DEFAULT_FREE_DAILY_LIMIT,
        "billing_cycle": "none",
        "subscription_status": "inactive",
        "subscription_renewal": None,
        "last_plan_change": now,
        "stripe_customer_id": None,
        "stripe_subscription_id": None,
    }
    users.append(user)
    _save_users(users)
    return _strip_sensitive(user)


# -------------------------------------------------------------------
# Credentials
# -------------------------------------------------------------------
def verify_user_credentials(email: str, password: str) -> Optional[Dict[str, Any]]:
    users = _load_users()
    email_lower = email.lower()
    changed = False
    user_out: Optional[Dict[str, Any]] = None

    for u in users:
        if u["email"].lower() != email_lower:
            continue

        salt = u.get("salt")
        pw_hash = u.get("password_hash")
        if not salt or not pw_hash:
            # Google-only account has no local password
            return None

        candidate_hash = _hash_password(password, salt)
        if candidate_hash != pw_hash:
            return None

        u["last_login"] = int(time.time())
        changed = True
        user_out = _strip_sensitive(u)
        break

    if changed:
        _save_users(users)

    return user_out


def update_user_plan_by_email(
    email: str,
    plan: str,
    billing_cycle: Optional[str] = None,
    status: str = "active",
    renewal: Optional[int] = None,
    stripe_customer_id: Optional[str] = None,
    stripe_subscription_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Legacy helper used by webhook: update plan by email and reset limits.
    """
    users = _load_users()
    email_lower = email.lower()
    changed = False
    updated_user: Optional[Dict[str, Any]] = None

    for u in users:
        if u["email"].lower() == email_lower:
            updated_user = _set_plan(
                u,
                plan=plan,
                billing_cycle=billing_cycle or u.get("billing_cycle", "none"),
                status=status or u.get("subscription_status", "active"),
                renewal=renewal if renewal is not None else u.get("subscription_renewal"),
                stripe_customer_id=stripe_customer_id or u.get("stripe_customer_id"),
                stripe_subscription_id=stripe_subscription_id or u.get("stripe_subscription_id"),
            )
            changed = True
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
# Plan upgrades / downgrades
# -------------------------------------------------------------------
def _set_plan(
    user: Dict[str, Any],
    plan: str,
    billing_cycle: str = "none",
    status: str = "active",
    renewal: Optional[int] = None,
    stripe_customer_id: Optional[str] = None,
    stripe_subscription_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Mutate the user record with plan + billing info and return safe view.
    """
    plan = plan if plan in {"free", "premium"} else "free"
    billing_cycle = billing_cycle if billing_cycle in {"monthly", "yearly", "none"} else "none"
    status = status if status in {"active", "canceled", "inactive"} else "inactive"

    user["plan"] = plan
    user["billing_cycle"] = billing_cycle
    user["subscription_status"] = status
    user["subscription_renewal"] = renewal
    user["last_plan_change"] = int(time.time())
    if stripe_customer_id:
        user["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id:
        user["stripe_subscription_id"] = stripe_subscription_id

    if plan == "premium":
        user["daily_limit"] = 999_999
    else:
        user["daily_limit"] = DEFAULT_FREE_DAILY_LIMIT

    return _strip_sensitive(user)


def update_user_plan(
    user_id: str,
    plan: str,
    billing_cycle: str = "none",
    status: str = "active",
    renewal: Optional[int] = None,
    stripe_customer_id: Optional[str] = None,
    stripe_subscription_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Update a user plan by id (used for self-serve subscription changes).
    """
    users = _load_users()
    changed = False
    updated_user: Optional[Dict[str, Any]] = None

    for u in users:
        if u["id"] != user_id:
            continue
        updated_user = _set_plan(
            u,
            plan=plan,
            billing_cycle=billing_cycle,
            status=status,
            renewal=renewal,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
        )
        changed = True
        break

    if changed:
        _save_users(users)
    return updated_user


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


# -------------------------------------------------------------------
# Account management (security / deletion)
# -------------------------------------------------------------------
def change_password(user_id: str, current_password: str, new_password: str) -> bool:
    """
    Change password for a user if current_password is correct.
    Returns True on success, False on failure.
    """
    users = _load_users()
    changed = False

    for u in users:
        if u["id"] != user_id:
            continue

        # google-only account has no password_hash
        method = u.get("auth_method", "password")
        if method == "google" and not u.get("password_hash"):
            return False

        salt = u.get("salt")
        pw_hash = u.get("password_hash")
        if not salt or not pw_hash:
            return False

        candidate_hash = _hash_password(current_password, salt)
        if candidate_hash != pw_hash:
            return False

        new_salt = secrets.token_hex(16)
        u["salt"] = new_salt
        u["password_hash"] = _hash_password(new_password, new_salt)
        u["auth_method"] = "password" if method == "password" else "mixed"
        changed = True
        break

    if changed:
        _save_users(users)
    return changed


def delete_user(user_id: str) -> bool:
    """
    Hard-delete user record and anonymize their scan logs.
    """
    users = _load_users()
    new_users = [u for u in users if u["id"] != user_id]
    if len(new_users) == len(users):
        return False

    _save_users(new_users)

    logs = _load_logs()
    touched = False
    for log in logs:
        if log.get("user_id") == user_id:
            log["user_id"] = None
            touched = True
    if touched:
        _save_logs(logs)

    return True


def _format_breakdown(counter: Counter) -> List[Dict[str, Any]]:
    """
    Convert a Counter into a sorted list of {label, count} pairs.
    """
    if not counter:
        return []
    return [
        {"label": label, "count": count}
        for label, count in counter.most_common()
    ]


def build_account_snapshot(user: Dict[str, Any], history_limit: int = 20) -> Dict[str, Any]:
    """
    Build a richer account payload for the dashboard page with usage + log stats.
    """
    user_id = user["id"]
    logs = get_scan_history_for_user(user_id, limit=history_limit)

    verdict_counter: Counter = Counter()
    category_counter: Counter = Counter()
    flagged_logs: List[Dict[str, Any]] = []
    now = int(time.time())

    for log in logs:
        verdict = (log.get("verdict") or "UNKNOWN").upper()
        if verdict not in {"SAFE", "SUSPICIOUS", "DANGEROUS"}:
            verdict = "OTHER"
        verdict_counter[verdict] += 1

        category = log.get("category") or "unknown"
        category_counter[category] += 1

        if log.get("verdict") != "SAFE" and len(flagged_logs) < 5:
            flagged_logs.append(log)

    last_scan_ts = logs[0]["timestamp"] if logs else None
    activity_24h = sum(1 for log in logs if now - log.get("timestamp", 0) <= 86_400)

    plan = user.get("plan", "free")
    daily_limit = user.get("daily_limit", DEFAULT_FREE_DAILY_LIMIT)
    daily_used = user.get("daily_scan_count", 0)
    if plan == "premium":
        daily_remaining = -1
    else:
        limit_value = daily_limit if isinstance(daily_limit, int) else DEFAULT_FREE_DAILY_LIMIT
        used_value = daily_used if isinstance(daily_used, int) else 0
        daily_remaining = max(limit_value - used_value, 0)

    usage = {
        "plan": plan,
        "daily_limit": daily_limit,
        "daily_used": daily_used,
        "daily_remaining": daily_remaining,
        "last_reset_date": user.get("daily_scan_date", ""),
        "last_login": user.get("last_login"),
        "created_at": user.get("created_at"),
        "billing_cycle": user.get("billing_cycle", "none"),
        "subscription_status": user.get("subscription_status", "inactive"),
        "subscription_renewal": user.get("subscription_renewal"),
        "last_plan_change": user.get("last_plan_change"),
        "stripe_customer_id": user.get("stripe_customer_id"),
        "stripe_subscription_id": user.get("stripe_subscription_id"),
    }

    stats = {
        "last_scan_ts": last_scan_ts,
        "activity_24h": activity_24h,
        "recent_total": len(logs),
        "verdict_breakdown": _format_breakdown(verdict_counter),
        "category_breakdown": _format_breakdown(category_counter),
    }

    return {
        "user": user,
        "usage": usage,
        "stats": stats,
        "recent_logs": logs,
        "flagged_logs": flagged_logs[:3],
    }
