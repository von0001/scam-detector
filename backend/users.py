# backend/users.py

from __future__ import annotations

from typing import List, Dict, Any, Optional, Tuple
from collections import Counter
from datetime import datetime, date, timezone
import uuid
import os

import bcrypt
from psycopg2.extras import Json

from backend.db import get_cursor, init_db

DEFAULT_FREE_DAILY_LIMIT = 8
OWNER_EMAIL = (os.getenv("OWNER_EMAIL") or os.getenv("ADMIN_EMAIL") or "").lower()

# Ensure tables exist on import
init_db()


def _to_epoch(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp())
    return None


def _date_str(value: Any) -> str:
    if isinstance(value, date):
        return value.isoformat()
    return ""


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def _normalize_plan(plan: str) -> str:
    return "premium" if plan == "premium" else "free"


def _normalize_billing_cycle(cycle: Optional[str]) -> str:
    allowed = {"monthly", "yearly", "none"}
    return cycle if cycle in allowed else "none"


def _normalize_status(status: Optional[str]) -> str:
    allowed = {"active", "canceled", "inactive"}
    return status if status in allowed else "inactive"


def _daily_limit_for_plan(plan: str) -> int:
    return 999_999 if plan == "premium" else DEFAULT_FREE_DAILY_LIMIT


def _strip_sensitive(row: Dict[str, Any]) -> Dict[str, Any]:
    plan = row.get("plan", "free")
    return {
        "id": str(row["id"]),
        "email": row["email"].lower(),
        "plan": plan,
        "auth_method": row.get("auth_method", "password"),
        "created_at": _to_epoch(row.get("created_at")),
        "last_login": _to_epoch(row.get("last_login")),
        "daily_scan_date": _date_str(row.get("daily_scan_date")),
        "daily_scan_count": row.get("daily_scan_count", 0),
        "daily_limit": row.get("daily_limit", DEFAULT_FREE_DAILY_LIMIT),
        "billing_cycle": row.get("billing_cycle", "none"),
        "subscription_status": row.get("subscription_status", "inactive"),
        "subscription_renewal": _to_epoch(row.get("subscription_renewal")),
        "last_plan_change": _to_epoch(row.get("last_plan_change")),
        "stripe_customer_id": row.get("stripe_customer_id"),
        "stripe_subscription_id": row.get("stripe_subscription_id"),
        "is_admin": bool(row.get("is_admin")),
    }


def _is_owner_email(email: str) -> bool:
    return bool(OWNER_EMAIL) and email.lower() == OWNER_EMAIL


def find_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT * FROM users WHERE lower(email) = lower(%s) LIMIT 1",
            (email,),
        )
        row = cur.fetchone()
    return _ensure_owner_row(row)


def _get_user_for_update(query: str, params: tuple) -> Optional[Dict[str, Any]]:
    with get_cursor() as (_, cur):
        cur.execute(query + " FOR UPDATE", params)
        return cur.fetchone()


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    with get_cursor() as (_, cur):
        cur.execute("SELECT * FROM users WHERE id = %s LIMIT 1", (user_id,))
        row = cur.fetchone()
    return _ensure_owner_row(row)


def _ensure_owner_row(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    if not _is_owner_email(row.get("email", "")):
        return _strip_sensitive(row)

    if row.get("is_admin") and row.get("plan") == "premium":
        return _strip_sensitive(row)

    return _apply_plan_update(
        row,
        plan="premium",
        billing_cycle="owner",
        status="active",
        renewal=row.get("subscription_renewal"),
        stripe_customer_id=row.get("stripe_customer_id"),
        stripe_subscription_id=row.get("stripe_subscription_id"),
        is_admin=True,
    )


def create_user(email: str, password: str) -> Dict[str, Any]:
    email_lower = email.lower()
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
        "utf-8"
    )
    now = datetime.now(timezone.utc)
    user_id = uuid.uuid4()
    owner_flag = _is_owner_email(email_lower)

    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT 1 FROM users WHERE lower(email) = lower(%s) LIMIT 1",
            (email_lower,),
        )
        if cur.fetchone():
            raise ValueError("Email already registered.")

        cur.execute(
            """
            INSERT INTO users (
                id, email, password_hash, plan, auth_method, created_at, last_login,
                daily_scan_date, daily_scan_count, daily_limit, billing_cycle,
                subscription_status, subscription_renewal, last_plan_change,
                stripe_customer_id, stripe_subscription_id, is_admin
            )
            VALUES (
                %s, %s, %s, %s, 'password', %s, %s,
                NULL, 0, %s, %s,
                %s, NULL, %s,
                NULL, NULL, %s
            )
            RETURNING *;
            """,
            (
                str(user_id),
                email_lower,
                password_hash,
                "premium" if owner_flag else "free",
                now,
                now,
                999_999 if owner_flag else DEFAULT_FREE_DAILY_LIMIT,
                "owner" if owner_flag else "none",
                "active" if owner_flag else "inactive",
                now,
                owner_flag,
            ),
        )
        row = cur.fetchone()

    return _ensure_owner_row(row)


def get_or_create_google_user(email: str, google_sub: str) -> Dict[str, Any]:
    email_lower = email.lower()
    now = datetime.now(timezone.utc)
    owner_flag = _is_owner_email(email_lower)

    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT * FROM users WHERE google_sub = %s LIMIT 1",
            (google_sub,),
        )
        row = cur.fetchone()
        if row:
            cur.execute(
                """
                UPDATE users
                SET last_login = %s,
                    is_admin = %s,
                    plan = CASE WHEN %s THEN 'premium' ELSE plan END,
                    billing_cycle = CASE WHEN %s THEN 'owner' ELSE billing_cycle END,
                    subscription_status = CASE WHEN %s THEN 'active' ELSE subscription_status END,
                    daily_limit = CASE WHEN %s THEN 999999 ELSE daily_limit END
                WHERE id = %s
                RETURNING *;
                """,
                (
                    now,
                    owner_flag or row.get("is_admin"),
                    owner_flag,
                    owner_flag,
                    owner_flag,
                    owner_flag,
                    row["id"],
                ),
            )
            return _ensure_owner_row(cur.fetchone())

        cur.execute(
            "SELECT * FROM users WHERE lower(email) = lower(%s) LIMIT 1",
            (email_lower,),
        )
        row = cur.fetchone()
        if row:
            method = row.get("auth_method") or "password"
            new_method = "mixed" if method == "password" else method
            cur.execute(
                """
                UPDATE users
                SET auth_method = %s,
                    google_sub = %s,
                    last_login = %s,
                    is_admin = %s,
                    plan = CASE WHEN %s THEN 'premium' ELSE plan END,
                    billing_cycle = CASE WHEN %s THEN 'owner' ELSE billing_cycle END,
                    subscription_status = CASE WHEN %s THEN 'active' ELSE subscription_status END,
                    daily_limit = CASE WHEN %s THEN 999999 ELSE daily_limit END
                WHERE id = %s
                RETURNING *;
                """,
                (
                    new_method,
                    google_sub,
                    now,
                    owner_flag or row.get("is_admin"),
                    owner_flag,
                    owner_flag,
                    owner_flag,
                    owner_flag,
                    row["id"],
                ),
            )
            return _ensure_owner_row(cur.fetchone())

        user_id = uuid.uuid4()
        cur.execute(
            """
            INSERT INTO users (
                id, email, plan, auth_method, google_sub, created_at, last_login,
                daily_scan_date, daily_scan_count, daily_limit, billing_cycle,
                subscription_status, subscription_renewal, last_plan_change,
                stripe_customer_id, stripe_subscription_id, is_admin
            )
            VALUES (
                %s, %s, %s, 'google', %s, %s, %s,
                NULL, 0, %s, %s,
                %s, NULL, %s,
                NULL, NULL, %s
            )
            RETURNING *;
            """,
            (
                str(user_id),
                email_lower,
                "premium" if owner_flag else "free",
                google_sub,
                now,
                now,
                999_999 if owner_flag else DEFAULT_FREE_DAILY_LIMIT,
                "owner" if owner_flag else "none",
                "active" if owner_flag else "inactive",
                now,
                owner_flag,
            ),
        )
        row = cur.fetchone()

    return _ensure_owner_row(row)


def verify_user_credentials(email: str, password: str) -> Optional[Dict[str, Any]]:
    email_lower = email.lower()
    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT * FROM users WHERE lower(email) = lower(%s) LIMIT 1",
            (email_lower,),
        )
        row = cur.fetchone()
        if not row or not row.get("password_hash"):
            return None

        stored_hash = row["password_hash"].encode("utf-8")
        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            return None

        now = datetime.now(timezone.utc)
        cur.execute(
            "UPDATE users SET last_login = %s WHERE id = %s RETURNING *",
            (now, row["id"]),
        )
        updated = cur.fetchone()

    return _ensure_owner_row(updated) if updated else None


def _apply_plan_update(
    row: Dict[str, Any],
    plan: str,
    billing_cycle: Optional[str],
    status: Optional[str],
    renewal: Optional[Any],
    stripe_customer_id: Optional[str],
    stripe_subscription_id: Optional[str],
    is_admin: Optional[bool] = None,
) -> Dict[str, Any]:
    desired_plan = _normalize_plan(plan)
    cycle = _normalize_billing_cycle(billing_cycle or row.get("billing_cycle"))
    sub_status = _normalize_status(status or row.get("subscription_status"))
    renewal_ts = _parse_timestamp(renewal if renewal is not None else row.get("subscription_renewal"))
    renewal_value = renewal_ts
    daily_limit = _daily_limit_for_plan(desired_plan)
    now = datetime.now(timezone.utc)

    with get_cursor() as (_, cur):
        cur.execute(
            """
            UPDATE users
            SET plan = %s,
                billing_cycle = %s,
                subscription_status = %s,
                subscription_renewal = %s,
                last_plan_change = %s,
                daily_limit = %s,
                is_admin = COALESCE(%s, is_admin),
                stripe_customer_id = COALESCE(%s, stripe_customer_id),
                stripe_subscription_id = COALESCE(%s, stripe_subscription_id)
            WHERE id = %s
            RETURNING *;
            """,
            (
                desired_plan,
                cycle,
                sub_status,
                renewal_value,
                now,
                daily_limit,
                is_admin,
                stripe_customer_id,
                stripe_subscription_id,
                row["id"],
            ),
        )
        updated = cur.fetchone()

    return _strip_sensitive(updated) if updated else None


def update_user_plan_by_email(
    email: str,
    plan: str,
    billing_cycle: Optional[str] = None,
    status: str = "active",
    renewal: Optional[int] = None,
    stripe_customer_id: Optional[str] = None,
    stripe_subscription_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    email_lower = email.lower()
    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT * FROM users WHERE lower(email) = lower(%s) FOR UPDATE",
            (email_lower,),
        )
        row = cur.fetchone()

    if not row:
        return None

    return _apply_plan_update(
        row,
        plan=plan,
        billing_cycle=billing_cycle,
        status=status,
        renewal=renewal,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=stripe_subscription_id,
    )


def update_user_plan(
    user_id: str,
    plan: str,
    billing_cycle: str = "none",
    status: str = "active",
    renewal: Optional[int] = None,
    stripe_customer_id: Optional[str] = None,
    stripe_subscription_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    row = _get_user_for_update("SELECT * FROM users WHERE id = %s", (user_id,))
    if not row:
        return None

    return _apply_plan_update(
        row,
        plan=plan,
        billing_cycle=billing_cycle,
        status=status,
        renewal=renewal,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=stripe_subscription_id,
    )


def register_scan_attempt(user_id: str) -> Tuple[bool, int, int]:
    today = date.today()
    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT * FROM users WHERE id = %s FOR UPDATE",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            return False, 0, DEFAULT_FREE_DAILY_LIMIT

        plan = row.get("plan", "free")
        limit = row.get("daily_limit") or DEFAULT_FREE_DAILY_LIMIT
        last_date = row.get("daily_scan_date")
        daily_count = row.get("daily_scan_count", 0)

        if last_date != today:
            daily_count = 0

        if plan == "premium":
            daily_count += 1
            remaining = -1
            new_limit = -1
            cur.execute(
                """
                UPDATE users
                SET daily_scan_date = %s,
                    daily_scan_count = %s
                WHERE id = %s
                """,
                (today, daily_count, user_id),
            )
            return True, remaining, new_limit

        if daily_count >= limit:
            cur.execute(
                "UPDATE users SET daily_scan_date = %s, daily_scan_count = %s WHERE id = %s",
                (today, daily_count, user_id),
            )
            return False, 0, limit

        daily_count += 1
        remaining = max(limit - daily_count, 0)
        cur.execute(
            "UPDATE users SET daily_scan_date = %s, daily_scan_count = %s WHERE id = %s",
            (today, daily_count, user_id),
        )
        return True, remaining, limit


def add_scan_log(
    user_id: Optional[str],
    category: str,
    mode: str,
    verdict: str,
    score: int,
    content_snippet: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    with get_cursor() as (_, cur):
        cur.execute(
            """
            INSERT INTO scan_logs (
                user_id, category, mode, verdict, score, snippet, details
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                category,
                mode,
                verdict,
                int(score),
                content_snippet[:280],
                Json(details or {}),
            ),
        )


def get_scan_history_for_user(user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    with get_cursor() as (_, cur):
        cur.execute(
            """
            SELECT id, user_id, timestamp, category, mode, verdict, score, snippet, details
            FROM scan_logs
            WHERE user_id = %s
            ORDER BY timestamp DESC
            LIMIT %s
            """,
            (user_id, limit),
        )
        rows = cur.fetchall() or []

    history: List[Dict[str, Any]] = []
    for row in rows:
        history.append(
            {
                "id": str(row["id"]),
                "user_id": row.get("user_id"),
                "timestamp": _to_epoch(row.get("timestamp")),
                "category": row.get("category"),
                "mode": row.get("mode"),
                "verdict": row.get("verdict"),
                "score": row.get("score"),
                "snippet": row.get("snippet"),
                "details": row.get("details") or {},
            }
        )
    return history


def change_password(user_id: str, current_password: str, new_password: str) -> bool:
    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT * FROM users WHERE id = %s FOR UPDATE",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            return False

        method = row.get("auth_method", "password")
        if method == "google" and not row.get("password_hash"):
            return False

        stored_hash = row.get("password_hash")
        if not stored_hash:
            return False

        if not bcrypt.checkpw(current_password.encode("utf-8"), stored_hash.encode("utf-8")):
            return False

        new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
        new_method = "password" if method == "password" else "mixed"

        cur.execute(
            """
            UPDATE users
            SET password_hash = %s,
                auth_method = %s
            WHERE id = %s
            """,
            (new_hash, new_method, user_id),
        )
    return True


def delete_user(user_id: str) -> bool:
    with get_cursor() as (_, cur):
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        deleted = cur.rowcount > 0
        if not deleted:
            return False
        cur.execute(
            "UPDATE scan_logs SET user_id = NULL WHERE user_id = %s",
            (user_id,),
        )
    return True


def _format_breakdown(counter: Counter) -> List[Dict[str, Any]]:
    if not counter:
        return []
    return [{"label": label, "count": count} for label, count in counter.most_common()]


def build_account_snapshot(user: Dict[str, Any], history_limit: int = 20) -> Dict[str, Any]:
    fresh_user = get_user_by_id(user["id"]) or user
    logs = get_scan_history_for_user(fresh_user["id"], limit=history_limit)

    verdict_counter: Counter = Counter()
    category_counter: Counter = Counter()
    flagged_logs: List[Dict[str, Any]] = []
    now_ts = int(datetime.now(timezone.utc).timestamp())

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
    activity_24h = sum(
        1
        for log in logs
        if log.get("timestamp") and now_ts - int(log["timestamp"]) <= 86_400
    )

    plan = fresh_user.get("plan", "free")
    daily_limit = fresh_user.get("daily_limit", DEFAULT_FREE_DAILY_LIMIT)
    daily_used = fresh_user.get("daily_scan_count", 0)
    if plan == "premium":
        daily_remaining = -1
    else:
        daily_remaining = max((daily_limit or DEFAULT_FREE_DAILY_LIMIT) - (daily_used or 0), 0)

    usage = {
        "plan": plan,
        "daily_limit": daily_limit,
        "daily_used": daily_used,
        "daily_remaining": daily_remaining,
        "last_reset_date": fresh_user.get("daily_scan_date", ""),
        "last_login": fresh_user.get("last_login"),
        "created_at": fresh_user.get("created_at"),
        "billing_cycle": fresh_user.get("billing_cycle", "none"),
        "subscription_status": fresh_user.get("subscription_status", "inactive"),
        "subscription_renewal": fresh_user.get("subscription_renewal"),
        "last_plan_change": fresh_user.get("last_plan_change"),
        "stripe_customer_id": fresh_user.get("stripe_customer_id"),
        "stripe_subscription_id": fresh_user.get("stripe_subscription_id"),
        "is_admin": fresh_user.get("is_admin", False),
    }

    stats = {
        "last_scan_ts": last_scan_ts,
        "activity_24h": activity_24h,
        "recent_total": len(logs),
        "verdict_breakdown": _format_breakdown(verdict_counter),
        "category_breakdown": _format_breakdown(category_counter),
    }

    return {
        "user": fresh_user,
        "usage": usage,
        "stats": stats,
        "recent_logs": logs,
        "flagged_logs": flagged_logs[:3],
    }
