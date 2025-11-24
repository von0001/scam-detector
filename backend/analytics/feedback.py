from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any, Dict, List, Sequence

from backend.db import get_cursor

RETENTION_DAYS = 90

CANONICAL_TAGS = [
    "Bug",
    "False Positive",
    "False Negative",
    "UI/UX Issue",
    "Performance Issue",
    "Feature Request",
    "Confusing Result",
]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().strip())


def _auto_tags(combined_text: str, expectation: str, context: Dict[str, Any], user_tags: List[str]) -> List[str]:
    text = _normalize(combined_text)
    inferred: set[str] = set(t for t in user_tags if t)
    keyword_map = {
        "bug": ["error", "broken", "crash", "fail", "issue", "not working"],
        "false positive": ["false alarm", "not scam"],
        "false negative": ["missed", "still scam", "did not catch"],
        "ui/ux issue": ["confusing", "layout", "hard to use"],
        "performance issue": ["slow", "lag", "timeout"],
        "feature request": ["should add", "wish", "feature"],
        "confusing result": ["uncertain", "why", "unclear"],
    }
    for tag, keywords in keyword_map.items():
        if any(kw in text for kw in keywords):
            inferred.add(tag.title())
    cleaned = []
    for tag in inferred:
        if tag.title() in CANONICAL_TAGS:
            cleaned.append(tag.title())
    return sorted(set(cleaned))


def _risk_impact(context: Dict[str, Any]) -> int:
    raw_score = context.get("risk_score") or context.get("score") or 0
    try:
        score = int(raw_score)
    except Exception:
        score = 0
    verdict = (context.get("verdict") or "").lower()
    base = 1
    if verdict == "dangerous":
        base = 3
    elif verdict == "suspicious":
        base = 2
    return max(base, min(4, (score // 25) + 1))


def add_feedback(
    *,
    what: str = "",
    expectation: str = "",
    confusion: str = "",
    frustration: int = 5,
    perfect: str = "",
    message: str = "",
    page: str = "",
    ip: str = "",
    user_agent: str = "",
    user_tags: List[str] | None = None,
    context: Dict[str, Any] | None = None,
    replay: Dict[str, Any] | None = None,
    email: str | None = None,
) -> Dict[str, Any]:
    now = int(time.time())
    user_tags = user_tags or []
    context = context or {}
    replay = replay or {}

    combined_text = " ".join([what or "", confusion or "", perfect or "", message or ""]).strip()
    auto_tags = _auto_tags(combined_text, expectation, context, user_tags)
    risk_impact = _risk_impact(context)
    priority = max(1, frustration) * max(1, risk_impact)
    record_id = str(uuid.uuid4())

    with get_cursor() as (_, cur):
        cur.execute(
            """
            INSERT INTO feedback (
                id, ts, email, message, combined_text, what, expectation, confusion,
                frustration, perfect, page, ip, user_agent, tags_user, tags_auto,
                priority, risk_impact, context, replay
            )
            VALUES (
                %s, to_timestamp(%s), %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb,
                %s, %s, %s::jsonb, %s::jsonb
            )
            RETURNING *
            """,
            (
                record_id,
                now,
                email,
                message or combined_text,
                combined_text,
                what,
                expectation or "unknown",
                confusion,
                frustration,
                perfect,
                page,
                ip,
                user_agent,
                json.dumps(sorted(set(user_tags))),
                json.dumps(auto_tags),
                priority,
                risk_impact,
                json.dumps(context),
                json.dumps(replay),
            ),
        )
        row = cur.fetchone()
    if now % 100 == 0:
        cleanup_old_feedback()
    return row or {}


def load_feedback(limit: int = 500) -> List[Dict[str, Any]]:
    with get_cursor() as (_, cur):
        cur.execute(
            """
            SELECT * FROM feedback
            ORDER BY ts DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall() or []
    return rows


def save_feedback(_: Sequence[Dict[str, Any]]) -> None:
    """No-op retained for compatibility; writes are handled via DB."""
    return None


def get_feedback_intel() -> Dict[str, Any]:
    with get_cursor() as (_, cur):
        cur.execute(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE expectation = 'no') AS expectation_no,
                COUNT(*) FILTER (WHERE expectation = 'yes') AS expectation_yes
            FROM feedback
            WHERE ts >= NOW() - INTERVAL '90 days'
            """
        )
        summary = cur.fetchone() or {}
        cur.execute(
            """
            SELECT tag, COUNT(*) as count FROM (
                SELECT jsonb_array_elements_text(tags_auto) AS tag FROM feedback
            ) t GROUP BY tag ORDER BY count DESC LIMIT 10;
            """
        )
        tags = cur.fetchall() or []
    return {"summary": summary, "top_tags": tags}


def add_changelog_link(feedback_id: str, link: str) -> Dict[str, Any] | None:
    with get_cursor() as (_, cur):
        cur.execute(
            """
            UPDATE feedback
            SET linked_changelog = array_append(COALESCE(linked_changelog, '{}'), %s)
            WHERE id = %s
            RETURNING *
            """,
            (link, feedback_id),
        )
        row = cur.fetchone()
    return row


def update_feedback_response(
    *,
    feedback_id: str,
    status: str | None = None,
    admin_response: str | None = None,
    developer_notes: str | None = None,
    tags: List[str] | None = None,
    changelog_links: List[str] | None = None,
) -> Dict[str, Any] | None:
    with get_cursor() as (_, cur):
        cur.execute(
            """
            UPDATE feedback
            SET status = COALESCE(%s, status),
                admin_response = COALESCE(%s, admin_response),
                developer_notes = COALESCE(%s, developer_notes),
                tags_admin = COALESCE(%s::jsonb, tags_admin),
                linked_changelog = COALESCE(%s, linked_changelog)
            WHERE id = %s
            RETURNING *
            """,
            (
                status,
                admin_response,
                developer_notes,
                json.dumps(tags or []),
                changelog_links,
                feedback_id,
            ),
        )
        row = cur.fetchone()
    return row


def cleanup_old_feedback() -> None:
    with get_cursor() as (_, cur):
        cur.execute(
            "DELETE FROM feedback WHERE ts < NOW() - INTERVAL '90 days';"
        )
