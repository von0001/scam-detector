from __future__ import annotations

import time
import json
from typing import Dict, Any

from backend.db import get_cursor

RETENTION_SECONDS = 90 * 24 * 60 * 60


def record_event(event_type: str, metadata: Dict[str, Any] | None = None) -> None:
    now = int(time.time())
    payload = metadata
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload)
    with get_cursor() as (_, cur):
        cur.execute(
            """
            INSERT INTO analytics_events (event_type, ts, metadata)
            VALUES (%s, to_timestamp(%s), %s::jsonb)
            """,
            (event_type, now, payload or {}),
        )
    # lightweight retention check
    if now % 100 == 0:
        cleanup_old_events()


def get_analytics(window_seconds: int = 86_400) -> Dict[str, Any]:
    """
    Return counts for the recent window (default 24h) and total lifetime aggregates.
    """
    with get_cursor() as (_, cur):
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE event_type = 'request') AS total_requests,
                COUNT(*) FILTER (WHERE event_type = 'scam') AS scam_detections,
                COUNT(*) FILTER (WHERE event_type = 'safe') AS safe_detections,
                COUNT(*) FILTER (WHERE event_type = 'ocr') AS ocr_uses,
                json_agg(ts ORDER BY ts DESC) FILTER (WHERE ts >= NOW() - INTERVAL '24 hours') AS timestamp_log
            FROM analytics_events
            WHERE ts >= NOW() - INTERVAL '90 days'
            """
        )
        row = cur.fetchone() or {}
    return {
        "total_requests": row.get("total_requests", 0),
        "scam_detections": row.get("scam_detections", 0),
        "safe_detections": row.get("safe_detections", 0),
        "ocr_uses": row.get("ocr_uses", 0),
        "timestamp_log": row.get("timestamp_log") or [],
    }


def cleanup_old_events() -> None:
    """Retention cleanup to keep analytics lean."""
    with get_cursor() as (_, cur):
        cur.execute(
            "DELETE FROM analytics_events WHERE ts < NOW() - INTERVAL '90 days';"
        )
