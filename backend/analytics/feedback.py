from __future__ import annotations

import json
import re
import statistics
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Sequence

FEEDBACK_FILE = Path("analytics/feedback.json")

# Ensure storage exists early
if not FEEDBACK_FILE.exists():
    FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    FEEDBACK_FILE.write_text("[]")

# Canonical tag set used across UI
CANONICAL_TAGS = [
    "Bug",
    "False Positive",
    "False Negative",
    "UI/UX Issue",
    "Performance Issue",
    "Feature Request",
    "Confusing Result",
]

STATUS_ORDER = [
    "submitted",
    "under_review",
    "in_progress",
    "fixed",
    "improved",
    "not_reproducible",
]


def load_feedback() -> List[Dict[str, Any]]:
    """Load persisted feedback items."""
    try:
        return json.loads(FEEDBACK_FILE.read_text())
    except Exception:
        return []


def save_feedback(data: Sequence[Dict[str, Any]]) -> None:
    """Persist all feedback items."""
    FEEDBACK_FILE.write_text(json.dumps(list(data), indent=2))


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower().strip())


def _auto_tags(
    combined_text: str, expectation: str, context: Dict[str, Any], user_tags: List[str]
) -> List[str]:
    """Infer tags based on text, expectation outcome, and context."""
    text = _normalize(combined_text)
    inferred: set[str] = set(t for t in user_tags if t)

    keyword_map = {
        "bug": ["error", "broken", "crash", "fail", "issue", "not working"],
        "false positive": ["safe", "legit", "real", "false alarm", "not scam"],
        "false negative": ["missed", "still scam", "did not catch", "slipped"],
        "ui/ux issue": ["confusing", "hard to find", "unclear", "layout"],
        "performance issue": ["slow", "lag", "loading", "timeout", "freeze"],
        "feature request": ["should add", "it would help", "wish", "feature", "add"],
        "confusing result": ["did not understand", "uncertain", "why", "unclear"],
    }

    for tag, keywords in keyword_map.items():
        if any(kw in text for kw in keywords):
            inferred.add(tag.title())

    verdict = (context.get("verdict") or "").lower()
    risk_score = context.get("risk_score") or context.get("score") or 0
    if expectation == "no" and verdict == "safe":
        inferred.add("False Negative")
    if expectation in {"somewhat", "no"} and "confus" in text:
        inferred.add("Confusing Result")
    if verdict == "dangerous" and "safe" in text:
        inferred.add("False Positive")
    if risk_score and risk_score >= 85:
        inferred.add("High Risk Context")

    # Keep only canonical + derived
    cleaned = []
    for tag in inferred:
        if tag.title() in CANONICAL_TAGS or tag == "High Risk Context":
            cleaned.append(tag.title() if tag != "High Risk Context" else tag)
    return sorted(set(cleaned))


def _similarity(a: str, b: str) -> float:
    """Quick Jaccard similarity on token sets."""
    set_a = set(_normalize(a).split())
    set_b = set(_normalize(b).split())
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def _cluster_key(text: str, page: str, mode: str) -> str:
    seed = f"{_normalize(text)}|{page}|{mode}"
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex[:12]


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


def _abuse_flags(text: str, frustration: int, time_on_page: float) -> List[str]:
    flags: List[str] = []
    if frustration >= 9 and len(text.split()) < 4:
        flags.append("rage-click signal")
    if text.count("http") > 3 or text.count("@") > 5:
        flags.append("spam pattern")
    if len(text) > 8000:
        flags.append("oversize payload")
    toxic_markers = ["hate", "idiot", "stupid", "trash", "worst"]
    if any(w in _normalize(text) for w in toxic_markers):
        flags.append("toxic language")
    if time_on_page is not None and time_on_page < 3:
        flags.append("suspiciously fast submission")
    return flags


def _predict_trust_gain(priority: float, risk_impact: int, frequency: int) -> float:
    """Rough heuristic: how much solving this reduces user risk perception."""
    raw = priority * (1 + (risk_impact * 0.2)) * (1 + (frequency * 0.1))
    return round(min(100.0, raw / 5), 1)


def _auto_response(tags: List[str]) -> str | None:
    if not tags:
        return None
    if "Feature Request" in tags:
        return "Logged as a feature request. We review these weekly and notify if shipped."
    if "False Positive" in tags:
        return "Thanks for flagging a false positive. We re-run these in our regression set."
    if "False Negative" in tags:
        return "Missed scam reports jump to the top of retraining. We will tighten rules."
    if "UI/UX Issue" in tags:
        return "UX feedback acknowledged. We will simplify the flow you highlighted."
    return None


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
    """
    Store rich feedback with derived signals.
    """
    now = int(time.time())
    existing = load_feedback()

    user_tags = user_tags or []
    context = context or {}
    replay = replay or {}

    combined_text = " ".join(
        [
            what or "",
            confusion or "",
            perfect or "",
            message or "",
        ]
    ).strip()

    mode = context.get("mode", "unknown")
    cluster = _cluster_key(combined_text or message, page, mode)

    # Estimate how many similar items already exist for priority weighting
    frequency = 1
    for item in existing:
        text_b = item.get("combined_text") or item.get("message", "")
        if _similarity(combined_text, text_b) >= 0.55 or item.get("cluster_key") == cluster:
            frequency += 1

    auto = _auto_tags(combined_text, expectation, context, user_tags)
    risk_impact = _risk_impact(context)
    priority = max(1, frustration) * max(1, frequency) * max(1, risk_impact)

    abuse = _abuse_flags(combined_text, frustration, context.get("time_on_page", 0.0))
    trust_gain = _predict_trust_gain(priority, risk_impact, frequency)
    auto_response = _auto_response(auto)

    record = {
        "id": str(uuid.uuid4()),
        "timestamp": now,
        "email": email,
        "message": message or combined_text,
        "combined_text": combined_text,
        "what": what,
        "expectation": expectation or "unknown",
        "confusion": confusion,
        "frustration": frustration,
        "perfect": perfect,
        "page": page,
        "context": {
            "page": page,
            "mode": mode,
            "risk_score": context.get("risk_score"),
            "verdict": context.get("verdict"),
            "time_on_page": context.get("time_on_page"),
            "device": context.get("device"),
            "browser": context.get("browser"),
            "timestamp": now,
            "risk_label": context.get("risk_label"),
            "time_on_flow": context.get("time_on_flow"),
        },
        "ip": ip,
        "user_agent": user_agent,
        "tags": {
            "user": sorted(set(user_tags)),
            "auto": auto,
        },
        "priority": priority,
        "risk_impact": risk_impact,
        "frequency": frequency,
        "cluster_key": cluster,
        "status": "submitted",
        "status_history": [
            {"state": "submitted", "ts": now, "note": "User submitted feedback"}
        ],
        "abuse_flags": abuse,
        "replay": replay,
        "score_impact_prediction": trust_gain,
        "auto_response": auto_response,
        "admin_response": None,
        "developer_notes": None,
        "linked_changelog": [],
    }

    existing.append(record)
    save_feedback(existing)
    return record


def _cluster_feedback(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    clusters: dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in items:
        key = item.get("cluster_key") or _cluster_key(
            item.get("combined_text", ""), item.get("page", ""), item.get("context", {}).get("mode", "")
        )
        clusters[key].append(item)

    grouped: List[Dict[str, Any]] = []
    for key, group in clusters.items():
        frustrations = [g.get("frustration", 0) for g in group]
        tags = Counter()
        for g in group:
            for tag in g.get("tags", {}).get("auto", []):
                tags[tag] += 1
            for tag in g.get("tags", {}).get("user", []):
                tags[tag] += 1

        sample = max(group, key=lambda g: g.get("priority", 0))
        grouped.append(
            {
                "id": key,
                "count": len(group),
                "sample": sample.get("combined_text") or sample.get("message"),
                "top_tags": [t for t, _ in tags.most_common(3)],
                "frustration_avg": round(statistics.mean(frustrations), 2) if frustrations else 0,
                "priority_peak": max(g.get("priority", 0) for g in group),
            }
        )
    grouped.sort(key=lambda g: g["priority_peak"], reverse=True)
    return grouped


def _trend_buckets(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    now = int(time.time())
    one_day = 86400
    weekly_cut = now - (one_day * 7)
    monthly_cut = now - (one_day * 30)

    weekly = [i for i in items if i.get("timestamp", 0) >= weekly_cut]
    monthly = [i for i in items if i.get("timestamp", 0) >= monthly_cut]

    def bucketize(data: List[Dict[str, Any]], days: int) -> Dict[str, int]:
        buckets: Dict[str, int] = {}
        for item in data:
            day = time.strftime("%Y-%m-%d", time.gmtime(item.get("timestamp", 0)))
            buckets[day] = buckets.get(day, 0) + 1
        return buckets

    return {
        "weekly": bucketize(weekly, 7),
        "monthly": bucketize(monthly, 30),
        "weekly_count": len(weekly),
        "monthly_count": len(monthly),
    }


def _heatmap(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_mode: Counter[str] = Counter()
    by_tag: Counter[str] = Counter()
    by_page: Counter[str] = Counter()

    for item in items:
        ctx = item.get("context", {}) or {}
        mode = ctx.get("mode") or "unknown"
        page = ctx.get("page") or item.get("page") or "unknown"
        by_mode[mode] += 1
        by_page[page] += 1
        for tag in item.get("tags", {}).get("auto", []) + item.get("tags", {}).get("user", []):
            by_tag[tag] += 1

    def top(counter: Counter[str]) -> List[Dict[str, Any]]:
        return [{"label": k, "count": v} for k, v in counter.most_common(8)]

    return {
        "modes": top(by_mode),
        "pages": top(by_page),
        "tags": top(by_tag),
    }


def _aiish_suggestions(clusters: List[Dict[str, Any]], heatmap: Dict[str, Any]) -> List[str]:
    suggestions: List[str] = []
    if clusters:
        top = clusters[0]
        suggestions.append(
            f"Cluster '{top.get('sample','')[:60]}' repeats {top['count']} times; tighten this flow first."
        )
    top_mode = heatmap.get("modes", [])
    if top_mode:
        suggestions.append(
            f"Mode '{top_mode[0]['label']}' draws the most complaints; prioritize UX tests there."
        )
    top_tag = heatmap.get("tags", [])
    if top_tag:
        suggestions.append(
            f"Tag '{top_tag[0]['label']}' leads volume; add regression coverage for it."
        )
    if not suggestions:
        suggestions.append("Volume is low. Keep passive monitoring on.")
    return suggestions


def add_changelog_link(feedback_id: str, link: str) -> Dict[str, Any] | None:
    items = load_feedback()
    for item in items:
        if item.get("id") == feedback_id:
            links = item.get("linked_changelog") or []
            links.append(link)
            item["linked_changelog"] = links
            save_feedback(items)
            return item
    return None


def update_feedback_response(
    *,
    feedback_id: str,
    status: str | None = None,
    admin_response: str | None = None,
    developer_notes: str | None = None,
    tags: List[str] | None = None,
    changelog_links: List[str] | None = None,
) -> Dict[str, Any] | None:
    items = load_feedback()
    updated: Dict[str, Any] | None = None
    for item in items:
        if item.get("id") != feedback_id:
            continue
        if status:
            item["status"] = status
            history = item.get("status_history") or []
            history.append({"state": status, "ts": int(time.time()), "note": "Admin update"})
            item["status_history"] = history
        if admin_response is not None:
            item["admin_response"] = admin_response
        if developer_notes is not None:
            item["developer_notes"] = developer_notes
        if tags is not None:
            deduped = sorted(set(tags + item.get("tags", {}).get("user", []) + item.get("tags", {}).get("auto", [])))
            item.setdefault("tags", {}).setdefault("admin", deduped)
        if changelog_links:
            existing_links = item.get("linked_changelog") or []
            item["linked_changelog"] = existing_links + changelog_links
        updated = item
        break
    if updated:
        save_feedback(items)
    return updated


def get_feedback_intel() -> Dict[str, Any]:
    items = load_feedback()
    clusters = _cluster_feedback(items)
    heatmap = _heatmap(items)
    trends = _trend_buckets(items)

    high_priority = sorted(items, key=lambda i: i.get("priority", 0), reverse=True)[:40]
    frustration_avg = (
        round(statistics.mean([i.get("frustration", 0) for i in items]), 2) if items else 0
    )

    return {
        "total": len(items),
        "frustration_avg": frustration_avg,
        "high_priority": high_priority,
        "clusters": clusters,
        "heatmap": heatmap,
        "trends": trends,
        "suggestions": _aiish_suggestions(clusters, heatmap),
        "abuse_filtered": len([i for i in items if i.get("abuse_flags")]),
    }
