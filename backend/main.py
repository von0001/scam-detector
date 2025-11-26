# main.py

from __future__ import annotations

from pathlib import Path
from typing import Optional, Literal, List

import os
import time
import json
import secrets
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from collections import deque
import copy
import traceback
import sentry_sdk
from io import BytesIO

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, Field
import redis
import logging
import uuid

from backend.text_scanner import analyze_text
from backend.url_scanner import analyze_url
from backend.ai_detector.classify_actor import analyze_actor
from backend.manipulation.profiler import analyze_manipulation
from backend.qr_scanner.qr_engine import process_qr_image

from backend.analytics.analytics import record_event, get_analytics
from backend.analytics.feedback import (
    add_feedback,
    get_feedback_intel,
    load_feedback,
    update_feedback_response,
)
from backend.users import (
    create_user,
    verify_user_credentials,
    get_user_by_id,
    register_scan_attempt,
    add_scan_log,
    get_scan_history_for_user,
    update_user_plan_by_email,
    update_user_plan,
    get_or_create_google_user,
    change_password,
    delete_user,
    build_account_snapshot,
)
from backend.db import get_cursor, init_db
from backend.user_auth import (
    create_access_token,
    create_refresh_token,
    verify_access_token,
    verify_refresh_token,
    USER_ACCESS_COOKIE,
    USER_REFRESH_COOKIE,
    ACCESS_TOKEN_MAX_AGE,
    REFRESH_TOKEN_MAX_AGE,
)
from backend.auth import (
    ADMIN_PASSWORD,
    ADMIN_COOKIE_NAME,
    ADMIN_MAX_AGE,
    create_admin_token,
    verify_admin_token,
)
from PIL import Image

try:
    import stripe  # type: ignore
except Exception:  # pragma: no cover
    stripe = None  # type: ignore

# Optional telemetry + orchestration
try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

try:
    import pyotp  # type: ignore
except Exception:  # pragma: no cover
    pyotp = None  # type: ignore

import requests  # type: ignore

# Optional: Google ID token verification
try:
    import google.auth.transport.requests
    import google.oauth2.id_token
except ImportError:  # pragma: no cover
    google = None  # type: ignore

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
if not GOOGLE_CLIENT_ID:
    raise RuntimeError("Google Client ID required (GOOGLE_CLIENT_ID).")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://scamdetectorapp.com")
REDIS_URL = os.getenv("REDIS_URL")
SENTRY_DSN = os.getenv("SENTRY_DSN", "")

STRIPE_PRICE_MONTHLY = os.getenv(
    "STRIPE_PRICE_MONTHLY", "price_1SWh0pLSwRqmFbmS16yHTkBQ"
)
STRIPE_PRICE_YEARLY = os.getenv(
    "STRIPE_PRICE_YEARLY", "price_1SWh0pLSwRqmFbmShWjQBjjn"
)

if stripe and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

AI_ASSISTANT_KEY = os.getenv("AI_ASSISTANT_KEY", "")
AI_ASSISTANT_MODEL = os.getenv("AI_ASSISTANT_MODEL", "gpt-4o")

# Init Sentry if configured
if SENTRY_DSN:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.2)

# ---------------------------------------------------------
# FastAPI + static
# ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
ACCOUNT_PAGE = BASE_DIR / "account.html"

logger = logging.getLogger("scamdetector")
logging.basicConfig(level=logging.INFO, format="%(message)s")

app = FastAPI(title="ScamDetector API")

FRONTEND_URL_ENV = os.getenv("FRONTEND_URL", "https://scamdetectorapp.com").rstrip("/")
ALLOWED_ORIGINS = list(
    {
        "https://scamdetectorapp.com",
        "https://www.scamdetectorapp.com",
        FRONTEND_URL_ENV,
        FRONTEND_URL_ENV.replace("www.", ""),
    }
)
EXTENSION_ID = os.getenv("EXTENSION_ID", "jehidgbogolbhmfjobodnecbcnbibkaf")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS + [f"chrome-extension://{EXTENSION_ID}"],
    allow_origin_regex=r"chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Return JSON for unexpected errors/validation failures to avoid empty/HTML responses
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(json.dumps({"event": "error", "path": str(request.url), "error": str(exc)}))
    return JSONResponse({"error": "Internal server error."}, status_code=500)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse({"error": "Invalid request.", "detail": exc.errors()}, status_code=422)


# Global headers middleware for security headers + request id
@app.middleware("http")
async def security_headers(request: Request, call_next):
    request_id = secrets.token_hex(8)
    request.state.request_id = request_id
    start_time = time.time()
    response = await call_next(request)
    duration = round((time.time() - start_time) * 1000, 2)
    user = get_current_user(request)
    log_payload = {
        "event": "request",
        "request_id": request_id,
        "path": request.url.path,
        "method": request.method,
        "status": response.status_code,
        "duration_ms": duration,
        "user_id": (user or {}).get("id"),
        "ip": _get_client_ip(request),
    }
    logger.info(json.dumps(log_payload))
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"
    return response


@app.middleware("http")
async def capture_errors(request: Request, call_next):
    start = time.time()
    status = 500
    response = None
    try:
        response = await call_next(request)
        status = response.status_code
    finally:
        duration = time.time() - start
        now = time.time()
        ERROR_EVENTS.append((now, status >= 500, duration))
        while ERROR_EVENTS and now - ERROR_EVENTS[0][0] > ERROR_WINDOW_SECONDS:
            ERROR_EVENTS.popleft()
        if response is not None:
            _issue_csrf_cookie(request, response)
    return response

# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class AnalyzeRequest(BaseModel):
    content: str
    mode: str = "auto"
    async_job: Optional[bool] = False


class FeedbackRequest(BaseModel):
    email: Optional[EmailStr] = None
    message: str
    page: Optional[str] = None


class StructuredFeedbackRequest(BaseModel):
    email: Optional[EmailStr] = None
    what: Optional[str] = ""
    expectation: Optional[Literal["yes", "somewhat", "no", "unknown"]] = "unknown"
    confusion: Optional[str] = ""
    frustration: int = Field(5, ge=1, le=10)
    perfect: Optional[str] = ""
    message: Optional[str] = None
    page: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    context: dict = Field(default_factory=dict)
    replay: Optional[dict] = Field(default_factory=dict)


class FeedbackAdminUpdateRequest(BaseModel):
    id: str
    status: Optional[
        Literal["submitted", "under_review", "in_progress", "fixed", "improved", "not_reproducible"]
    ] = None
    response: Optional[str] = None
    developer_notes: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    changelog_links: List[str] = Field(default_factory=list)


class UserSignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str
    otp_code: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = None


class SelfSubscriptionRequest(BaseModel):
    plan: Literal["free", "premium"]
    billing_cycle: Optional[Literal["monthly", "yearly", "none"]] = "monthly"


class CheckoutSessionRequest(BaseModel):
    plan: Literal["monthly", "yearly"] = "monthly"


class AdminLoginRequest(BaseModel):
    password: str


class GoogleAuthRequest(BaseModel):
    credential: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class DeleteAccountRequest(BaseModel):
    password: Optional[str] = None
    confirm: str


class FeatureFlagRequest(BaseModel):
    name: str
    value: Optional[bool] = None


class EngineConfigRequest(BaseModel):
    sensitivity: Optional[int] = None
    confidence: Optional[int] = None
    model: Optional[str] = None
    pipeline: Optional[str] = None


class SimulationRequest(BaseModel):
    scenario: str = "default"


class AdminTotpVerifyRequest(BaseModel):
    code: str


MAINTENANCE_MODE = False
CRISIS_MODE = False
FEATURE_FLAGS = {
    "beta_ui": False,
    "ai_mode": False,
    "active_blocking": False,
}
ENGINE_CONFIG = {
    "sensitivity": 65,
    "confidence": 60,
    "model": "Default v1",
    "pipeline": "Standard",
}
SYSTEM_HEALTH = {
    "api_status": "unknown",
    "server_load": None,
    "error_rate": None,
    "db_latency": None,
}
ADMIN_LOGS: deque = deque(maxlen=200)
CHANGE_SNAPSHOTS: deque = deque(maxlen=50)
ERROR_WINDOW_SECONDS = 300
ERROR_EVENTS: deque = deque()
CSRF_COOKIE_NAME = "sd_csrf"
CSRF_HEADER_NAME = "x-csrf-token"
CSRF_MAX_AGE = REFRESH_TOKEN_MAX_AGE
TASK_EXECUTOR = ThreadPoolExecutor(max_workers=4)


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def is_url_like(text: str) -> bool:
    lowered = text.strip().lower()
    return lowered.startswith(("http://", "https://", "www.")) or "." in lowered


def _normalize_score(score: int | float) -> int:
    # Ensure 0-100
    try:
        s = float(score)
    except Exception:
        return 0
    return int(max(0, min(100, s)))


def _admin_log(event: str, level: str = "info") -> None:
    ADMIN_LOGS.append(
        {
            "timestamp": int(datetime.utcnow().timestamp()),
            "event": event,
            "level": level,
        }
    )


def _snapshot_state(reason: str = "") -> None:
    CHANGE_SNAPSHOTS.append(
        {
            "timestamp": int(datetime.utcnow().timestamp()),
            "reason": reason or "config-change",
            "maintenance": MAINTENANCE_MODE,
            "crisis": CRISIS_MODE,
            "engine": copy.deepcopy(ENGINE_CONFIG),
            "flags": copy.deepcopy(FEATURE_FLAGS),
        }
    )


def _redis_client() -> redis.Redis:
    if not REDIS_URL:
        raise RuntimeError("REDIS_URL must be set for rate limiting and queues.")
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _get_client_ip(request: Request) -> str:
    xfwd = request.headers.get("x-forwarded-for")
    if xfwd:
        return xfwd.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _issue_csrf_cookie(request: Request, response) -> str:
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if not token:
        token = secrets.token_urlsafe(32)
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        max_age=CSRF_MAX_AGE,
        secure=True,
        httponly=False,
        samesite="None",
    )
    return token


def _validate_csrf(request: Request) -> bool:
    token = request.cookies.get(CSRF_COOKIE_NAME)
    header = request.headers.get(CSRF_HEADER_NAME)
    if not token or not header:
        return False
    try:
        return secrets.compare_digest(token, header)
    except Exception:
        return False


def _csrf_failure():
    return JSONResponse({"error": "CSRF validation failed."}, status_code=403)


def _rate_limit_key(user: Optional[dict], ip: str, scope: str) -> tuple[str, int]:
    plan = (user or {}).get("plan", "guest")
    if plan == "premium":
        limit = 5000
    elif plan == "free":
        limit = 200
    else:
        limit = 50
    key = f"rate:{scope}:{plan}:{ip}"
    return key, limit


def _enforce_rate_limit(user: Optional[dict], request: Request, scope: str) -> Optional[JSONResponse]:
    ip = _get_client_ip(request)
    try:
        r = _redis_client()
    except Exception as exc:
        return JSONResponse({"error": f"Rate limit backend unavailable: {exc}"}, status_code=503)

    key, limit = _rate_limit_key(user, ip, scope)
    count = r.incr(key)
    if count == 1:
        r.expire(key, 86400)

    # Exponential backoff delay after limit exceeded
    if count > limit:
        delay = min(2 ** (count - limit), 30)
        r.setex(f"rate:block:{ip}", delay, "1")
        return JSONResponse(
            {"error": "Too many requests. Slow down.", "retry_after": delay, "captcha_required": True},
            status_code=429,
        )

    # Soft warning near threshold
    if count > int(limit * 0.8):
        return JSONResponse(
            {
                "error": "Rate limit nearly reached. Complete CAPTCHA to continue.",
                "remaining": max(limit - count, 0),
                "captcha_required": True,
            },
            status_code=429,
        )
    return None


def _login_fail_key(email: str, ip: str) -> str:
    return f"login:fail:{email.lower()}:{ip}"


def _check_bruteforce(email: str, ip: str) -> Optional[JSONResponse]:
    try:
        r = _redis_client()
    except Exception as exc:
        return JSONResponse({"error": f"Auth backend unavailable: {exc}"}, status_code=503)
    key = _login_fail_key(email, ip)
    fail_count = r.get(key)
    fail_count = int(fail_count) if fail_count else 0
    if fail_count >= 5:
        ttl = r.ttl(key)
        return JSONResponse(
            {"error": "Account temporarily locked due to failed attempts.", "retry_after": max(ttl, 0)},
            status_code=423,
        )
    return None


def _record_login_failure(email: str, ip: str) -> int:
    r = _redis_client()
    key = _login_fail_key(email, ip)
    count = r.incr(key)
    if count == 1:
        r.expire(key, 900)
    delay = min(0.5 * (2 ** max(count - 1, 0)), 8)
    return delay


def _clear_login_failures(email: str, ip: str) -> None:
    r = _redis_client()
    r.delete(_login_fail_key(email, ip))


def _set_task_status(task_id: str, status: str, result: dict | None = None, error: str | None = None):
    r = _redis_client()
    payload = {"status": status}
    if result is not None:
        payload["result"] = result
    if error:
        payload["error"] = error
    r.setex(f"task:{task_id}", 86400, json.dumps(payload))


def _enqueue_task(name: str, func, *args, **kwargs) -> str:
    task_id = secrets.token_hex(12)
    _set_task_status(task_id, "queued")

    def runner():
        try:
            result = func(*args, **kwargs)
            _set_task_status(task_id, "finished", result=result)
        except Exception as exc:
            _set_task_status(task_id, "failed", error=str(exc))

    TASK_EXECUTOR.submit(runner)
    return task_id


def _analyze_task(mode: str, content: str, user_id: Optional[str]):
    if mode == "text" or mode == "auto":
        raw = analyze_text(content) or {}
        base_score = raw.get("score", 0)
        score = _normalize_score(base_score)
        verdict = raw.get("verdict")
        explanation = raw.get("explanation") or "Scam text analysis."
        reasons = raw.get("reasons", [])
        details = raw.get("details", {})
        resp = build_response(
            score=score,
            category="text",
            reasons=reasons,
            explanation=explanation,
            verdict=verdict,
            details=details,
            ai_used=bool(raw.get("ai_used")),
        )
        return resp
    return {"error": "Unsupported task mode."}


def _compute_error_rate() -> float:
    now = time.time()
    total = 0
    errors = 0
    for ts, is_error, _ in list(ERROR_EVENTS):
        if now - ts <= ERROR_WINDOW_SECONDS:
            total += 1
            errors += 1 if is_error else 0
    if total == 0:
        return 0.0
    return round((errors / total) * 100, 2)


def _db_ping_latency_ms() -> Optional[float]:
    try:
        start = time.time()
        with get_cursor() as (conn, cur):
            cur.execute("SELECT 1;")
            _ = cur.fetchone()
        return round((time.time() - start) * 1000, 2)
    except Exception:
        return None


def _system_health_snapshot() -> dict:
    cpu = psutil.cpu_percent(interval=0.1) if psutil else None
    mem = psutil.virtual_memory().percent if psutil else None
    db_latency = _db_ping_latency_ms()
    error_rate = _compute_error_rate()

    SYSTEM_HEALTH.update(
        {
            "cpu_percent": cpu,
            "mem_percent": mem,
            "db_latency_ms": db_latency,
            "error_rate_pct": error_rate,
        }
    )
    return SYSTEM_HEALTH


def _log_audit(
    *,
    admin_id: Optional[str],
    action: str,
    target: Optional[str],
    risk_score: int,
    metadata: Optional[dict],
    request: Optional[Request] = None,
) -> None:
    ip = request.client.host if request and request.client else None
    ua = request.headers.get("user-agent") if request else None
    device_uuid = request.headers.get("x-admin-fingerprint") if request else None
    with get_cursor() as (_, cur):
        cur.execute(
            """
            INSERT INTO admin_audit (admin_id, action, target, risk_score, metadata, device_uuid, user_agent, ip)
            VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s)
            """,
            (
                admin_id,
                action,
                target,
                risk_score,
                json.dumps(metadata or {}),
                device_uuid,
                ua,
                ip,
            ),
        )


def _record_device(admin_id: str, request: Request) -> bool:
    device_uuid = request.headers.get("x-admin-fingerprint")
    if not device_uuid:
        return False
    ua = request.headers.get("user-agent", "")
    ip = request.client.host if request and request.client else ""
    is_new = False
    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT 1 FROM admin_devices WHERE admin_id = %s AND device_uuid = %s",
            (admin_id, device_uuid),
        )
        is_new = cur.fetchone() is None
        cur.execute(
            """
            INSERT INTO admin_devices (admin_id, device_uuid, user_agent, ip, last_seen)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (admin_id, device_uuid)
            DO UPDATE SET user_agent = EXCLUDED.user_agent, ip = EXCLUDED.ip, last_seen = NOW();
            """,
            (admin_id, device_uuid, ua, ip),
        )
    return is_new


def _cleanup_devices():
    with get_cursor() as (_, cur):
        cur.execute("DELETE FROM admin_devices WHERE last_seen < NOW() - INTERVAL '90 days';")


def _add_fp_case(user_id: Optional[str], verdict: str, reason: str):
    with get_cursor() as (_, cur):
        cur.execute(
            """
            INSERT INTO false_positive_queue (user_id, verdict, reason, status)
            VALUES (%s, %s, %s, 'pending')
            """,
            (user_id, verdict, reason),
        )


def _resolve_fp_case(case_id: int, status: str):
    with get_cursor() as (_, cur):
        cur.execute(
            """
            UPDATE false_positive_queue
            SET status = %s
            WHERE id = %s
            """,
            (status, case_id),
        )


def build_response(
    *,
    score: int,
    category: str,
    reasons: List[str],
    explanation: str,
    verdict: Optional[str] = None,
    details: Optional[dict] = None,
    ai_used: bool = False,
):
    if verdict is None:
        if score >= 60:
            verdict = "DANGEROUS"
        elif score >= 25:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

    return {
        "score": score,
        "category": category,
        "reasons": reasons,
        "explanation": explanation,
        "verdict": verdict,
        "details": details or {},
        "ai_used": ai_used,
    }


GUEST_DAILY_LIMIT = int(os.getenv("GUEST_DAILY_LIMIT", "3"))


def _check_guest_limit(request: Request) -> tuple[bool, int, int]:
    """
    Redis-backed per-IP guest limit.
    """
    host = _get_client_ip(request)
    try:
        r = _redis_client()
    except Exception:
        # Fallback to allow to avoid false positives
        return True, GUEST_DAILY_LIMIT, GUEST_DAILY_LIMIT
    key = f"guest:limit:{host}"
    used = r.incr(key)
    if used == 1:
        r.expire(key, 86_400)
    if used > GUEST_DAILY_LIMIT:
        return False, 0, GUEST_DAILY_LIMIT
    remaining = max(GUEST_DAILY_LIMIT - used, 0)
    return True, remaining, GUEST_DAILY_LIMIT


def get_current_user(request: Request) -> Optional[dict]:
    token = None

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()

    if not token:
        token = request.cookies.get(USER_ACCESS_COOKIE)

    if not token:
        return None

    payload = verify_access_token(token)
    if not payload:
        return None

    uid = payload.get("uid")
    if not uid:
        return None

    return get_user_by_id(uid)


def _user_response(user: dict) -> dict:
    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "plan": user.get("plan", "free"),
            "is_admin": bool(user.get("is_admin")),
            "auth_method": user.get("auth_method", "password"),
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login"),
            "daily_scan_date": user.get("daily_scan_date", ""),
            "daily_scan_count": user.get("daily_scan_count", 0),
            "daily_limit": user.get("daily_limit"),
            "billing_cycle": user.get("billing_cycle", "none"),
            "subscription_status": user.get("subscription_status", "inactive"),
            "subscription_renewal": user.get("subscription_renewal"),
            "last_plan_change": user.get("last_plan_change"),
            "stripe_customer_id": user.get("stripe_customer_id"),
            "stripe_subscription_id": user.get("stripe_subscription_id"),
        }
    }


def _stripe_price_for_plan(plan: str) -> str:
    plan = plan.lower()
    if plan == "yearly":
        return STRIPE_PRICE_YEARLY
    return STRIPE_PRICE_MONTHLY


def _plan_cycle_from_price(price_id: str) -> tuple[str, str]:
    if price_id == STRIPE_PRICE_YEARLY:
        return "premium", "yearly"
    return "premium", "monthly"


def _should_be_premium(status: str) -> bool:
    status_lower = (status or "").lower()
    return status_lower in {"active", "trialing", "past_due", "incomplete"}


def _apply_subscription_update(
    user_id: str,
    *,
    price_id: Optional[str] = None,
    status: str = "active",
    customer_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
    current_period_end: Optional[int] = None,
):
    plan, cycle = _plan_cycle_from_price(price_id or STRIPE_PRICE_MONTHLY)
    desired_plan = plan if _should_be_premium(status) else "free"
    subscription_status = "active" if _should_be_premium(status) else "canceled"
    update_user_plan(
        user_id=user_id,
        plan=desired_plan,
        billing_cycle=cycle if desired_plan == "premium" else "none",
        status=subscription_status,
        renewal=current_period_end,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
    )


def mask_emails(text: str) -> str:
    return re.sub(r"([A-Za-z0-9._%+-])[^@\\s]*@([^@\\s]{2})[^\\s]{0,20}", r"\\1***@\\2***", text)


def mask_phone_numbers(text: str) -> str:
    phone_pattern = r"(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)(\d{3})([-.\s]?)(\d{4})"
    return re.sub(phone_pattern, r"(***) ***-\5", text)


def mask_names(text: str) -> str:
    return re.sub(r"\b([A-Z][a-z]+)\s([A-Z][a-z]+)\b", r"\1 ***", text)


def sanitize_pii(text: str) -> str:
    if not text:
        return text
    masked = mask_emails(text)
    masked = mask_phone_numbers(masked)
    masked = mask_names(masked)
    return masked


def _create_checkout_session_for_user(user: dict, cycle: str):
    price_id = _stripe_price_for_plan(cycle)
    session = stripe.checkout.Session.create(
        mode="subscription",
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{FRONTEND_URL}/account?checkout=success",
        cancel_url=f"{FRONTEND_URL}/subscribe?checkout=cancel",
        metadata={"userId": user["id"], "plan": cycle},
        subscription_data={"metadata": {"userId": user["id"], "plan": cycle}},
        customer=user.get("stripe_customer_id") or None,
        customer_email=user.get("email"),
    )
    return session


# ---------------------------------------------------------
# Pages
# ---------------------------------------------------------
@app.get("/")
def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/support")
def support_page():
    return FileResponse(STATIC_DIR / "support.html")


@app.get("/privacy")
def privacy_page():
    return FileResponse(STATIC_DIR / "privacy.html")


@app.get("/terms")
def terms_page():
    return FileResponse(STATIC_DIR / "terms.html")


@app.get("/feedback")
def feedback_page():
    return FileResponse(STATIC_DIR / "feedback.html")


@app.get("/subscribe")
def subscribe_page():
    return FileResponse(STATIC_DIR / "subscribe.html")


@app.get("/contact")
def contact_page():
    return FileResponse(STATIC_DIR / "contact.html")


@app.get("/login-admin")
def login_admin_page():
    # Dedicated admin login surface
    admin_login = STATIC_DIR / "admin_login.html"
    if admin_login.exists():
        return FileResponse(admin_login)
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/admin")
def admin_page(request: Request):
    if not _require_admin(request):
        return FileResponse(STATIC_DIR / "login.html")
    _admin_log("Admin console viewed", "info")
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/account")
def account_page():
    target = ACCOUNT_PAGE if ACCOUNT_PAGE.exists() else STATIC_DIR / "account.html"
    return FileResponse(target)


@app.get("/account/dashboard")
def account_dashboard(request: Request, limit: int = 25):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    limit = max(5, min(limit, 200))
    snapshot = build_account_snapshot(user, history_limit=limit)
    return snapshot


@app.post("/create-checkout-session")
def create_checkout_session(body: CheckoutSessionRequest, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    if stripe is None or not STRIPE_SECRET_KEY:
        return JSONResponse(
            {"error": "Stripe is not configured on the server."}, status_code=503
        )

    if user.get("plan") == "premium":
        return JSONResponse({"error": "Account is already on Premium."}, status_code=400)

    try:
        session = _create_checkout_session_for_user(user, body.plan)
    except Exception as exc:  # pragma: no cover
        return JSONResponse({"error": f"Unable to start checkout: {exc}"}, status_code=500)

    return {"url": session.url}


@app.post("/billing-portal")
def billing_portal(request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    if stripe is None or not STRIPE_SECRET_KEY:
        return JSONResponse(
            {"error": "Stripe is not configured on the server."}, status_code=503
        )

    customer_id = user.get("stripe_customer_id")
    if not customer_id:
        return JSONResponse(
            {"error": "No billing profile found for this account."}, status_code=400
        )

    try:
        portal = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=f"{FRONTEND_URL}/account",
        )
    except Exception as exc:  # pragma: no cover
        return JSONResponse({"error": str(exc)}, status_code=500)

    return {"url": portal.url}


# ---------------------------------------------------------
# USER ACCOUNT SYSTEM
# ---------------------------------------------------------
@app.post("/signup")
def signup(body: UserSignupRequest, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    if CRISIS_MODE:
        return JSONResponse(
            {"error": "Signups are temporarily frozen during an incident. Please try later."},
            status_code=503,
        )
    try:
        user = create_user(body.email, body.password)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    access = create_access_token(user)
    refresh = create_refresh_token(user)

    resp = JSONResponse(
        {
            **_user_response(user),
            "message": "Signed up successfully.",
        }
    )
    resp.set_cookie(
        USER_ACCESS_COOKIE,
        access,
        max_age=ACCESS_TOKEN_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="None",
    )
    resp.set_cookie(
        USER_REFRESH_COOKIE,
        refresh,
        max_age=REFRESH_TOKEN_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="None",
    )
    return resp


@app.post("/login")
def user_login(body: UserLoginRequest, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    ip = _get_client_ip(request)
    locked = _check_bruteforce(body.email, ip)
    if locked:
        return locked
    user = verify_user_credentials(body.email, body.password)
    if not user:
        delay = _record_login_failure(body.email, ip)
        time.sleep(delay)
        return JSONResponse({"error": "Invalid email or password."}, status_code=401)

    # Enforce TOTP for admin if configured
    if user.get("is_admin") and user.get("totp_secret"):
        if not pyotp:
            return JSONResponse({"error": "2FA library missing"}, status_code=500)
        totp = pyotp.TOTP(user["totp_secret"])
        if not body.otp_code or not totp.verify(body.otp_code, valid_window=1):
            return JSONResponse(
                {"error": "TOTP code required or invalid.", "requires_totp": True},
                status_code=401,
            )

    _clear_login_failures(body.email, ip)

    access = create_access_token(user)
    refresh = create_refresh_token(user)

    resp = JSONResponse(
        {
            **_user_response(user),
            "message": "Logged in.",
        }
    )
    resp.set_cookie(
        USER_ACCESS_COOKIE,
        access,
        max_age=ACCESS_TOKEN_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="None",
    )
    resp.set_cookie(
        USER_REFRESH_COOKIE,
        refresh,
        max_age=REFRESH_TOKEN_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="None",
    )

    if user.get("is_admin"):
        is_new_device = _record_device(user["id"], request)
        _cleanup_devices()
        _log_audit(
            admin_id=user["id"],
            action="admin_login",
            target=None,
            risk_score=60 if is_new_device else 10,
            metadata={"email": user["email"]},
            request=request,
        )
    return resp


@app.post("/auth/google")
def google_auth(body: GoogleAuthRequest, request: Request):
    if not body.credential:
        return JSONResponse({"error": "Missing credential."}, status_code=400)

    if not _validate_csrf(request):
        return _csrf_failure()
    ip = _get_client_ip(request)
    locked = _check_bruteforce("google_oauth", ip)
    if locked:
        return locked

    if "google" not in globals() or google is None:  # type: ignore
        return JSONResponse(
            {
                "error": "Google auth not configured on server (google-auth library missing)."
            },
            status_code=500,
        )

    try:
        request_adapter = google.auth.transport.requests.Request()  # type: ignore
        # If GOOGLE_CLIENT_ID is empty, audience is not enforced (less strict but easier to start)
        idinfo = google.oauth2.id_token.verify_oauth2_token(  # type: ignore
            body.credential,
            request_adapter,
            GOOGLE_CLIENT_ID,
        )
        email = idinfo.get("email")
        sub = idinfo.get("sub")
        aud = idinfo.get("aud")
        if aud != GOOGLE_CLIENT_ID:
            raise ValueError("Invalid audience.")
        if not email or not sub:
            raise ValueError("Missing email or sub.")
    except Exception:
        _record_login_failure("google_oauth", ip)
        return JSONResponse({"error": "Invalid Google token."}, status_code=401)

    user = get_or_create_google_user(email=email, google_sub=sub)

    access = create_access_token(user)
    refresh = create_refresh_token(user)

    resp = JSONResponse(
        {
            **_user_response(user),
            "message": "Google auth success.",
        }
    )
    resp.set_cookie(
        USER_ACCESS_COOKIE,
        access,
        max_age=ACCESS_TOKEN_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="None",
    )
    resp.set_cookie(
        USER_REFRESH_COOKIE,
        refresh,
        max_age=REFRESH_TOKEN_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="None",
    )
    return resp


@app.post("/logout")
def user_logout(request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    resp = JSONResponse({"success": True})
    resp.delete_cookie(USER_ACCESS_COOKIE)
    resp.delete_cookie(USER_REFRESH_COOKIE)
    return resp


@app.get("/me")
def me(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"authenticated": False}, status_code=401)
    return {"authenticated": True, **_user_response(user)}


@app.post("/refresh-token")
def refresh_token(body: RefreshTokenRequest, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    token = body.refresh_token or request.cookies.get(USER_REFRESH_COOKIE)
    if not token:
        return JSONResponse({"error": "No refresh token provided."}, status_code=400)

    payload = verify_refresh_token(token)
    if not payload:
        return JSONResponse({"error": "Invalid or expired refresh token."}, status_code=401)

    uid = payload.get("uid")
    if not uid:
        return JSONResponse({"error": "Invalid token payload."}, status_code=401)

    user = get_user_by_id(uid)
    if not user:
        return JSONResponse({"error": "User not found."}, status_code=404)

    new_access = create_access_token(user)
    new_refresh = create_refresh_token(user)

    resp = JSONResponse(
        {
            **_user_response(user),
            "message": "Token refreshed.",
        }
    )
    resp.set_cookie(
        USER_ACCESS_COOKIE,
        new_access,
        max_age=ACCESS_TOKEN_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="None",
    )
    resp.set_cookie(
        USER_REFRESH_COOKIE,
        new_refresh,
        max_age=REFRESH_TOKEN_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="None",
    )
    return resp


@app.get("/scan-history")
def scan_history(request: Request, limit: int = 100):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    logs = get_scan_history_for_user(user["id"], limit=limit)
    return {"items": logs}


@app.post("/log-scan")
async def log_scan(request: Request):
    user = get_current_user(request)
    body = await request.json()
    category = body.get("category", "unknown")
    mode = body.get("mode", "auto")
    verdict = body.get("verdict", "SAFE")
    score = int(body.get("score", 0))
    snippet = body.get("snippet", "")[:280]
    details = body.get("details") or {}

    add_scan_log(
        user_id=user["id"] if user else None,
        category=category,
        mode=mode,
        verdict=verdict,
        score=score,
        content_snippet=snippet,
        details=details,
    )
    return {"success": True}


@app.post("/account/subscribe")
def account_subscribe(body: SelfSubscriptionRequest, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    if stripe is None or not STRIPE_SECRET_KEY:
        return JSONResponse(
            {"error": "Stripe is not configured on the server."}, status_code=503
        )

    if body.plan != "premium":
        return JSONResponse(
            {"error": "Subscriptions are managed via Stripe checkout only."},
            status_code=400,
        )

    billing_cycle = body.billing_cycle or "monthly"
    if user.get("plan") == "premium":
        return JSONResponse(
            {"error": "Account is already on Premium."},
            status_code=400,
        )

    try:
        session = _create_checkout_session_for_user(user, billing_cycle)
    except Exception as exc:  # pragma: no cover
        return JSONResponse({"error": f"Unable to start checkout: {exc}"}, status_code=500)

    return {"url": session.url}


@app.post("/account/downgrade")
def account_downgrade(request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    updated = update_user_plan(
        user_id=user["id"],
        plan="free",
        billing_cycle="none",
        status="canceled",
    )
    if not updated:
        return JSONResponse({"error": "Could not downgrade."}, status_code=400)

    return {"success": True, **_user_response(updated)}


# ---------------------------------------------------------
# Stripe Webhooks
# ---------------------------------------------------------
@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    if stripe is None or not STRIPE_WEBHOOK_SECRET:
        return JSONResponse({"error": "Stripe not configured."}, status_code=503)

    signature = request.headers.get("stripe-signature")
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, signature, STRIPE_WEBHOOK_SECRET
        )
    except Exception as exc:  # pragma: no cover
        return JSONResponse({"error": f"Invalid webhook: {exc}"}, status_code=400)

    event_type = event.get("type", "")
    data_object = event.get("data", {}).get("object", {})

    def _meta_user_id(meta: dict) -> Optional[str]:
        return (meta or {}).get("userId") or (meta or {}).get("user_id")

    if event_type == "checkout.session.completed":
        meta = data_object.get("metadata") or {}
        user_id = _meta_user_id(meta)
        if user_id and data_object.get("subscription"):
            try:
                sub = stripe.Subscription.retrieve(data_object["subscription"])
                price_id = sub["items"]["data"][0]["price"]["id"]
                _apply_subscription_update(
                    user_id,
                    price_id=price_id,
                    status=sub.get("status", "active"),
                    customer_id=sub.get("customer"),
                    subscription_id=sub.get("id"),
                    current_period_end=sub.get("current_period_end"),
                )
            except Exception:
                pass
    elif event_type in {
        "invoice.paid",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    }:
        subscription = data_object
        # For invoice events, subscription is nested
        if event_type == "invoice.paid":
            subscription_id = data_object.get("subscription")
            if subscription_id:
                try:
                    subscription = stripe.Subscription.retrieve(subscription_id)
                except Exception:
                    subscription = None
        if subscription:
            meta = subscription.get("metadata") or {}
            user_id = _meta_user_id(meta)
            if user_id:
                price_id = (
                    (subscription.get("items", {}).get("data") or [{}])[0]
                    .get("price", {})
                    .get("id")
                )
                _apply_subscription_update(
                    user_id,
                    price_id=price_id,
                    status=subscription.get("status", "active"),
                    customer_id=subscription.get("customer"),
                    subscription_id=subscription.get("id"),
                    current_period_end=subscription.get("current_period_end"),
                )

    return {"received": True}


@app.post("/account/change-password")
def account_change_password(body: ChangePasswordRequest, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    ok = change_password(user["id"], body.current_password, body.new_password)
    if not ok:
        return JSONResponse(
            {
                "error": "Current password is incorrect or this account is Google-only."
            },
            status_code=400,
        )

    return {"success": True}


@app.post("/account/delete")
def account_delete(body: DeleteAccountRequest, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    if body.confirm.strip().lower() != "delete":
        return JSONResponse(
            {"error": 'Type DELETE (all caps) to confirm.'}, status_code=400
        )

    # If they have password auth, require password
    method = user.get("auth_method", "password")
    if method in ("password", "mixed"):
        if not body.password:
            return JSONResponse(
                {"error": "Password required to delete this account."},
                status_code=400,
            )
        verify = verify_user_credentials(user["email"], body.password)
        if not verify:
            return JSONResponse({"error": "Incorrect password."}, status_code=400)

    ok = delete_user(user["id"])
    if not ok:
        return JSONResponse({"error": "Account not found."}, status_code=404)

    resp = JSONResponse({"success": True})
    resp.delete_cookie(USER_ACCESS_COOKIE)
    resp.delete_cookie(USER_REFRESH_COOKIE)
    return resp


# ---------------------------------------------------------
# Admin login + analytics
# ---------------------------------------------------------
@app.post("/admin/login")
def admin_login(body: AdminLoginRequest, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    ip = _get_client_ip(request)
    locked = _check_bruteforce("admin", ip)
    if locked:
        return locked
    password = body.password or ""
    if not ADMIN_PASSWORD:
        return JSONResponse({"error": "ADMIN_SECRET is not configured."}, status_code=503)
    if password != ADMIN_PASSWORD:
        delay = _record_login_failure("admin", ip)
        time.sleep(delay)
        return JSONResponse({"error": "Invalid admin password."}, status_code=401)

    _clear_login_failures("admin", ip)
    token = create_admin_token()
    resp = JSONResponse({"success": True, "admin": True})
    resp.set_cookie(
        ADMIN_COOKIE_NAME,
        token,
        max_age=ADMIN_MAX_AGE,
        httponly=True,
        samesite="Strict",
        secure=True,
    )
    _admin_log("Admin password login succeeded", "info")
    return resp


def _require_admin(request: Request) -> bool:
    # First allow admin token cookie (owner password flow)
    admin_token = request.cookies.get(ADMIN_COOKIE_NAME)
    if admin_token and verify_admin_token(admin_token):
        return True

    # Fallback to user-based admin accounts
    user = get_current_user(request)
    return bool(user and user.get("is_admin"))


@app.post("/admin/2fa/setup")
def admin_2fa_setup(request: Request):
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not pyotp:
        return JSONResponse({"error": "pyotp not installed"}, status_code=500)
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="ScamDetector Admin")
    with get_cursor() as (_, cur):
        cur.execute("UPDATE users SET totp_secret = %s WHERE id = %s", (secret, user["id"]))
    _admin_log("Admin 2FA secret generated", "warn")
    _log_audit(
        admin_id=user["id"],
        action="2fa_setup",
        target=None,
        risk_score=30,
        metadata={},
        request=request,
    )
    return {"secret": secret, "provisioning_uri": uri}


@app.post("/admin/2fa/verify")
def admin_2fa_verify(request: Request, body: AdminTotpVerifyRequest):
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not pyotp or not user.get("totp_secret"):
        return JSONResponse({"error": "2FA not configured"}, status_code=400)
    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(body.code, valid_window=1):
        return JSONResponse({"error": "Invalid code"}, status_code=401)
    return {"success": True}


@app.get("/admin/health")
def admin_health(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    data = get_analytics()
    now = datetime.utcnow().timestamp()
    last_ts = data["timestamp_log"][-1] if data.get("timestamp_log") else None
    api_status = "up" if last_ts else "unknown"

    health = _system_health_snapshot()
    health["api_status"] = api_status

    return {
        "health": health,
        "maintenance": MAINTENANCE_MODE,
        "crisis": CRISIS_MODE,
        "feature_flags": FEATURE_FLAGS,
        "engine": ENGINE_CONFIG,
        "last_event": last_ts,
        "timestamp": now,
    }


@app.get("/admin/flags")
def admin_flags(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return {"feature_flags": FEATURE_FLAGS}


@app.post("/admin/flags")
def admin_update_flag(request: Request, body: FeatureFlagRequest):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    name = body.name
    if not name:
        return JSONResponse({"error": "Missing name"}, status_code=400)
    FEATURE_FLAGS[name] = bool(body.value)
    _admin_log(f"Flag {name} set to {FEATURE_FLAGS[name]}", "info")
    return {"success": True, "feature_flags": FEATURE_FLAGS}


@app.post("/admin/engine")
def admin_engine(request: Request, body: EngineConfigRequest):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if body.sensitivity is not None:
        ENGINE_CONFIG["sensitivity"] = int(max(0, min(100, body.sensitivity)))
    if body.confidence is not None:
        ENGINE_CONFIG["confidence"] = int(max(0, min(100, body.confidence)))
    if body.model:
        ENGINE_CONFIG["model"] = body.model
    if body.pipeline:
        ENGINE_CONFIG["pipeline"] = body.pipeline
    _admin_log("Engine config updated", "info")
    _snapshot_state("engine-update")
    return {"success": True, "engine": ENGINE_CONFIG}


@app.get("/admin/logs")
def admin_logs(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return {"logs": list(ADMIN_LOGS)}


@app.get("/admin/audit")
def admin_audit(request: Request, limit: int = 50, offset: int = 0):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_cursor() as (_, cur):
        cur.execute(
            """
            SELECT * FROM admin_audit
            ORDER BY ts DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        rows = cur.fetchall() or []
    return {"items": rows}


@app.get("/admin/changes")
def admin_changes(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return {"changes": list(CHANGE_SNAPSHOTS)}


@app.post("/admin/rollback")
def admin_rollback(request: Request):
    global MAINTENANCE_MODE, CRISIS_MODE
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not CHANGE_SNAPSHOTS:
        return JSONResponse({"error": "No snapshots to rollback"}, status_code=400)

    snap = CHANGE_SNAPSHOTS.pop()
    MAINTENANCE_MODE = snap.get("maintenance", False)
    CRISIS_MODE = snap.get("crisis", False)
    ENGINE_CONFIG.update(snap.get("engine", {}))
    FEATURE_FLAGS.update(snap.get("flags", {}))
    _admin_log("Rolled back to previous config snapshot", "warn")
    return {
        "success": True,
        "maintenance": MAINTENANCE_MODE,
        "crisis": CRISIS_MODE,
        "engine": ENGINE_CONFIG,
        "feature_flags": FEATURE_FLAGS,
    }


@app.post("/admin/simulate")
def admin_simulate(request: Request, body: SimulationRequest):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    data = get_analytics()
    total = data.get("total_requests", 0)
    scam = data.get("scam_detections", 0)
    safe = data.get("safe_detections", 0)

    projected_fp = int(scam * 0.08)
    affected = int(total * 0.12)
    return {
        "scenario": body.scenario,
        "projected_false_positive_increase": projected_fp,
        "affected_verdicts": affected,
        "note": "Simulation uses historical aggregates. Wire to detailed replay for accuracy.",
    }


@app.get("/admin/assistant")
def admin_assistant(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if not AI_ASSISTANT_KEY:
        return {"available": False, "message": "Assistant unavailable"}

    data = get_analytics()
    feedback = load_feedback()
    logs = list(ADMIN_LOGS)[-20:]

    prompt = (
        "You are an internal admin assistant. Summarize anomalies, suggest optimizations, "
        "and recommend actions with confidence (0-100). Be concise.\n\n"
        f"Analytics: {json.dumps(data)}\n"
        f"Crisis: {CRISIS_MODE}\n"
        f"Recent logs: {json.dumps(logs)}\n"
        f"Recent feedback: {json.dumps(feedback[-10:] if feedback else [])}\n"
    )

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {AI_ASSISTANT_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": AI_ASSISTANT_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            },
            timeout=20,
        )
        if resp.status_code >= 400:
            return JSONResponse({"error": "Assistant call failed"}, status_code=resp.status_code)
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {"available": True, "analysis": content}
    except Exception as exc:
        return JSONResponse({"error": f"Assistant unavailable: {exc}"}, status_code=500)


@app.get("/admin/system-map")
def admin_system_map(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    health = _system_health_snapshot()
    nodes = [
        {"id": "api", "load": health.get("cpu_percent"), "errors": _compute_error_rate()},
        {"id": "db", "load": health.get("db_latency_ms"), "errors": 0},
        {"id": "detection", "load": ENGINE_CONFIG.get("sensitivity"), "errors": 0},
    ]
    edges = [
        {"from": "user", "to": "api", "latency_ms": health.get("db_latency_ms") or 0},
        {"from": "api", "to": "detection", "latency_ms": 40},
        {"from": "detection", "to": "db", "latency_ms": health.get("db_latency_ms") or 0},
    ]
    return {"nodes": nodes, "edges": edges}


@app.get("/admin/fp")
def admin_fp(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    with get_cursor() as (_, cur):
        cur.execute(
            "SELECT * FROM false_positive_queue ORDER BY created_at DESC LIMIT 100"
        )
        rows = cur.fetchall() or []
    return {"items": rows}


@app.post("/admin/fp/add")
async def admin_fp_add(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    user_id = body.get("user_id")
    verdict = body.get("verdict", "")
    reason = body.get("reason", "")
    if not verdict or not reason:
        return JSONResponse({"error": "verdict and reason required"}, status_code=400)
    _add_fp_case(user_id, verdict, reason)
    _admin_log("False positive case added", "info")
    _log_audit(
        admin_id=(get_current_user(request) or {}).get("id"),
        action="fp_add",
        target=user_id,
        risk_score=20,
        metadata={"verdict": verdict, "reason": reason},
        request=request,
    )
    return {"success": True}


@app.post("/admin/fp/resolve")
async def admin_fp_resolve(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    body = await request.json()
    case_id = body.get("id")
    status = body.get("status", "").lower()
    if status not in {"approved", "rejected"}:
        return JSONResponse({"error": "Invalid status"}, status_code=400)
    try:
        _resolve_fp_case(int(case_id), status)
    except Exception:
        return JSONResponse({"error": "Unable to resolve"}, status_code=400)
    _admin_log(f"False positive case {case_id} set to {status}", "info")
    _log_audit(
        admin_id=(get_current_user(request) or {}).get("id"),
        action="fp_resolve",
        target=str(case_id),
        risk_score=30,
        metadata={"status": status},
        request=request,
    )
    return {"success": True}


@app.get("/admin/analytics")
def admin_analytics(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized."}, status_code=401)
    return get_analytics()


@app.get("/tasks/status/{task_id}")
def task_status(task_id: str):
    try:
        r = _redis_client()
        raw = r.get(f"task:{task_id}")
    except Exception as exc:
        return JSONResponse({"error": f"Task backend unavailable: {exc}"}, status_code=503)
    if not raw:
        return JSONResponse({"error": "Task not found"}, status_code=404)
    return json.loads(raw)


@app.get("/admin/feedback")
def admin_feedback(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized."}, status_code=401)
    return load_feedback()


@app.get("/admin/feedback/intel")
def admin_feedback_intel(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized."}, status_code=401)
    return get_feedback_intel()


@app.post("/admin/feedback/respond")
def admin_feedback_respond(request: Request, body: FeedbackAdminUpdateRequest):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized."}, status_code=401)

    updated = update_feedback_response(
        feedback_id=body.id,
        status=body.status,
        admin_response=body.response,
        developer_notes=body.developer_notes,
        tags=body.tags,
        changelog_links=body.changelog_links,
    )
    if not updated:
        return JSONResponse({"error": "Feedback not found."}, status_code=404)
    return updated


# ---------------------------------------------------------
# Feedback API (public)
# ---------------------------------------------------------
@app.post("/api/feedback")
async def api_feedback(request: Request):
    raw = await request.json()
    try:
        body = StructuredFeedbackRequest(**raw)
    except Exception as exc:
        return JSONResponse({"error": f"Invalid feedback payload: {exc}"}, status_code=400)

    primary_message = (body.message or body.confusion or body.what or "").strip()
    if not primary_message:
        return JSONResponse({"error": "Message is required."}, status_code=400)

    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    context = dict(body.context or {})
    context.setdefault("page", body.page or request.headers.get("referer", "") or "")
    context.setdefault("mode", context.get("mode", "unknown"))

    record = add_feedback(
        what=body.what or "",
        expectation=(body.expectation or "unknown").lower(),
        confusion=body.confusion or "",
        frustration=body.frustration or 5,
        perfect=body.perfect or "",
        message=primary_message,
        page=body.page or context.get("page") or "",
        ip=ip,
        user_agent=user_agent,
        user_tags=body.tags,
        context=context,
        replay=body.replay or {},
        email=body.email,
    )

    tracking = [
        {"label": "Submitted", "state": "done"},
        {"label": "Under Review", "state": "pending"},
        {"label": "Improved", "state": "pending"},
    ]

    return {
        "success": True,
        "id": record.get("id"),
        "priority": record.get("priority"),
        "score_impact_prediction": record.get("score_impact_prediction"),
        "auto_response": record.get("auto_response"),
        "abuse_flags": record.get("abuse_flags"),
        "status": record.get("status"),
        "tracking": tracking,
    }


# ---------------------------------------------------------
# ANALYZE / QR
# ---------------------------------------------------------
async def process_scan(payload: dict, request: Request):
    if not _validate_csrf(request):
        return _csrf_failure()
    current_user = get_current_user(request)
    rl = _enforce_rate_limit(current_user, request, "scan")
    if rl:
        return rl
    record_event("request")

    content = (payload.get("content") or "").strip()
    mode = str(payload.get("mode") or "auto").strip().lower()
    print(f"[analyze] incoming mode={mode}")

    if len(content) > 10000 and mode != "qr":
        return JSONResponse({"error": "Input too large. Max 10,000 characters."}, status_code=413)

    content = sanitize_pii(content)

    if MAINTENANCE_MODE:
        return JSONResponse(
            {"error": "Maintenance mode is active. Please try again later."}, status_code=503
        )

    if not content and mode != "qr":
        return JSONResponse({"error": "content is empty"}, status_code=400)

    user = get_current_user(request)
    user_id = user["id"] if user else None
    plan = user.get("plan", "free") if user else "guest"
    is_premium = plan == "premium"

    if CRISIS_MODE:
        _admin_log("Scan during crisis mode", "warn")

    # Guest limit: simple per-IP daily cap
    if not user:
        allowed, remaining, limit = _check_guest_limit(request)
        if not allowed:
            return JSONResponse(
                {
                    "error": "Guest limit reached. Create a free account to continue scanning.",
                    "plan": "guest",
                    "limit": limit,
                    "remaining": 0,
                },
                status_code=429,
            )

    url_like = is_url_like(content)

    # Premium-only modes
    if mode in {"chat", "manipulation"} and not is_premium:
        return JSONResponse(
            {
                "error": "This scan mode is available for Premium accounts only.",
                "plan": plan,
            },
            status_code=402,
        )

    # --------------------- TEXT --------------------
    if mode == "text" or (mode == "auto" and not url_like):
        if user:
            allowed, remaining, limit = register_scan_attempt(user_id)
            if not allowed:
                return JSONResponse(
                    {
                        "error": "Daily free limit reached. Upgrade to Premium for unlimited scans.",
                        "plan": plan,
                        "limit": limit,
                        "remaining": 0,
                    },
                    status_code=429,
                )

        try:
            result = analyze_text(content) or {}
        except Exception:
            result = {
                "score": 0,
                "verdict": "SAFE",
                "explanation": "AI unavailable; offline fallback used.",
                "reasons": ["Offline fallback applied"],
                "details": {"mode": "fallback"},
                "ai_used": False,
            }
        base_score = result.get("score", 0)
        score = _normalize_score(base_score)
        verdict = result.get("verdict")
        explanation = result.get("explanation") or "Scam text analysis."
        reasons = result.get("reasons", [])
        details = result.get("details", {})

        resp = build_response(
            score=score,
            category="text",
            reasons=reasons,
            explanation=explanation,
            verdict=verdict,
            details=details,
            ai_used=bool(result.get("ai_used")),
        )
        if CRISIS_MODE:
            resp["score"] = min(100, resp["score"] + 15)

        if resp["verdict"] == "SAFE":
            record_event("safe")
        else:
            record_event("scam")

        add_scan_log(
            user_id=user_id,
            category="text",
            mode=mode,
            verdict=resp["verdict"],
            score=resp["score"],
            content_snippet=content,
            details=resp.get("details"),
        )
        return resp

    # --------------------- URL / AUTO --------------------
    if mode == "url" or (mode == "auto" and url_like):
        if user:
            allowed, remaining, limit = register_scan_attempt(user_id)
            if not allowed:
                return JSONResponse(
                    {
                        "error": "Daily free limit reached. Upgrade to Premium for unlimited scans.",
                        "plan": plan,
                        "limit": limit,
                        "remaining": 0,
                    },
                    status_code=429,
                )

        text_scan_resp = None
        if mode == "auto":
            is_pure_url = url_like and not re.search(r"\s", content)
            if not is_pure_url or len(content) > 0:
                try:
                    hybrid_text = analyze_text(content) or {}
                    text_score = _normalize_score(hybrid_text.get("score", 0))
                    text_scan_resp = build_response(
                        score=text_score,
                        category="text",
                        reasons=hybrid_text.get("reasons", []),
                        explanation=hybrid_text.get("explanation") or "Scam text analysis.",
                        verdict=hybrid_text.get("verdict"),
                        details=hybrid_text.get("details", {}),
                        ai_used=bool(hybrid_text.get("ai_used")),
                    )
                except Exception:
                    text_scan_resp = None

        try:
            raw = analyze_url(content) or {}
        except Exception:
            return JSONResponse({"error": "URL scanner unavailable. Please try again later."}, status_code=503)

        base_score = raw.get("score", 0)
        score = _normalize_score(base_score)

        verdict = raw.get("verdict")
        explanation = raw.get("explanation") or "URL risk analysis."
        reasons = raw.get("reasons", [])
        details = raw.get("details", raw)

        url_resp = build_response(
            score=score,
            category="url",
            reasons=reasons,
            explanation=explanation,
            verdict=verdict,
            details=details,
            ai_used=False,
        )

        resp = url_resp
        if text_scan_resp:
            combined = {
                "url": url_resp,
                "text": text_scan_resp,
            }
            if text_scan_resp["score"] > url_resp["score"]:
                resp = copy.deepcopy(text_scan_resp)
                resp["category"] = "hybrid"
                resp["details"] = {**(resp.get("details") or {}), "sources": combined}
            else:
                resp = copy.deepcopy(url_resp)
                resp["details"] = {**(resp.get("details") or {}), "sources": combined}

        if CRISIS_MODE:
            resp["score"] = min(100, resp["score"] + 15)

        if resp["verdict"] == "SAFE":
            record_event("safe")
        else:
            record_event("scam")

        add_scan_log(
            user_id=user_id,
            category=resp.get("category", "url"),
            mode=mode,
            verdict=resp["verdict"],
            score=resp["score"],
            content_snippet=content,
            details=resp.get("details"),
        )

        return resp

    # ----------------- AI Actor Detection -----------------
    if mode == "chat":
        if user:
            allowed, remaining, limit = register_scan_attempt(user_id)
            if not allowed:
                return JSONResponse(
                    {
                        "error": "Daily free limit reached. Upgrade to Premium for unlimited scans.",
                        "plan": plan,
                        "limit": limit,
                        "remaining": 0,
                    },
                    status_code=429,
                )

        result = analyze_actor(content)
        score = _normalize_score(result.get("ai_probability", 0))
        explanation = f"Detected actor type: {result.get('actor_type')}"
        reasons = result.get("signals", [])

        resp = build_response(
            score=score,
            category="ai_detector",
            reasons=reasons,
            explanation=explanation,
            verdict=None,
            details=result,
            ai_used=True,
        )

        add_scan_log(
            user_id=user_id,
            category="ai_detector",
            mode=mode,
            verdict=resp["verdict"],
            score=resp["score"],
            content_snippet=content,
            details=resp.get("details"),
        )

        return resp

    # -------------- Manipulation Profiler -----------------
    if mode == "manipulation":
        if user:
            allowed, remaining, limit = register_scan_attempt(user_id)
            if not allowed:
                return JSONResponse(
                    {
                        "error": "Daily free limit reached. Upgrade to Premium for unlimited scans.",
                        "plan": plan,
                        "limit": limit,
                        "remaining": 0,
                    },
                    status_code=429,
                )

        result = analyze_manipulation(content)
        score = _normalize_score(result.get("risk_score", 0))
        profile = result.get("scam_profile", "unclear")

        explanation = (
            "Emotional manipulation patterns detected."
            if score > 0
            else "No strong emotional manipulation detected."
        )

        reasons = result.get("primary_tactics", [])

        resp = build_response(
            score=score,
            category="manipulation",
            reasons=reasons,
            explanation=explanation,
            verdict=None,
            details=result,
            ai_used=True,
        )

        add_scan_log(
            user_id=user_id,
            category="manipulation",
            mode=mode,
            verdict=resp["verdict"],
            score=resp["score"],
            content_snippet=content,
            details=resp.get("details"),
        )

        return resp

    # ----------------- QR (not supported in /analyze) -----------------
    if mode == "qr":
        return JSONResponse({"error": "QR scans require image upload via /qr."}, status_code=400)

    return JSONResponse({"error": "Unsupported mode."}, status_code=400)


@app.post("/analyze")
async def analyze(request: Request):
    try:
        payload = await request.json()
        print("==== ANALYZE PAYLOAD ====")
        print(payload)

        result = await process_scan(payload, request)
        return result

    except Exception as e:
        print("🔥 ANALYZE CRASH 🔥:", str(e))
        print(traceback.format_exc())

        return JSONResponse(
            status_code=500,
            content={
                "error": "Backend crash",
                "details": str(e)
            }
        )


@app.post("/ocr")
async def ocr_endpoint(request: Request, image: UploadFile = File(...)):
    if not _validate_csrf(request):
        return _csrf_failure()
    rl = _enforce_rate_limit(get_current_user(request), request, "ocr")
    if rl:
        return rl
    record_event("request")

    max_bytes = 5 * 1024 * 1024
    img_bytes = await image.read()
    if len(img_bytes) > max_bytes:
        return JSONResponse({"error": "Image too large. Max 5MB."}, status_code=413)

    filename = image.filename or "upload"
    mime = image.content_type or "unknown"
    width = None
    height = None
    try:
        with Image.open(BytesIO(img_bytes)) as im:
            width, height = im.size
    except Exception:
        pass

    print(f"OCR endpoint hit name={filename} size={len(img_bytes)} bytes mime={mime} dims=({width}x{height})")

    return JSONResponse(
        {
            "status": "received",
            "filename": filename,
            "size": len(img_bytes),
            "mime": mime,
            "width": width,
            "height": height,
        }
    )


@app.post("/qr")
async def qr(request: Request, image: UploadFile = File(...), async_job: bool = False):
    if not _validate_csrf(request):
        return _csrf_failure()
    rl = _enforce_rate_limit(get_current_user(request), request, "qr")
    if rl:
        return rl
    record_event("request")

    max_qr_bytes = 5 * 1024 * 1024
    content_length = request.headers.get("content-length")
    try:
        if content_length and int(content_length) > max_qr_bytes:
            return JSONResponse({"error": "Image too large. Max 5MB."}, status_code=413)
    except Exception:
        pass

    user = get_current_user(request)
    user_id = user["id"] if user else None
    plan = user.get("plan", "free") if user else "guest"

    if user:
        allowed, remaining, limit = register_scan_attempt(user_id)
        if not allowed:
            return JSONResponse(
                {
                    "error": "Daily free limit reached. Upgrade to Premium for unlimited scans.",
                    "plan": plan,
                    "limit": limit,
                    "remaining": 0,
                },
                status_code=429,
            )

    img_bytes = await image.read()
    if len(img_bytes) > max_qr_bytes:
        return JSONResponse({"error": "Image too large. Max 5MB."}, status_code=413)
    try:
        result = process_qr_image(img_bytes)
    except Exception:
        return JSONResponse({"error": "QR scanner unavailable. Try again later."}, status_code=503)

    verdict = result.get("overall", {}).get("combined_verdict", "SAFE")
    score = result.get("overall", {}).get("combined_risk_score", 0)

    if verdict == "SAFE":
        record_event("safe")
    else:
        record_event("scam")

    add_scan_log(
        user_id=user_id,
        category="qr",
        mode="qr",
        verdict=verdict,
        score=score,
        content_snippet=f"{result.get('count', 0)} QR code(s)",
        details=result,
    )

    return result
