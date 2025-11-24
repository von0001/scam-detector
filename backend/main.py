# main.py

from __future__ import annotations

from pathlib import Path
from typing import Optional, Literal, List

import os
import time
import json
import subprocess
from datetime import datetime, timedelta
from collections import deque
import copy

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from backend.text_scanner import analyze_text
from backend.url_scanner import analyze_url
from backend.ai_detector.classify_actor import analyze_actor
from backend.manipulation.profiler import analyze_manipulation
from backend.qr_scanner.qr_engine import process_qr_image

from backend.analytics.analytics import record_event, get_analytics
from backend.analytics.feedback import add_feedback, load_feedback
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
    create_admin_token,
    verify_admin_token,
)

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
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://scamdetectorapp.com")

STRIPE_PRICE_MONTHLY = os.getenv(
    "STRIPE_PRICE_MONTHLY", "price_1SWh0pLSwRqmFbmS16yHTkBQ"
)
STRIPE_PRICE_YEARLY = os.getenv(
    "STRIPE_PRICE_YEARLY", "price_1SWh0pLSwRqmFbmShWjQBjjn"
)

if stripe and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

RESTART_COMMAND = os.getenv("RESTART_COMMAND", "./scripts/restart.sh")
FLUSH_CACHE_COMMAND = os.getenv("FLUSH_CACHE_COMMAND", "./scripts/flush_cache.sh")
CACHE_ENDPOINT = os.getenv("CACHE_ENDPOINT", "")
CONTROL_TOKEN = os.getenv("CONTROL_TOKEN", "")
ADMIN_CONFIRM_TOKEN = os.getenv("ADMIN_CONFIRM_TOKEN", "")
AI_ASSISTANT_KEY = os.getenv("AI_ASSISTANT_KEY", "")
AI_ASSISTANT_MODEL = os.getenv("AI_ASSISTANT_MODEL", "gpt-4o")

# ---------------------------------------------------------
# FastAPI + static
# ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
ACCOUNT_PAGE = BASE_DIR / "account.html"

app = FastAPI(title="ScamDetector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # you can restrict later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def capture_errors(request: Request, call_next):
    start = time.time()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        duration = time.time() - start
        now = time.time()
        ERROR_EVENTS.append((now, status >= 500, duration))
        # prune window
        while ERROR_EVENTS and now - ERROR_EVENTS[0][0] > ERROR_WINDOW_SECONDS:
            ERROR_EVENTS.popleft()

# ---------------------------------------------------------
# Models
# ---------------------------------------------------------
class AnalyzeRequest(BaseModel):
    content: str
    mode: str = "auto"


class FeedbackRequest(BaseModel):
    email: Optional[EmailStr] = None
    message: str
    page: Optional[str] = None


class UserSignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str
    otp_code: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = None


class SubscriptionUpdateRequest(BaseModel):
    email: EmailStr
    plan: Literal["free", "premium"]
    secret: Optional[str] = None
    billing_cycle: Optional[Literal["monthly", "yearly", "none"]] = None


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


class AdminControlRequest(BaseModel):
    action: str
    dry_run: Optional[bool] = False
    confirm_token: Optional[str] = None


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


SUBSCRIPTION_WEBHOOK_SECRET = os.getenv("SUBSCRIPTION_WEBHOOK_SECRET", "change-this")

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
    }


GUEST_DAILY_LIMIT = int(os.getenv("GUEST_DAILY_LIMIT", "3"))
_guest_usage: dict = {"date": "", "counts": {}}


def _check_guest_limit(request: Request) -> tuple[bool, int, int]:
    """
    Simple per-IP daily limit for guests. Not perfect, but prevents infinite use without auth.
    """
    global _guest_usage
    today = datetime.utcnow().strftime("%Y-%m-%d")
    host = request.client.host if request.client else "unknown"

    if _guest_usage.get("date") != today:
        _guest_usage = {"date": today, "counts": {}}

    counts = _guest_usage["counts"]
    used = counts.get(host, 0)

    if used >= GUEST_DAILY_LIMIT:
        return False, 0, GUEST_DAILY_LIMIT

    counts[host] = used + 1
    remaining = max(0, GUEST_DAILY_LIMIT - counts[host])
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
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
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
def signup(body: UserSignupRequest):
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
            "access_token": access,
            "refresh_token": refresh,
        }
    )
    resp.set_cookie(
        USER_ACCESS_COOKIE,
        access,
        max_age=ACCESS_TOKEN_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    resp.set_cookie(
        USER_REFRESH_COOKIE,
        refresh,
        max_age=REFRESH_TOKEN_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return resp


@app.post("/login")
def user_login(body: UserLoginRequest, request: Request):
    user = verify_user_credentials(body.email, body.password)
    if not user:
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

    access = create_access_token(user)
    refresh = create_refresh_token(user)

    resp = JSONResponse(
        {
            **_user_response(user),
            "access_token": access,
            "refresh_token": refresh,
        }
    )
    resp.set_cookie(
        USER_ACCESS_COOKIE,
        access,
        max_age=ACCESS_TOKEN_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    resp.set_cookie(
        USER_REFRESH_COOKIE,
        refresh,
        max_age=REFRESH_TOKEN_MAX_AGE,
        httponly=True,
        samesite="lax",
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
def google_auth(body: GoogleAuthRequest):
    if not body.credential:
        return JSONResponse({"error": "Missing credential."}, status_code=400)

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
            GOOGLE_CLIENT_ID or None,
        )
        email = idinfo.get("email")
        sub = idinfo.get("sub")
        if not email or not sub:
            raise ValueError("Missing email or sub.")
    except Exception:
        return JSONResponse({"error": "Invalid Google token."}, status_code=401)

    user = get_or_create_google_user(email=email, google_sub=sub)

    access = create_access_token(user)
    refresh = create_refresh_token(user)

    resp = JSONResponse(
        {
            **_user_response(user),
            "access_token": access,
            "refresh_token": refresh,
        }
    )
    resp.set_cookie(
        USER_ACCESS_COOKIE,
        access,
        max_age=ACCESS_TOKEN_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    resp.set_cookie(
        USER_REFRESH_COOKIE,
        refresh,
        max_age=REFRESH_TOKEN_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return resp


@app.post("/logout")
def user_logout():
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
            "access_token": new_access,
            "refresh_token": new_refresh,
        }
    )
    resp.set_cookie(
        USER_ACCESS_COOKIE,
        new_access,
        max_age=ACCESS_TOKEN_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    resp.set_cookie(
        USER_REFRESH_COOKIE,
        new_refresh,
        max_age=REFRESH_TOKEN_MAX_AGE,
        httponly=True,
        samesite="lax",
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


@app.post("/update-subscription-status")
def update_subscription(body: SubscriptionUpdateRequest):
    if body.secret != SUBSCRIPTION_WEBHOOK_SECRET:
        return JSONResponse({"error": "Unauthorized."}, status_code=401)

    user = update_user_plan_by_email(
        body.email,
        body.plan,
        billing_cycle=body.billing_cycle,
        status="active" if body.plan == "premium" else "inactive",
    )
    if not user:
        return JSONResponse({"error": "User not found."}, status_code=404)

    return {"success": True, **_user_response(user)}


@app.post("/account/subscribe")
def account_subscribe(body: SelfSubscriptionRequest, request: Request):
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
def admin_login(body: AdminLoginRequest):
    return JSONResponse(
        {
            "error": "Admin login is reserved for the owner account. Sign in with the owner email instead."
        },
        status_code=403,
    )


def _require_admin(request: Request) -> bool:
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


@app.post("/admin/control")
def admin_control(request: Request, body: AdminControlRequest):
    global MAINTENANCE_MODE, CRISIS_MODE
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    action = body.action.lower()
    dry_run = bool(body.dry_run)
    confirm = body.confirm_token or ""

    destructive_actions = {"restart", "cache", "lockdown", "crisis"}
    if action in destructive_actions and ADMIN_CONFIRM_TOKEN:
        if confirm != ADMIN_CONFIRM_TOKEN:
            return JSONResponse({"error": "Confirmation token required"}, status_code=401)

    def _run_command(cmd: str):
        if dry_run:
            return {"dry_run": True, "command": cmd}
        subprocess.run(cmd, shell=True, check=True, timeout=20)
        return {"dry_run": False, "command": cmd}

    def _call_cache_api():
        if dry_run:
            return {"dry_run": True, "endpoint": CACHE_ENDPOINT}
        headers = {"Authorization": f"Bearer {CONTROL_TOKEN}"} if CONTROL_TOKEN else {}
        resp = requests.post(CACHE_ENDPOINT, headers=headers, timeout=10)
        if resp.status_code >= 400:
            raise RuntimeError(f"Cache API failed: {resp.text}")
        return {"status": resp.status_code}

    audit_risk = 10
    audit_meta = {"action": action, "dry_run": dry_run}

    try:
        if action == "restart":
            _admin_log("Restart requested", "warn")
            _run_command(RESTART_COMMAND)
            audit_risk = 70
        elif action == "cache":
            _admin_log("Cache flush requested", "info")
            if CACHE_ENDPOINT:
                _call_cache_api()
            else:
                _run_command(FLUSH_CACHE_COMMAND)
            audit_risk = 40
        elif action == "maintenance":
            MAINTENANCE_MODE = not MAINTENANCE_MODE
            _admin_log(f"Maintenance toggled to {MAINTENANCE_MODE}", "warn")
            _snapshot_state("maintenance-toggle")
            audit_risk = 30
        elif action == "alerts":
            _admin_log("Alerts silenced temporarily", "info")
            audit_risk = 10
        elif action == "sync":
            _admin_log("Force data sync requested", "info")
            audit_risk = 20
        elif action.startswith("flag-"):
            name = action.replace("flag-", "")
            FEATURE_FLAGS[name] = not FEATURE_FLAGS.get(name, False)
            _admin_log(f"Flag {name} toggled to {FEATURE_FLAGS[name]}", "info")
            _snapshot_state(f"flag-{name}")
            audit_meta["flag"] = name
            audit_risk = 20
        elif action in {"override-safe", "override-block"}:
            _admin_log(f"Override action: {action}", "warn")
            audit_risk = 30
        elif action == "save-engine":
            _admin_log("Engine config saved", "info")
            audit_risk = 20
        elif action == "save-settings":
            _admin_log("Settings saved", "info")
            audit_risk = 20
        elif action == "lockdown":
            MAINTENANCE_MODE = True
            _admin_log("Emergency lockdown enabled", "danger")
            _snapshot_state("lockdown")
            audit_risk = 90
        elif action == "crisis":
            CRISIS_MODE = not CRISIS_MODE
            if CRISIS_MODE:
                MAINTENANCE_MODE = False
                _admin_log("Crisis mode enabled: signups frozen, strict detection, verbose logging", "danger")
                _snapshot_state("crisis-on")
                audit_risk = 90
            else:
                _admin_log("Crisis mode disabled", "warn")
                _snapshot_state("crisis-off")
                audit_risk = 40
        else:
            return JSONResponse({"error": "Unknown action"}, status_code=400)
    except Exception as exc:
        _admin_log(f"Control action {action} failed: {exc}", "danger")
        _log_audit(
            admin_id=user.get("id"),
            action=f"control:{action}",
            target=None,
            risk_score=80,
            metadata={"error": str(exc), **audit_meta},
            request=request,
        )
        return JSONResponse({"error": f"Action failed: {exc}"}, status_code=500)

    _log_audit(
        admin_id=user.get("id"),
        action=f"control:{action}",
        target=None,
        risk_score=audit_risk,
        metadata=audit_meta,
        request=request,
    )

    return {
        "success": True,
        "maintenance": MAINTENANCE_MODE,
        "crisis": CRISIS_MODE,
        "feature_flags": FEATURE_FLAGS,
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


@app.get("/admin/feedback")
def admin_feedback(request: Request):
    if not _require_admin(request):
        return JSONResponse({"error": "Unauthorized."}, status_code=401)
    return load_feedback()


# ---------------------------------------------------------
# Feedback API (public)
# ---------------------------------------------------------
@app.post("/api/feedback")
async def api_feedback(request: Request):
    body = await request.json()
    message = body.get("message", "").strip()
    email = body.get("email", "")
    page = body.get("page", "")

    if not message:
        return JSONResponse({"error": "Message is required."}, status_code=400)

    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    add_feedback(message=message, page=page, ip=ip, user_agent=user_agent)

    return {"success": True}


# ---------------------------------------------------------
# ANALYZE / QR
# ---------------------------------------------------------
@app.post("/analyze")
def analyze(req: AnalyzeRequest, request: Request):
    record_event("request")

    content = req.content.strip()
    mode = req.mode.lower()

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

    # --------------------- TEXT (auto) --------------------
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

    # --------------------- URL (auto) ---------------------
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

        raw = analyze_url(content) or {}
        base_score = raw.get("score", 0)
        score = _normalize_score(base_score)

        verdict = raw.get("verdict")
        explanation = raw.get("explanation") or "URL risk analysis."
        reasons = raw.get("reasons", [])
        details = raw.get("details", raw)

        resp = build_response(
            score=score,
            category="url",
            reasons=reasons,
            explanation=explanation,
            verdict=verdict,
            details=details,
        )
        if CRISIS_MODE:
            resp["score"] = min(100, resp["score"] + 15)

        if resp["verdict"] == "SAFE":
            record_event("safe")
        else:
            record_event("scam")

        add_scan_log(
            user_id=user_id,
            category="url",
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

    # Unknown mode
    return JSONResponse({"error": "Unsupported mode."}, status_code=400)


@app.post("/qr")
async def qr(request: Request, image: UploadFile = File(...)):
    record_event("request")

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
    result = process_qr_image(img_bytes)

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
