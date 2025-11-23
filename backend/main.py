# main.py

from __future__ import annotations

from pathlib import Path
from typing import Optional, Literal, List, Tuple

import os
import time

import stripe
from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel, EmailStr, Field

from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

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
    get_or_create_google_user,
)
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
    SECRET_KEY,
)

# ---------------------------------------------------------
# FastAPI + static
# ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="ScamDetector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # you can restrict later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ---------------------------------------------------------
# Billing / Google / guest config
# ---------------------------------------------------------
SUBSCRIPTION_WEBHOOK_SECRET = os.getenv("SUBSCRIPTION_WEBHOOK_SECRET", "change-this")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID_MONTHLY = os.getenv("STRIPE_PRICE_ID_MONTHLY", "")
STRIPE_PRICE_ID_YEARLY = os.getenv("STRIPE_PRICE_ID_YEARLY", "")
STRIPE_SUCCESS_URL = os.getenv(
    "STRIPE_SUCCESS_URL", "https://scamdetectorapp.com/pricing?status=success"
)
STRIPE_CANCEL_URL = os.getenv(
    "STRIPE_CANCEL_URL", "https://scamdetectorapp.com/pricing?status=cancelled"
)
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")

GUEST_DAILY_LIMIT = 2
GUEST_SCAN_COOKIE = "sd_guest_scans"
_guest_serializer = URLSafeSerializer(SECRET_KEY, salt="guest-scans-v1")


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


class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = None


class SubscriptionUpdateRequest(BaseModel):
    email: EmailStr
    plan: Literal["free", "premium"]
    secret: Optional[str] = None


class AdminLoginRequest(BaseModel):
    password: str


class GoogleAuthRequest(BaseModel):
    id_token: str


class CheckoutSessionRequest(BaseModel):
    billing_period: Literal["month", "year"] = "month"


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def is_url_like(text: str) -> bool:
    lowered = text.strip().lower()
    return lowered.startswith(("http://", "https://", "www.")) or "." in lowered


def _normalize_score(score: int | float) -> int:
    # Ensure 0–100
    try:
        s = float(score)
    except Exception:
        return 0
    return int(max(0, min(100, s)))


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
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login"),
            "daily_scan_date": user.get("daily_scan_date", ""),
            "daily_scan_count": user.get("daily_scan_count", 0),
            "daily_limit": user.get("daily_limit"),
            "auth_method": user.get("auth_method", "password"),
        }
    }


# -------- Guest scan helpers --------
def _get_guest_state(request: Request) -> dict:
    raw = request.cookies.get(GUEST_SCAN_COOKIE)
    if not raw:
        return {"date": "", "count": 0}
    try:
        data = _guest_serializer.loads(raw)
        if not isinstance(data, dict):
            return {"date": "", "count": 0}
        return {
            "date": str(data.get("date", "")),
            "count": int(data.get("count", 0)),
        }
    except BadSignature:
        return {"date": "", "count": 0}


def _set_guest_state_cookie(resp: JSONResponse, state: dict) -> None:
    try:
        token = _guest_serializer.dumps(
            {
                "date": state.get("date", ""),
                "count": int(state.get("count", 0)),
            }
        )
    except Exception:
        return
    resp.set_cookie(
        GUEST_SCAN_COOKIE,
        token,
        max_age=60 * 60 * 24 * 7,
        httponly=True,
        samesite="lax",
    )


def check_scan_limit(
    request: Request, user: Optional[dict]
) -> Tuple[bool, Optional[JSONResponse], Optional[dict]]:
    """
    Unified scan limit checker for logged-in and guest users.
    Returns (allowed, error_response_if_any, guest_state_if_guest).
    """
    if user:
        allowed, _remaining, limit = register_scan_attempt(user["id"])
        if not allowed:
            return (
                False,
                JSONResponse(
                    {
                        "error": "Daily free limit reached. Upgrade to Premium for unlimited scans.",
                        "plan": user.get("plan", "free"),
                        "limit": limit,
                        "remaining": 0,
                    },
                    status_code=429,
                ),
                None,
            )
        return True, None, None

    # Guest
    state = _get_guest_state(request)
    today = time.strftime("%Y-%m-%d")
    if state.get("date") != today:
        state = {"date": today, "count": 0}

    limit = GUEST_DAILY_LIMIT
    if state["count"] >= limit:
        err = JSONResponse(
            {
                "error": "Guest limit reached. Create a free account for more scans.",
                "plan": "guest",
                "limit": limit,
                "remaining": 0,
            },
            status_code=429,
        )
        return False, err, state

    state["count"] += 1
    return True, None, state


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


@app.get("/contact")
def contact_page():
    return FileResponse(STATIC_DIR / "contact.html")


@app.get("/pricing")
def pricing_page():
    return FileResponse(STATIC_DIR / "pricing.html")


@app.get("/login-admin")
def login_admin_page():
    # Optional separate URL to load login.html
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/admin")
def admin_page(request: Request):
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token or not verify_admin_token(token):
        # Redirect to login page
        return FileResponse(STATIC_DIR / "login.html")
    return FileResponse(STATIC_DIR / "admin.html")


# ---------------------------------------------------------
# USER ACCOUNT SYSTEM
# ---------------------------------------------------------
@app.post("/signup")
def signup(body: UserSignupRequest):
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
def user_login(body: UserLoginRequest):
    user = verify_user_credentials(body.email, body.password)
    if not user:
        return JSONResponse({"error": "Invalid email or password."}, status_code=401)

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


@app.post("/auth/google")
def auth_google(body: GoogleAuthRequest):
    if not GOOGLE_CLIENT_ID:
        return JSONResponse(
            {"error": "Google Sign-In not configured."}, status_code=500
        )

    try:
        idinfo = google_id_token.verify_oauth2_token(
            body.id_token,
            google_requests.Request(),
            GOOGLE_CLIENT_ID,
        )
    except Exception:
        return JSONResponse({"error": "Invalid Google token."}, status_code=401)

    email = idinfo.get("email")
    sub = idinfo.get("sub")

    if not email or not sub:
        return JSONResponse(
            {"error": "Google profile missing email."}, status_code=400
        )

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
    # also reset guest counter
    resp.delete_cookie(GUEST_SCAN_COOKIE)
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
        return JSONResponse(
            {"error": "Invalid or expired refresh token."}, status_code=401
        )

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
    # simple shared-secret hook if you don't want to use Stripe webhooks
    if body.secret != SUBSCRIPTION_WEBHOOK_SECRET:
        return JSONResponse({"error": "Unauthorized."}, status_code=401)

    user = update_user_plan_by_email(body.email, body.plan)
    if not user:
        return JSONResponse({"error": "User not found."}, status_code=404)

    return {"success": True, **_user_response(user)}


# ---------------------------------------------------------
# Billing with Stripe
# ---------------------------------------------------------
@app.post("/billing/create-checkout-session")
def create_checkout_session(req: CheckoutSessionRequest, request: Request):
    if not STRIPE_SECRET_KEY:
        return JSONResponse(
            {"error": "Billing is not configured."}, status_code=500
        )

    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "Authentication required."}, status_code=401)

    price_id = (
        STRIPE_PRICE_ID_YEARLY if req.billing_period == "year" else STRIPE_PRICE_ID_MONTHLY
    )
    if not price_id:
        return JSONResponse(
            {"error": "No price ID configured for this plan."}, status_code=500
        )

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            customer_email=user["email"],
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=STRIPE_SUCCESS_URL,
            cancel_url=STRIPE_CANCEL_URL,
            metadata={"user_id": user["id"], "email": user["email"]},
        )
    except Exception:
        return JSONResponse(
            {"error": "Unable to create checkout session."}, status_code=500
        )

    return {"url": session.url}


@app.post("/billing/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        return JSONResponse(
            {"error": "Webhook secret not configured."}, status_code=500
        )

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return JSONResponse({"error": "Invalid payload."}, status_code=400)
    except stripe.error.SignatureVerificationError:
        return JSONResponse({"error": "Invalid signature."}, status_code=400)

    event_type = event["type"]
    data = event["data"]["object"]

    email = None
    if isinstance(data, dict):
        if data.get("customer_details"):
            email = data["customer_details"].get("email")
        if not email:
            email = data.get("customer_email")

    if email:
        if event_type in (
            "checkout.session.completed",
            "customer.subscription.created",
            "customer.subscription.updated",
        ):
            update_user_plan_by_email(email, "premium")
        elif event_type in (
            "customer.subscription.deleted",
            "invoice.payment_failed",
        ):
            update_user_plan_by_email(email, "free")

    return {"received": True}


# ---------------------------------------------------------
# Admin login + analytics
# ---------------------------------------------------------
@app.post("/admin/login")
def admin_login(body: AdminLoginRequest):
    if body.password != ADMIN_PASSWORD:
        return JSONResponse({"error": "Invalid admin password."}, status_code=401)

    token = create_admin_token()
    resp = JSONResponse({"success": True})
    resp.set_cookie(
        ADMIN_COOKIE_NAME,
        token,
        max_age=60 * 60 * 4,
        httponly=True,
        samesite="lax",
    )
    return resp


def _require_admin(request: Request) -> bool:
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    return bool(token and verify_admin_token(token))


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

    if not content and mode != "qr":
        return JSONResponse({"error": "content is empty"}, status_code=400)

    user = get_current_user(request)
    plan = user.get("plan", "free") if user else "guest"
    is_premium = plan == "premium"

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
        allowed, error_resp, guest_state = check_scan_limit(request, user)
        if not allowed:
            if not user and guest_state:
                _set_guest_state_cookie(error_resp, guest_state)
            return error_resp

        raw = analyze_text(content) or {}
        base_score = raw.get("score", 0)
        score = _normalize_score(base_score)

        verdict = raw.get("verdict")
        explanation = raw.get("explanation") or "Scam text analysis."
        reasons = raw.get("reasons", [])
        details = raw.get("details", {})

        resp_dict = build_response(
            score=score,
            category="text",
            reasons=reasons,
            explanation=explanation,
            verdict=verdict,
            details=details,
        )

        if resp_dict["verdict"] == "SAFE":
            record_event("safe")
        else:
            record_event("scam")

        add_scan_log(
            user_id=user["id"] if user else None,
            category="text",
            mode=mode,
            verdict=resp_dict["verdict"],
            score=resp_dict["score"],
            content_snippet=content,
            details=resp_dict.get("details"),
        )

        resp = JSONResponse(resp_dict)
        if not user and guest_state:
            _set_guest_state_cookie(resp, guest_state)
        return resp

    # --------------------- URL (auto) ---------------------
    if mode == "url" or (mode == "auto" and url_like):
        allowed, error_resp, guest_state = check_scan_limit(request, user)
        if not allowed:
            if not user and guest_state:
                _set_guest_state_cookie(error_resp, guest_state)
            return error_resp

        raw = analyze_url(content) or {}
        base_score = raw.get("score", 0)
        score = _normalize_score(base_score)

        verdict = raw.get("verdict")
        explanation = raw.get("explanation") or "URL risk analysis."
        reasons = raw.get("reasons", [])
        details = raw.get("details", raw)

        resp_dict = build_response(
            score=score,
            category="url",
            reasons=reasons,
            explanation=explanation,
            verdict=verdict,
            details=details,
        )

        if resp_dict["verdict"] == "SAFE":
            record_event("safe")
        else:
            record_event("scam")

        add_scan_log(
            user_id=user["id"] if user else None,
            category="url",
            mode=mode,
            verdict=resp_dict["verdict"],
            score=resp_dict["score"],
            content_snippet=content,
            details=resp_dict.get("details"),
        )

        resp = JSONResponse(resp_dict)
        if not user and guest_state:
            _set_guest_state_cookie(resp, guest_state)
        return resp

    # ----------------- AI Actor Detection -----------------
    if mode == "chat":
        allowed, error_resp, guest_state = check_scan_limit(request, user)
        if not allowed:
            if not user and guest_state:
                _set_guest_state_cookie(error_resp, guest_state)
            return error_resp

        result = analyze_actor(content)
        score = _normalize_score(result.get("ai_probability", 0))
        explanation = f"Detected actor type: {result.get('actor_type')}"
        reasons = result.get("signals", [])

        resp_dict = build_response(
            score=score,
            category="ai_detector",
            reasons=reasons,
            explanation=explanation,
            verdict=None,
            details=result,
        )

        add_scan_log(
            user_id=user["id"] if user else None,
            category="ai_detector",
            mode=mode,
            verdict=resp_dict["verdict"],
            score=resp_dict["score"],
            content_snippet=content,
            details=resp_dict.get("details"),
        )

        resp = JSONResponse(resp_dict)
        if not user and guest_state:
            _set_guest_state_cookie(resp, guest_state)
        return resp

    # -------------- Manipulation Profiler -----------------
    if mode == "manipulation":
        allowed, error_resp, guest_state = check_scan_limit(request, user)
        if not allowed:
            if not user and guest_state:
                _set_guest_state_cookie(error_resp, guest_state)
            return error_resp

        result = analyze_manipulation(content)
        score = _normalize_score(result.get("risk_score", 0))
        profile = result.get("scam_profile", "unclear")

        explanation = (
            "Emotional manipulation patterns detected."
            if score > 0
            else "No strong emotional manipulation detected."
        )

        reasons = result.get("primary_tactics", [])

        resp_dict = build_response(
            score=score,
            category="manipulation",
            reasons=reasons,
            explanation=explanation,
            verdict=None,
            details=result,
        )

        add_scan_log(
            user_id=user["id"] if user else None,
            category="manipulation",
            mode=mode,
            verdict=resp_dict["verdict"],
            score=resp_dict["score"],
            content_snippet=content,
            details=resp_dict.get("details"),
        )

        resp = JSONResponse(resp_dict)
        if not user and guest_state:
            _set_guest_state_cookie(resp, guest_state)
        return resp

    # Unknown mode
    return JSONResponse({"error": "Unsupported mode."}, status_code=400)


@app.post("/qr")
async def qr(request: Request, image: UploadFile = File(...)):
    record_event("request")

    user = get_current_user(request)
    plan = user.get("plan", "free") if user else "guest"
    is_premium = plan == "premium"

    # QR is premium-only
    if not is_premium:
        return JSONResponse(
            {
                "error": "QR scanning is available for Premium accounts only.",
                "plan": plan,
            },
            status_code=402,
        )

    allowed, error_resp, guest_state = check_scan_limit(request, user)
    if not allowed:
        if not user and guest_state:
            _set_guest_state_cookie(error_resp, guest_state)
        return error_resp

    img_bytes = await image.read()
    result = process_qr_image(img_bytes)

    verdict = result.get("overall", {}).get("combined_verdict", "SAFE")
    score = result.get("overall", {}).get("combined_risk_score", 0)

    if verdict == "SAFE":
        record_event("safe")
    else:
        record_event("scam")

    add_scan_log(
        user_id=user["id"] if user else None,
        category="qr",
        mode="qr",
        verdict=verdict,
        score=score,
        content_snippet=f"{result.get('count', 0)} QR code(s)",
        details=result,
    )

    resp = JSONResponse(result)
    if not user and guest_state:
        _set_guest_state_cookie(resp, guest_state)
    return resp