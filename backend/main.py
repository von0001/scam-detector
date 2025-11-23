# main.py

from __future__ import annotations

from pathlib import Path
from typing import Optional, Literal, List

import os
import time

import stripe
from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from authlib.integrations.starlette_client import OAuth

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
    register_guest_scan,
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
)

# ---------------------------------------------------------
# FastAPI + static
# ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="ScamDetector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ---------------------------------------------------------
# External services: Stripe + Google OAuth
# ---------------------------------------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_MONTHLY = os.getenv("STRIPE_PRICE_MONTHLY", "")
STRIPE_PRICE_YEARLY = os.getenv("STRIPE_PRICE_YEARLY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "https://scamdetectorapp.com")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

oauth = OAuth()
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

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


class CheckoutSessionRequest(BaseModel):
    mode: Literal["monthly", "yearly"]  # billing interval


SUBSCRIPTION_WEBHOOK_SECRET = os.getenv("SUBSCRIPTION_WEBHOOK_SECRET", "change-this")


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def is_url_like(text: str) -> bool:
    lowered = text.strip().lower()
    return lowered.startswith(("http://", "https://", "www.")) or "." in lowered


def _normalize_score(score: int | float) -> int:
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
        }
    }


def _client_ip(request: Request) -> str:
    # Respect proxy headers if present (Railway / load balancer)
    xfwd = request.headers.get("x-forwarded-for")
    if xfwd:
        return xfwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _apply_free_tier_view(resp: dict, is_premium: bool) -> dict:
    """
    Free / guest users get:
      - shorter explanation
      - up to 3–5 reasons
      - no technical 'details' blob
    Premium sees the full thing.
    """
    if is_premium:
        return resp

    out = dict(resp)
    reasons = out.get("reasons") or []
    out["reasons"] = reasons[:5]

    explanation = out.get("explanation") or ""
    if len(explanation) > 280:
        out["explanation"] = explanation[:277] + "..."

    out["details"] = {}
    return out


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


@app.get("/login-admin")
def login_admin_page():
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/admin")
def admin_page(request: Request):
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token or not verify_admin_token(token):
        return FileResponse(STATIC_DIR / "login.html")
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/subscribe")
def subscribe_page():
    return FileResponse(STATIC_DIR / "subscribe.html")


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

    plan = user.get("plan", "free")
    if plan != "premium":
        limit = min(limit, 5)  # free: last 3–5 scans only

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

    user = update_user_plan_by_email(body.email, body.plan)
    if not user:
        return JSONResponse({"error": "User not found."}, status_code=404)

    return {"success": True, **_user_response(user)}


# ---------------------------------------------------------
# Google OAuth (Sign in with Google)
# ---------------------------------------------------------
@app.get("/auth/google/login")
async def google_login(request: Request):
    if "google" not in oauth:
        return JSONResponse(
            {"error": "Google login not configured."}, status_code=503
        )

    redirect_uri = request.url_for("google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google/callback")
async def google_callback(request: Request):
    if "google" not in oauth:
        return JSONResponse(
            {"error": "Google login not configured."}, status_code=503
        )

    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception:
        return JSONResponse(
            {"error": "Google authentication failed."}, status_code=400
        )

    userinfo = token.get("userinfo")
    if not userinfo:
        return JSONResponse(
            {"error": "No user info from Google."}, status_code=400
        )

    email = userinfo.get("email")
    if not email:
        return JSONResponse({"error": "No email from Google."}, status_code=400)

    user = get_or_create_google_user(email)

    access = create_access_token(user)
    refresh = create_refresh_token(user)

    resp = RedirectResponse(url="/")
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


# ---------------------------------------------------------
# Stripe subscription endpoints
# ---------------------------------------------------------
@app.post("/create-checkout-session")
def create_checkout_session(body: CheckoutSessionRequest, request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            {"error": "Sign in to start a subscription."}, status_code=401
        )

    if not STRIPE_SECRET_KEY:
        return JSONResponse(
            {"error": "Billing is not configured."}, status_code=503
        )

    if body.mode == "monthly":
        price_id = STRIPE_PRICE_MONTHLY
    else:
        price_id = STRIPE_PRICE_YEARLY

    if not price_id:
        return JSONResponse(
            {"error": "Price ID not configured."}, status_code=500
        )

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=user["email"],
            success_url=f"{FRONTEND_BASE_URL}/subscribe-success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{FRONTEND_BASE_URL}/subscribe?canceled=1",
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    return {"url": session.url}


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        # Safety: you can also return 503
        return JSONResponse({"error": "Webhook not configured."}, status_code=503)

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return JSONResponse({"error": "Invalid payload"}, status_code=400)
    except stripe.error.SignatureVerificationError:
        return JSONResponse({"error": "Invalid signature"}, status_code=400)

    event_type = event["type"]
    data = event["data"]["object"]

    # When checkout finishes successfully, upgrade to premium
    if event_type == "checkout.session.completed":
        email = (
            data.get("customer_details", {}) or {}
        ).get("email") or data.get("customer_email")
        if email:
            update_user_plan_by_email(email, "premium")

    # (Optional) handle subscription cancel events to downgrade

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
    user_id = user["id"] if user else None
    plan = user.get("plan", "free") if user else "guest"
    is_premium = plan == "premium"

    # Small artificial delay to make free feel "lighter" than Premium
    if not is_premium:
        time.sleep(1.0)

    url_like = is_url_like(content)

    # Premium-only modes from this endpoint
    premium_only_modes = {"chat", "manipulation"}
    if mode in premium_only_modes and not is_premium:
        return JSONResponse(
            {
                "error": "This scan mode is available for Premium accounts only.",
                "plan": plan,
            },
            status_code=402,
        )

    # Helper for rate limiting (free + guests)
    def _check_limit():
        if user:
            allowed, remaining, limit = register_scan_attempt(user_id)
        else:
            ip = _client_ip(request)
            allowed, remaining, limit = register_guest_scan(ip)

        if not allowed:
            return JSONResponse(
                {
                    "error": "Daily free limit reached. Create a free account and upgrade to Premium for more scans.",
                    "plan": plan,
                    "limit": limit,
                    "remaining": 0,
                },
                status_code=429,
            )
        return None

    # --------------------- TEXT (auto) --------------------
    if mode == "text" or (mode == "auto" and not url_like):
        limit_resp = _check_limit()
        if limit_resp is not None:
            return limit_resp

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

        resp = _apply_free_tier_view(resp, is_premium)

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
        limit_resp = _check_limit()
        if limit_resp is not None:
            return limit_resp

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

        resp = _apply_free_tier_view(resp, is_premium)

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

    # ----------------- AI Actor Detection (Premium only) -----------------
    if mode == "chat":
        limit_resp = _check_limit()
        if limit_resp is not None:
            return limit_resp

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

        resp = _apply_free_tier_view(resp, is_premium)

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

    # -------------- Manipulation Profiler (Premium only) -----------------
    if mode == "manipulation":
        limit_resp = _check_limit()
        if limit_resp is not None:
            return limit_resp

        result = analyze_manipulation(content)
        score = _normalize_score(result.get("risk_score", 0))

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

        resp = _apply_free_tier_view(resp, is_premium)

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
    if not user or user.get("plan") != "premium":
        return JSONResponse(
            {
                "error": "QR and image scanning are available for Premium accounts only.",
                "plan": user.get("plan", "guest") if user else "guest",
            },
            status_code=402,
        )

    user_id = user["id"]
    plan = user.get("plan", "free")

    allowed, remaining, limit = register_scan_attempt(user_id)
    if not allowed:
        return JSONResponse(
            {
                "error": "Daily limit reached. Your Premium plan should normally be unlimited — contact support if this persists.",
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

    result = _apply_free_tier_view(
        {
            "score": score,
            "category": "qr",
            "reasons": [],
            "explanation": f"Detected {result.get('count', 0)} QR code(s).",
            "verdict": verdict,
            "details": result,
        },
        is_premium=True,  # QR is premium-only anyway
    )

    return result