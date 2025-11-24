# main.py

from __future__ import annotations

from pathlib import Path
from typing import Optional, Literal, List

import os
from datetime import datetime

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


SUBSCRIPTION_WEBHOOK_SECRET = os.getenv("SUBSCRIPTION_WEBHOOK_SECRET", "change-this")


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
    # Optional separate URL to load login.html
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/admin")
def admin_page(request: Request):
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        return FileResponse(STATIC_DIR / "login.html")
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
