# backend/main.py

import os
import base64
import re
from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.analytics.feedback import add_feedback, load_feedback

from .text_scanner import analyze_text
from .url_scanner import analyze_url

from groq import Groq
from .ai_detector.classify_actor import analyze_actor
from .manipulation.profiler import analyze_manipulation

from .qr_scanner.qr_engine import process_qr_image

from backend.analytics.analytics import record_event, get_analytics
from backend.auth import verify_password, create_session, verify_session, COOKIE_NAME

from backend.utils.reason_cleaner import clean_reasons
from backend.models import AnalyzeRequest  # use shared model


app = FastAPI()

# ======================================================================
#                                CORS
# ======================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ======================================================================
#                     ADMIN SESSION PROTECTION MIDDLEWARE
# ======================================================================
@app.middleware("http")
async def admin_protect(request: Request, call_next):
    path = request.url.path

    if path.startswith("/admin") and not path.startswith("/admin/login"):
        session = request.cookies.get(COOKIE_NAME)
        if not session or not verify_session(session):
            return RedirectResponse("/admin/login")

    return await call_next(request)


# ======================================================================
#                                   OCR
# ======================================================================
@app.post("/ocr")
async def ocr(image: UploadFile = File(...)):
    record_event("ocr")

    img_bytes = await image.read()
    b64 = base64.b64encode(img_bytes).decode()

    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    response = client.chat.completions.create(
        model="llava",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "Extract all text from this image."},
                    {"type": "input_image", "image_url": f"data:image/jpeg;base64,{b64}"},
                ],
            }
        ],
    )

    extracted = response.choices[0].message["content"].strip()
    return {"text": extracted}


# ======================================================================
#                                QR SCANNER
# ======================================================================
@app.post("/qr")
async def qr(image: UploadFile = File(...)):
    record_event("qr_scan")

    img_bytes = await image.read()

    # Handle base64 data URLs
    if img_bytes.startswith(b"data:image"):
        _, b64data = img_bytes.split(b",", 1)
        img_bytes = base64.b64decode(b64data)

    return process_qr_image(img_bytes)


# ======================================================================
#                         STANDARDIZED RESPONSE BUILDER
# ======================================================================

def _normalize_score(raw_score) -> int:
    """
    Normalize scores so UI stays consistent.

    - If score <= 10, treat it as a 0–10 risk index and scale to 0–100.
    - If score > 10, assume it's already on a larger scale (URL rules),
      just clamp to [0, 100].
    """
    try:
        s = float(raw_score)
    except (TypeError, ValueError):
        return 0

    if s <= 10:
        s = s * 10.0

    if s < 0:
        s = 0.0
    if s > 100:
        s = 100.0

    return int(round(s))


def build_response(
    score: int,
    category: str,
    reasons,
    explanation: str | None = None,
    verdict: str | None = None,
    details: dict | None = None,
):
    """
    Shared response builder.

    - Uses AI/model verdict if provided.
    - Otherwise, falls back to 30/70 score thresholds.
    """
    if verdict is None:
        if score >= 70:
            verdict = "DANGEROUS"
        elif score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

    if explanation is None:
        explanation = "Scam analysis."

    resp = {
        "score": int(score),
        "verdict": verdict,
        "category": category,
        "explanation": explanation,
        "reasons": clean_reasons(reasons or []),
    }

    if details is not None:
        resp["details"] = details

    return resp


# ======================================================================
#                        GOOGLE SEARCH CONSOLE VERIFY
# ======================================================================
@app.get("/google01a58a8eec834058.html")
def google_verification():
    file_path = os.path.join(os.path.dirname(__file__), "google01a58a8eec834058.html")
    return FileResponse(file_path)


# ======================================================================
#                                 HEALTH
# ======================================================================
@app.get("/health")
def health():
    return {"status": "ok"}


# URL-like detector for AUTO mode
URL_LIKE_RE = re.compile(r"^(https?://|www\.)\S+$", re.IGNORECASE)


# ======================================================================
#                             MEGA ANALYZE ENGINE
# ======================================================================
@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    record_event("request")

    content = req.content.strip()
    mode = req.mode.lower()

    if not content:
        return JSONResponse({"error": "content is empty"}, status_code=400)

    if mode == "qr":
        return JSONResponse(
            {"error": "QR mode requires uploading an image to /qr"},
            status_code=400,
        )

    # ===============================================================
    #                     AI DETECTOR MODE
    # ===============================================================
    if mode == "chat":
        raw = analyze_actor(content)
        score = raw.get("ai_probability", 0)

        return {
            "category": "chat",
            "score": score,
            "verdict":
                "DANGEROUS" if score >= 70 else
                "SUSPICIOUS" if score >= 30 else
                "SAFE",
            "explanation": f"Actor type detected: {raw.get('actor_type')}",
            "reasons": clean_reasons(raw.get("signals", [])),
            "details": raw,
        }

    # ===============================================================
    #                 MANIPULATION PROFILER MODE
    # ===============================================================
    if mode == "manipulation":
        raw = analyze_manipulation(content)
        score = raw.get("risk_score", 0)

        tactics_raw = raw.get("primary_tactics", []) or []
        tactics_clean = clean_reasons(tactics_raw)

        if score == 0 or not tactics_clean:
            explanation = "No manipulation detected."
            tactics_clean = ["No manipulation patterns detected."]
        else:
            explanation = "Emotional manipulation patterns detected."

        return {
            "category": "manipulation",
            "score": score,
            "verdict":
                "DANGEROUS" if score >= 70 else
                "SUSPICIOUS" if score >= 30 else
                "SAFE",
            "explanation": explanation,
            "reasons": tactics_clean,
            "details": raw,
        }

    # ===============================================================
    #            AUTO DETECTION: URL vs TEXT (SMARTER)
    # ===============================================================
    # "URL-like" if the whole content looks like a URL.
    is_url_like = bool(URL_LIKE_RE.match(content))

    # ===============================================================
    #              TEXT ANALYSIS (AUTO if not URL-like)
    # ===============================================================
    if mode == "text" or (mode == "auto" and not is_url_like):
        raw = analyze_text(content) or {}
        base_score = raw.get("score", 0)
        score = _normalize_score(base_score)

        verdict = raw.get("verdict")
        explanation = raw.get("explanation") or "Scam text analysis."
        reasons = raw.get("reasons", [])
        details = raw.get("details", {})

        return build_response(
            score=score,
            category="text",
            reasons=reasons,
            explanation=explanation,
            verdict=verdict,
            details=details,
        )

    # ===============================================================
    #                 URL ANALYSIS (AUTO if URL-like)
    # ===============================================================
    if mode == "url" or (mode == "auto" and is_url_like):
        raw = analyze_url(content) or {}
        base_score = raw.get("score", 0)
        score = _normalize_score(base_score)

        verdict = raw.get("verdict")
        explanation = raw.get("explanation") or "URL risk analysis."
        reasons = raw.get("reasons", [])
        # Hybrid URL scanner usually returns structured details
        details = raw.get("details", raw)

        return build_response(
            score=score,
            category="url",
            reasons=reasons,
            explanation=explanation,
            verdict=verdict,
            details=details,
        )

    # ===============================================================
    #                     FALLBACK (UNKNOWN MODE)
    # ===============================================================
    return build_response(
        score=0,
        category="unknown",
        reasons=[],
        explanation="Unable to classify content.",
    )


# ======================================================================
#                             ADMIN LOGIN
# ======================================================================
class LoginRequest(BaseModel):
    password: str


@app.get("/admin/login")
def login_page():
    return FileResponse("backend/static/login.html")


@app.post("/admin/login")
def login(req: LoginRequest):
    if verify_password(req.password):
        session = create_session()
        response = JSONResponse({"success": True})
        response.set_cookie(
            COOKIE_NAME,
            session,
            max_age=86400,
            httponly=True,
            samesite="strict",
        )
        return response

    return JSONResponse({"error": "Invalid password"}, status_code=401)


@app.post("/api/feedback")
async def submit_feedback(request: Request):
    body = await request.json()
    message = body.get("message", "")
    page = body.get("page", "unknown")

    if not message.strip():
        return JSONResponse({"error": "Empty feedback"}, status_code=400)

    add_feedback(
        message=message,
        page=page,
        ip=request.client.host,
        user_agent=request.headers.get("user-agent", "unknown"),
    )

    return {"success": True}


# ======================================================================
#                                ADMIN UI
# ======================================================================
@app.get("/admin")
def serve_admin():
    return FileResponse("backend/static/admin.html")


@app.get("/admin/analytics")
def analytics_admin():
    return get_analytics()


@app.get("/admin/feedback")
def get_feedback():
    return load_feedback()


# ======================================================================
#                           FRONTEND ROUTES
# ======================================================================
@app.get("/")
def serve_frontend():
    return FileResponse("backend/static/index.html")


@app.get("/privacy")
def serve_privacy():
    return FileResponse("backend/static/privacy.html")


@app.get("/terms")
def serve_terms():
    return FileResponse("backend/static/terms.html")


@app.get("/support")
def serve_support():
    return FileResponse("backend/static/support.html")


@app.get("/feedback")
def feedback_page():
    return FileResponse("backend/static/feedback.html")


# ======================================================================
#                                STATIC
# ======================================================================
app.mount("/static", StaticFiles(directory="backend/static"), name="static")