# backend/main.py

import os
import base64
from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .text_scanner import analyze_text
from .url_scanner import analyze_url

from groq import Groq
from .ai_detector.classify_actor import analyze_actor
from .manipulation.profiler import analyze_manipulation

from .qr_scanner.qr_engine import process_qr_image

from backend.analytics.analytics import record_event, get_analytics
from backend.auth import verify_password, create_session, verify_session, COOKIE_NAME

from backend.utils.reason_cleaner import clean_reasons


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
#                          UNIFIED ANALYZE REQUEST
# ======================================================================
class AnalyzeRequest(BaseModel):
    content: str
    mode: str = "auto"


# ======================================================================
#                         STANDARDIZED RESPONSE BUILDER
# ======================================================================
def build_response(score: int, category: str, reasons, explanation: str):
    if score >= 70:
        verdict = "DANGEROUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "score": score,
        "verdict": verdict,
        "category": category,
        "explanation": explanation,
        "reasons": clean_reasons(reasons or []),
    }


# ======================================================================
#                                 HEALTH
# ======================================================================
@app.get("/health")
def health():
    return {"status": "ok"}


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
            status_code=400
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
    #              TEXT ANALYSIS (AUTO if not URL)
    # ===============================================================
    is_url = content.startswith("http")

    if mode == "text" or (mode == "auto" and not is_url):
        raw = analyze_text(content)
        return build_response(
            score=raw["score"],
            category="text",
            reasons=raw.get("reasons", []),
            explanation="Scam text analysis.",
        )

    # ===============================================================
    #                 URL ANALYSIS (AUTO if URL)
    # ===============================================================
    if mode == "url" or is_url:
        raw = analyze_url(content)
        return build_response(
            score=raw["score"],
            category="url",
            reasons=raw.get("reasons", []),
            explanation="URL risk analysis.",
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


# ======================================================================
#                                ADMIN UI
# ======================================================================
@app.get("/admin")
def serve_admin():
    return FileResponse("backend/static/admin.html")


@app.get("/admin/analytics")
def analytics_admin():
    return get_analytics()


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