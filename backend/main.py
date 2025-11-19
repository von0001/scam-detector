# backend/main.py

import os
import base64
from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Text & URL scanners
from .text_scanner import analyze_text
from .url_scanner import analyze_url

# Groq-powered modules
from groq import Groq
from .ai_detector.classify_actor import analyze_actor
from .manipulation.profiler import analyze_manipulation

# QR scanner
from .qr_scanner.qr_engine import process_qr_image

# Analytics
from backend.analytics.analytics import record_event, get_analytics

# Auth
from backend.auth import verify_password, create_session, verify_session, COOKIE_NAME


app = FastAPI()


# ================================================================
# CORS
# ================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ================================================================
# Admin Authentication Middleware
# ================================================================
@app.middleware("http")
async def admin_protect(request: Request, call_next):
    path = request.url.path

    if path.startswith("/admin") and not path.startswith("/admin/login"):
        session = request.cookies.get(COOKIE_NAME)
        if not session or not verify_session(session):
            return RedirectResponse("/admin/login")

    return await call_next(request)


# ================================================================
# OCR (Groq Vision)
# ================================================================
@app.post("/ocr")
async def ocr(image: UploadFile = File(...)):
    record_event("ocr")

    img_bytes = await image.read()

    # Groq OCR
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    b64 = base64.b64encode(img_bytes).decode()

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

    extracted_text = response.choices[0].message["content"]
    return {"text": extracted_text.strip()}


# ================================================================
# QR Scanner Endpoint
# ================================================================
@app.post("/qr")
async def qr(image: UploadFile = File(...)):
    record_event("qr_scan")

    img_bytes = await image.read()
    return process_qr_image(img_bytes)


# ================================================================
# Analyze Request Model
# ================================================================
class AnalyzeRequest(BaseModel):
    content: str
    mode: str = "auto"


# ================================================================
# Verdict Builder
# ================================================================
def build_response(score: int, category: str, reasons, explanation: str):
    if score >= 30:
        verdict = "DANGEROUS"
    elif score >= 10:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "score": score,
        "verdict": verdict,
        "category": category,
        "explanation": explanation,
        "reasons": reasons or []
    }


# ================================================================
# Health Check
# ================================================================
@app.get("/health")
def health():
    return {"status": "ok"}


# ================================================================
# Universal Analyzer Endpoint
# ================================================================
@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    record_event("request")

    content = req.content.strip()
    mode = req.mode.lower()

    if not content:
        return JSONResponse({"error": "content is empty"}, status_code=400)

    # QR mode requires file upload
    if mode == "qr":
        return JSONResponse(
            {"error": "QR mode requires uploading an image to /qr"},
            status_code=400
        )

    # AI Detector
    if mode == "chat":
        raw = analyze_actor(content)
        score = raw.get("ai_probability", 0)

        return {
            "category": "chat",
            "score": score,
            "verdict": "DANGEROUS" if score >= 70 else "SUSPICIOUS" if score >= 30 else "SAFE",
            "explanation": f"Actor type detected: {raw.get('actor_type')}",
            "reasons": raw.get("signals", []),
            "details": raw
        }

    # Manipulation profiler
    if mode == "manipulation":
        raw = analyze_manipulation(content)
        score = raw.get("risk_score", 0)

        return {
            "category": "manipulation",
            "score": score,
            "verdict": "DANGEROUS" if score >= 70 else "SUSPICIOUS" if score >= 30 else "SAFE",
            "explanation": "Emotional manipulation patterns detected.",
            "reasons": raw.get("primary_tactics", []),
            "details": raw
        }

    # Text mode
    if mode == "text" or (mode == "auto" and not content.startswith("http")):
        raw = analyze_text(content)
        return build_response(
            score=raw["score"],
            category="text",
            reasons=raw.get("reasons", []),
            explanation="Scam text analysis."
        )

    # URL mode
    if mode == "url" or content.startswith("http"):
        raw = analyze_url(content)
        return build_response(
            score=raw["score"],
            category="url",
            reasons=raw.get("reasons", []),
            explanation="URL risk analysis."
        )

    # Unknown fallback
    return build_response(
        score=0,
        category="unknown",
        reasons=[],
        explanation="Unable to classify content."
    )


# ================================================================
# Admin Login
# ================================================================
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
            samesite="strict"
        )
        return response

    return JSONResponse({"error": "Invalid password"}, status_code=401)


# ================================================================
# Admin Dashboard
# ================================================================
@app.get("/admin")
def serve_admin():
    return FileResponse("backend/static/admin.html")


@app.get("/admin/analytics")
def analytics_admin():
    return get_analytics()


# ================================================================
# Frontend Pages
# ================================================================
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


# ================================================================
# Static Folder
# ================================================================
app.mount("/static", StaticFiles(directory="backend/static"), name="static")