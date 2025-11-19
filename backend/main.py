# backend/main.py

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from PIL import Image
import io
import pytesseract

# Text & URL scanners
from .text_scanner import analyze_text
from .url_scanner import analyze_url

# New Groq-powered modules
from .ai_detector.classify_actor import analyze_actor
from .manipulation.profiler import analyze_manipulation

# QR scanner (OpenCV version)
from .qr_scanner.qr_engine import process_qr_image

# Analytics system
from backend.analytics.analytics import record_event, get_analytics

# Auth system
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
# OCR Endpoint
# ================================================================
@app.post("/ocr")
async def ocr(image: UploadFile = File(...)):
    record_event("ocr")

    img_bytes = await image.read()
    img = Image.open(io.BytesIO(img_bytes))
    text = pytesseract.image_to_string(img)

    return {"text": text.strip()}


# ================================================================
# QR Scanner Endpoint
# ================================================================
@app.post("/qr")
async def qr(image: UploadFile = File(...)):
    record_event("qr_scan")

    img_bytes = await image.read()
    result = process_qr_image(img_bytes)

    return result


# ================================================================
# Analyze Request Model
# ================================================================
class AnalyzeRequest(BaseModel):
    content: str
    mode: str = "auto"


# ================================================================
# Utility: Verdict builder
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

    # ----------------------------
    # QR MODE IS FILE-ONLY
    # ----------------------------
    if mode == "qr":
        return JSONResponse(
            {"error": "QR mode requires uploading an image to /qr"},
            status_code=400
        )

    # ----------------------------
    # AI / HUMAN DETECTOR
    # ----------------------------
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

    # ----------------------------
    # EMOTIONAL MANIPULATION PROFILER
    # ----------------------------
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

    # ----------------------------
    # TEXT MODE
    # ----------------------------
    if mode == "text" or (mode == "auto" and not content.startswith("http")):
        raw = analyze_text(content)
        response = build_response(
            score=raw["score"],
            category="text",
            reasons=raw.get("reasons", []),
            explanation="Scam text analysis."
        )

    # ----------------------------
    # URL MODE
    # ----------------------------
    elif mode == "url" or content.startswith("http"):
        raw = analyze_url(content)
        response = build_response(
            score=raw["score"],
            category="url",
            reasons=raw.get("reasons", []),
            explanation="URL risk analysis."
        )

    else:
        response = build_response(
            score=0,
            category="unknown",
            reasons=[],
            explanation="Unable to classify content."
        )

    # Analytics
    try:
        record_event("scam" if response["score"] else "safe")
    except:
        pass

    return response


# ================================================================
# Admin Login + Cookies
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
# Frontend Routes
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