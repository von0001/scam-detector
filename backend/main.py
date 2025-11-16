from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from PIL import Image
import pytesseract
import io

# Import scanners
from .text_scanner import analyze_text
from .url_scanner import analyze_url

# Analytics
from backend.analytics.analytics import record_event, get_analytics

# Auth
from backend.auth import verify_password, create_session, verify_session, COOKIE_NAME


app = FastAPI()

# -----------------------------
# CORS
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# ADMIN LOGIN PROTECTION MIDDLEWARE
# -----------------------------
@app.middleware("http")
async def admin_protect(request: Request, call_next):

    path = request.url.path

    # Protect admin pages EXCEPT the login page
    if path.startswith("/admin") and not path.startswith("/admin/login"):

        cookie = request.cookies.get(COOKIE_NAME)
        if not cookie or not verify_session(cookie):
            return RedirectResponse("/admin/login")   # redirect to login

    return await call_next(request)


# -----------------------------
# OCR ENDPOINT
# -----------------------------
@app.post("/ocr")
async def ocr(image: UploadFile = File(...)):
    record_event("ocr")

    img_bytes = await image.read()
    img = Image.open(io.BytesIO(img_bytes))
    text = pytesseract.image_to_string(img)

    return {"text": text.strip()}


# -----------------------------
# ANALYZE ENDPOINT
# -----------------------------
class AnalyzeRequest(BaseModel):
    content: str
    mode: str = "auto"

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    record_event("request")

    content = req.content.strip()
    mode = req.mode.lower()

    if not content:
        return JSONResponse({"error": "content is empty"}, status_code=400)

    # Text
    if mode == "text" or (mode == "auto" and not content.startswith("http")):
        result = analyze_text(content)

    # URL
    elif mode == "url" or content.startswith("http"):
        result = analyze_url(content)

    else:
        result = {
            "score": 0,
            "verdict": "SAFE",
            "category": "unknown",
            "reasons": [],
            "explanation": "Unable to classify."
        }

    # Record result type
    try:
        if result.get("score", 0) == 0:
            record_event("safe")
        else:
            record_event("scam")
    except:
        pass

    return result


# -----------------------------
# ADMIN LOGIN ROUTES
# -----------------------------
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
            max_age=86400,      # 24h
            httponly=True,
            samesite="strict"
        )
        return response

    return JSONResponse({"error": "Invalid password"}, status_code=401)


# -----------------------------
# ADMIN DASHBOARD + API
# -----------------------------
@app.get("/admin")
def serve_admin():
    return FileResponse("backend/static/admin.html")

@app.get("/admin/analytics")
def analytics_admin():
    return get_analytics()


# -----------------------------
# FRONTEND
# -----------------------------
@app.get("/")
def serve_frontend():
    return FileResponse("backend/static/index.html")


# -----------------------------
# STATIC FILES
# -----------------------------
app.mount("/static", StaticFiles(directory="backend/static"), name="static")