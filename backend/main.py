from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from PIL import Image
import pytesseract
import io

# Import scanners
from .text_scanner import analyze_text
from .url_scanner import analyze_url

# ⭐ Import analytics
from analytics.analytics import record_event, get_analytics

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
# OCR ENDPOINT
# -----------------------------
@app.post("/ocr")
async def ocr(image: UploadFile = File(...)):
    record_event("ocr")   # ⭐ analytics

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
    record_event("request")   # ⭐ analytics

    content = req.content.strip()
    mode = req.mode.lower()

    if not content:
        return JSONResponse({"error": "content is empty"}, status_code=400)

    # Text mode
    if mode == "text" or (mode == "auto" and not content.startswith("http")):
        result = analyze_text(content)

    # URL mode
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

    # ⭐ analytics for result type
    try:
        if result.get("score", 0) == 0:
            record_event("safe")
        else:
            record_event("scam")
    except:
        pass

    return result


# -----------------------------
# ANALYTICS DASHBOARD ENDPOINT
# -----------------------------
@app.get("/admin/analytics")
def analytics_admin():
    return get_analytics()


# -----------------------------
# FRONTEND (Index Route)
# -----------------------------
@app.get("/")
def serve_frontend():
    return FileResponse("backend/static/index.html")


# -----------------------------
# STATIC FILES (MOUNT LAST)
# -----------------------------
app.mount("/static", StaticFiles(directory="backend/static"), name="static")