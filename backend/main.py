from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .text_scanner import analyze_text
from .url_scanner import analyze_url

app = FastAPI()

# CORS (frontend + backend on same domain)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static frontend files
app.mount("/static", StaticFiles(directory="backend/static"), name="static")


class AnalyzeRequest(BaseModel):
    content: str
    mode: str = "auto"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    content = req.content.strip()
    mode = req.mode.lower()

    if not content:
        return JSONResponse({"error": "content is empty"}, status_code=400)

    if mode == "text" or (mode == "auto" and not content.startswith("http")):
        return analyze_text(content)

    if mode == "url" or content.startswith("http"):
        return analyze_url(content)

    return {
        "verdict": "SAFE",
        "category": "unknown",
        "reasons": [],
        "explanation": "Unable to classify."
    }


# ⭐ FRONTEND INDEX ROUTE ⭐
@app.get("/")
def serve_frontend():
    return FileResponse("backend/static/index.html")

from fastapi.staticfiles import StaticFiles

app.mount("/", StaticFiles(directory="backend/static", html=True), name="static")