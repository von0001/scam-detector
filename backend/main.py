from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from text_scanner import analyze_text
from url_scanner import analyze_url

app = FastAPI()

# CORS (allows your frontend to call backend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve /static files
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
        return JSONResponse({"error": "Content cannot be empty"}, status_code=400)

    if mode == "text" or (mode == "auto" and not content.startswith("http")):
        return analyze_text(content)

    if mode == "url" or content.startswith("http"):
        return analyze_url(content)

    return {"verdict": "SAFE", "category": "unknown", "reasons": [], "explanation": "Could not classify"}

# SERVE THE FRONTEND
@app.get("/")
async def serve_home():
    return FileResponse("backend/static/index.html")
