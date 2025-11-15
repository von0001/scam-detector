from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.models import AnalyzeRequest, AnalyzeResponse
from backend.url_scanner import analyze_url
from backend.text_scanner import analyze_text

app = FastAPI()

# Allow frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    content = request.content.strip()

    if not content:
        raise HTTPException(status_code=400, detail="Content is empty.")

    # Determine mode
    if request.mode == "url":
        mode = "url"
    elif request.mode == "text":
        mode = "text"
    else:
        # Auto-detect
        looks_like_url = (
            ("http://" in content.lower())
            or ("https://" in content.lower())
            or ("www." in content.lower())
            or (" " not in content and "." in content)
        )
        mode = "url" if looks_like_url else "text"

    # Run correct scanner
    if mode == "url":
        result = analyze_url(content)
    else:
        result = analyze_text(content)

    score = result["score"]
    reasons = result.get("reasons", [])

    # Score → verdict
    if score <= 1:
        verdict = "SAFE"
    elif score <= 4:
        verdict = "SUSPICIOUS"
    else:
        verdict = "DANGEROUS"

    explanation = (
        "Flagged for: " + "; ".join(reasons)
        if reasons else
        "No strong scam signs detected (not a guarantee of safety)."
    )

    return AnalyzeResponse(
        category=mode,
        verdict=verdict,
        score=score,
        explanation=explanation,
        reasons=reasons
    )
