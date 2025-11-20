from typing import List, Literal
from pydantic import BaseModel, Field

class AnalyzeRequest(BaseModel):
    content: str = Field(..., min_length=1, description="Text or URL to analyze.")
    mode: Literal["auto", "url", "text", "chat", "manipulation"] = Field(
        "auto",
        description="Force mode manually or let backend auto-detect.",
    )

class AnalyzeResponse(BaseModel):
    category: Literal["url", "text"]
    verdict: Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]
    score: int
    explanation: str
    reasons: List[str]