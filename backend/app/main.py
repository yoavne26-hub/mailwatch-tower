"""FastAPI entrypoint for the MailWatch Tower backend."""

from fastapi import FastAPI

from app.models import AnalyzeRequest, AnalyzeResponse
from app.scoring.engine import score_email

app = FastAPI(
    title="MailWatch Tower Backend",
    description="Explainable email risk analysis service for the Gmail Add-on.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Return basic service health for local setup and deployment checks."""
    return {"status": "ok", "service": "MailWatch Tower backend"}


@app.post("/analyze", response_model=AnalyzeResponse, response_model_by_alias=True)
def analyze_email(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze an email using deterministic local risk signals."""
    return score_email(request)
