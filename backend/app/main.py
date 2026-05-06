"""FastAPI entrypoint for the MailWatch Tower backend."""

from fastapi import FastAPI

from app.feedback.service import FeedbackService
from app.models import AnalyzeRequest, AnalyzeResponse, FeedbackRequest, FeedbackResponse
from app.scoring.engine import analyze_email

app = FastAPI(
    title="MailWatch Tower Backend",
    description="Explainable email risk analysis service for the Gmail Add-on.",
    version="1.0.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Return backend health for setup and add-on checks."""
    return {
        "status": "ok",
        "service": "mailwatch-tower-backend",
        "version": "1.0.0",
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_email_endpoint(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze sanitized email input and return UI-ready details."""
    return analyze_email(request)


@app.post("/feedback", response_model=FeedbackResponse)
def save_feedback(request: FeedbackRequest) -> FeedbackResponse:
    """Save trusted or malicious user feedback for an indicator."""
    return FeedbackService().save_feedback(request)
