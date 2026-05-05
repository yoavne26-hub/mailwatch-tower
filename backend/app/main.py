"""FastAPI entrypoint for the MailWatch Tower backend.

This scaffold intentionally exposes only a health endpoint and a placeholder
analysis endpoint. The scoring engine will be implemented in a later step.
"""

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

from app.models import AnalyzeRequest

app = FastAPI(
    title="MailWatch Tower Backend",
    description="Explainable email risk analysis service for the Gmail Add-on.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Return basic service health for local setup and deployment checks."""
    return {"status": "ok", "service": "MailWatch Tower backend"}


@app.post("/analyze")
def analyze_email(request: AnalyzeRequest) -> JSONResponse:
    """Placeholder for the planned email analysis endpoint.

    TODO: Wire this endpoint to analyzers, deterministic scoring, verdict
    mapping, recommendations, and limitations.
    """
    _ = request
    return JSONResponse(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        content={
            "detail": "Email analysis is not implemented in the scaffold yet.",
        },
    )

