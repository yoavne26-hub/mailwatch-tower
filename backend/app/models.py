"""Pydantic models for the planned MailWatch Tower API contract."""

from pydantic import BaseModel, Field


class AttachmentInput(BaseModel):
    """Attachment metadata sent by the Gmail Add-on.

    The backend must never open, download, or execute attachments.
    """

    filename: str
    mime_type: str | None = None


class AnalyzeRequest(BaseModel):
    """Minimal email fields required for deterministic risk analysis."""

    message_id: str | None = None
    subject: str | None = None
    from_: str | None = Field(default=None, alias="from")
    reply_to: str | None = None
    to: list[str] = Field(default_factory=list)
    date: str | None = None
    plain_body: str | None = None
    html_body: str | None = None
    attachments: list[AttachmentInput] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)


class Signal(BaseModel):
    """Explainable risk signal returned to the Gmail Add-on."""

    category: str
    category_label: str
    category_color: str
    signal_name: str = Field(alias="name")
    severity: str
    points: int
    explanation: str


class AnalyzeResponse(BaseModel):
    """Planned structured analysis response.

    TODO: Populate from the scoring engine after analyzers are implemented.
    """

    score: int
    raw_score: int
    verdict: str
    verdict_color: str
    summary: str
    category_breakdown: dict[str, int]
    signals: list[Signal]
    recommendations: list[str]
    limitations: list[str]
