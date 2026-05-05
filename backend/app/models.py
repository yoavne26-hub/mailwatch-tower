"""Pydantic models for the MailWatch Tower API contract."""

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import get_settings


class AttachmentInput(BaseModel):
    """Attachment metadata sent by the Gmail Add-on.

    The backend must never open, download, or execute attachments.
    """

    filename: str
    mime_type: str | None = None


class AnalyzeRequest(BaseModel):
    """Minimal email fields required for deterministic risk analysis."""

    model_config = ConfigDict(populate_by_name=True)

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

    @field_validator("plain_body", "html_body", mode="before")
    @classmethod
    def cap_body_text(cls, value: object) -> str | None:
        """Apply configured body length limits before analysis."""
        if value is None:
            return None
        settings = get_settings()
        return str(value)[: settings.max_body_chars]

    @field_validator("attachments", mode="before")
    @classmethod
    def cap_attachments(cls, value: object) -> object:
        """Limit attachment metadata items before analyzers see them."""
        if isinstance(value, list):
            return value[: get_settings().max_attachments]
        return value


class Signal(BaseModel):
    """Explainable risk signal returned to the Gmail Add-on."""

    model_config = ConfigDict(populate_by_name=True)

    category: str
    category_label: str
    category_color: str
    signal_name: str = Field(alias="name")
    severity: str
    points: int
    explanation: str


class AnalyzeResponse(BaseModel):
    """Structured analysis response returned by the backend."""

    model_config = ConfigDict(populate_by_name=True)

    score: int
    raw_score: int
    verdict: str
    verdict_color: str
    summary: str
    category_breakdown: dict[str, int]
    signals: list[Signal]
    recommendations: list[str]
    limitations: list[str]
