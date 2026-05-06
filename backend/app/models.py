"""Pydantic models for the MailWatch Tower backend API."""

from hashlib import sha256
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.config import get_settings
from app.utils.email_parsing import parse_email_field
from app.utils.text_utils import strip_html

CheckResult = Literal["passed", "failed", "warning", "not_available", "match", "no_match"]
CategoryStatus = Literal["passed", "warning", "failed", "not_available"]
FeedbackActionType = Literal["mark_trusted", "mark_malicious"]
IndicatorType = Literal[
    "sender_email",
    "sender_domain",
    "reply_to_domain",
    "url",
    "link_domain",
    "attachment_extension",
    "attachment_filename_pattern",
]
FeedbackLabel = Literal["trusted", "malicious"]


class AttachmentInput(BaseModel):
    """Attachment metadata sent by the Gmail Add-on."""

    filename: str = Field(default="", max_length=300)
    mime_type: str | None = Field(default=None, max_length=200)

    @field_validator("filename", "mime_type", mode="before")
    @classmethod
    def trim_string(cls, value: object) -> str | None:
        if value is None:
            return None
        return str(value).strip()


class UrlInput(BaseModel):
    """URL metadata extracted by the add-on or backend text parser."""

    url: str = Field(default="", max_length=2_000)
    source: str | None = Field(default=None, max_length=100)
    anchor_text: str | None = Field(default=None, max_length=500)
    surrounding_text: str | None = Field(default=None, max_length=1_000)

    @field_validator("url", "source", "anchor_text", "surrounding_text", mode="before")
    @classmethod
    def trim_string(cls, value: object) -> str | None:
        if value is None:
            return None
        return str(value).strip()


class AnalyzeRequest(BaseModel):
    """Sanitized email payload for analysis.

    The model accepts both the planned API shape and the earlier Gmail Add-on
    payload fields (`from`, `plain_body`, `html_body`) for compatibility.
    """

    model_config = ConfigDict(populate_by_name=True)

    message_id: str | None = Field(default=None, max_length=500)
    message_fingerprint: str | None = Field(default=None, max_length=128)
    user_scope: str | None = Field(default=None, max_length=200)

    sender_email: str | None = Field(default=None, max_length=320)
    sender_display_name: str | None = Field(default=None, max_length=300)
    from_header: str | None = Field(default=None, alias="from", max_length=1_000)
    reply_to: str | None = Field(default=None, max_length=1_000)
    return_path: str | None = Field(default=None, max_length=1_000)

    subject: str | None = Field(default=None)
    body_text: str | None = None
    plain_body: str | None = None
    html_body: str | None = None

    urls: list[UrlInput] = Field(default_factory=list)
    attachments: list[AttachmentInput] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator(
        "message_id",
        "message_fingerprint",
        "user_scope",
        "sender_email",
        "sender_display_name",
        "from_header",
        "reply_to",
        "return_path",
        mode="before",
    )
    @classmethod
    def trim_optional_string(cls, value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @field_validator("subject", mode="before")
    @classmethod
    def cap_subject(cls, value: object) -> str | None:
        if value is None:
            return None
        return str(value).strip()[: get_settings().max_subject_chars]

    @field_validator("body_text", "plain_body", "html_body", mode="before")
    @classmethod
    def cap_body_text(cls, value: object) -> str | None:
        if value is None:
            return None
        return str(value)[: get_settings().max_body_chars]

    @field_validator("urls", mode="before")
    @classmethod
    def normalize_url_inputs(cls, value: object) -> object:
        if not isinstance(value, list):
            return []
        limited = value[: get_settings().max_urls]
        normalized: list[Any] = []
        for item in limited:
            if isinstance(item, str):
                normalized.append({"url": item, "source": "payload"})
            else:
                normalized.append(item)
        return normalized

    @field_validator("attachments", mode="before")
    @classmethod
    def cap_attachments(cls, value: object) -> object:
        if isinstance(value, list):
            return value[: get_settings().max_attachments]
        return []

    @field_validator("headers", mode="before")
    @classmethod
    def normalize_headers(cls, value: object) -> dict[str, str]:
        if not isinstance(value, dict):
            return {}
        return {str(key).strip(): str(item).strip() for key, item in value.items()}

    @model_validator(mode="after")
    def fill_derived_fields(self) -> "AnalyzeRequest":
        if not self.body_text:
            html_text = strip_html(self.html_body)
            self.body_text = " ".join(part for part in [self.plain_body, html_text] if part)[: get_settings().max_body_chars]

        if not self.from_header:
            header_from = _case_insensitive_header(self.headers, "from")
            if header_from:
                self.from_header = header_from

        parsed_from = parse_email_field(self.from_header)
        if not self.sender_email and parsed_from.address:
            self.sender_email = parsed_from.address
        if not self.sender_display_name and parsed_from.display_name:
            self.sender_display_name = parsed_from.display_name

        if not self.reply_to:
            self.reply_to = _case_insensitive_header(self.headers, "reply-to")
        if not self.return_path:
            self.return_path = _case_insensitive_header(self.headers, "return-path")

        if not self.message_fingerprint:
            seed = "|".join(
                [
                    self.message_id or "",
                    self.sender_email or "",
                    self.subject or "",
                    (self.body_text or "")[:500],
                ]
            )
            self.message_fingerprint = sha256(seed.encode("utf-8", errors="ignore")).hexdigest()

        return self


class Check(BaseModel):
    """A drill-down check shown inside an analysis category."""

    name: str
    result: CheckResult
    points: int = 0
    explanation: str
    evidence_summary: str = ""
    indicator_type: IndicatorType | None = None
    indicator_value: str | None = None
    is_critical: bool = False


class FeedbackAction(BaseModel):
    """UI-ready trusted/malicious feedback action."""

    label: str
    action: FeedbackActionType
    indicator_type: IndicatorType
    indicator_value: str
    source_category: str


class CategoryDetail(BaseModel):
    """Drill-down category details for the Gmail Add-on."""

    title: str
    score: int
    max_score: int
    status: CategoryStatus
    short_summary: str
    checks: list[Check] = Field(default_factory=list)
    feedback_actions: list[FeedbackAction] = Field(default_factory=list)


class AppliedAdjustment(BaseModel):
    """Feedback or enrichment adjustment applied after base scoring."""

    type: str
    points: int
    explanation: str
    indicator_type: IndicatorType | None = None
    indicator_value: str | None = None


class AnalyzeResponse(BaseModel):
    """UI-ready analysis response."""

    analysis_id: str
    message_fingerprint: str
    final_score: int
    base_score: int
    verdict: str
    summary: str
    category_scores: dict[str, int]
    applied_adjustments: list[AppliedAdjustment]
    categories: dict[str, CategoryDetail]
    recommended_actions: list[str]

    # Backward-compatible fields for the current Apps Script MVP.
    score: int
    raw_score: int
    verdict_color: str
    category_breakdown: dict[str, int]
    signals: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class FeedbackRequest(BaseModel):
    """Request to save trusted or malicious user feedback."""

    message_fingerprint: str | None = Field(default=None, max_length=128)
    user_scope: str | None = Field(default=None, max_length=200)
    indicator_type: IndicatorType
    indicator_value: str = Field(min_length=1, max_length=2_000)
    label: FeedbackLabel
    source_category: str = Field(min_length=1, max_length=100)

    @field_validator("message_fingerprint", "user_scope", "indicator_value", "source_category", mode="before")
    @classmethod
    def trim_string(cls, value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class FeedbackResponse(BaseModel):
    saved: bool
    message: str
    recommended_reanalysis: bool = True


class Signal(BaseModel):
    """Compatibility model for older analyzer tests and responses."""

    model_config = ConfigDict(populate_by_name=True)

    category: str
    category_label: str
    category_color: str
    signal_name: str = Field(alias="name")
    severity: str
    points: int
    explanation: str


def _case_insensitive_header(headers: dict[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None
