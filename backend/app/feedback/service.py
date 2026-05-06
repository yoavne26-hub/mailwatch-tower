"""Feedback service for saving and matching trusted/malicious indicators."""

from app.config import get_settings
from app.feedback.repository import FeedbackIndicator, FeedbackRepository, default_repository
from app.models import AnalyzeRequest, FeedbackRequest, FeedbackResponse, IndicatorType
from app.utils.email_parsing import normalize_domain, parse_email_field
from app.utils.url_utils import hostname_for_url, normalize_url_for_analysis
from app.utils.url_utils import extract_urls_from_text


class FeedbackService:
    """High-level feedback operations."""

    def __init__(self, repository: FeedbackRepository | None = None) -> None:
        self.repository = repository or default_repository()

    def save_feedback(self, request: FeedbackRequest) -> FeedbackResponse:
        user_scope = request.user_scope or get_settings().default_user_scope
        self.repository.save(
            user_scope=user_scope,
            indicator_type=request.indicator_type,
            indicator_value=request.indicator_value,
            label=request.label,
            source_category=request.source_category,
        )
        subject = _friendly_indicator_name(request.indicator_type)
        label_text = "trusted" if request.label == "trusted" else "marked as malicious"
        return FeedbackResponse(
            saved=True,
            message=f"{subject} {label_text}.",
            recommended_reanalysis=True,
        )

    def matching_feedback(self, request: AnalyzeRequest) -> list[FeedbackIndicator]:
        user_scope = request.user_scope or get_settings().default_user_scope
        return self.repository.find_matches(user_scope=user_scope, indicators=extract_indicators(request))


def extract_indicators(request: AnalyzeRequest) -> list[tuple[IndicatorType, str]]:
    """Extract normalized feedback candidate indicators from an analysis request."""
    indicators: list[tuple[IndicatorType, str]] = []
    sender = request.sender_email or parse_email_field(request.from_header).address
    sender_domain = parse_email_field(sender).domain
    reply_domain = parse_email_field(request.reply_to).domain

    if sender:
        indicators.append(("sender_email", sender))
    if sender_domain:
        indicators.append(("sender_domain", sender_domain))
    if reply_domain:
        indicators.append(("reply_to_domain", reply_domain))

    for url_input in request.urls:
        if url_input.url:
            normalized_url = normalize_url_for_analysis(url_input.url)
            indicators.append(("url", normalized_url))
            domain = hostname_for_url(normalized_url)
            if domain:
                indicators.append(("link_domain", domain))

    for extracted_url in extract_urls_from_text(request.body_text):
        normalized_url = normalize_url_for_analysis(extracted_url)
        indicators.append(("url", normalized_url))
        domain = hostname_for_url(normalized_url)
        if domain:
            indicators.append(("link_domain", domain))

    for attachment in request.attachments:
        filename = attachment.filename.lower()
        parts = [part for part in filename.split(".") if part]
        if len(parts) > 1:
            indicators.append(("attachment_extension", parts[-1]))
        if filename:
            indicators.append(("attachment_filename_pattern", filename))

    deduped: list[tuple[IndicatorType, str]] = []
    seen: set[tuple[str, str]] = set()
    for indicator_type, value in indicators:
        normalized_value = normalize_domain(value) if indicator_type.endswith("domain") else value
        if not normalized_value:
            continue
        key = (indicator_type, normalized_value)
        if key not in seen:
            seen.add(key)
            deduped.append((indicator_type, normalized_value))
    return deduped


def _friendly_indicator_name(indicator_type: IndicatorType) -> str:
    return {
        "sender_email": "Sender",
        "sender_domain": "Sender domain",
        "reply_to_domain": "Reply-To domain",
        "url": "URL",
        "link_domain": "Domain",
        "attachment_extension": "Attachment extension",
        "attachment_filename_pattern": "Attachment filename pattern",
    }[indicator_type]
