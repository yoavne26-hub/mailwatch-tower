"""Attachment metadata analyzer."""

from pathlib import PurePosixPath

from app.analyzers.common import build_category
from app.models import AnalyzeRequest, CategoryDetail, Check, FeedbackAction
from app.scoring.config import ARCHIVE_EXTENSIONS, CATEGORY_TITLES, MACRO_OFFICE_EXTENSIONS, RISKY_EXECUTABLE_EXTENSIONS

MISLEADING_KEYWORDS = ("invoice", "payment", "receipt", "order", "wire", "payroll", "security")


def analyze_attachments(request: AnalyzeRequest) -> CategoryDetail:
    """Analyze attachment metadata only."""
    checks: list[Check] = []
    actions: list[FeedbackAction] = []
    seen: set[tuple[str, str]] = set()

    for attachment in request.attachments:
        filename = PurePosixPath((attachment.filename or "").replace("\\", "/")).name.lower()
        parts = [part for part in filename.split(".") if part]
        extension = parts[-1] if len(parts) > 1 else ""
        if extension:
            actions.append(
                FeedbackAction(
                    label="Mark attachment extension malicious",
                    action="mark_malicious",
                    indicator_type="attachment_extension",
                    indicator_value=extension,
                    source_category="attachments",
                )
            )
        if filename:
            actions.append(
                FeedbackAction(
                    label="Mark attachment filename pattern malicious",
                    action="mark_malicious",
                    indicator_type="attachment_filename_pattern",
                    indicator_value=filename,
                    source_category="attachments",
                )
            )

        if extension in RISKY_EXECUTABLE_EXTENSIONS:
            _append_unique(
                checks,
                seen,
                Check(
                    name="Executable-like attachment extension",
                    result="failed",
                    points=20,
                    explanation="An attachment filename has an executable-like extension. MailWatch Tower does not open attachments.",
                    evidence_summary=f"Attachment filename: {filename}",
                    indicator_type="attachment_extension",
                    indicator_value=extension,
                    is_critical=True,
                ),
            )
        if extension in MACRO_OFFICE_EXTENSIONS:
            _append_unique(
                checks,
                seen,
                Check(
                    name="Macro-enabled Office attachment",
                    result="failed",
                    points=18,
                    explanation="An attachment appears to be a macro-enabled Office document, which can carry risky automation.",
                    evidence_summary=f"Attachment filename: {filename}",
                    indicator_type="attachment_extension",
                    indicator_value=extension,
                    is_critical=True,
                ),
            )
        if extension in ARCHIVE_EXTENSIONS:
            _append_unique(
                checks,
                seen,
                Check(
                    name="Archive attachment",
                    result="warning",
                    points=10,
                    explanation="An attachment appears to be an archive file, which can hide file types from casual inspection.",
                    evidence_summary=f"Attachment filename: {filename}",
                    indicator_type="attachment_extension",
                    indicator_value=extension,
                ),
            )
        if len(parts) >= 3:
            _append_unique(
                checks,
                seen,
                Check(
                    name="Double extension attachment",
                    result="failed",
                    points=20,
                    explanation="An attachment filename uses multiple extensions, which can be used to disguise the true file type.",
                    evidence_summary=f"Attachment filename: {filename}",
                    indicator_type="attachment_filename_pattern",
                    indicator_value=filename,
                    is_critical=True,
                ),
            )
        if any(keyword in filename for keyword in MISLEADING_KEYWORDS) and extension in ARCHIVE_EXTENSIONS | RISKY_EXECUTABLE_EXTENSIONS:
            _append_unique(
                checks,
                seen,
                Check(
                    name="Misleading attachment filename",
                    result="warning",
                    points=12,
                    explanation="The attachment name combines lure wording with a file type that deserves caution.",
                    evidence_summary=f"Attachment filename: {filename}",
                    indicator_type="attachment_filename_pattern",
                    indicator_value=filename,
                ),
            )

    return build_category(
        key="attachments",
        title=CATEGORY_TITLES["attachments"],
        checks=checks,
        feedback_actions=_dedupe_actions(actions),
        empty_summary="No attachment metadata risk indicators were detected.",
        risk_summary="Attachment metadata indicators require review.",
    )


def _append_unique(checks: list[Check], seen: set[tuple[str, str]], check: Check) -> None:
    key = (check.name, check.indicator_value or check.evidence_summary)
    if key not in seen:
        checks.append(check)
        seen.add(key)


def _dedupe_actions(actions: list[FeedbackAction]) -> list[FeedbackAction]:
    unique: dict[tuple[str, str], FeedbackAction] = {}
    for action in actions:
        unique.setdefault((action.indicator_type, action.indicator_value), action)
    return list(unique.values())[:8]
