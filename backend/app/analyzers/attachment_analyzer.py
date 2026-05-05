"""Attachment metadata analyzer."""

from pathlib import PurePosixPath

from app.models import AnalyzeRequest, Signal
from app.scoring.weights import make_signal
from app.utils.text_utils import contains_any_pattern, normalized_text, strip_html

EXECUTABLE_EXTENSIONS = {"exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "jar", "msi"}
MACRO_OFFICE_EXTENSIONS = {"docm", "xlsm", "pptm"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz"}
MISLEADING_KEYWORDS = ("invoice", "payment", "receipt", "order", "wire", "payroll")
URGENT_PAYMENT_PATTERNS = (
    r"\burgent\b",
    r"\bimmediately\b",
    r"\btoday\b",
    r"\bwire transfer\b",
    r"\bpayment\b",
    r"\binvoice\b",
)


def analyze_attachments(request: AnalyzeRequest) -> list[Signal]:
    """Detect attachment risk signals using filename and MIME metadata only."""
    found_signal_ids: set[str] = set()

    for attachment in request.attachments:
        filename = PurePosixPath((attachment.filename or "").replace("\\", "/")).name.lower()
        parts = [part for part in filename.split(".") if part]
        extension = parts[-1] if len(parts) > 1 else ""

        if extension in EXECUTABLE_EXTENSIONS:
            found_signal_ids.add("attachments.executable_extension")
        if extension in MACRO_OFFICE_EXTENSIONS:
            found_signal_ids.add("attachments.macro_office")
        if extension in ARCHIVE_EXTENSIONS:
            found_signal_ids.add("attachments.archive")
        if len(parts) >= 3:
            found_signal_ids.add("attachments.double_extension")
        if extension in ARCHIVE_EXTENSIONS and any(keyword in filename for keyword in MISLEADING_KEYWORDS):
            found_signal_ids.add("attachments.misleading_filename")

    if request.attachments:
        text = normalized_text(request.subject, request.plain_body, strip_html(request.html_body))
        if contains_any_pattern(text, URGENT_PAYMENT_PATTERNS):
            found_signal_ids.add("attachments.urgent_payment_language")

    return [make_signal(signal_id) for signal_id in sorted(found_signal_ids)]
