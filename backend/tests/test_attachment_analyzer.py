from app.analyzers.attachment_analyzer import analyze_attachments
from app.models import AnalyzeRequest


def test_attachment_analyzer_detects_double_extension() -> None:
    request = AnalyzeRequest(
        plain_body="Please review the invoice today.",
        attachments=[{"filename": "invoice.pdf.exe", "mime_type": "application/octet-stream"}],
    )

    signals = analyze_attachments(request)
    signal_names = {signal.signal_name for signal in signals}

    assert "Double extension" in signal_names
    assert "Executable-like extension" in signal_names
    assert "Attachment plus urgent/payment language" in signal_names
