from app.models import AnalyzeRequest, Signal
from app.scoring.engine import _category_breakdown, score_email


def test_raw_score_can_exceed_100_while_score_is_capped() -> None:
    request = AnalyzeRequest(
        subject="Urgent PayPal security reset and payment",
        from_="PayPal Security <security@paypa1-security.xyz>",
        reply_to="approval@external.example",
        plain_body=(
            "Dear customer, verify your password immediately at "
            "http://198.51.100.24/login and send payment for the invoice today. "
            "Bypass the normal process."
        ),
        html_body='<a href="http://198.51.100.24/login">paypal.com</a>',
        attachments=[{"filename": "invoice.pdf.exe", "mime_type": "application/octet-stream"}],
        headers={
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
            "Return-Path": "approval@external.example",
        },
    )

    result = score_email(request)

    assert result.raw_score > 100
    assert result.score == 100
    assert result.verdict == "Dangerous"


def test_category_breakdown_equals_signal_points_by_category() -> None:
    signals = [
        Signal(category="sender", category_label="Sender Identity", category_color="#A67C52", name="A", severity="low", points=5, explanation="x"),
        Signal(category="sender", category_label="Sender Identity", category_color="#A67C52", name="B", severity="low", points=7, explanation="x"),
        Signal(category="links", category_label="Links and URLs", category_color="#0B3D91", name="C", severity="low", points=8, explanation="x"),
    ]

    breakdown = _category_breakdown(signals)

    assert breakdown["sender"] == 12
    assert breakdown["links"] == 8
    assert breakdown["attachments"] == 0


def test_header_failures_are_detected_by_scoring_engine() -> None:
    request = AnalyzeRequest(
        from_="Sender <sender@example.com>",
        headers={"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
    )

    result = score_email(request)
    signal_names = {signal.signal_name for signal in result.signals}

    assert {"SPF fail", "DKIM fail", "DMARC fail"} <= signal_names
