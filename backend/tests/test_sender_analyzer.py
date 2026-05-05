from app.analyzers.sender_analyzer import analyze_sender
from app.models import AnalyzeRequest


def test_sender_analyzer_detects_reply_to_mismatch() -> None:
    request = AnalyzeRequest(
        from_="Support <support@example.com>",
        reply_to="case@other-example.com",
    )

    signals = analyze_sender(request)

    assert "Reply-To mismatch" in {signal.signal_name for signal in signals}


def test_sender_analyzer_detects_free_provider_org_identity() -> None:
    request = AnalyzeRequest(from_="Finance Team <finance.team@gmail.com>")

    signals = analyze_sender(request)

    assert "Free email provider pretending to be an organization" in {
        signal.signal_name for signal in signals
    }
