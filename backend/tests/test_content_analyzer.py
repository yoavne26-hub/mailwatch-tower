from app.analyzers.content_analyzer import analyze_content
from app.models import AnalyzeRequest


def test_repeated_urgency_words_trigger_urgency_once() -> None:
    request = AnalyzeRequest(
        subject="Urgent urgent urgent",
        plain_body="This is urgent and must be handled immediately today.",
    )

    signals = analyze_content(request)
    urgency_signals = [
        signal for signal in signals if signal.signal_name == "Urgency language"
    ]

    assert len(urgency_signals) == 1
