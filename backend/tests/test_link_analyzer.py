import socket

from app.analyzers.link_analyzer import analyze_links
from app.models import AnalyzeRequest


def test_link_analyzer_detects_risky_url_signals_without_fetching(monkeypatch) -> None:
    def fail_if_network_is_used(*args, **kwargs):
        raise AssertionError("link analyzer must not use network access")

    monkeypatch.setattr(socket, "create_connection", fail_if_network_is_used)
    request = AnalyzeRequest(
        plain_body="Please login at http://198.51.100.24/reset or https://bit.ly/case",
        html_body='<a href="http://198.51.100.24/reset">paypal.com</a>',
    )

    signals = analyze_links(request)
    signal_names = {signal.signal_name for signal in signals}

    assert "HTTP link" in signal_names
    assert "IP-based URL" in signal_names
    assert "Shortened URL" in signal_names
    assert "Anchor text domain differs from actual URL domain" in signal_names
    assert "Login/payment/security keyword near link" in signal_names
