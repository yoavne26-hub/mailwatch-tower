"""Header and authentication analyzer."""

from app.models import AnalyzeRequest, Signal
from app.scoring.weights import make_signal
from app.utils.email_parsing import get_header, parse_email_field


def analyze_headers(request: AnalyzeRequest) -> list[Signal]:
    """Detect email authentication and header consistency risk signals."""
    signals: list[Signal] = []
    auth_results = get_header(request.headers, "Authentication-Results")

    if auth_results is None:
        signals.append(make_signal("headers.missing_auth_results"))
    else:
        lowered = auth_results.lower()
        if "dmarc=fail" in lowered:
            signals.append(make_signal("headers.dmarc_fail"))
        if "spf=fail" in lowered:
            signals.append(make_signal("headers.spf_fail"))
        if "dkim=fail" in lowered:
            signals.append(make_signal("headers.dkim_fail"))

    return_path = get_header(request.headers, "Return-Path")
    from_domain = parse_email_field(request.from_).domain
    return_path_domain = parse_email_field(return_path).domain
    if from_domain and return_path_domain and from_domain != return_path_domain:
        signals.append(make_signal("headers.return_path_mismatch"))

    return signals
