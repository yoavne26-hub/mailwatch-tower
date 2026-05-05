"""Content and social engineering analyzer."""

from app.models import AnalyzeRequest, Signal
from app.scoring.weights import make_signal
from app.utils.text_utils import contains_any_pattern, normalized_text, strip_html

SIGNAL_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("content.urgency", (r"\burgent\b", r"\bimmediately\b", r"\bwithin\s+24\s+hours?\b", r"\btoday\b", r"\bexpires?\b", r"\bfinal notice\b")),
    ("content.threat", (r"\bsuspend(?:ed)?\b", r"\bterminate(?:d)?\b", r"\bclosed?\b", r"\blocked?\b", r"\bpenalt(?:y|ies)\b", r"\blose access\b")),
    ("content.credential_request", (r"\bpassword\b", r"\bcredential", r"\blog\s?in\b", r"\bsign\s?in\b", r"\bverify (?:your )?account\b", r"\bconfirm (?:your )?account\b")),
    ("content.payment_request", (r"\bwire transfer\b", r"\bbank transfer\b", r"\bpayment\b", r"\bpay\b", r"\biban\b", r"\bach\b")),
    ("content.mfa_security_reset", (r"\bmfa\b", r"\b2fa\b", r"\bmulti-factor\b", r"\bsecurity reset\b", r"\bpassword reset\b", r"\breset your password\b")),
    ("content.invoice_order_payment", (r"\binvoice\b", r"\border\b", r"\breceipt\b", r"\bpurchase\b", r"\bbilling\b")),
    ("content.delivery_package", (r"\bdelivery\b", r"\bpackage\b", r"\bshipment\b", r"\btracking\b", r"\bcourier\b")),
    ("content.hr_payroll", (r"\bpayroll\b", r"\bbenefits\b", r"\btax form\b", r"\bhuman resources\b", r"\bhr department\b")),
    ("content.generic_greeting", (r"\bdear customer\b", r"\bdear user\b", r"\bdear account holder\b", r"\bhello user\b", r"\bhi there\b")),
    ("content.bypass_process", (r"\bbypass\b", r"\boutside (?:the )?normal process\b", r"\bskip (?:the )?approval\b", r"\bdo not tell\b", r"\bkeep this confidential\b")),
)


def analyze_content(request: AnalyzeRequest) -> list[Signal]:
    """Detect body text risk signals from bounded, untrusted input."""
    text = normalized_text(request.subject, request.plain_body, strip_html(request.html_body))
    signals: list[Signal] = []

    for signal_id, patterns in SIGNAL_PATTERNS:
        if contains_any_pattern(text, patterns):
            signals.append(make_signal(signal_id))

    return signals
