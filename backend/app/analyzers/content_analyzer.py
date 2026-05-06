"""Content and social engineering analyzer."""

import re

from app.analyzers.common import build_category
from app.models import AnalyzeRequest, CategoryDetail, Check
from app.scoring.config import CATEGORY_TITLES, KNOWN_BRANDS
from app.utils.text_utils import normalized_text

PATTERNS: tuple[tuple[str, str, int, str, tuple[str, ...]], ...] = (
    ("Urgency or pressure language", "warning", 8, "The message uses urgency language to pressure quick action.", (r"\burgent\b", r"\bimmediately\b", r"\bwithin\s+24\s+hours?\b", r"\btoday\b", r"\bfinal notice\b")),
    ("Credential request", "failed", 12, "The message asks the user to provide, verify, or reset credentials.", (r"\bpassword\b", r"\bcredential", r"\blog\s?in\b", r"\bsign\s?in\b", r"\bverify (?:your )?account\b")),
    ("Password, OTP, MFA, or login lure", "warning", 10, "The message references password, OTP, MFA, or login workflows commonly used in phishing lures.", (r"\botp\b", r"\bmfa\b", r"\b2fa\b", r"\bpassword reset\b", r"\blogin\b")),
    ("Payment, invoice, or bank transfer request", "failed", 12, "The message requests payment, invoice handling, banking, or wire transfer activity.", (r"\bwire transfer\b", r"\bbank transfer\b", r"\binvoice\b", r"\bpayment\b", r"\biban\b", r"\bach\b")),
    ("Threat or account suspension language", "warning", 10, "The message uses threat or account suspension language that may pressure unsafe action.", (r"\bsuspend(?:ed)?\b", r"\bterminate(?:d)?\b", r"\block(?:ed)?\b", r"\blose access\b")),
    ("Delivery or package lure", "warning", 6, "The message references delivery or package tracking language commonly used as a lure.", (r"\bdelivery\b", r"\bpackage\b", r"\bshipment\b", r"\btracking\b")),
    ("HR or payroll lure", "warning", 8, "The message references HR or payroll themes commonly used in social engineering.", (r"\bpayroll\b", r"\bbenefits\b", r"\btax form\b", r"\bhuman resources\b")),
    ("Support impersonation language", "warning", 8, "The message uses support-team language that may indicate impersonation when combined with other signals.", (r"\bsupport team\b", r"\bhelpdesk\b", r"\bsecurity team\b", r"\baccount support\b")),
    ("Request to bypass normal process", "failed", 12, "The message asks the user to bypass normal process, a common social engineering tactic.", (r"\bbypass\b", r"\bskip (?:the )?approval\b", r"\boutside (?:the )?normal process\b", r"\bkeep this confidential\b")),
)


def analyze_content(request: AnalyzeRequest) -> CategoryDetail:
    """Detect social-engineering signals without over-counting repeats."""
    text = normalized_text(request.subject, request.body_text)
    checks: list[Check] = []

    for name, result, points, explanation, patterns in PATTERNS:
        matched = _first_match(text, patterns)
        if matched:
            checks.append(
                Check(
                    name=name,
                    result=result,  # type: ignore[arg-type]
                    points=points,
                    explanation=explanation,
                    evidence_summary=f"Matched phrase pattern: {matched}",
                )
            )

    for brand in KNOWN_BRANDS:
        if brand in text:
            checks.append(
                Check(
                    name="Brand impersonation hint",
                    result="warning",
                    points=6,
                    explanation="The message references a known brand. This is a weak content signal unless supported by sender or URL indicators.",
                    evidence_summary=f"Referenced brand: {brand}",
                )
            )
            break

    return build_category(
        key="content",
        title=CATEGORY_TITLES["content"],
        checks=checks,
        feedback_actions=[],
        empty_summary="No social-engineering content indicators were detected.",
        risk_summary="Content and social-engineering indicators require review.",
    )


def _first_match(text: str, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(0)
    return None
