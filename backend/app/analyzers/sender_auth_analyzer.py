"""Sender and authentication analyzer."""

from app.analyzers.common import build_category
from app.models import AnalyzeRequest, CategoryDetail, Check, FeedbackAction
from app.scoring.config import CATEGORY_TITLES, KNOWN_BRANDS
from app.utils.email_parsing import get_header, parse_email_field


def analyze_sender_auth(request: AnalyzeRequest) -> CategoryDetail:
    """Analyze sender identity and available authentication headers."""
    sender = parse_email_field(request.sender_email or request.from_header)
    reply_to = parse_email_field(request.reply_to)
    return_path = parse_email_field(request.return_path or get_header(request.headers, "Return-Path"))
    display_name = (request.sender_display_name or sender.display_name or "").lower()
    checks: list[Check] = []

    if sender.domain and reply_to.domain and sender.domain != reply_to.domain:
        checks.append(
            Check(
                name="Reply-To domain mismatch",
                result="failed",
                points=10,
                explanation="The Reply-To domain differs from the sender domain, which may indicate reply redirection or impersonation.",
                evidence_summary=f"Sender domain: {sender.domain}; Reply-To domain: {reply_to.domain}",
                indicator_type="reply_to_domain",
                indicator_value=reply_to.domain,
            )
        )

    if sender.domain and return_path.domain and sender.domain != return_path.domain:
        checks.append(
            Check(
                name="Return-Path domain mismatch",
                result="warning",
                points=8,
                explanation="The Return-Path domain differs from the visible sender domain, which may indicate sender inconsistency.",
                evidence_summary=f"Sender domain: {sender.domain}; Return-Path domain: {return_path.domain}",
                indicator_type="sender_domain",
                indicator_value=sender.domain,
            )
        )

    for brand in KNOWN_BRANDS:
        if brand in display_name and sender.domain and brand not in sender.domain:
            checks.append(
                Check(
                    name="Suspicious display name",
                    result="warning",
                    points=8,
                    explanation="The display name references a known brand, but the sender domain does not appear to match that brand.",
                    evidence_summary=f"Display name references {brand}; sender domain: {sender.domain}",
                    indicator_type="sender_domain",
                    indicator_value=sender.domain,
                )
            )
            break

    auth_results = get_header(request.headers, "Authentication-Results") or get_header(request.headers, "authentication_results")
    received_spf = get_header(request.headers, "Received-SPF") or get_header(request.headers, "received_spf")
    if not auth_results and not received_spf:
        checks.append(
            Check(
                name="Authentication results unavailable",
                result="not_available",
                points=0,
                explanation="Authentication results were not available in the provided headers.",
                evidence_summary="SPF, DKIM, and DMARC could not be evaluated from the payload.",
            )
        )
    else:
        combined_auth = f"{auth_results or ''} {received_spf or ''}".lower()
        checks.extend(_authentication_checks(combined_auth))

    actions = _sender_feedback_actions(sender.address, sender.domain)
    return build_category(
        key="sender_auth",
        title=CATEGORY_TITLES["sender_auth"],
        checks=checks,
        feedback_actions=actions,
        empty_summary="No sender or authentication risk indicators were detected in the provided fields.",
        risk_summary="Sender or authentication indicators require review.",
    )


def _authentication_checks(auth_text: str) -> list[Check]:
    checks: list[Check] = []
    for name, token, points in (
        ("SPF fail", "spf=fail", 8),
        ("DKIM fail", "dkim=fail", 8),
        ("DMARC fail", "dmarc=fail", 12),
    ):
        if token in auth_text:
            checks.append(
                Check(
                    name=name,
                    result="failed",
                    points=points,
                    explanation=f"Authentication results indicate {name.split()[0]} failed. This may indicate sender spoofing or unauthorized sending infrastructure.",
                    evidence_summary=f"Authentication-Results contains {token}.",
                    is_critical=True,
                )
            )
        else:
            checks.append(
                Check(
                    name=name.replace("fail", "status"),
                    result="passed" if f"{token.split('=')[0]}=pass" in auth_text else "not_available",
                    points=0,
                    explanation=f"No {name.split()[0]} failure was found in the provided authentication headers.",
                    evidence_summary=f"Looked for {token}.",
                )
            )
    return checks


def _sender_feedback_actions(sender_email: str, sender_domain: str | None) -> list[FeedbackAction]:
    actions: list[FeedbackAction] = []
    if sender_email:
        actions.extend(
            [
                FeedbackAction(
                    label="Trust this sender",
                    action="mark_trusted",
                    indicator_type="sender_email",
                    indicator_value=sender_email,
                    source_category="sender_auth",
                ),
                FeedbackAction(
                    label="Mark sender malicious",
                    action="mark_malicious",
                    indicator_type="sender_email",
                    indicator_value=sender_email,
                    source_category="sender_auth",
                ),
            ]
        )
    if sender_domain:
        actions.extend(
            [
                FeedbackAction(
                    label="Trust this sender domain",
                    action="mark_trusted",
                    indicator_type="sender_domain",
                    indicator_value=sender_domain,
                    source_category="sender_auth",
                ),
                FeedbackAction(
                    label="Mark sender domain malicious",
                    action="mark_malicious",
                    indicator_type="sender_domain",
                    indicator_value=sender_domain,
                    source_category="sender_auth",
                ),
            ]
        )
    return actions
