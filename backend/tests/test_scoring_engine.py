from app.models import AnalyzeRequest
from app.scoring.engine import analyze_email
from app.scoring.verdicts import verdict_for_score


def test_category_caps_and_final_score_clamp() -> None:
    request = AnalyzeRequest(
        sender_email="security@paypa1-security.xyz",
        sender_display_name="PayPal Security",
        reply_to="approval@example.net",
        return_path="bounce@example.net",
        subject="Urgent password reset invoice payment delivery payroll",
        body_text=(
            "Dear customer, verify your password and OTP immediately. "
            "Send payment for the invoice today. Your account will be suspended. "
            "Track the delivery and review payroll."
        ),
        urls=[
            {"url": "http://198.51.100.24/login", "surrounding_text": "verify password payment"},
            {"url": "https://bit.ly/pay", "surrounding_text": "payment"},
            {"url": "https://xn--pple-43d.com", "surrounding_text": "login"},
            {"url": "https://example.click/path", "surrounding_text": "security"},
            {"url": "https://one.example/a"},
            {"url": "https://two.example/a"},
        ],
        attachments=[{"filename": "invoice.pdf.exe", "mime_type": "application/octet-stream"}],
        headers={"Authentication-Results": "spf=fail dkim=fail dmarc=fail"},
    )

    result = analyze_email(request)

    assert result.categories["sender_auth"].score <= 25
    assert result.categories["links"].score <= 35
    assert result.categories["attachments"].score <= 25
    assert result.categories["content"].score <= 30
    assert 0 <= result.final_score <= 100
    assert result.verdict == "Dangerous"


def test_verdict_mapping() -> None:
    assert verdict_for_score(0)[0] == "Safe"
    assert verdict_for_score(20)[0] == "Low Risk"
    assert verdict_for_score(40)[0] == "Suspicious"
    assert verdict_for_score(60)[0] == "High Risk"
    assert verdict_for_score(80)[0] == "Dangerous"


def test_checks_include_points_and_explanations() -> None:
    result = analyze_email(
        AnalyzeRequest(
            sender_email="support@example.com",
            reply_to="case@example.net",
            headers={"Authentication-Results": "spf=fail"},
        )
    )

    checks = result.categories["sender_auth"].checks
    assert any(check.points > 0 for check in checks)
    assert all(check.explanation for check in checks)
    assert all(check.evidence_summary for check in checks)
