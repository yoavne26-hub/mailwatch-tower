# Scoring Model

MailWatch Tower scoring is deterministic, explainable, and category-based. It reports risk indicators found, not certainty.

Do not use wording such as "this email is definitely malicious", "this link is safe", or "Google confirmed this domain is safe." Prefer:

- "risk indicators found"
- "suspicious signals detected"
- "external threat intelligence reported a match"
- "no known Safe Browsing match found"

## Score Formula

```text
base_score =
  sender_auth_score
+ links_score
+ attachments_score
+ content_score
+ external_intel_score

feedback_adjusted_score =
  apply trusted feedback reductions
  apply malicious feedback penalties

final_score = min(100, max(0, feedback_adjusted_score))
```

The backend should also return `base_score`, category scores, applied adjustments, and enough check-level evidence to explain why the score changed.

## Category Caps

Category caps prevent one noisy category from dominating the entire result.

| Category | Max score |
| --- | ---: |
| Sender & Authentication | 25 |
| Links | 35 |
| Attachments | 25 |
| Content & Social Engineering | 30 |
| External Intelligence | 50 |

User feedback adjustments are documented separately. Malicious feedback has its own total cap to avoid duplicate inflation.

## Verdict Mapping

| Final score | Verdict |
| --- | --- |
| 0-19 | Safe |
| 20-39 | Low Risk |
| 40-59 | Suspicious |
| 60-79 | High Risk |
| 80-100 | Dangerous |

## Category Details

### Sender & Authentication

Examples:

- Sender display name resembles a known brand.
- Reply-To domain differs from sender domain.
- Return-Path differs from From domain.
- SPF, DKIM, or DMARC failure.
- Sender domain appears typo-squatted.

Trusted sender feedback can reduce sender-identity heuristics, but it cannot suppress major authentication failures, blacklist hits, dangerous attachment signals, or Safe Browsing matches.

### Links

Examples:

- HTTP link.
- IP-based URL.
- Shortened URL.
- Punycode domain.
- Suspicious TLD.
- Anchor text domain differs from actual href domain.
- Login/payment/security keywords near a URL.

URL/domain trust can reduce URL heuristics for the trusted indicator, but Safe Browsing and malicious feedback can override user trust.

### Attachments

Examples:

- Executable-like extension.
- Macro-enabled Office file.
- Archive file.
- Double extension.
- Misleading filename.
- Attachment plus urgent/payment language.

Attachments are never opened or executed. Analysis uses filename, extension, and MIME metadata only.

### Content & Social Engineering

Examples:

- Urgency language.
- Threat language.
- Credential request.
- Payment or wire transfer request.
- MFA/security reset lure.
- Invoice/order/payment lure.
- Delivery/package lure.
- HR/payroll lure.
- Generic greeting.
- Request to bypass normal process.

Repeated occurrences of the same signal should not repeatedly inflate the score.

### External Intelligence

External Intelligence is optional. The planned MVP uses Google Safe Browsing as backend-side enrichment.

- Safe Browsing match: high-confidence external indicator.
- No Safe Browsing match: report as `no_match`, not as "safe".
- Missing API key or unavailable service: report as `not_available` and continue with local heuristics.

## User Feedback Rules

### Trusted Sender

- If the exact sender email is trusted, sender identity score becomes `0`.
- Remaining heuristic score is reduced by `20%`.
- Trusted sender does not suppress:
  - Google Safe Browsing matches.
  - User blacklist matches.
  - Dangerous attachment signals.
  - Major authentication failures if present.

Reason: trusted accounts can be compromised and sender identity can be spoofed.

### Trusted URL or Domain

- If the exact URL is trusted, URL heuristic score for that URL becomes `0`.
- If the link domain is trusted, URL heuristic score for that domain is reduced or cleared depending on implementation.
- Google Safe Browsing wins if it contradicts user trust.
- If user trust conflicts with Safe Browsing, show:

```text
User marked this indicator as trusted, but external threat intelligence reported it as unsafe.
```

### Malicious Feedback

- If sender, domain, URL, or link domain was previously marked malicious, raise a visible flag.
- Add `+50` points to raw score for matched malicious feedback.
- Cap total malicious feedback contribution to avoid duplicate inflation.
- Suggested cap: `+50` or `+60` total from feedback blacklist hits.
- Multiple matched indicators should be listed in the explanation, even if score contribution is capped.

### Global Rule

User feedback can influence heuristic scoring, but it cannot silence high-confidence external or critical safety signals.

## Expected Response Transparency

The backend should return:

- `base_score`
- `final_score`
- `category_scores`
- `applied_adjustments`
- check-level explanations
- feedback conflicts
- Safe Browsing availability/match status when configured
