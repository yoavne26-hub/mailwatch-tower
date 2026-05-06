# Security

MailWatch Tower analyzes untrusted email data. Security and privacy constraints are core product requirements.

## Untrusted Input

Treat all of the following as untrusted:

- Email body text.
- Subject lines.
- Headers.
- Sender and recipient fields.
- URLs and domains.
- Attachment filenames and MIME types.
- User feedback values.

The backend should validate and size-limit request payloads before analysis.

## Storage Boundaries

- Do not store full email bodies.
- Do not store attachment contents.
- Do not log body text.
- Do not log sensitive headers.
- Do not log full URLs with tracking tokens or secrets.
- Feedback storage should contain only normalized indicators needed for allowlist/blocklist behavior.

## URL Safety

- Do not visit links automatically.
- Parse URLs safely and defensively.
- Normalize domains carefully.
- Strip or hash sensitive URL components where possible.
- Safe Browsing checks are optional known-threat lookups, not proof that a URL is safe.

## Attachment Safety

- Do not open attachments.
- Do not download attachments.
- Do not execute attachments.
- Do not scan attachment contents in this MVP.
- Analyze only metadata such as filename, extension, and MIME type.

## Secrets and Configuration

- Keep API keys in environment variables.
- Do not commit secrets.
- The Safe Browsing key belongs on the backend only.
- The Gmail Add-on should never receive or store backend enrichment API keys.

Planned environment variables:

- `APP_ENV`
- `DATABASE_URL`
- `SAFE_BROWSING_API_KEY`
- `LOG_LEVEL`
- `ALLOWED_ORIGINS`
- `ADDON_SHARED_SECRET`

## Add-on to Backend Communication

The Gmail Add-on needs to call a public HTTPS backend. For demo use, a local tunnel is acceptable. For production-style deployment, add backend-side controls such as:

- HTTPS only.
- Allowed origins where applicable.
- Optional shared secret or signed request header.
- Request size limits.
- Structured error responses.

Apps Script OAuth scopes should remain least privilege. Gmail modification scopes are not required for the read-only analysis MVP.

## Feedback Security

User feedback is local preference, not global truth.

- Trusted sender feedback should not completely bypass critical signals.
- Trusted URL/domain feedback should not override Safe Browsing matches.
- Malicious feedback should be capped to prevent score inflation.
- Store minimal indicators.
- Normalize indicators before matching.
- Multiple matched malicious indicators can be shown even if the score contribution is capped.

Global rule: user feedback can influence heuristic scoring, but it cannot silence high-confidence external or critical safety signals.

## Privacy Trade-Offs for Safe Browsing

When Safe Browsing is enabled, extracted URLs may be sent to Google for known-threat checks. MailWatch Tower should not send full email bodies or attachments to Safe Browsing.

No Safe Browsing match should be displayed as "no known Safe Browsing match found", not "safe".

## Honest Limitations

- Deterministic scoring can miss novel attacks.
- Legitimate emails can contain suspicious-looking patterns.
- Header availability varies by Gmail/Add-on context.
- Safe Browsing coverage is not complete.
- This MVP is not a full secure email gateway.
