# Limitations

MailWatch Tower is designed for an interview-ready demo and a clear MVP architecture. It is not a production secure email gateway.

## Product Limitations

- The product reports risk indicators, not definitive truth.
- A low score does not prove an email is safe.
- A high score indicates suspicious signals that require review.
- User feedback is local preference, not global threat intelligence.

## Technical Limitations

- Scoring is deterministic, not machine learning.
- Category weights and caps require tuning.
- Header availability can vary by Gmail/Add-on context.
- URL extraction can miss unusual formats.
- Domain normalization is subtle and must be implemented carefully.
- Safe Browsing checks known-threat lists and does not provide complete domain reputation.

## Security Limitations

- Attachments are not opened or scanned.
- Links are not automatically visited.
- The backend should not store email bodies.
- Feedback storage should be minimal and indicator-based.
- Safe Browsing, when enabled, receives extracted URLs for known-threat checks.

## Future Work

- Organization-wide allowlist/blocklist policy.
- Admin-managed feedback controls.
- Richer SPF/DKIM/DMARC and ARC parsing.
- More threat intelligence sources.
- Sandboxed attachment scanning in a separate explicitly permissioned service.
- Better evidence redaction for URLs with tokens.
- Deployment hardening for authentication, rate limits, and monitoring.
