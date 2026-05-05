# Security and Privacy

MailWatch Tower analyzes untrusted email data. Security and privacy decisions are part of the product, not implementation details to hide.

## Input Handling

- Emails, URLs, headers, attachment names, and body text are untrusted input.
- The backend should validate input and enforce size limits.
- Malformed URLs and malformed email addresses must be parsed safely.
- The Gmail Add-on should extract only the minimum fields needed for analysis.

## Data Handling

- The backend must not store email content.
- The backend must not log full email bodies.
- The backend must not log sensitive headers, secrets, tokens, or API keys.
- Configuration should use environment variables.
- Secrets must not be committed to source code.

## Network and Attachment Safety

- The backend must not visit URLs.
- The backend must not open, download, execute, or scan attachments.
- URL and attachment checks should use metadata and string analysis only.

## Gmail Permissions

- The Gmail Add-on should use least-privilege scopes.
- The MVP should remain read-only.
- Optional labeling requires broader Gmail permissions and should be separated from the read-only MVP.
- Optional risk labels should be user-triggered, not automatic.

