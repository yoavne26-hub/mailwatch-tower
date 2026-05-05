# API Contract

This document defines the planned MailWatch Tower backend API. The scaffold may expose placeholders before full analysis logic is implemented.

## GET /health

Response:

```json
{
  "status": "ok",
  "service": "MailWatch Tower backend"
}
```

## POST /analyze

Request:

```json
{
  "message_id": "string or null",
  "subject": "string or null",
  "from": "string or null",
  "reply_to": "string or null",
  "to": ["string"],
  "date": "string or null",
  "plain_body": "string or null",
  "html_body": "string or null",
  "attachments": [
    {
      "filename": "string",
      "mime_type": "string or null"
    }
  ],
  "headers": {
    "header-name": "header-value"
  }
}
```

Response:

```json
{
  "score": 72,
  "raw_score": 72,
  "verdict": "High Risk",
  "verdict_color": "#F57C00",
  "summary": "Human-readable summary.",
  "category_breakdown": {
    "sender": 25,
    "links": 18,
    "attachments": 0,
    "content": 22,
    "headers": 7,
    "metadata": 0
  },
  "signals": [
    {
      "category": "sender",
      "category_label": "Sender Identity",
      "category_color": "#A67C52",
      "name": "Reply-To mismatch",
      "severity": "high",
      "points": 15,
      "explanation": "The Reply-To domain differs from the sender domain, which can indicate reply redirection or impersonation."
    }
  ],
  "recommendations": [
    "Do not click links or open attachments.",
    "Verify the request through a trusted channel.",
    "Report the message if it was unexpected."
  ],
  "limitations": [
    "MailWatch Tower does not open attachments or visit links.",
    "The score is based on risk indicators, not definitive malware confirmation."
  ]
}
```

## Contract Notes

- Request fields are untrusted input and must be validated and size-limited.
- `from` is represented as `from_` in Python models and serialized with the `from` alias.
- Signal `name` is the public API field; backend code may use `signal_name` internally for clarity.
- The backend should return stable response fields so the Gmail Add-on can render cards predictably.
- The score reports risk indicators found, not definitive malware confirmation.
