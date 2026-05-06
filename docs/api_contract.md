# API Contract

This document describes the planned backend API for the Gmail Add-on UI and feedback-aware scoring model.

## GET /health

Purpose: check backend availability.

Example response:

```json
{
  "status": "ok",
  "service": "mailwatch-tower-backend",
  "version": "1.0.0"
}
```

## POST /analyze

Purpose: analyze sanitized email input and return a full UI-ready result for the Gmail Add-on.

### Request Fields

The add-on should send only minimum necessary fields:

- `message_id` or `message_fingerprint`
- `sender_email`
- `sender_display_name`
- `from_header`
- `reply_to`
- `return_path`
- `subject`
- `body_text`
- `urls`
- `attachments`
- `headers` and authentication fields where available

Example request:

```json
{
  "message_id": "gmail-message-id",
  "message_fingerprint": "sha256-normalized-message-fingerprint",
  "sender_email": "sender@example.com",
  "sender_display_name": "Example Support",
  "from_header": "Example Support <sender@example.com>",
  "reply_to": "reply@example.net",
  "return_path": "bounce@example.com",
  "subject": "Action required",
  "body_text": "Bounded plain text extracted by the add-on.",
  "urls": [
    {
      "url": "https://example.com/login",
      "source": "body",
      "anchor_text": "example.com"
    }
  ],
  "attachments": [
    {
      "filename": "invoice.pdf.exe",
      "mime_type": "application/octet-stream"
    }
  ],
  "headers": {
    "authentication_results": "spf=fail dkim=fail dmarc=fail",
    "received_spf": "fail"
  }
}
```

### Response Fields

The response must include:

- `analysis_id`
- `message_fingerprint`
- `final_score`
- `base_score`
- `verdict`
- `summary`
- `category_scores`
- `applied_adjustments`
- `categories`
- `recommended_actions`

Example response shape:

```json
{
  "analysis_id": "analysis_123",
  "message_fingerprint": "sha256-normalized-message-fingerprint",
  "final_score": 84,
  "base_score": 72,
  "verdict": "Dangerous",
  "summary": "This message was marked as Dangerous because multiple high-risk indicators were found across sender identity, links, content, and external intelligence.",
  "category_scores": {
    "sender_auth": 25,
    "links": 22,
    "attachments": 0,
    "content": 25,
    "external_intel": 12,
    "user_feedback": 0
  },
  "applied_adjustments": [
    {
      "type": "trusted_sender_reduction",
      "points": -8,
      "explanation": "Exact sender was trusted by the user, so sender identity heuristics were reduced. High-confidence signals were not suppressed."
    }
  ],
  "categories": {
    "sender_auth": {
      "title": "Sender & Authentication",
      "score": 25,
      "max_score": 25,
      "status": "failed",
      "short_summary": "Sender and authentication indicators require review.",
      "checks": [
        {
          "name": "Reply-To mismatch",
          "result": "failed",
          "points": 15,
          "explanation": "The Reply-To domain differs from the From domain, which may indicate reply redirection or impersonation.",
          "evidence_summary": "From domain: example.com; Reply-To domain: example.net"
        }
      ],
      "feedback_actions": [
        {
          "label": "Trust this sender",
          "action": "mark_trusted",
          "indicator_type": "sender_email",
          "indicator_value": "sender@example.com",
          "source_category": "sender_auth"
        },
        {
          "label": "Mark sender malicious",
          "action": "mark_malicious",
          "indicator_type": "sender_email",
          "indicator_value": "sender@example.com",
          "source_category": "sender_auth"
        }
      ]
    }
  },
  "recommended_actions": [
    "Do not click links or open attachments.",
    "Verify the request through a separate trusted channel.",
    "Report the message using your organization's phishing reporting process."
  ]
}
```

## Category Object Contract

Each category should include:

- `title`
- `score`
- `max_score`
- `status`
- `short_summary`
- `checks`
- `feedback_actions`

Allowed category statuses can include:

- `passed`
- `warning`
- `failed`
- `not_available`

## Check Contract

Each check should include:

- `name`
- `result`: `passed | failed | warning | not_available | match | no_match`
- `points`
- `explanation`
- `evidence_summary`

Evidence summaries should be safe for UI display. Do not include full email bodies or full URLs with sensitive query tokens.

## Feedback Action Contract

Each feedback action should include:

- `label`
- `action`: `mark_trusted | mark_malicious`
- `indicator_type`
- `indicator_value`
- `source_category`

Examples:

- Trust this sender
- Trust this URL
- Trust this domain
- Mark sender malicious
- Mark URL malicious
- Mark domain malicious

## POST /feedback

Purpose: save user trusted/malicious feedback for an indicator.

Request:

```json
{
  "message_fingerprint": "sha256-normalized-message-fingerprint",
  "indicator_type": "sender_email",
  "indicator_value": "sender@example.com",
  "label": "trusted",
  "source_category": "sender_auth"
}
```

Response:

```json
{
  "saved": true,
  "message": "Sender marked as trusted.",
  "recommended_reanalysis": true
}
```

After feedback, the Gmail Add-on should either show confirmation or re-run `/analyze` so the user can see the updated score and applied adjustments.

## Safe Browsing Enrichment

Safe Browsing is optional external enrichment:

- The backend, not Apps Script, calls Safe Browsing.
- The API key is stored in `SAFE_BROWSING_API_KEY`.
- The add-on never receives or stores the API key.
- If the key is missing, `/analyze` continues with local heuristics and returns enrichment status as `not_available`.
- Safe Browsing checks extracted URLs and may optionally check sender-domain URL form.
- No Safe Browsing match does not mean the URL is safe.

When enabled, extracted URLs may be sent to Google for known-threat checks. Email bodies and attachments are not sent to Safe Browsing.
