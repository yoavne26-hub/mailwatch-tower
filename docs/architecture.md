# Architecture

MailWatch Tower is a Gmail Add-on backed by a Python FastAPI analysis service. The add-on is the user-facing product surface. The backend owns parsing, feature extraction, scoring, optional external enrichment, feedback adjustment, and response shaping for the Gmail UI.

This document describes the planned final backend design before the Python implementation is updated.

## High-Level Flow

```text
Gmail opened message
  -> Apps Script Gmail Add-on extracts minimum necessary fields
  -> Add-on sends sanitized payload to FastAPI backend
  -> Backend validates input
  -> Backend runs analyzers
  -> Backend applies scoring model
  -> Backend applies user feedback adjustments
  -> Backend optionally runs Google Safe Browsing enrichment
  -> Backend returns structured JSON
  -> Add-on renders main card and drill-down cards
  -> User can submit trusted/malicious feedback
  -> Backend stores feedback indicators
  -> Add-on can re-run analysis
```

## Product Boundary

- Gmail Add-on: product surface, user actions, CardService rendering, current-message field extraction.
- FastAPI backend: stateless analysis service for sanitized email payloads.
- SQLite feedback store: local demo/MVP persistence for trusted and malicious indicators.
- Optional Safe Browsing client: backend-only enrichment for extracted URLs.

The Gmail Add-on should receive UI-ready JSON. It should not need to run scoring logic, parse headers deeply, enrich URLs, or decide how feedback affects risk.

## Data Handling Boundaries

- The backend should not store email bodies.
- User feedback stores indicators only, not full email content.
- Attachments are never opened, executed, downloaded, or scanned.
- URLs are parsed, normalized, and optionally checked via Safe Browsing. They are not automatically visited.
- Safe Browsing, when enabled, receives extracted URLs for known-threat checks. Email bodies and attachments are not sent to Safe Browsing.

## Planned Backend Structure

```text
backend/
  app/
    main.py
    models.py

    analyzers/
      sender_auth_analyzer.py
      url_analyzer.py
      attachment_analyzer.py
      content_analyzer.py
      enrichment_analyzer.py

    scoring/
      engine.py
      config.py
      verdicts.py
      feedback_adjustments.py

    feedback/
      repository.py
      service.py
      normalization.py

    storage/
      database.py

  tests/
    test_scoring_engine.py
    test_feedback_adjustments.py
    test_safe_browsing_override.py
    test_blacklist_hits.py
    test_analyze_endpoint.py
```

## Module Responsibilities

| Module | Responsibility |
| --- | --- |
| `main.py` | FastAPI app, route registration, request/response orchestration. |
| `models.py` | Pydantic request/response models, category/check/action schemas. |
| `analyzers/sender_auth_analyzer.py` | Sender identity, Reply-To, Return-Path, SPF/DKIM/DMARC, display-name and domain consistency checks. |
| `analyzers/url_analyzer.py` | URL extraction, normalization, link-domain checks, suspicious URL heuristics, anchor mismatch checks. |
| `analyzers/attachment_analyzer.py` | Attachment metadata checks using filename, extension, and MIME type only. |
| `analyzers/content_analyzer.py` | Subject/body social engineering signals such as urgency, credential request, payment language, and process bypass. |
| `analyzers/enrichment_analyzer.py` | Optional backend-side Safe Browsing enrichment and enrichment status reporting. |
| `scoring/engine.py` | Category score aggregation, category caps, final score calculation, verdict selection, response summaries. |
| `scoring/config.py` | Category caps, signal weights, feedback caps, scoring constants. |
| `scoring/verdicts.py` | Verdict thresholds, verdict labels, verdict colors. |
| `scoring/feedback_adjustments.py` | Trusted indicator reductions, malicious indicator penalties, conflict handling with high-confidence signals. |
| `feedback/repository.py` | SQLite CRUD for feedback indicators. |
| `feedback/service.py` | Feedback business rules, hit matching, action result messages. |
| `feedback/normalization.py` | Normalize emails, domains, URLs, attachment patterns, and hashes before storage/matching. |
| `storage/database.py` | SQLite connection/session setup and local database initialization. |

## Gmail Add-on UI Compatibility

The backend response should support:

- Main analysis card summary.
- Category score widgets.
- Category drill-down cards.
- Trusted/malicious feedback action buttons.
- Re-analysis after feedback.
- Enough structured detail to render each category without additional backend calls.

Planned drill-down categories:

- Sender & Authentication
- Links & External Intelligence
- Attachments
- Content & Social Engineering
- User Feedback / Overrides

Each category should include a score, max score, status, short summary, checks, feedback actions, and evidence summaries safe for UI display.

## Design Constraints

- Keep the backend stateless for analysis. Feedback persistence is indicator storage, not message storage.
- Keep analyzers modular and independently testable.
- Keep optional Gmail labeling separate from the read-only MVP because labels require broader Gmail permissions.
- Do not introduce paid APIs or external LLM APIs.
- Document planned features as TODOs until implemented in code.

See [feedback_storage.md](feedback_storage.md) for the planned local SQLite feedback schema.
