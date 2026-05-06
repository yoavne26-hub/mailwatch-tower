# MailWatch Tower

MailWatch Tower is an explainable Gmail Add-on plus Python FastAPI backend that analyzes the currently opened Gmail message and returns a maliciousness risk score, verdict, reasoning, category breakdown, and recommended actions.

The core product question is:

> Is this email safe, suspicious, or dangerous, and why?

## Overview

MailWatch Tower is designed as an interview-ready security analyst product, not just a technical prototype. The Gmail Add-on is the user-facing surface. The backend owns parsing, feature extraction, scoring, optional enrichment, feedback adjustment, and UI-ready response shaping.

The current codebase contains an implemented local deterministic backend MVP and a Gmail CardService add-on MVP. The documentation also describes the planned next backend design: category drill-down cards, user trusted/malicious feedback, local SQLite feedback storage, optional Google Safe Browsing enrichment, and re-analysis after feedback.

## Why This Project Exists

Email security tools often show opaque labels. MailWatch Tower focuses on clarity:

- What risk indicators were found?
- Which category contributed to the score?
- What evidence can the user inspect?
- What action should the user take next?
- Which signals are heuristic, user-adjusted, or external-intelligence based?

The project is evaluated on product thinking, creativity, architecture, code quality, security awareness, and communication.

## Architecture

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

Key design choices:

- The Gmail Add-on is the product surface.
- The backend is a stateless analysis service for email payloads.
- Email bodies are not stored.
- User feedback stores indicators only, not full email content.
- Attachments are never opened, executed, downloaded, or scanned.
- URLs are parsed and normalized. They may be checked through Safe Browsing when configured, but are not automatically visited.

See [docs/architecture.md](docs/architecture.md).

## Main Features

- Gmail sidebar homepage and contextual opened-message analysis.
- FastAPI backend with `/health` and `/analyze`.
- Planned `/feedback` endpoint for trusted and malicious indicators.
- Deterministic scoring with explainable category contributions.
- UI-ready response shape for main card and category drill-down cards.
- Category drill-down design:
  - Sender & Authentication
  - Links & External Intelligence
  - Attachments
  - Content & Social Engineering
  - User Feedback / Overrides
- Planned feedback actions:
  - Trust this sender
  - Trust this URL
  - Trust this domain
  - Mark sender malicious
  - Mark URL malicious
  - Mark domain malicious
- Optional Google Safe Browsing enrichment controlled by backend environment variables.

## Scoring Model Summary

MailWatch Tower uses deterministic weighted scoring. It does not use paid APIs or external LLM APIs.

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

Category caps prevent one noisy category from dominating:

| Category | Max |
| --- | ---: |
| Sender & Authentication | 25 |
| Links | 35 |
| Attachments | 25 |
| Content & Social Engineering | 30 |
| External Intelligence | 50 |

Verdicts:

| Score | Verdict |
| --- | --- |
| 0-19 | Safe |
| 20-39 | Low Risk |
| 40-59 | Suspicious |
| 60-79 | High Risk |
| 80-100 | Dangerous |

The product avoids certainty language. It reports "risk indicators found", "suspicious signals detected", and "external threat intelligence reported a match", not absolute claims.

See [docs/scoring_model.md](docs/scoring_model.md).

## API Overview

Planned backend endpoints:

- `GET /health`: backend availability and version.
- `POST /analyze`: analyze sanitized email input and return a full UI-ready result.
- `POST /feedback`: save trusted or malicious user feedback for an indicator.

The `/analyze` response is designed so the Gmail Add-on can render the main card, category score widgets, category drill-down buttons, feedback action buttons, recommendations, and limitations without making additional read calls.

See [docs/api_contract.md](docs/api_contract.md).

Feedback storage is planned as local SQLite indicator storage, not message storage. See [docs/feedback_storage.md](docs/feedback_storage.md).

## Security and Privacy

Security decisions are part of the product:

- Emails, URLs, attachments, and headers are untrusted input.
- Request payloads must be validated and size-limited.
- Full email bodies are not stored.
- Email body text, sensitive headers, secrets, and full URLs with tokens should not be logged.
- Attachments are never executed or opened.
- Links are not automatically visited.
- API keys stay in environment variables.
- User feedback is treated as local preference, not global truth.
- User trust cannot silence high-confidence external or critical safety signals.

See [docs/security.md](docs/security.md).

## Setup

Backend setup:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

For Gmail testing, the backend must be reachable over public HTTPS. Apps Script cannot call `localhost` or `127.0.0.1` from Gmail. Use a tunnel such as ngrok/cloudflared or deploy the backend.

Environment variables documented for the planned backend:

- `APP_ENV=local|demo|prod`
- `DATABASE_URL=sqlite:///mailwatch.db`
- `SAFE_BROWSING_API_KEY` optional
- `LOG_LEVEL=INFO`
- `ALLOWED_ORIGINS` optional
- `ADDON_SHARED_SECRET` planned optional backend-auth control

See [docs/setup.md](docs/setup.md) and [docs/gmail-add-on-setup.md](docs/gmail-add-on-setup.md).

## Testing

Backend tests live under `backend/tests`.

```bash
cd backend
python -m pytest
```

Planned next tests include feedback adjustments, blacklist hits, and Safe Browsing override behavior.

## Demo Guide

The live demo should show:

1. Backend health.
2. Gmail Add-on homepage.
3. Safe email analysis with low score and category breakdown.
4. Suspicious or malicious email analysis with drill-down details.
5. Links & External Intelligence and Content & Social Engineering categories.
6. Trusted/malicious feedback and re-analysis.
7. Security/privacy trade-offs.

See [docs/demo_script.md](docs/demo_script.md).

## Limitations

- MailWatch Tower is not production-grade.
- Scoring is deterministic, not ML-based.
- It does not execute attachments.
- It does not automatically visit links.
- Safe Browsing is optional and not a guarantee.
- User feedback influences local analysis but does not establish global truth.

See [docs/limitations.md](docs/limitations.md).

## Future Work

- Implement feedback persistence and `/feedback`.
- Add category drill-down response details.
- Add optional Safe Browsing enrichment.
- Add organization-wide feedback and admin policy controls.
- Add richer authentication parsing.
- Add more threat intelligence sources.
- Explore sandboxed attachment scanning as a separate, explicitly permissioned capability.
