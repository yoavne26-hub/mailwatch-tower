# MailWatch Tower

An explainable Gmail Add-on concept for analyzing the currently opened email and showing risk indicators, a maliciousness score, a verdict, and recommended user actions.

## Overview

MailWatch Tower is an interview home assignment for Upwind Security. The product goal is to make email risk understandable inside Gmail, with clear evidence rather than vague labels.

## Why This Project Exists

The core question is: "Is this email safe, suspicious, or dangerous, and why?"

The project is designed to demonstrate product thinking, architecture, code quality, security awareness, and clear communication in a compact MVP.

## Architecture

The Gmail Add-on is the user-facing product surface. It sends minimal email fields to a stateless Python FastAPI backend, which will analyze risk indicators and return structured JSON for rendering.

See [docs/architecture.md](docs/architecture.md).

## Product Experience

The add-on should show the score, verdict, explanation, category legend, detected signals, recommendations, and technical breakdown in a concise Gmail card.

## Scoring Model

MailWatch Tower uses deterministic weighted scoring. Multiple different risk signals are summed, the final score is capped at 100, and the uncapped `raw_score` is kept for transparency.

See [docs/scoring-model.md](docs/scoring-model.md).

## Security and Privacy

The backend must not store email contents, visit URLs, or open attachments. Inputs are treated as untrusted, and configuration belongs in environment variables.

See [docs/security-privacy.md](docs/security-privacy.md).

## Local Development

Backend dependencies are listed in `backend/requirements.txt`. The backend scaffold exposes a planned FastAPI app under `backend/app`.

```bash
cd backend
python -m venv .venv
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Copy `.env.example` to `.env` for local configuration when environment-specific settings are needed.

## Testing

Tests will live under `backend/tests`. The initial scaffold includes placeholders only; scoring tests should be added with the backend implementation.

```bash
cd backend
pytest
```

## Demo Flow

The demo should show a safe email first, then a suspicious or dangerous email with colored risk categories, recommendations, and a technical breakdown.

See [docs/demo-script.md](docs/demo-script.md).

## Limitations

- The initial scaffold does not implement the full scoring engine.
- The Gmail Add-on files are placeholders and do not yet render the production card.
- The planned MVP does not visit links or inspect attachment contents.

## Future Work

- Implement deterministic analyzers and scoring.
- Build the Gmail CardService UI.
- Add focused tests for scoring behavior and edge cases.
- Add optional user-triggered Gmail risk labels behind broader permissions.

