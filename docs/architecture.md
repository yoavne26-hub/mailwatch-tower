# Architecture

MailWatch Tower is built as a Gmail Add-on backed by a Python FastAPI analysis service. The Gmail Add-on is the product surface: it is what the user sees during the live demo, and it should make the answer to "Is this email safe, suspicious, or dangerous, and why?" clear within seconds.

## Components

- Gmail Add-on: extracts only the minimum necessary fields from the currently opened Gmail message and renders the analysis card.
- FastAPI backend: receives structured email metadata and body snippets, performs parsing, feature extraction, scoring, verdict mapping, and recommendations.
- Scoring engine: combines deterministic risk signals into a transparent score from 0 to 100.
- Analyzer modules: detect sender, link, attachment, content, header, and metadata risk indicators.

## Flow

```text
Gmail opened message
  -> Apps Script Add-on
  -> FastAPI /analyze
  -> scoring engine
  -> structured JSON
  -> Gmail card
```

## Design Decisions

- The Gmail Add-on is first-class because it is the user's actual product experience.
- The backend is stateless and does not store email contents.
- The add-on sends minimal email fields needed for analysis instead of full mailbox context.
- The backend must not visit URLs automatically.
- The backend must not open, download, execute, or scan attachments.
- Optional Gmail risk-labeling is separate from the read-only MVP because it requires broader Gmail permissions.
- Backend modules should stay testable and loosely coupled: API models, analyzers, scoring, recommendations, utilities, and UI rendering each have separate responsibilities.

