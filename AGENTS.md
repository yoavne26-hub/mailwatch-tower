# AGENTS.md

Permanent project instructions for Codex and other coding agents working on MailWatch Tower.

## 1. Project Mission

MailWatch Tower is an interview home assignment for Upwind Security. It should feel like a real security analyst product, not just a technical prototype.

The core user question is:

> Is this email safe, suspicious, or dangerous, and why?

Every implementation choice should support a clear, credible Gmail Add-on demo where a user opens an email, runs the analysis, and quickly understands the risk, the evidence, and the recommended next action.

## 2. Product Principles

- Prefer a polished, explainable MVP over an unfinished overbuilt system.
- Every feature should support the live Gmail demo.
- Treat the Gmail Add-on as the first-class product surface.
- The backend should return structured, explainable analysis, not vague labels.
- Use careful language such as "risk indicators found" instead of "this is definitely malicious."
- Prioritize clarity, trust, and fast user understanding.
- Optimize for interview evaluation: product thinking, creativity, architecture, code quality, security awareness, and clear communication.

## 3. Architecture Principles

- The Gmail Add-on extracts only the minimum necessary email fields needed for analysis.
- The backend performs parsing, feature extraction, scoring, verdict mapping, and recommendations.
- The backend should be stateless.
- Do not store email contents.
- Keep analyzers modular and testable.
- Use clear boundaries between API models, analyzers, scoring engine, utilities, and UI code.
- Keep optional Gmail labeling separate from the read-only MVP because it requires broader Gmail permissions.
- Avoid coupling Gmail-specific rendering logic to backend scoring logic.
- Endpoint responses should be stable, explicit, and easy for the Gmail Add-on to render.

## 4. Security and Privacy Rules

- Treat emails, headers, URLs, attachment names, and all external input as untrusted.
- Never open, execute, or download attachments.
- Never visit or fetch suspicious URLs automatically.
- Do not log full email bodies, sensitive headers, authorization tokens, API keys, or secrets.
- Use environment variables for configuration.
- Keep secrets out of source code, documentation examples, screenshots, and test fixtures.
- Validate and limit input size before analysis.
- Safely parse malformed URLs and malformed email addresses.
- Prefer least-privilege Gmail scopes.
- Make security and privacy decisions explicit in README and project docs.
- Prefer deterministic local analysis over external services that would expose email content.

## 5. Scoring and Explainability Rules

- Use deterministic weighted scoring, not paid APIs or external LLM APIs.
- Every detected signal must include:
  - `category`
  - `category_label`
  - `category_color`
  - `signal_name`
  - `severity`
  - `points`
  - `explanation`
- Multiple different signals can be detected in one email and their weights should be summed.
- Do not count the same exact signal repeatedly just because a keyword appears many times.
- Cap the final score at `100`, but keep `raw_score` for transparency.
- Return `category_breakdown` showing points by category.
- Avoid overclaiming certainty. The product reports risk indicators and evidence, not absolute truth.
- Keep the scoring model readable enough to explain during a demo.

## 6. Visual UX Rules

Category color explains the type of risk signal. Verdict color explains overall risk severity.

Use these category colors:

| Category | Color |
| --- | --- |
| Sender identity | `#A67C52` |
| Links and URLs | `#0B3D91` |
| Attachments | `#E91E63` |
| Content/social engineering | `#000000` |
| Headers/authentication | `#6A1B9A` |
| Metadata/context | `#4A4A4A` |

Use these verdict colors:

| Verdict | Color |
| --- | --- |
| Safe | `#188038` |
| Low Risk | `#4FC3F7` |
| Suspicious | `#FBC02D` |
| High Risk | `#F57C00` |
| Dangerous | `#D93025` |

Gmail Add-on cards should make the score, verdict, summary, legend, detected signals, recommendations, and technical breakdown readable at a glance.

## 7. Backend Coding Standards

- Use Python 3.11+.
- Use FastAPI and Pydantic.
- Keep functions small and readable.
- Prefer explicit names over clever abstractions.
- Use type hints.
- Keep constants in dedicated files.
- Avoid unnecessary dependencies.
- Add tests for scoring behavior and edge cases.
- Make endpoint responses stable and easy for the Gmail Add-on to render.
- Keep analyzers deterministic and independently testable.
- Separate API models, analyzer modules, scoring engine, recommendation logic, and utility functions.

## 8. Gmail Add-on Coding Standards

- Use Google Apps Script and CardService unless explicitly changed.
- Keep the Gmail UI concise and readable.
- Show score, verdict, summary, legend, detected signals, recommendations, and technical breakdown.
- Show graceful error cards when backend calls fail.
- Do not request broader Gmail scopes unless needed for a clearly separated optional feature.
- Optional risk labels should be user-triggered, not automatic in the MVP.
- Keep read-only analysis as the default Gmail Add-on behavior.
- Do not expose raw sensitive email content in UI sections unless it is necessary for explanation.

## 9. README and Documentation Standards

- Treat README as part of the product.
- Explain what the project does and why it was built this way.
- Document architecture, scoring model, security and privacy choices, local setup, demo flow, limitations, and future work.
- Document trade-offs clearly.
- Keep writing professional, practical, and interview-ready.
- Make the live demo path easy to follow.
- Explain the difference between the read-only MVP and optional broader-permission features such as Gmail labeling.

## 10. Workflow Rules for Codex

- Before coding, briefly restate the task and identify files that will change.
- Do not introduce broad architectural changes unless requested.
- Prefer incremental, testable steps.
- After changes, summarize what was changed and how to test it.
- If a requested feature has security or privacy implications, call them out in the implementation summary.
- Do not add paid services or external APIs.
- Do not add Gmail code during backend-only tasks.
- Do not add backend code during Gmail-only tasks unless explicitly requested.
- Respect existing project structure and style once files exist.
- Do not rewrite unrelated files or revert user changes.

