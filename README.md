# MailWatch Tower

Explainable malicious-email risk assessment for Gmail.

MailWatch Tower is a Gmail Add-on backed by a Python FastAPI analysis service. It analyzes the currently opened email and returns a maliciousness score, verdict, signal breakdown, explanations, recommended actions, and staged user feedback controls.

The core product question is:

> Is this email safe, suspicious, or dangerous - and why?

## Product Preview

<img src="screenshots/home-main-card.png" alt="MailWatch Tower home card" width="720">

*Home card explaining the product and privacy posture inside Gmail.*

<img src="screenshots/high-risk-example.png" alt="High-risk phishing-style email result" width="720">

*High-risk phishing-style email analyzed directly inside Gmail.*

<img src="screenshots/suspicious-example.png" alt="Suspicious newsletter example" width="720">

*Suspicious newsletter example before user validation feedback is applied.*

## Why This Project Exists

This project is an Upwind Security interview home assignment. The prompt is intentionally open-ended: build a Gmail Add-on, connect it to a backend service, and present an email maliciousness score with explainable reasoning.

MailWatch Tower does not claim perfect malware detection. The goal is to build a useful Gmail security assistant that shows risk indicators, explains what produced the score, and gives the user a fast way to review evidence before taking action.

## Key Features

- Gmail contextual add-on for the currently opened message.
- FastAPI backend analysis service.
- Maliciousness score from `0` to `100`.
- Verdicts: Safe, Low Risk, Suspicious, High Risk, Dangerous.
- Explainable category breakdown with check-level evidence.
- Sender and authentication analysis.
- Links and URL heuristics.
- Attachment metadata analysis.
- Content and social-engineering analysis.
- Optional Google Safe Browsing enrichment.
- Staged trusted/malicious feedback actions.
- SQLite-backed local indicator memory.
- No email body storage.
- No attachment execution.
- No automatic link visiting.

## Demo Walkthrough

### 1. High-risk phishing-style email

The high-risk sample uses the subject `Final warning: Account verification required`. It contains urgency, account-verification pressure, an IP-based HTTP login URL, and a suspicious attachment-like reference such as `invoice.pdf.exe`.

<img src="screenshots/high-risk-example.png" alt="High-risk phishing-style email result" width="720">

*The main card shows a strong score and High Risk verdict.*

<img src="screenshots/high-risk-example-bottom-screen.png" alt="High-risk result lower card content" width="720">

*The lower part of the result shows recommendations, applied context, and controls.*

<img src="screenshots/high-risk-example-links-drilldown.png" alt="Links and URLs drill-down for high-risk email" width="720">

*The Links & URLs drill-down explains individual URL indicators with points and evidence.*

<img src="screenshots/high-risk-example-links-drilldown-bottom-screen.png" alt="Links drill-down feedback actions" width="720">

*Feedback actions are staged. Nothing is applied until Refresh Analysis is pressed.*

<img src="screenshots/high-risk-example-malicious-markdown.png" alt="Malicious feedback staged for high-risk email" width="720">

*The user stages malicious feedback for the domain.*

<img src="screenshots/high-risk-example-verdict-after-markdown-dangerous.png" alt="Dangerous verdict after malicious feedback" width="720">

*After refresh, the backend applies stored malicious feedback and the verdict becomes Dangerous.*

This flow demonstrates explainability, category drill-downs, staged feedback, and local malicious-indicator memory.

### 2. Suspicious newsletter that can be validated

The suspicious newsletter sample uses the subject `Will AI Kill Cybersecurity Jobs? | Shahzaib in ILLUMINATION`. A legitimate newsletter can still trigger suspicious indicators because of links, forwarding infrastructure, return-path differences, or security-themed wording.

<img src="screenshots/suspicious-example.png" alt="Suspicious newsletter main result" width="720">

*The newsletter starts as Suspicious because several explainable indicators are present.*

<img src="screenshots/suspicious-example-author-drilldown.png" alt="Sender authentication drill-down for suspicious newsletter" width="720">

*The Sender & Authentication drill-down shows why the sender/authentication category contributed to the score.*

<img src="screenshots/suspicious-example-trust-markdown.png" alt="Trusted feedback staged for suspicious newsletter" width="720">

*The user stages trusted feedback for the sender or domain.*

<img src="screenshots/suspicious-example-verdict-after-markdown-safe.png" alt="Safe verdict after trusted feedback" width="720">

*After Refresh Analysis, trusted feedback is applied and the verdict updates to Safe.*

This flow shows that MailWatch Tower is not only punitive. It supports analyst-style validation and user-controlled trust decisions while still preserving critical signals.

### 3. Backend health check

<img src="screenshots/backend-health-status-check.png" alt="Backend health status check from Gmail Add-on" width="720">

*The Gmail Add-on can verify backend availability from inside the sidebar.*

The health check is useful during a live demo because it confirms that the deployed backend is reachable before analyzing a Gmail message.

## Architecture

```text
Gmail opened message
  -> Google Apps Script Gmail Add-on
  -> sanitized payload
  -> FastAPI backend
  -> analyzers
  -> scoring engine
  -> feedback adjustment
  -> optional Safe Browsing enrichment
  -> UI-ready JSON response
  -> Gmail card rendering
```

The Gmail Add-on:

- Extracts current-message fields only.
- Sends minimal data to the backend.
- Renders cards, drill-downs, recommendations, and buttons.
- Stages feedback actions locally until Refresh Analysis is pressed.

The backend:

- Validates the request payload.
- Runs sender/authentication, URL, attachment, content, and enrichment analyzers.
- Computes deterministic capped category scores.
- Applies trusted or malicious feedback memory.
- Optionally calls Google Safe Browsing for extracted URLs.
- Returns a UI-ready response for the Gmail card.

Storage:

- SQLite stores feedback indicators only.
- Email bodies are not stored.
- Attachment contents are not stored or opened.

See [docs/architecture.md](docs/architecture.md) for more detail.

## Backend API

The backend exposes:

- `GET /health` - returns service availability and version.
- `POST /analyze` - analyzes sanitized email input and returns a full UI-ready result.
- `POST /feedback` - stores trusted or malicious feedback indicators.

`POST /analyze` returns fields including:

- `final_score`
- `base_score`
- `verdict`
- `category_scores`
- `categories`
- `checks`
- `recommended_actions`
- `applied_adjustments`

Feedback is staged in the add-on and only submitted when the user presses Refresh Analysis. The add-on does not compute feedback impact locally; it submits pending actions to `/feedback`, then re-runs `/analyze` and trusts the backend result.

See [docs/api_contract.md](docs/api_contract.md).

## Scoring Model

MailWatch Tower uses deterministic capped weighted scoring. It does not use paid APIs or external LLM APIs.

```text
base_score =
  sender_auth_score
+ links_score
+ attachments_score
+ content_score
+ external_intel_score

final_score = min(100, max(0, feedback_adjusted_score))
```

Category caps:

| Category | Max score |
| --- | ---: |
| Sender & Authentication | 25 |
| Links & URLs | 35 |
| Attachments | 25 |
| Content & Social Engineering | 30 |
| External Intelligence | 50 |

Verdict mapping:

| Final score | Verdict |
| --- | --- |
| 0-19 | Safe |
| 20-39 | Low Risk |
| 40-59 | Suspicious |
| 60-79 | High Risk |
| 80-100 | Dangerous |

MailWatch Tower avoids certainty language. It reports "risk indicators", "suspicious signals", and "no known Safe Browsing match found." It does not claim absolute certainty about an email or URL.

See [docs/scoring_model.md](docs/scoring_model.md).

## Signal Categories and Colors

Category color explains the type of risk signal. Verdict color explains overall severity.

| Signal Category | Color | Meaning |
| --- | --- | --- |
| Sender identity | `#A67C52` | Sender/domain identity and trust context |
| Links and URLs | `#0B3D91` | URL/link risk indicators |
| Attachments | `#E91E63` | Attachment metadata risk |
| Content / social engineering | `#000000` | Urgency, credential, payment, and threat language |
| Headers / authentication | `#6A1B9A` | SPF, DKIM, DMARC, and header-related context |
| Metadata / context | `#4A4A4A` | External intelligence and feedback context |

Verdict colors:

| Verdict | Color |
| --- | --- |
| Safe | `#188038` |
| Low Risk | `#4FC3F7` |
| Suspicious | `#FBC02D` |
| High Risk | `#F57C00` |
| Dangerous | `#D93025` |

## Security and Privacy

Security decisions are part of the product, not an afterthought.

- Emails, URLs, attachments, and headers are treated as untrusted input.
- The add-on sends only current-message fields needed for analysis.
- The backend does not store email bodies.
- Attachment contents are not sent, opened, downloaded, or executed.
- Links are parsed but not visited automatically.
- Safe Browsing, when enabled, receives extracted URLs only.
- API keys are stored in environment variables, never in Apps Script or source code.
- Logs should avoid body text, sensitive headers, and full URLs with tokens.
- SQLite stores feedback indicators only.
- User trust does not override Safe Browsing matches or malicious feedback.

See [docs/security.md](docs/security.md).

## Google Safe Browsing

Google Safe Browsing is optional backend-side enrichment.

- It requires `SAFE_BROWSING_API_KEY`.
- If the key is missing, the backend still works with local heuristics and marks enrichment as `not_available`.
- A Safe Browsing match adds strong External Intelligence risk.
- A no-match result means "no known Safe Browsing match found", not "safe".
- The Gmail Add-on never receives or stores the API key.

When enabled, only extracted URLs are sent to Google Safe Browsing. Email bodies and attachments are not sent.

## Setup

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check the backend:

```bash
curl http://127.0.0.1:8000/health
```

### Render Deployment

Suggested Render settings:

| Setting | Value |
| --- | --- |
| Root Directory | `backend` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| Health Check Path | `/health` |

Environment variables:

- `DATABASE_URL` optional
- `SAFE_BROWSING_API_KEY` optional
- `LOG_LEVEL` optional
- `ADDON_SHARED_SECRET` optional future hardening control

### Gmail Add-on

1. Open [script.google.com](https://script.google.com).
2. Create a new Apps Script project.
3. Copy files from `addon/`.
4. Set Script Property:

```text
BACKEND_BASE_URL=https://mailwatch-tower.onrender.com
```

Use your deployed backend URL if different.

5. Deploy or test as a Gmail Add-on.
6. Open Gmail, open a message, and launch MailWatch Tower from the side panel.

Apps Script cannot call `localhost` or `127.0.0.1` from Gmail. For local backend testing, expose FastAPI through a public HTTPS tunnel such as ngrok or cloudflared.

See [docs/gmail-add-on-setup.md](docs/gmail-add-on-setup.md).

## Local Testing

Backend tests:

```bash
cd backend
python -m pytest tests --basetemp C:\Users\yoavn\pytest-mailwatch-tmp
```

The explicit `--basetemp` path avoids a Windows/OneDrive temp-directory permission issue seen during local testing.

Sample payloads live in `backend/examples/`:

- `safe_email.json`
- `suspicious_email.json`
- `malicious_email.json`

Useful checks:

- `GET /health`
- `POST /analyze` with a sample JSON payload
- `POST /feedback` followed by a second `/analyze`

Apps Script syntax can be checked locally with Node by piping each `.gs` file through `node --check --input-type=commonjs -`.

## Repository Structure

```text
backend/      FastAPI backend, analyzers, scoring, feedback storage, tests, examples
addon/        Google Apps Script Gmail Add-on files
docs/         Architecture, API, scoring, security, setup, and demo notes
screenshots/  Gmail Add-on screenshots used in this README
```

## Design Decisions and Trade-offs

- Deterministic scoring instead of ML: easier to explain, test, and demo.
- Gmail Add-on as the product surface: the user experience happens where the email is opened.
- Backend for analysis: keeps parsing, scoring, enrichment, and feedback behavior testable.
- Staged feedback instead of immediate refresh: gives users control before updating backend memory.
- SQLite for demo/local feedback memory: simple and transparent for the assignment.
- Optional Safe Browsing instead of paid APIs: useful external enrichment without making the product dependent on it.
- No attachment sandboxing: attachment execution is intentionally out of scope for a safe MVP.
- Render deployment: provides a stable HTTPS backend URL for Gmail and live demo use.

## Limitations

- Not a production phishing detector.
- Deterministic heuristics can produce false positives and false negatives.
- Safe Browsing no-match is not proof of safety.
- Gmail header availability may vary by message and add-on context.
- SQLite on Render free tier is not durable across restarts or redeploys unless configured with persistent storage.
- No attachment content scanning.
- No organization-wide policy or admin console.
- No ML model or LLM-based classification.

## Future Improvements

- Organization-level allow/block lists.
- Persistent managed database.
- Richer SPF/DKIM/DMARC and header parsing.
- Additional threat-intelligence sources.
- Admin policy controls.
- Better HTML anchor extraction.
- Sandboxed attachment analysis in a safe environment.
- Phishing reporting workflow integration.
- Per-tenant authentication between add-on and backend.

## Compact Demo Script

1. Show backend health from the add-on.
2. Open the MailWatch Tower home card.
3. Analyze the suspicious newsletter.
4. Drill into Sender & Authentication.
5. Stage trusted feedback and press Refresh Analysis.
6. Analyze the high-risk phishing-style sample.
7. Drill into Links & URLs.
8. Stage malicious feedback and press Refresh Analysis.
9. Explain architecture, deterministic scoring, Safe Browsing, security/privacy boundaries, and limitations.
