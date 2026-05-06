# Setup

This document covers local backend setup, environment configuration, optional enrichment, and Gmail Add-on demo setup.

## Backend Setup

From the repository root:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Swagger UI:

```text
http://127.0.0.1:8000/docs
```

## Environment Variables

Planned backend variables:

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `APP_ENV` | No | `local` | Runtime mode: `local`, `demo`, or `prod`. |
| `DATABASE_URL` | No | `sqlite:///mailwatch.db` | Local feedback indicator database. |
| `SAFE_BROWSING_API_KEY` | No | unset | Enables optional Google Safe Browsing URL checks. |
| `LOG_LEVEL` | No | `INFO` | Backend log level. |
| `ALLOWED_ORIGINS` | No | unset | Planned CORS/origin policy if needed for deployment. |
| `ADDON_SHARED_SECRET` | No | unset | Planned optional shared secret for add-on to backend requests. |

The existing `.env.example` can be extended when these planned features are implemented.

## SQLite Feedback Database

Planned MVP feedback storage uses local SQLite. If `DATABASE_URL` is omitted, the default should be:

```text
sqlite:///mailwatch.db
```

The implementation should provide an initialization path for the `feedback_indicators` table. Until implemented, treat this as a backend TODO.

## Optional Safe Browsing

Safe Browsing is optional. If `SAFE_BROWSING_API_KEY` is missing:

- The backend should continue local heuristic analysis.
- The response should mark enrichment as `not_available`.
- The Gmail Add-on should still render the result.

When configured, the backend may send extracted URLs to Google Safe Browsing for known-threat checks. Email bodies and attachments should not be sent.

## Gmail Add-on Setup

Apps Script cannot call `localhost` or `127.0.0.1` directly from Gmail. For a live Gmail demo, expose the backend through public HTTPS:

- ngrok
- cloudflared
- deployed backend service

Then copy files from `addon/` into Apps Script and set `BACKEND_BASE_URL` in `Config.gs`.

See [gmail-add-on-setup.md](gmail-add-on-setup.md).

## Demo Payloads

Sample emails live under:

```text
backend/sample_emails/
```

They can be used for local `/analyze` testing and demo preparation. Future feedback demos should add sample indicators for trusted sender, trusted URL/domain, and malicious URL/domain behavior.
