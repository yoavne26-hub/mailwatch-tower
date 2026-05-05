# Gmail Add-on Setup

This guide explains how to run the MailWatch Tower Gmail Add-on MVP manually in Google Apps Script.

## Steps

1. Open [script.google.com](https://script.google.com).
2. Create a new Apps Script project.
3. Copy the files from `addon/` into the Apps Script project:
   - `appsscript.json`
   - `Code.gs`
   - `Cards.gs`
   - `ApiClient.gs`
   - `Config.gs`
   - `Labels.gs`
4. Set `BACKEND_BASE_URL` in `Config.gs` to the public HTTPS URL of the FastAPI backend.
5. For local backend testing, expose FastAPI through a public HTTPS URL such as ngrok or cloudflared, or deploy the backend to a public HTTPS environment.
6. Run or test the add-on in Gmail from Apps Script.
7. Open a Gmail message.
8. Open MailWatch Tower from the Gmail sidebar.
9. Confirm the card shows score, verdict, colored legend, detected signals, recommendations, technical breakdown, and limitations.

## Important Notes

- Apps Script cannot call `localhost` or `127.0.0.1` directly from Gmail. The backend must be reachable over public HTTPS.
- The MVP uses current-message readonly access.
- The MVP does not apply Gmail labels.
- Optional labels require broader Gmail permissions and are future work.
- The add-on sends minimal current-message fields to the backend and does not send attachment bytes.
- MailWatch Tower does not open attachments or visit links.
- Optional polish: replace `logoUrl` with a custom hosted MailWatch Tower watchtower icon.
