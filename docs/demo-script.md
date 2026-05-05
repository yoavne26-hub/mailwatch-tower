# Demo Script

## 1. Introduce MailWatch Tower

"MailWatch Tower is an explainable Gmail Add-on that helps answer one question while viewing an email: is this safe, suspicious, or dangerous, and why?"

## 2. Show a Safe Email

- Open a normal email in Gmail.
- Launch the MailWatch Tower add-on.
- Point out the score, verdict, short summary, and no or low risk indicators found.
- Emphasize that the UI avoids false certainty and explains what it did and did not find.

## 3. Show a Suspicious or Dangerous Email

- Open a sample suspicious or dangerous email.
- Run the analysis.
- Show the colored signal legend.
- Walk through detected signals, recommendations, and technical breakdown.
- Explain that category colors describe risk types while verdict colors describe overall severity.

## 4. Explain Architecture

- Gmail Add-on extracts minimal email fields.
- FastAPI backend performs deterministic local analysis.
- The backend returns structured JSON for the Gmail card.
- The backend is stateless and does not store email contents.

## 5. Explain Security and Privacy Choices

- MailWatch Tower does not visit links.
- MailWatch Tower does not open, download, execute, or scan attachments.
- Email content is treated as untrusted input.
- Optional Gmail labeling is separate because it requires broader permissions.

## 6. Close With Trade-Offs and Future Work

- The MVP favors explainability, privacy, and demo reliability over external enrichment.
- Future work could add user-triggered Gmail labels, richer header parsing, more brand impersonation checks, and organization-specific policy tuning.

