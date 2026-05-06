# Demo Script

## 1. Product Story

"MailWatch Tower helps a Gmail user understand whether an opened message contains malicious-email risk indicators, why the score was produced, and what to do next."

Position it as a security analyst assistant inside Gmail: fast, explainable, and careful about uncertainty.

## 2. Backend Health

- Open the backend `/health` endpoint.
- Show that the service is reachable.
- Mention that the Gmail Add-on calls this backend over HTTPS during the live demo.

## 3. Open Gmail With the Add-on

- Open a real Gmail account.
- Open the MailWatch Tower sidebar.
- Show the homepage card and backend health action.
- Explain that the add-on uses current-message readonly access for the MVP.

## 4. Analyze a Safe Email

- Open a normal project or university update email.
- Run analysis.
- Show low score and verdict.
- Show category breakdown.
- Drill into Sender & Authentication or Content & Social Engineering.
- Explain that no single signal proves safety. The product reports no major risk indicators found in the analyzed fields.

## 5. Analyze a Suspicious or Malicious Sample

- Open a suspicious/malicious sample email.
- Run analysis.
- Show high score and verdict.
- Drill into Links & External Intelligence.
- Show suspicious URL checks and Safe Browsing status if available.
- Drill into Content & Social Engineering.
- Show urgency, credential request, payment/request language, generic greeting, or process-bypass checks.
- Mention that attachments are evaluated by metadata only and are never opened.

## 6. Demonstrate Feedback

- Mark a sender, URL, or domain trusted/malicious.
- Re-run analysis.
- Show the updated score and applied adjustments.
- Explain why some signals cannot be overridden:
  - Safe Browsing matches still count.
  - User blacklist matches still count.
  - Dangerous attachment signals still count.
  - Major authentication failures still count.

Use the language: "User feedback can influence heuristic scoring, but it cannot silence high-confidence external or critical safety signals."

## 7. Walk Through Architecture

- The add-on extracts minimum necessary fields.
- The backend validates and analyzes the payload.
- Scoring is deterministic and category-based.
- Feedback is stored as indicators, not full emails.
- Safe Browsing is optional backend enrichment.
- No email bodies are stored.
- Attachments are not opened.
- Links are not automatically visited.

## 8. End With Trade-Offs

- Not production-grade.
- Deterministic, not ML.
- No attachment execution.
- No automatic link visiting.
- Safe Browsing is not a guarantee.
- Header availability can vary.

Future work:

- Organization-wide feedback.
- Richer authentication parsing.
- Admin policy controls.
- More threat intelligence sources.
- Sandboxed attachment scanning as a separate explicitly permissioned capability.
