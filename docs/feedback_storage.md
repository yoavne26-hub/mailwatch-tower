# Feedback Storage

MailWatch Tower feedback is planned as simple local SQLite storage for demo/MVP use. It stores indicators only, not email bodies.

## Table: `feedback_indicators`

| Column | Purpose |
| --- | --- |
| `id` | Primary key. |
| `user_scope` | Scope for the feedback, such as local demo user, Gmail account hash, or organization scope in future work. |
| `indicator_type` | Type of indicator being trusted or marked malicious. |
| `indicator_value` | Normalized indicator value when safe to store. |
| `indicator_value_hash` | Hash of the normalized indicator for sensitive values. |
| `label` | `trusted` or `malicious`. |
| `source_category` | Category where the action originated, such as `sender_auth` or `links`. |
| `created_at` | First time the indicator was saved. |
| `last_seen_at` | Most recent time the indicator matched analysis input. |
| `hit_count` | Number of times the indicator matched. |

## Allowed `indicator_type` Values

- `sender_email`
- `sender_domain`
- `reply_to_domain`
- `url`
- `link_domain`
- `attachment_extension`
- `attachment_filename_pattern`

## Allowed `label` Values

- `trusted`
- `malicious`

## Normalization Rules

Normalize before storing or matching:

- Lowercase email addresses and domains.
- Strip surrounding whitespace.
- Normalize domains to registrable comparison form where possible.
- Normalize URLs by lowercasing scheme/host, removing fragments, and avoiding unnecessary tracking query parameters.
- Hash sensitive full indicators when exact storage is not necessary.

## Privacy Guidance

- Do not store full email bodies.
- Do not store raw message HTML.
- Do not store attachment bytes.
- Avoid storing full URLs with tracking query parameters unless required for exact allowlist/blocklist behavior.
- Prefer normalized domains and hashes for sensitive values.
- Store only what is required to reproduce allowlist/blocklist behavior.

## Feedback Semantics

Trusted feedback reduces heuristic risk for matching indicators. It does not silence high-confidence or critical signals.

Malicious feedback raises a visible flag and adds score penalties up to the configured feedback cap. Multiple matched indicators should appear in explanations even when the score contribution is capped.
