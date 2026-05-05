# Scoring Model

MailWatch Tower uses deterministic weighted scoring. It does not use paid APIs or external LLM APIs.

## Score Calculation

```text
score = min(100, sum(points from all detected signals))
```

`raw_score` keeps the uncapped sum for transparency.

Multiple different signals can be detected in one email and summed. The same exact signal should not be counted repeatedly just because a keyword appears many times.

Avoid certainty language. Use phrases such as "risk indicators found" rather than claiming that a message is definitely malicious.

## Verdict Thresholds

| Score | Verdict |
| --- | --- |
| 0-14 | Safe |
| 15-34 | Low Risk |
| 35-59 | Suspicious |
| 60-79 | High Risk |
| 80-100 | Dangerous |

## Verdict Colors

| Verdict | Color |
| --- | --- |
| Safe | `#188038` |
| Low Risk | `#4FC3F7` |
| Suspicious | `#FBC02D` |
| High Risk | `#F57C00` |
| Dangerous | `#D93025` |

## Signal Category Colors

Category color explains the type of risk signal. Verdict color explains overall risk severity.

| Category | Color |
| --- | --- |
| Sender identity | light brown `#A67C52` |
| Links and URLs | dark blue `#0B3D91` |
| Attachments | pink `#E91E63` |
| Content/social engineering | black `#000000` |
| Headers/authentication | purple `#6A1B9A` |
| Metadata/context | dark gray `#4A4A4A` |

## Planned Signal Weights

### Sender Identity

| Signal | Points |
| --- | ---: |
| Reply-To domain differs from From domain | +15 |
| Display name imitates a known brand | +15 |
| Free email provider pretending to be an organization | +12 |
| Sender domain appears typo-squatted | +15 |
| Sender domain mentioned in body does not match From domain | +10 |
| Suspicious sender formatting | +6 |

### Links and URLs

| Signal | Points |
| --- | ---: |
| HTTP link | +8 |
| IP-based URL | +15 |
| Shortened URL | +10 |
| Punycode domain | +15 |
| Suspicious TLD | +8 |
| More than 5 links | +7 |
| Anchor text domain differs from actual URL domain | +15 |
| Login/payment/security keyword near link | +10 |

### Attachments

| Signal | Points |
| --- | ---: |
| Executable-like extension | +20 |
| Macro-enabled Office file | +18 |
| Archive file | +10 |
| Double extension | +20 |
| Misleading filename | +12 |
| Attachment plus urgent/payment language | +10 |

### Content/Social Engineering

| Signal | Points |
| --- | ---: |
| Urgency language | +10 |
| Threat language | +10 |
| Credential request | +15 |
| Payment or wire transfer request | +12 |
| MFA/security reset lure | +12 |
| Fake invoice/order/payment lure | +10 |
| Delivery/package lure | +8 |
| HR/payroll lure | +10 |
| Generic greeting | +5 |
| Request to bypass normal process | +12 |

### Headers/Authentication

| Signal | Points |
| --- | ---: |
| DMARC fail | +15 |
| SPF fail | +10 |
| DKIM fail | +10 |
| Missing Authentication-Results header | +5 |
| From domain and Return-Path domain mismatch | +10 |

