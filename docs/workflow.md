# Application workflow

## Email scan

1. The dashboard obtains an anti-CSRF token and checks whether the configured local Ollama service/model is available.
2. The user submits the sender, subject and body. Server-side validation enforces required fields, address shape and size limits.
3. The rule engine checks five documented indicators and captures a short excerpt for every match.
4. Flask submits the text as untrusted content to the local Ollama model with a bounded timeout. It requests JSON and validates required fields, types, score range and overlap IDs.
5. If the model is unavailable or its output is invalid, the dashboard reports an incomplete analysis without assigning a low-risk score or saving a successful scan.
6. Otherwise, each distinct rule signal contributes its documented weight, the rule subtotal is capped at 60, and the AI score (0–40) is adjusted by 10 points for each reported overlapping indicator.
7. Flask displays the score, category, confidence, evidence, score breakdown, uncertainty and next steps. It stores metadata and findings in SQLite, but not the body.

## History and reports

1. The history page loads scan metadata and accepts a parameterized sender/subject search and category filter.
2. A detail page loads a scan by ID and presents stored evidence and score contributions, including backward-compatible details for earlier records.
3. Individual deletion and clear-all operations require a CSRF token; the browser asks for confirmation before either action.
4. JSON and plain-text downloads include the timestamp, risk result, findings and recommendations, but not the email body.

## Scoring reference

| Indicator | Points |
|---|---:|
| Suspicious URL | 15 |
| Urgency/threat language | 10 |
| Credential request | 15 |
| Financial request | 10 |
| IP-literal/punycode sender domain | 10 |
| Rule subtotal cap | 60 |
| Raw AI assessment | 0–40 |
| Each AI-reported overlap | −10 AI points, no lower than zero |

Categories are Low (0–24), Medium (25–49), High (50–74), and Critical (75–100). The result is advisory, not a guarantee.
