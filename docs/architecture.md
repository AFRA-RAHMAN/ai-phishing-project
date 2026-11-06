# System architecture

The application keeps analysis local: the browser sends a form to Flask, Flask validates the fields, runs deterministic rules and requests structured JSON from the configured Ollama service. Only validated results are scored and persisted. SQLite stores scan metadata and findings, not email bodies.

```mermaid
flowchart LR
    U[User / browser] -->|sender, subject, body + CSRF token| F[Flask routes]
    F --> V[Server-side validation]
    V --> R[Deterministic rule engine]
    V -->|untrusted email text| O[Local Ollama service]
    O -->|structured JSON| J[Response validation]
    R --> S[Explainable score and category]
    J --> S
    S --> T[Results dashboard]
    S --> D[(SQLite scan metadata)]
    D --> H[History, details and JSON/TXT reports]
    H --> U
```

## Component responsibilities

- **Browser templates:** collect email text, show local service status, provide accessible analysis/loading/error/results views, and submit CSRF tokens for state-changing requests.
- **Flask application (`app.py`):** validate and normalize inputs, enforce request-size and CSRF checks, orchestrate analysis, render routes, report errors, and safely access SQLite using parameterized values.
- **Rule engine:** identify URL, urgency, credential, financial, and unusual sender-domain indicators. Each signal contributes at most once and exposes its evidence and weight.
- **Ollama:** analyze the untrusted email text locally and return the validated verdict, reasons, evidence, uncertainty, recommendations, confidence and AI score.
- **Scoring:** add the rule subtotal to the model score after deducting points for AI-reported overlaps. Confidence is displayed separately from risk.
- **SQLite:** preserve scan timestamp, sender, subject, score, category and findings; migration adds nullable analysis fields to existing databases without discarding rows. The submitted email body is not stored.

## Trust boundaries and privacy

Treat email content and model responses as untrusted. Do not follow URLs. Jinja templates escape interpolated values; SQL values are parameterized. Local processing does not secure the device or database. Keep `instance/*.db`, secrets and real message content out of source control.
