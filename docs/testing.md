# Testing and demonstration

## Automated suite

Run from the project root:

```powershell
python -m pytest -q
```

`tests/test_app.py` replaces the Ollama call with deterministic fixtures and creates an isolated temporary SQLite database per test. It covers:

- all five indicators, their evidence and one-count-per-category behavior;
- scoring, overlap adjustment and category boundaries;
- empty, malformed and oversized inputs;
- mocked AI success, unavailable service, invalid JSON, missing fields and out-of-range scores;
- CSRF rejection, SQLite persistence, history search/filter, detail pages, deletion and clear-all;
- JSON/TXT downloads and preservation of records during schema migration.

Latest verification: `python -m pytest -q` completed with **37 passed** using the selected Python 3.14 interpreter.

## Manual local demonstration

1. Install Ollama, start its local service, and pull the configured model.
2. Run `python app.py`; confirm the dashboard reports Ollama and the model status.
3. Use only synthetic or explicitly authorized messages. Try a clearly suspicious message, a benign-looking example, and ambiguous wording.
4. Explain the triggered rule excerpts, weights, overlap adjustment, final category and separate confidence value.
5. Confirm the scan appears in history; try search and category filtering, open details, export JSON/TXT, delete one scan, and confirm the clear-all prompt.
6. Stop Ollama and repeat a scan to confirm an incomplete result is shown without a misleading risk score or persisted successful scan.
7. Review the [dashboard](../screenshots/dashboard.png), [analysis result](../screenshots/analysis-result.png), and [history](../screenshots/scan-history.png) screenshots captured with a synthetic sample.

The automated tests use mocked responses. A live Ollama demonstration and a fresh-install check still require the local environment.
