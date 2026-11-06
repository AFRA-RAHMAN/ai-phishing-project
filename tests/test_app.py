import json
import sqlite3

import ollama
import pytest

import app as detector


@pytest.fixture
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "test-scans.db"
    monkeypatch.setattr(detector, "DB_PATH", database_path)
    monkeypatch.setattr(
        detector,
        "get_ollama_status",
        lambda: {
            "available": True,
            "model_available": True,
            "model": detector.MODEL,
            "message": "Test Ollama is ready.",
        },
    )
    detector.init_db()
    detector.app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
    with detector.app.test_client() as test_client:
        yield test_client


def ai_response(
    score=0,
    *,
    overlaps=None,
    reasons=None,
    evidence=None,
    actions=None,
    confidence="Medium",
    uncertainty="The original message source is unavailable.",
):
    return {
        "message": {
            "content": json.dumps(
                {
                    "verdict": "Inconclusive",
                    "ai_score": score,
                    "confidence": confidence,
                    "reasons": reasons if reasons is not None else ["Test explanation"],
                    "evidence": evidence if evidence is not None else [],
                    "recommended_actions": (
                        actions if actions is not None else ["Verify independently."]
                    ),
                    "uncertainty": uncertainty,
                    "overlapping_indicators": overlaps if overlaps is not None else [],
                }
            )
        }
    }


def install_ai(monkeypatch, response=None):
    def fake_call(prompt):
        assert "untrusted_email" in prompt
        return response if response is not None else ai_response()

    monkeypatch.setattr(detector, "_call_ollama", fake_call)


def csrf_token(client):
    page = client.get("/")
    assert page.status_code == 200
    marker = 'name="csrf_token" value="'
    start = page.get_data(as_text=True).index(marker) + len(marker)
    return page.get_data(as_text=True)[start:].split('"', 1)[0]


def post_email(client, **overrides):
    data = {
        "csrf_token": csrf_token(client),
        "sender": "security@example.test",
        "subject": "Account update",
        "body": "Please review this notice.",
    }
    data.update(overrides)
    return client.post("/", data=data)


def persist_scan(sender="security@example.test", subject="Notice", body="Test"):
    result = detector.check_email(sender, subject, body)
    return detector.save_scan(sender, subject, result)


def test_five_rule_indicators_include_evidence_and_weights():
    findings = detector._rule_findings(
        "support@xn--paypa1-4ve.example",
        "URGENT: verify password",
        "Use https://example.invalid now to make a credit card payment.",
    )
    indicators = {finding["indicator"] for finding in findings}
    assert indicators == set(detector.RULE_WEIGHTS)
    assert all(finding["evidence"] and finding["score"] > 0 for finding in findings)
    assert sum(finding["score"] for finding in findings) == 60


def test_legitimate_text_has_no_rule_findings(monkeypatch):
    install_ai(monkeypatch)
    result = detector.check_email(
        "alex@example.test",
        "Meeting notes",
        "The meeting is scheduled for Thursday. Please review the attached agenda.",
    )
    assert result["rule_findings"] == []
    assert result["rule_score"] == 0
    assert result["score"] == 0
    assert result["category"] == "Low"


def test_model_confidence_is_separate_from_risk_score(monkeypatch):
    install_ai(
        monkeypatch,
        ai_response(
            20,
            confidence="Low",
            uncertainty="The sender identity cannot be confirmed from text.",
        ),
    )
    result = detector.check_email(
        "alex@example.test",
        "Follow-up",
        "Could you confirm whether the meeting time changed?",
    )
    assert result["score"] == 20
    assert result["category"] == "Low"
    assert result["ai"]["confidence"] == "Low"
    assert "cannot be confirmed" in result["ai"]["uncertainty"]


def test_ai_overlap_only_reduces_signals_found_by_rules(monkeypatch):
    install_ai(monkeypatch, ai_response(20, overlaps=["suspicious_url"]))
    result = detector.check_email(
        "alex@example.test",
        "Meeting notes",
        "Please review the agenda before Thursday.",
    )
    assert result["rule_findings"] == []
    assert result["score"] == 20
    assert result["score_breakdown"]["ai_overlap_penalty"] == 0
    assert result["ai"]["overlapping_indicators"] == []


def test_each_rule_indicator_is_reported_once():
    findings = detector._rule_findings(
        "alex@example.test",
        "Urgent urgent action",
        "Urgent action. Password and OTP needed. payment and payment. "
        "https://one.example https://two.example",
    )
    ids = [finding["indicator"] for finding in findings]
    assert len(ids) == len(set(ids))
    assert "urgency" in ids
    assert "credential_request" in ids
    assert "financial_request" in ids
    assert "suspicious_url" in ids


@pytest.mark.parametrize(
    ("ai_score", "body", "overlaps", "expected_score", "expected_category"),
    [
        (0, "", [], 0, "Low"),
        (24, "", [], 24, "Low"),
        (25, "", [], 25, "Medium"),
        (34, "https://example.invalid", [], 49, "Medium"),
        (0, "https://example.invalid urgent password payment", [], 50, "High"),
        (14, "https://example.invalid urgent password payment", [], 64, "High"),
        (15, "https://example.invalid urgent password payment", [], 65, "High"),
        (
            14,
            "https://example.invalid urgent password payment "
            "from security@127.0.0.1",
            [],
            74,
            "High",
        ),
        (
            15,
            "https://example.invalid urgent password payment "
            "from security@127.0.0.1",
            [],
            75,
            "Critical",
        ),
        (
            40,
            "https://example.invalid urgent password payment "
            "from security@127.0.0.1",
            [],
            100,
            "Critical",
        ),
        (40, "https://example.invalid urgent password payment", [], 90, "Critical"),
        (40, "https://example.invalid urgent password payment", [
            "suspicious_url", "urgency", "credential_request", "financial_request"
        ], 50, "High"),
        (30, "", [], 30, "Medium"),
    ],
)
def test_score_formula_and_category_thresholds(
    monkeypatch, ai_score, body, overlaps, expected_score, expected_category
):
    install_ai(monkeypatch, ai_response(ai_score, overlaps=overlaps))
    sender = (
        "security@127.0.0.1"
        if "security@127.0.0.1" in body
        else "user@example.test"
    )
    result = detector.check_email(sender, "Notice", body)
    assert result["score"] == expected_score
    assert result["category"] == expected_category
    assert result["score"] == (
        result["score_breakdown"]["rule_score"]
        + result["score_breakdown"]["ai_effective_score"]
    )


def test_risk_categories_at_high_and_critical_boundaries(monkeypatch):
    install_ai(monkeypatch, ai_response(0))
    high = detector.check_email(
        "user@example.test",
        "Urgent",
        "https://example.invalid password payment",
    )
    assert high["score"] == 50
    assert high["category"] == "High"

    install_ai(monkeypatch, ai_response(25))
    critical = detector.check_email(
        "security@127.0.0.1",
        "Urgent",
        "https://example.invalid password payment "
        "Please verify your account.",
    )
    assert critical["score"] == 85
    assert critical["category"] == "Critical"


@pytest.mark.parametrize(
    "data",
    [
        {"sender": "", "subject": "Notice", "body": "Content"},
        {"sender": "not-an-address", "subject": "Notice", "body": "Content"},
        {
            "sender": "user@example.test",
            "subject": "Notice",
            "body": "x" * (detector.MAX_BODY_LENGTH + 1),
        },
        {
            "sender": "user@example.test",
            "subject": "x" * (detector.MAX_SUBJECT_LENGTH + 1),
            "body": "Content",
        },
    ],
)
def test_invalid_form_inputs_are_rejected_without_ai(client, monkeypatch, data):
    def should_not_call_ai(_prompt):
        assert isinstance(_prompt, str)
        pytest.fail("AI should not run for invalid input")

    monkeypatch.setattr(detector, "_call_ollama", should_not_call_ai)
    response = post_email(client, **data)
    assert response.status_code == 400
    assert b"Analysis result" not in response.data


def test_analysis_submission_persists_scan_without_body(client, monkeypatch):
    install_ai(monkeypatch, ai_response(12, evidence=["account review"]))
    response = post_email(
        client,
        subject="Urgent account review",
        body="Please check https://example.invalid",
    )
    assert response.status_code == 200
    assert b"Score breakdown" in response.data
    assert b"URL present" in response.data

    with sqlite3.connect(detector.DB_PATH) as connection:
        row = connection.execute(
            "SELECT sender, subject, score, findings, ai_evidence FROM scans"
        ).fetchone()
        columns = {
            column[1] for column in connection.execute("PRAGMA table_info(scans)")
        }
    assert row[0] == "security@example.test"
    assert row[1] == "Urgent account review"
    assert json.loads(row[3])[0]["indicator"] == "suspicious_url"
    assert json.loads(row[4]) == ["account review"]
    assert "body" not in columns


@pytest.mark.parametrize(
    "invalid_response",
    [
        {"message": {"content": "not json"}},
        {"message": {"content": json.dumps({"verdict": "Incomplete"})}},
        ai_response(41),
        ai_response(-1),
    ],
)
def test_invalid_or_missing_ai_data_is_incomplete_not_low(
    client, monkeypatch, invalid_response
):
    def fake_invalid_response(prompt):
        assert "untrusted_email" in prompt
        return invalid_response

    monkeypatch.setattr(detector, "_call_ollama", fake_invalid_response)
    response = post_email(client)
    assert response.status_code == 502
    assert b"Analysis incomplete" in response.data
    assert b"Low risk" not in response.data
    with sqlite3.connect(detector.DB_PATH) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_unavailable_ollama_is_reported_and_not_saved(client, monkeypatch):
    def fail_ollama(prompt):
        assert "Sender:" in prompt
        raise ollama.RequestError("connection refused")

    monkeypatch.setattr(
        detector,
        "_call_ollama",
        fail_ollama,
    )
    response = post_email(client)
    assert response.status_code == 503
    assert b"Analysis incomplete" in response.data
    with sqlite3.connect(detector.DB_PATH) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_missing_csrf_token_rejects_state_change(client, monkeypatch):
    install_ai(monkeypatch)
    response = client.post(
        "/",
        data={
            "sender": "security@example.test",
            "subject": "Notice",
            "body": "Content",
        },
    )
    assert response.status_code == 400


def test_oversized_http_request_returns_clear_error(client):
    response = client.post(
        "/",
        data={
            "csrf_token": csrf_token(client),
            "sender": "security@example.test",
            "subject": "Notice",
            "body": "x" * (detector.app.config["MAX_CONTENT_LENGTH"] + 1),
        },
    )
    assert response.status_code == 413
    assert b"request is too large" in response.data


def test_history_search_and_filter(client, monkeypatch):
    install_ai(monkeypatch, ai_response(25))
    detector.save_scan(
        "security@example.test",
        "Quarterly alert",
        detector.check_email("security@example.test", "Quarterly alert", "Notice"),
    )
    detector.save_scan(
        "billing@example.test",
        "Receipt",
        detector.check_email("billing@example.test", "Receipt", "Notice"),
    )

    response = client.get("/history?search=security&category=Medium")
    assert response.status_code == 200
    assert b"security@example.test" in response.data
    assert b"billing@example.test" not in response.data


def test_detail_and_json_txt_exports(client, monkeypatch):
    install_ai(
        monkeypatch,
        ai_response(
            15,
            evidence=["urgent account warning"],
            actions=["Visit the official site directly."],
        ),
    )
    scan_id = persist_scan(
        "security@example.test",
        "Urgent notice",
        "Urgent, use https://example.invalid",
    )

    details = client.get(f"/history/{scan_id}")
    json_report = client.get(f"/history/{scan_id}/export")
    text_report = client.get(f"/history/{scan_id}/export.txt")
    assert details.status_code == 200
    assert b"Score breakdown" in details.data
    assert json_report.status_code == 200
    report = json.loads(json_report.get_data(as_text=True))
    assert report["scan_id"] == scan_id
    assert report["risk_score"] > 0
    assert report["recommended_actions"] == ["Visit the official site directly."]
    assert text_report.status_code == 200
    assert b"Scan Report" in text_report.data
    assert b"advisory assessment" in text_report.data
    assert text_report.mimetype == "text/plain"


def test_delete_and_clear_history_require_csrf(client, monkeypatch):
    install_ai(monkeypatch)
    first_id = persist_scan("first@example.test", "First", "Content")
    persist_scan("second@example.test", "Second", "Content")
    token = csrf_token(client)

    deleted = client.post(
        f"/history/{first_id}/delete",
        data={"csrf_token": token},
    )
    assert deleted.status_code == 302
    with sqlite3.connect(detector.DB_PATH) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1

    cleared = client.post("/history/clear", data={"csrf_token": token})
    assert cleared.status_code == 302
    with sqlite3.connect(detector.DB_PATH) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_database_failure_is_reported_without_hiding_completed_analysis(
    client, monkeypatch
):
    install_ai(monkeypatch)

    def fail_save(sender, subject, result):
        assert sender and subject
        assert result["analysis_complete"]
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(detector, "save_scan", fail_save)
    response = post_email(client)
    assert response.status_code == 500
    assert b"Analysis result" in response.data
    assert b"could not be saved" in response.data


def test_ollama_status_reports_selected_model(monkeypatch):
    class Model:
        model = detector.MODEL

    class FakeClient:
        def __init__(self, *, host, timeout):
            assert host == detector.OLLAMA_HOST
            assert timeout == detector.OLLAMA_STATUS_TIMEOUT

        def list(self):
            return type("Response", (), {"models": [Model()]})()

    monkeypatch.setattr(detector.ollama, "Client", FakeClient)
    status = detector.get_ollama_status()
    assert status["available"]
    assert status["model_available"]
    assert status["model"] == detector.MODEL


def test_existing_database_schema_migrates_without_losing_scans(tmp_path, monkeypatch):
    old_database = tmp_path / "existing.db"
    with sqlite3.connect(old_database) as connection:
        connection.execute(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT NOT NULL,
                subject TEXT NOT NULL,
                score INTEGER NOT NULL,
                category TEXT NOT NULL,
                findings TEXT NOT NULL,
                ai_verdict TEXT,
                ai_reasons TEXT,
                advice TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO scans (
                timestamp, sender, subject, score, category, findings,
                ai_verdict, ai_reasons, advice
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-01-01T10:00:00",
                "legacy@example.test",
                "Old scan",
                20,
                "Low",
                json.dumps(["Email contains a URL."]),
                "Inconclusive",
                json.dumps(["Legacy record"]),
                "Verify separately.",
            ),
        )

    monkeypatch.setattr(detector, "DB_PATH", old_database)
    detector.init_db()
    scan = detector._get_scan(1)
    assert scan["sender"] == "legacy@example.test"
    assert scan["score"] == 20
    assert scan["findings"][0]["label"] == "Earlier rule finding"
    assert scan["ai_confidence"] is None

    with sqlite3.connect(old_database) as connection:
        count = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
    assert count == 1
    assert "ai_confidence" in columns
