import json

from fastapi.testclient import TestClient

import app


client = TestClient(app.app)


def test_health_returns_200():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "AEGIS"}


def test_homepage_returns_200():
    response = client.get("/")
    assert response.status_code == 200
    assert "AEGIS" in response.text


def test_live_investigation_script_is_loaded():
    response = client.get("/")
    assert '<script src="/static/app.js" defer></script>' in response.text
    assert 'id="investigation-form"' in response.text
    assert 'id="run-investigation"' in response.text


def test_live_remediation_controls_are_present_in_frontend_assets():
    page = client.get("/").text
    script = client.get("/static/app.js").text
    assert "LIVE REPOSITORY INVESTIGATION" in page
    assert "INVESTIGATE" in script
    assert "/api/remediation-plan" in script
    assert "VERIFY AFTER FIX" in script


def test_live_remediation_renderer_handles_structured_plan_values():
    script = client.get("/static/app.js").text
    assert "renderRemediationPlan" in script
    assert "typeof value === 'object'" in script
    assert "PROPOSED - NOT EXECUTED" in script
    assert "Verification required" in script
    assert "[object Object]" not in script


def test_live_remediation_handles_fastapi_validation_errors():
    script = client.get("/static/app.js").text
    assert "formatApiError" in script
    assert "item.loc.join('.')" in script
    assert "Request failed. Check API contract." in script
    assert "investigation.findings.findIndex" in script


def test_live_evidence_and_verification_controls_are_present():
    script = client.get("/static/app.js").text
    assert "/api/root-cause" in script
    assert "/api/verify-repository" in script
    assert "DETERMINISTIC / SCANNER EVIDENCE" in script


def test_canonical_finding_appears():
    response = client.get("/")
    assert "finding-0001" in response.text
    assert "PUBLIC_BUCKET_ACL" in response.text


def test_risk_87_appears():
    response = client.get("/")
    assert "87" in response.text


def test_critical_appears():
    response = client.get("/")
    assert "CRITICAL" in response.text


def test_commit_f3a8e91_appears():
    response = client.get("/")
    assert "f3a8e91" in response.text


def test_deploy_004_appears():
    response = client.get("/")
    assert "deploy-004" in response.text


def test_attack_path_source_target_appear():
    response = client.get("/")
    assert "internet" in response.text
    assert "aegis-sensitive-data-bucket" in response.text


def test_verification_before_and_after_risk_appear():
    response = client.get("/")
    assert "Before" in response.text
    assert "After" in response.text
    assert "87" in response.text
    assert "0" in response.text


def test_ui_does_not_calculate_authoritative_security_values():
    response = client.get("/")
    page_text = response.text
    assert "analyze_security" not in page_text.lower()
    assert "risk_score" not in page_text.lower()


def test_invalid_finding_returns_clean_error():
    response = client.get("/api/case/not-found")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_case_endpoint_works():
    response = client.get("/api/case/finding-0001")
    assert response.status_code == 200
    payload = response.json()
    assert payload["finding"]["finding_id"] == "finding-0001"
    assert payload["attack_path"]["risk_score"] == 87
    assert payload["verification"]["before_risk"] == 87
    assert payload["verification"]["after_risk"] == 0


def test_no_gemini_call_occurs_during_page_rendering(monkeypatch):
    called = {"value": False}

    def fake_call(*args, **kwargs):
        called["value"] = True
        raise AssertionError("Gemini should not be called during UI rendering")

    monkeypatch.setattr("app.run_gemini_if_needed", fake_call, raising=False)
    response = client.get("/")
    assert response.status_code == 200
    assert called["value"] is False


def test_dashboard_does_not_falsely_claim_ai_remediation_succeeded():
    response = client.get("/")
    page_text = response.text
    assert "AI Remediation Status" in page_text
    assert "Not executed in latest run" in page_text or "not executed" in page_text.lower()
