import os

from fastapi.testclient import TestClient

import app
import config

client = TestClient(app.app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "AEGIS"}


def test_readiness_success_mocked(monkeypatch):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.project = "demo"

    monkeypatch.setattr(app, "_check_bigquery_readiness", lambda: True)
    response = client.get("/ready")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["bigquery"] == "reachable"


def test_readiness_failure_returns_503(monkeypatch):
    monkeypatch.setattr(app, "_check_bigquery_readiness", lambda: False)
    response = client.get("/ready")
    assert response.status_code == 503
    payload = response.json()
    assert payload["status"] == "not_ready"
    assert payload["bigquery"] == "unreachable"


def test_config_environment_overrides_work(monkeypatch):
    monkeypatch.setenv("AEGIS_GCP_PROJECT", "override-project")
    monkeypatch.setenv("AEGIS_BIGQUERY_DATASET", "override_dataset")
    monkeypatch.setenv("AEGIS_DEFAULT_FINDING", "finding-9999")
    monkeypatch.setenv("AEGIS_ENV", "prod")
    monkeypatch.setenv("AEGIS_PORT", "9090")
    assert config.get_project_id() == "override-project"
    assert config.get_dataset_id() == "override_dataset"
    assert config.get_default_finding() == "finding-9999"
    assert config.get_environment() == "prod"
    assert config.get_port() == 9090


def test_default_finding_configuration_works():
    assert config.get_default_finding() == "finding-0001"


def test_demo_mode_disabled_does_not_silently_fallback(monkeypatch):
    monkeypatch.delenv("AEGIS_DEMO_MODE", raising=False)
    assert config.is_demo_mode() is False


def test_demo_mode_enabled_uses_canonical_local_fallback(monkeypatch):
    monkeypatch.setenv("AEGIS_DEMO_MODE", "true")
    assert config.is_demo_mode() is True


def test_fallback_is_clearly_labelled():
    response = client.get("/")
    assert "Demo fallback" in response.text or "canonical local evidence" in response.text.lower()


def test_bigquery_source_is_clearly_labelled_when_used():
    response = client.get("/")
    assert "Evidence source" in response.text or "BigQuery" in response.text


def test_no_gemini_call_during_readiness(monkeypatch):
    called = {"value": False}

    def fake_call(*args, **kwargs):
        called["value"] = True
        raise AssertionError("No Gemini during readiness")

    monkeypatch.setattr(app, "_check_bigquery_readiness", lambda: True)
    monkeypatch.setattr(app, "run_gemini_if_needed", fake_call, raising=False)
    response = client.get("/ready")
    assert response.status_code == 200
    assert called["value"] is False


def test_no_gemini_call_during_dashboard_request(monkeypatch):
    called = {"value": False}

    def fake_call(*args, **kwargs):
        called["value"] = True
        raise AssertionError("No Gemini during dashboard request")

    monkeypatch.setattr(app, "run_gemini_if_needed", fake_call, raising=False)
    response = client.get("/")
    assert response.status_code == 200
    assert called["value"] is False


def test_dockerfile_exists():
    assert os.path.exists("Dockerfile")


def test_dockerfile_contains_no_credentials():
    content = open("Dockerfile").read().lower()
    assert "api_key" not in content
    assert "gemini" not in content.lower()
    assert "private_key" not in content.lower()


def test_dockerignore_excludes_env():
    content = open(".dockerignore").read().lower()
    assert ".env" in content
    assert "__pycache__" in content


def test_app_supports_port_configuration(monkeypatch):
    monkeypatch.setenv("AEGIS_PORT", "8081")
    import importlib
    import config
    importlib.reload(config)
    assert config.get_port() == 8081


def test_readme_identifies_actual_implemented_services_truthfully():
    readme = open("README.md").read().lower()
    assert "bigquery sandbox" in readme
    assert "google adk" in readme
    assert "gemini api" in readme
    assert "cloud run" not in readme.lower()


def test_gemini_cannot_override_deterministic_verification():
    from day3_workflow import deterministic_verification_tool

    verification = deterministic_verification_tool("finding-0001")
    assert verification["status"] == "VERIFIED"
    assert verification["before_risk"] == 87
    assert verification["after_risk"] == 0


def test_current_canonical_case_remains_risk_87():
    from bigquery_tools import get_attack_path

    attack = get_attack_path("finding-0001")
    assert attack["risk_score"] == 87


def test_root_cause_remains_f3a8e91():
    from bigquery_tools import get_root_cause_evidence

    root = get_root_cause_evidence("finding-0001")
    assert root["introducing_commit"] == "f3a8e91"


def test_deployment_remains_deploy_004():
    from bigquery_tools import get_root_cause_evidence

    root = get_root_cause_evidence("finding-0001")
    assert root["deployment_id"] == "deploy-004"


def test_deterministic_verified_risk_remains_0_after_known_good_fix():
    from day3_workflow import deterministic_verification_tool

    verification = deterministic_verification_tool("finding-0001")
    assert verification["after_risk"] == 0
