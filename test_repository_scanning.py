from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app
import repository_investigator
import live_evidence
from repository_profiler import profile_repository
from repository_scanner import validate_github_url
from remediation_planner import plan_remediation
from scanner_osv import _normalize as normalize_osv
from scanner_osv import scan_with_osv
from scanner_trivy import _normalize as normalize_trivy
from scanner_trivy import _category
from scanner_trivy import redact_secret, scan_with_trivy
from security_models import SecurityFinding
from security_triage import category_summary, deduplicate_findings, triage_findings


client = TestClient(app.app)


@pytest.mark.parametrize("url", [
    "https://github.com/owner/repo",
    "https://github.com/owner/repo.git",
])
def test_valid_github_urls_are_normalized(url):
    assert validate_github_url(url) == "https://github.com/owner/repo.git"


@pytest.mark.parametrize("url", [
    "http://github.com/owner/repo",
    "https://gitlab.com/owner/repo",
    "https://localhost/owner/repo",
    "https://127.0.0.1/owner/repo",
    "file:///tmp/repo",
    "ssh://git@github.com/owner/repo",
    "https://user:password@github.com/owner/repo",
    "https://github.com/owner/repo?token=x",
    "https://github.com/owner/repo#readme",
    "https://github.com/owner/repo/extra",
])
def test_unsafe_github_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_github_url(url)


@pytest.mark.parametrize(("files", "expected"), [
    ({"requirements.txt": "", "app.py": ""}, ("Python", "pip")),
    ({"package.json": "{}", "index.js": ""}, ("Node.js", "npm")),
    ({"main.tf": "resource {}"}, (None, None)),
])
def test_repository_profile_detects_common_stacks(tmp_path, files, expected):
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    profile = profile_repository(tmp_path)
    if expected[0]:
        assert expected[0] in profile["languages"]
        assert expected[1] in profile["package_managers"]
    else:
        assert profile["terraform"] is True


def test_osv_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr("scanner_osv.shutil.which", lambda _: None)
    assert scan_with_osv(tmp_path)["status"] == "unavailable"


def test_osv_v2_source_command_accepts_findings_exit_code(monkeypatch, tmp_path):
    class Completed:
        returncode = 1
        stdout = '{"results": []}'
        stderr = "vulnerabilities found"

    monkeypatch.setattr("scanner_osv.shutil.which", lambda _: "/usr/local/bin/osv-scanner")
    calls = []
    monkeypatch.setattr("scanner_osv.subprocess.run", lambda command, **kwargs: (calls.append((command, kwargs)) or Completed()))
    result = scan_with_osv(tmp_path)
    assert result["status"] == "completed"
    assert calls[0][0][1:5] == ["scan", "source", "-r", "--format"]
    assert calls[0][1]["shell"] is False


def test_osv_failure_has_short_sanitized_reason(monkeypatch, tmp_path):
    class Completed:
        returncode = 1
        stdout = "not json"
        stderr = "unsupported CLI arguments\n" * 100

    monkeypatch.setattr("scanner_osv.shutil.which", lambda _: "/usr/local/bin/osv-scanner")
    monkeypatch.setattr("scanner_osv.subprocess.run", lambda *args, **kwargs: Completed())
    result = scan_with_osv(tmp_path)
    assert result["status"] == "failed"
    assert result["error"] == "unsupported CLI arguments"
    assert len(result["error"]) < 200


def test_trivy_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr("scanner_trivy.shutil.which", lambda _: None)
    assert scan_with_trivy(tmp_path)["status"] == "unavailable"


def test_osv_normalization_preserves_unknown_severity():
    finding = normalize_osv({"id": "GHSA-test", "package": {"name": "demo", "version": "1.0"}, "vulnerability": {"summary": "Issue"}}, "requirements.txt")
    assert finding["severity"] == "UNKNOWN"
    assert finding["package"] == "demo"
    assert finding["file"] == "requirements.txt"


def test_trivy_normalization_redacts_secret_evidence():
    finding = normalize_trivy({"Type": "secret"}, {"SecretID": "token-rule", "Title": "token=super-secret", "Match": "password=hunter2", "Severity": "HIGH"})
    assert finding["category"] == "secret_exposure"
    assert "super-secret" not in str(finding)
    assert "hunter2" not in str(finding)
    assert redact_secret("api_key=abc123") == "api_key=[REDACTED]"


def test_trivy_categories_use_result_metadata():
    assert _category({"Type": "secret", "Target": "config.js"}, {"Title": "Asymmetric Private Key"}) == "secret_exposure"
    assert _category({"Type": "dockerfile", "Target": "Dockerfile"}, {"ID": "DS-0026", "Title": "No HEALTHCHECK defined"}) == "container_misconfiguration"
    assert _category({"Type": "vulnerability", "Target": "package-lock.json"}, {"VulnerabilityID": "CVE-1"}) == "dependency_vulnerability"
    assert _category({"Type": "terraform", "Target": "main.tf"}, {"ID": "AVD-TF-1"}) == "iac_misconfiguration"
    assert _category({"Type": "kubernetes", "Target": "k8s/deployment.yaml"}, {"ID": "KSV-1"}) == "kubernetes_misconfiguration"


def _finding(identifier, severity="LOW", category="dependency_vulnerability", version="1.0", file="package.json"):
    return SecurityFinding(id=identifier, source="trivy", category=category, severity=severity, installed_version=version, file=file)


def test_deduplication_preserves_same_cve_with_different_versions():
    findings = [_finding("CVE-1", version="1.0"), _finding("CVE-1", version="2.0"), _finding("CVE-1", version="1.0")]
    unique = deduplicate_findings(findings)
    assert len(unique) == 2


def test_triage_orders_severity_then_category_and_limits_to_ten():
    findings = [_finding(f"F{i}", severity="LOW") for i in range(11)]
    findings.extend([_finding("secret", severity="HIGH", category="secret_exposure"), _finding("dependency", severity="HIGH")])
    top = triage_findings(findings)
    assert len(top) == 10
    assert top[0].id == "secret"
    assert top[1].id == "dependency"


def test_category_summary_reports_all_supported_categories():
    findings = [_finding("a", category="secret_exposure"), _finding("b", category="container_misconfiguration")]
    summary = category_summary(findings)
    assert summary["secret_exposure"] == 1
    assert summary["container_misconfiguration"] == 1
    assert summary["dependency_vulnerability"] == 0


def test_dependency_remediation_preserves_fixed_version():
    finding = SecurityFinding(id="CVE-2019-10746", source="trivy", category="dependency_vulnerability", title="Prototype pollution", package="mixin-deep", installed_version="1.3.1", fixed_version="1.3.2", severity="HIGH")
    plan = plan_remediation(finding)
    assert plan.recommended_version == "1.3.2"
    assert "mixin-deep@1.3.2" in plan.commands[0]
    assert "not executed" in plan.commands[0].lower()
    assert plan.ai_status == "not_requested"


def test_dependency_remediation_preserves_multiple_fixed_versions():
    finding = _finding("CVE-1", version="1.0")
    finding = finding.model_copy(update={"package": "demo", "fixed_version": "1.3.2 / 2.0.1"})
    plan = plan_remediation(finding)
    assert plan.recommended_version == "1.3.2 / 2.0.1"
    assert "compatible patched release" in plan.action


def test_missing_fixed_version_is_conservative():
    plan = plan_remediation(_finding("CVE-unknown").model_copy(update={"fixed_version": ""}))
    assert plan.recommended_version == ""
    assert "will not invent one" in plan.action


def test_secret_remediation_never_returns_secret_value():
    finding = SecurityFinding(id="private-key", source="trivy", category="secret_exposure", title="Asymmetric Private Key", description="private-key=[REDACTED]", severity="CRITICAL")
    plan = plan_remediation(finding)
    assert plan.remediation_type == "credential_rotation"
    assert "rotate" in plan.action.lower()
    assert "private-key=[REDACTED]" not in plan.model_dump_json()


def test_container_remediation_is_configuration_level():
    finding = SecurityFinding(id="DS-0026", source="trivy", category="container_misconfiguration", title="No HEALTHCHECK defined", severity="LOW")
    plan = plan_remediation(finding)
    assert plan.remediation_type == "configuration_change"
    assert "container configuration" in plan.action


def test_api_returns_live_remediation_plan_without_canonical_data():
    finding = {"id": "CVE-2019-10746", "source": "trivy", "category": "dependency_vulnerability", "severity": "CRITICAL", "title": "nodejs-mixin-deep: prototype pollution in function mixin-deep", "description": "mixin-deep is vulnerable to Prototype Pollution", "package": "mixin-deep", "installed_version": "1.3.1", "fixed_version": "1.3.2, 2.0.1", "cve": "CVE-2019-10746", "file": "", "line": None, "confidence": "HIGH"}
    response = client.post("/api/remediation-plan", json={"finding": finding, "repository_url": "https://github.com/OWASP/NodeGoat"})
    assert response.status_code == 200
    payload = response.json()["plan"]
    assert payload["package"] == "mixin-deep"
    assert "1.3.1" in response.text
    assert "1.3.2, 2.0.1" in response.text
    assert "not executed" in response.text.lower()
    assert "main.tf" not in response.text
    assert "allUsers" not in response.text
    assert "f3a8e91" not in response.text
    assert "deploy-004" not in response.text


def test_root_cause_success_from_git_history(tmp_path, monkeypatch):
    finding = _finding("CVE-1").model_copy(update={"package": "mixin-deep"})
    (tmp_path / "package.json").write_text('{}')
    monkeypatch.setattr(live_evidence, "_git", lambda path, args: (0, "abc123\x00Add mixin-deep\n", ""))
    result = live_evidence.attribute_root_cause(tmp_path, finding)
    assert result["status"] == "attributable"
    assert result["introducing_commit"] == "abc123"


def test_root_cause_returns_not_attributable_without_evidence(tmp_path):
    finding = _finding("CVE-1").model_copy(update={"package": "missing-package"})
    result = live_evidence.attribute_root_cause(tmp_path, finding)
    assert result["status"] == "not_attributable"


def test_verification_requires_patched_revision():
    finding = _finding("CVE-1")
    result = live_evidence.verify_patched_repository("https://github.com/owner/repo", None, finding)
    assert result["status"] == "VERIFICATION_REQUIRED"


def test_verification_success_when_original_finding_is_absent(monkeypatch):
    finding = _finding("CVE-1")
    monkeypatch.setattr(live_evidence, "clone_public_repo", lambda url, destination: destination.mkdir())
    monkeypatch.setattr(live_evidence, "scan_with_trivy", lambda path: {"status": "completed", "findings": []})
    result = live_evidence.verify_patched_repository("https://github.com/owner/repo", "https://github.com/owner/patched", finding)
    assert result["status"] == "VERIFIED"


def test_verification_not_verified_when_finding_remains(monkeypatch):
    finding = _finding("CVE-1")
    monkeypatch.setattr(live_evidence, "clone_public_repo", lambda url, destination: destination.mkdir())
    monkeypatch.setattr(live_evidence, "scan_with_trivy", lambda path: {"status": "completed", "findings": [finding.model_dump()]})
    result = live_evidence.verify_patched_repository("https://github.com/owner/repo", "https://github.com/owner/patched", finding)
    assert result["status"] == "NOT_VERIFIED"


def test_verification_reports_scanner_failure(monkeypatch):
    finding = _finding("CVE-1")
    monkeypatch.setattr(live_evidence, "clone_public_repo", lambda url, destination: destination.mkdir())
    monkeypatch.setattr(live_evidence, "scan_with_trivy", lambda path: {"status": "failed", "findings": [], "error": "scanner failed"})
    result = live_evidence.verify_patched_repository("https://github.com/owner/repo", "https://github.com/owner/patched", finding)
    assert result["status"] == "NOT_VERIFIED"


def test_investigator_isolates_scanner_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(repository_investigator, "clone_public_repo", lambda url, destination: destination.mkdir())
    monkeypatch.setattr(repository_investigator, "scan_with_osv", lambda path: (_ for _ in ()).throw(RuntimeError()))
    monkeypatch.setattr(repository_investigator, "scan_with_trivy", lambda path: {"scanner": "trivy", "status": "completed", "findings": [{"id": "T1", "source": "trivy", "category": "dependency_vulnerability", "severity": "HIGH"}]})
    result = repository_investigator.investigate_repository("https://github.com/owner/repo")
    assert result.summary == {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0}
    assert result.scanner_results[0].status == "failed"
    assert result.scanner_results[1].status == "completed"


def test_api_rejects_invalid_url():
    response = client.post("/api/investigate-repository", json={"repository_url": "https://gitlab.com/owner/repo"})
    assert response.status_code == 400


def test_api_rejects_malformed_payload():
    response = client.post("/api/investigate-repository", json={})
    assert response.status_code == 422


def test_api_valid_request_is_mocked(monkeypatch):
    monkeypatch.setattr(app, "investigate_repository", lambda url: {"repository_url": url, "findings": []})
    response = client.post("/api/investigate-repository", json={"repository_url": "https://github.com/owner/repo"})
    assert response.status_code == 200
    assert response.json()["findings"] == []