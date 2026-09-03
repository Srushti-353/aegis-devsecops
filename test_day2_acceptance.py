import json
from pathlib import Path

from graph_tools import analyze_security
from git_history_tools import correlate_finding, find_introducing_commit
from terraform_parser_tools import parse_terraform, unquote

ROOT = Path(__file__).parent


def scenario_files():
    return ROOT / "main.tf", ROOT / "main.patched.tf", ROOT / "commit_history.json", ROOT / "deployment_events.json", json.loads((ROOT / "finding.json").read_text())


def test_vulnerable_and_patched_paths():
    vulnerable, patched, *_ = scenario_files()
    assert analyze_security(parse_terraform(vulnerable))["attack_path"] == ["internet", "aegis-sensitive-data-bucket"]
    assert analyze_security(parse_terraform(patched))["path_exists"] is False


def test_parse_terraform_rejects_directories(tmp_path):
    """Verify parse_terraform validates that path is a file, not a directory."""
    import pytest
    result_dir = tmp_path / "scenario"
    result_dir.mkdir()
    
    with pytest.raises(FileNotFoundError) as exc_info:
        parse_terraform(result_dir)
    assert "not found or is not a file" in str(exc_info.value)


def test_parse_terraform_rejects_missing_files(tmp_path):
    """Verify parse_terraform validates that path exists."""
    import pytest
    missing = tmp_path / "missing.tf"
    
    with pytest.raises(FileNotFoundError) as exc_info:
        parse_terraform(missing)
    assert "not found or is not a file" in str(exc_info.value)


def test_quote_normalization_matches_hcl2_8_shape():
    assert unquote('"google_storage_bucket"') == "google_storage_bucket"
    assert unquote('"allUsers"') == "allUsers"
    assert unquote("plain") == "plain"


def test_history_and_deployment_correlation():
    vulnerable, _, commits, deployments, finding = scenario_files()
    result = correlate_finding(finding, parse_terraform(vulnerable), commits, deployments)
    assert result["introducing_commit"] == "f3a8e91"
    assert result["deployment_id"] == "deploy-004"
    assert result["temporal_relationship"] == "deployment_after_commit"


def test_load_rejects_directories(tmp_path):
    """Verify _load validates that path is a file, not a directory."""
    import pytest
    from git_history_tools import _load
    result_dir = tmp_path / "data"
    result_dir.mkdir()
    
    with pytest.raises(FileNotFoundError) as exc_info:
        _load(result_dir)
    assert "not found or is not a file" in str(exc_info.value)


def test_load_rejects_missing_files(tmp_path):
    """Verify _load validates that path exists."""
    import pytest
    from git_history_tools import _load
    missing = tmp_path / "missing.json"
    
    with pytest.raises(FileNotFoundError) as exc_info:
        _load(missing)
    assert "not found or is not a file" in str(exc_info.value)


def test_load_graceful_on_invalid_json(tmp_path):
    """Verify _load handles invalid JSON gracefully (returns empty list)."""
    from git_history_tools import _load
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not valid json")
    result = _load(invalid)
    assert result == []


def test_unrelated_commit_is_not_introducing():
    _, _, commits, _, finding = scenario_files()
    records = json.loads(Path(commits).read_text())
    assert find_introducing_commit(records[:3], finding["resource_name"]) is None


def test_alternate_compute_path_is_inert():
    vulnerable, *_ = scenario_files()
    result = analyze_security(parse_terraform(vulnerable))
    assert result["attack_path"] == ["internet", "aegis-sensitive-data-bucket"]
    assert result["blast_radius"] == 1


def test_risk_score_is_deterministic():
    vulnerable, *_ = scenario_files()
    result = analyze_security(parse_terraform(vulnerable))
    assert (result["risk_score"], result["severity"]) == (87, "CRITICAL")


def test_missing_history_is_graceful(tmp_path):
    vulnerable, _, _, deployments, finding = scenario_files()
    missing = tmp_path / "missing.json"
    missing.write_text("[]")
    result = correlate_finding(finding, parse_terraform(vulnerable), missing, deployments)
    assert result["confidence"] == 0.0


def test_invalid_deployment_data_is_graceful(tmp_path):
    vulnerable, _, commits, _, finding = scenario_files()
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not json")
    result = correlate_finding(finding, parse_terraform(vulnerable), commits, invalid)
    assert result["deployment_id"] is None