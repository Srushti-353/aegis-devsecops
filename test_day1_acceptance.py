"""
Day 1 acceptance tests for the AEGIS scenario package.

Purpose: verify the *data* (Terraform + synthetic history + finding) is
internally consistent BEFORE any agent/tool code is written. No ADK, no
Gemini, no GCP calls here — pure static checks.

Run with:
    pip install pytest jsonschema python-hcl2
    pytest tests/test_day1_acceptance.py -v
"""
import json
from pathlib import Path

import hcl2
import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent
SCENARIO = ROOT
SCHEMA = ROOT
TARGET_INFRA = ROOT


def load_json(path: Path):
    with open(path) as f:
        return json.load(f)


def load_hcl(path: Path):
    with open(path) as f:
        return hcl2.load(f)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def commit_history():
    return load_json(SCENARIO / "commit_history.json")


@pytest.fixture(scope="module")
def deployment_events():
    return load_json(SCENARIO / "deployment_events.json")


@pytest.fixture(scope="module")
def finding():
    return load_json(SCENARIO / "finding.json")


@pytest.fixture(scope="module")
def vulnerable_tf():
    return load_hcl(TARGET_INFRA / "main.tf")


@pytest.fixture(scope="module")
def patched_tf():
    return load_hcl(TARGET_INFRA / "main.patched.tf")


# ---------------------------------------------------------------------------
# 1. Schema validation
# ---------------------------------------------------------------------------

def test_commit_history_matches_schema(commit_history):
    schema = load_json(SCHEMA / "commit.schema.json")
    for commit in commit_history:
        jsonschema.validate(instance=commit, schema=schema)


def test_deployment_events_match_schema(deployment_events):
    schema = load_json(SCHEMA / "deployment_event.schema.json")
    for event in deployment_events:
        jsonschema.validate(instance=event, schema=schema)


def test_finding_matches_schema(finding):
    schema = load_json(SCHEMA / "finding.schema.json")
    jsonschema.validate(instance=finding, schema=schema)


# ---------------------------------------------------------------------------
# 2. Terraform parses cleanly
# ---------------------------------------------------------------------------

def test_vulnerable_tf_parses(vulnerable_tf):
    assert "resource" in vulnerable_tf


def test_patched_tf_parses(patched_tf):
    assert "resource" in patched_tf


# ---------------------------------------------------------------------------
# Helpers to dig resources out of parsed HCL
# ---------------------------------------------------------------------------

def _unquote(value):
    """
    python-hcl2 8.x keeps literal double-quote characters around string
    literals (e.g. a dict key of '"google_storage_bucket"', an attribute
    value of '"allUsers"') instead of stripping them. terraform_parser_tools.py
    must normalize this on Day 2 — this helper is the reference
    implementation for that normalization.
    """
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _resources_of_type(parsed_tf, resource_type):
    """Yield (resource_name, attributes) for every block of a given type."""
    for resource_block in parsed_tf.get("resource", []):
        for raw_type_key, named_blocks in resource_block.items():
            if _unquote(raw_type_key) != resource_type:
                continue
            for raw_name_key, attrs in named_blocks.items():
                clean_attrs = {
                    k: _unquote(v) for k, v in attrs.items() if k != "__is_block__"
                }
                yield _unquote(raw_name_key), clean_attrs


def _find_bucket_name(parsed_tf):
    buckets = list(_resources_of_type(parsed_tf, "google_storage_bucket"))
    assert len(buckets) == 1, "Expected exactly one google_storage_bucket resource"
    _, attrs = buckets[0]
    return attrs["name"]


# ---------------------------------------------------------------------------
# 3. Finding references the real bucket resource
# ---------------------------------------------------------------------------

def test_finding_resource_name_matches_bucket_in_vulnerable_tf(finding, vulnerable_tf):
    bucket_name = _find_bucket_name(vulnerable_tf)
    assert finding["resource_name"] == bucket_name


# ---------------------------------------------------------------------------
# 4. Exactly one allUsers binding in the vulnerable file
# ---------------------------------------------------------------------------

def test_vulnerable_tf_has_exactly_one_public_binding(vulnerable_tf):
    iam_bindings = list(
        _resources_of_type(vulnerable_tf, "google_storage_bucket_iam_member")
    )
    public_bindings = [
        (name, attrs)
        for name, attrs in iam_bindings
        if attrs.get("member") == "allUsers"
    ]
    assert len(public_bindings) == 1, (
        f"Expected exactly one allUsers binding, found {len(public_bindings)}"
    )


# ---------------------------------------------------------------------------
# 5. Exactly one introducing commit, linked to a successful deployment
# ---------------------------------------------------------------------------

def test_exactly_one_introducing_commit(commit_history):
    introducing = [c for c in commit_history if c.get("is_introducing_commit")]
    assert len(introducing) == 1, (
        f"Expected exactly one introducing commit, found {len(introducing)}"
    )


def test_introducing_commit_diff_adds_all_users(commit_history):
    introducing = next(c for c in commit_history if c["is_introducing_commit"])
    assert "allUsers" in introducing["diff"]


def test_introducing_commit_has_successful_deployment(commit_history, deployment_events):
    introducing = next(c for c in commit_history if c["is_introducing_commit"])
    matching_deployments = [
        e for e in deployment_events if e["commit_sha"] == introducing["commit_sha"]
    ]
    assert len(matching_deployments) == 1, (
        "Introducing commit must have exactly one linked deployment event"
    )
    assert matching_deployments[0]["status"] == "success"


# ---------------------------------------------------------------------------
# 6. Patched file has no public bindings, same bucket identity
# ---------------------------------------------------------------------------

def test_patched_tf_has_no_public_binding(patched_tf):
    iam_bindings = list(
        _resources_of_type(patched_tf, "google_storage_bucket_iam_member")
    )
    for name, attrs in iam_bindings:
        member = attrs.get("member", "")
        assert member not in ("allUsers", "allAuthenticatedUsers"), (
            f"Patched file still has a public binding: {name}"
        )


def test_patched_bucket_identity_unchanged(vulnerable_tf, patched_tf):
    assert _find_bucket_name(vulnerable_tf) == _find_bucket_name(patched_tf)


# ---------------------------------------------------------------------------
# 7. Alternate path is present but inert (no assertions require it to work)
# ---------------------------------------------------------------------------

def test_alt_path_resources_present_but_optional(vulnerable_tf):
    service_accounts = list(_resources_of_type(vulnerable_tf, "google_service_account"))
    compute_instances = list(_resources_of_type(vulnerable_tf, "google_compute_instance"))
    # Presence is nice-to-have for future wiring; this test only documents
    # that they exist, it does not require the graph engine to use them.
    assert len(service_accounts) >= 1
    assert len(compute_instances) >= 1


# ---------------------------------------------------------------------------
# 8. Cross-file resource name consistency (no invented names)
# ---------------------------------------------------------------------------

def test_bucket_name_consistent_across_all_scenario_files(finding, vulnerable_tf, patched_tf):
    bucket_name = _find_bucket_name(vulnerable_tf)
    assert finding["resource_name"] == bucket_name
    assert _find_bucket_name(patched_tf) == bucket_name


def test_finding_detected_after_introducing_deployment(finding, commit_history, deployment_events):
    introducing = next(c for c in commit_history if c["is_introducing_commit"])
    deployment = next(
        e for e in deployment_events if e["commit_sha"] == introducing["commit_sha"]
    )
    assert finding["detected_at"] > deployment["applied_at"]
