"""BigQuery evidence layer for the canonical AEGIS scenario.

This module stores and reads evidence in BigQuery without taking over the
security decision boundary. The deterministic Python modules remain the source
of truth for attack-path existence, risk scoring, and verification.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from google.cloud import bigquery
except ImportError:  # pragma: no cover - optional in test environments
    bigquery = None

from git_history_tools import correlate_finding
from graph_tools import analyze_security
from terraform_parser_tools import parse_terraform

ROOT = Path(__file__).resolve().parent
PROJECT_ID = "aegis-devsecops-2026"
DATASET_ID = "aegis_security"


def get_project_id() -> str:
    return os.getenv("AEGIS_GCP_PROJECT", PROJECT_ID)


def get_dataset_id() -> str:
    return os.getenv("AEGIS_BIGQUERY_DATASET", DATASET_ID)


def get_bigquery_client():
    if bigquery is None:
        raise RuntimeError("google-cloud-bigquery is not installed")
    return bigquery.Client(project=get_project_id())


def _read_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open() as handle:
        return json.load(handle)


def _iso_to_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return value


def prepare_findings_rows() -> list[dict[str, Any]]:
    finding = _read_json(ROOT / "finding.json")
    return [{
        "finding_id": finding.get("finding_id"),
        "finding_type": finding.get("finding_type"),
        "resource_name": finding.get("resource_name"),
        "severity": finding.get("severity"),
        "description": finding.get("description"),
        "detected_at": _iso_to_timestamp(finding.get("detected_at")),
    }]


def prepare_resource_rows() -> list[dict[str, Any]]:
    parsed = parse_terraform(ROOT / "main.tf")
    rows: list[dict[str, Any]] = []
    for resource in parsed.get("resources", []):
        if resource.get("resource_type") != "google_storage_bucket":
            continue
        attributes = resource.get("attributes", {})
        resource_name = attributes.get("name") or resource.get("resource_name")
        public_access = any(
            rel.get("source") == "allUsers"
            for rel in parsed.get("relationships", [])
        )
        rows.append({
            "resource_id": resource_name,
            "resource_name": resource_name,
            "resource_type": "google_storage_bucket",
            "sensitive": bool(attributes.get("labels", {}).get("data_classification") == "sensitive"),
            "public_access": public_access,
            "environment": attributes.get("labels", {}).get("environment", "prod"),
        })
    return rows


def prepare_commit_rows() -> list[dict[str, Any]]:
    commits = _read_json(ROOT / "commit_history.json")
    rows: list[dict[str, Any]] = []
    for commit in commits:
        rows.append({
            "commit_sha": commit.get("commit_sha"),
            "message": commit.get("message"),
            "author": commit.get("author"),
            "committed_at": _iso_to_timestamp(commit.get("timestamp")),
            "is_introducing_commit": bool(commit.get("is_introducing_commit")),
        })
    return rows


def prepare_deployment_rows() -> list[dict[str, Any]]:
    deployments = _read_json(ROOT / "deployment_events.json")
    rows: list[dict[str, Any]] = []
    for deployment in deployments:
        rows.append({
            "deployment_id": deployment.get("deployment_id"),
            "commit_sha": deployment.get("commit_sha"),
            "deployed_at": _iso_to_timestamp(deployment.get("applied_at")),
            "environment": deployment.get("environment"),
            "status": deployment.get("status"),
        })
    return rows


def prepare_attack_path_rows() -> list[dict[str, Any]]:
    finding = _read_json(ROOT / "finding.json")
    parsed = parse_terraform(ROOT / "main.tf")
    result = analyze_security(parsed, finding)
    target = result.get("attack_path", [None, None])[1] if len(result.get("attack_path", [])) > 1 else finding["resource_name"]
    rows = [{
        "finding_id": finding.get("finding_id"),
        "source": "internet",
        "target": target,
        "path_exists": bool(result.get("path_exists")),
        "risk_score": int(result.get("risk_score", 0)),
        "severity": result.get("severity", "LOW"),
        "blast_radius": int(result.get("blast_radius", 0)),
        "analyzed_at": _iso_to_timestamp(finding.get("detected_at")),
    }]
    return rows


def _table_name(table: str) -> str:
    return f"{get_project_id()}.{get_dataset_id()}.{table}"


def _query_rows(client: Any, sql: str) -> list[dict[str, Any]]:
    if client is None or not hasattr(client, "query"):
        return []
    job = client.query(sql)
    if hasattr(job, "result"):
        rows = job.result()
        try:
            return [dict(row) for row in rows]
        except TypeError:
            return []
    return []


def load_aegis_data(client: Any | None = None) -> dict[str, int]:
    """Load canonical AEGIS demo evidence into BigQuery using sandbox-safe batch jobs.

    This uses WRITE_TRUNCATE on a fixed dataset to remain idempotent without DML or
    streaming inserts, which are not supported in BigQuery Sandbox.
    """
    rows_by_table = {
        "findings": prepare_findings_rows(),
        "resources": prepare_resource_rows(),
        "commits": prepare_commit_rows(),
        "deployments": prepare_deployment_rows(),
        "attack_paths": prepare_attack_path_rows(),
    }

    if client is None:
        try:
            client = get_bigquery_client()
        except RuntimeError:
            return {name: len(rows) for name, rows in rows_by_table.items()}

    for table_name, rows in rows_by_table.items():
        if not rows:
            continue
        if hasattr(client, "load_table_from_json"):
            job_config = None
            if hasattr(bigquery, "LoadJobConfig") and hasattr(bigquery, "WriteDisposition"):
                job_config = bigquery.LoadJobConfig(write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE)
            elif hasattr(client, "LoadJobConfig"):
                job_config = client.LoadJobConfig(write_disposition="WRITE_TRUNCATE")
            if job_config is None:
                job = client.load_table_from_json(rows, _table_name(table_name))
            else:
                job = client.load_table_from_json(rows, _table_name(table_name), job_config=job_config)
            if hasattr(job, "result"):
                job.result()

    return {name: len(rows) for name, rows in rows_by_table.items()}


def get_finding(finding_id: str, client: Any | None = None) -> dict[str, Any] | None:
    if client is not None and hasattr(client, "query"):
        rows = _query_rows(client, f"SELECT * FROM `{_table_name('findings')}` WHERE finding_id = '{finding_id}' LIMIT 1")
        if rows:
            return rows[0]
    finding = _read_json(ROOT / "finding.json")
    return finding if finding.get("finding_id") == finding_id else None


def get_attack_path(finding_id: str, client: Any | None = None) -> dict[str, Any] | None:
    if client is not None and hasattr(client, "query"):
        rows = _query_rows(client, f"SELECT * FROM `{_table_name('attack_paths')}` WHERE finding_id = '{finding_id}' LIMIT 1")
        if rows:
            return rows[0]
    finding = _read_json(ROOT / "finding.json")
    if finding.get("finding_id") != finding_id:
        return None
    result = analyze_security(parse_terraform(ROOT / "main.tf"), finding)
    return {
        "finding_id": finding.get("finding_id"),
        "source": "internet",
        "target": finding.get("resource_name"),
        "path_exists": result.get("path_exists"),
        "risk_score": result.get("risk_score"),
        "severity": result.get("severity"),
        "blast_radius": result.get("blast_radius"),
    }


def get_root_cause_evidence(finding_id: str, client: Any | None = None) -> dict[str, Any] | None:
    if client is not None and hasattr(client, "query"):
        rows = _query_rows(client, f"SELECT * FROM `{_table_name('commits')}` WHERE is_introducing_commit = TRUE LIMIT 1")
        if rows:
            commit = rows[0]
            deployment_rows = _query_rows(client, f"SELECT * FROM `{_table_name('deployments')}` WHERE commit_sha = '{commit['commit_sha']}' LIMIT 1")
            return {
                "introducing_commit": commit.get("commit_sha"),
                "deployment_id": deployment_rows[0].get("deployment_id") if deployment_rows else None,
            }
    finding = _read_json(ROOT / "finding.json")
    if finding.get("finding_id") != finding_id:
        return None
    terraform = parse_terraform(ROOT / "main.tf")
    commits = _read_json(ROOT / "commit_history.json")
    deployments = _read_json(ROOT / "deployment_events.json")
    root_cause = correlate_finding(finding, terraform, ROOT / "commit_history.json", ROOT / "deployment_events.json")
    deployment = next((deployment for deployment in deployments if deployment.get("deployment_id") == root_cause.get("deployment_id")), None)
    return {
        "introducing_commit": root_cause.get("introducing_commit"),
        "deployment_id": root_cause.get("deployment_id"),
        "commit_message": next((commit.get("message") for commit in commits if commit.get("commit_sha") == root_cause.get("introducing_commit")), None),
        "deployment_status": deployment.get("status") if deployment else None,
    }


def get_case_evidence(finding_id: str, client: Any | None = None) -> dict[str, Any]:
    finding = get_finding(finding_id, client=client) or {}
    resource_rows = prepare_resource_rows()
    matching_resource = next((row for row in resource_rows if row.get("resource_name") == finding.get("resource_name")), None)
    attack_path = get_attack_path(finding_id, client=client) or {}
    root_cause = get_root_cause_evidence(finding_id, client=client) or {}
    risk_score = int(attack_path.get("risk_score", 0))
    severity = attack_path.get("severity") or finding.get("severity")
    return {
        "finding": finding,
        "resource": matching_resource,
        "attack_path": attack_path.get("source") + " -> " + attack_path.get("target", "") if attack_path else None,
        "risk_score": risk_score,
        "severity": severity,
        "root_cause_commit": root_cause.get("introducing_commit"),
        "deployment": root_cause.get("deployment_id"),
    }
