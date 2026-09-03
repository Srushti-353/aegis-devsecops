"""Deterministic correlation of scenario Terraform, commits, and deployments."""

from __future__ import annotations

import json
from datetime import datetime
from json import JSONDecodeError
from pathlib import Path
from typing import Any


def _load(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    # Validate path is a file (catches Errno 21: Is a directory)
    if not source.is_file():
        raise FileNotFoundError(f"Data file not found or is not a file: {source}")
    # Try to parse; silently return [] on JSON errors for backward compatibility
    try:
        with source.open() as data_file:
            value = json.load(data_file)
    except (JSONDecodeError, TypeError):
        return []
    return value if isinstance(value, list) else []


def commits_touching_resource(commits: list[dict[str, Any]], resource: str) -> list[dict[str, Any]]:
    return [commit for commit in commits if any(resource in str(part) for part in commit.get("files_changed", []) + [commit.get("diff", "")])]


def find_introducing_commit(commits: list[dict[str, Any]], resource: str | None = None) -> dict[str, Any] | None:
    candidates = [commit for commit in commits if commit.get("is_introducing_commit") is True and "allUsers" in commit.get("diff", "")]
    if resource:
        matching = [commit for commit in candidates if resource in commit.get("diff", "")]
        if matching:
            candidates = matching
    return candidates[0] if len(candidates) == 1 else None


def find_deployment_for_commit(deployments: list[dict[str, Any]], commit_sha: str, successful_only: bool = True) -> dict[str, Any] | None:
    candidates = [event for event in deployments if event.get("commit_sha") == commit_sha and (not successful_only or event.get("status") == "success")]
    return min(candidates, key=lambda event: event.get("applied_at", ""), default=None)


def temporal_relationship(commit: dict[str, Any], deployment: dict[str, Any] | None) -> str:
    if not deployment:
        return "no_deployment"
    commit_time = datetime.fromisoformat(commit["timestamp"].replace("Z", "+00:00"))
    deployment_time = datetime.fromisoformat(deployment["applied_at"].replace("Z", "+00:00"))
    return "deployment_after_commit" if deployment_time >= commit_time else "deployment_before_commit"


def correlate_finding(finding: dict[str, Any], terraform: dict[str, Any], commit_path: str | Path, deployment_path: str | Path) -> dict[str, Any]:
    resource_name = finding["resource_name"]
    commits = _load(commit_path)
    deployments = _load(deployment_path)
    local_names = [
        resource["resource_name"]
        for resource in terraform.get("resources", [])
        if resource.get("resource_type") == finding.get("resource_type")
        and resource.get("attributes", {}).get("name") == resource_name
    ]
    terraform_reference = f"google_storage_bucket.{local_names[0]}" if local_names else resource_name
    introducing = find_introducing_commit(commits, terraform_reference)
    deployment = find_deployment_for_commit(deployments, introducing["commit_sha"]) if introducing else None
    return {
        "resource": resource_name,
        "introducing_commit": introducing.get("commit_sha") if introducing else None,
        "changed_attribute": "member" if introducing and "allUsers" in introducing.get("diff", "") else None,
        "deployment_id": deployment.get("deployment_id") if deployment else None,
        "temporal_relationship": temporal_relationship(introducing, deployment) if introducing else "no_introducing_commit",
        "confidence": 1.0 if introducing and deployment else 0.0,
        "evidence": ["resource appears in introducing diff", "matching successful deployment"] if introducing and deployment else [],
    }


load_commits = _load
load_deployments = _load