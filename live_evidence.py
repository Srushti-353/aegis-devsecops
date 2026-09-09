from __future__ import annotations

import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from repository_scanner import clone_public_repo, validate_github_url
from scanner_osv import scan_with_osv
from scanner_trivy import scan_with_trivy
from security_models import SecurityFinding


MANIFEST_NAMES = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "poetry.lock", "pyproject.toml", "pom.xml", "build.gradle", "go.mod", "cargo.lock",
}


def _git(repo_path: Path, args: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            ["git", *args], cwd=str(repo_path), capture_output=True, text=True, timeout=30, shell=False
        )
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired):
        return 1, "", "git history unavailable"


def _candidate_files(repo_path: Path, finding: SecurityFinding) -> list[str]:
    candidates = []
    if finding.file:
        candidate = repo_path / finding.file
        if candidate.is_file():
            candidates.append(finding.file)
    candidates.extend(
        str(path.relative_to(repo_path))
        for path in repo_path.rglob("*")
        if path.is_file() and path.name.lower() in MANIFEST_NAMES and ".git" not in path.parts
    )
    return list(dict.fromkeys(candidates))


def attribute_root_cause(repo_path: Path, finding: SecurityFinding) -> dict:
    if finding.category != "dependency_vulnerability" or not finding.package:
        return {
            "status": "not_attributable", "introducing_commit": None, "commit_message": None,
            "affected_file": finding.file or None, "attribution_method": "insufficient_dependency_history_evidence", "confidence": "LOW",
        }
    files = _candidate_files(repo_path, finding)
    if not files:
        return {
            "status": "not_attributable", "introducing_commit": None, "commit_message": None,
            "affected_file": None, "attribution_method": "no_manifest_or_lockfile_found", "confidence": "LOW",
        }
    for affected_file in files:
        code, output, _ = _git(repo_path, ["log", "--all", "--format=%H%x00%s", "-S", finding.package, "--", affected_file])
        if code != 0 or not output.strip():
            continue
        commit_sha, _, message = output.splitlines()[0].partition("\x00")
        if commit_sha:
            return {
                "status": "attributable", "introducing_commit": commit_sha, "commit_message": message,
                "affected_file": affected_file, "attribution_method": "git_log_package_string_search", "confidence": "MEDIUM",
            }
    return {
        "status": "not_attributable", "introducing_commit": None, "commit_message": None,
        "affected_file": files[0], "attribution_method": "package_not_found_in_git_history", "confidence": "LOW",
    }


def investigate_root_cause(repository_url: str, finding: SecurityFinding) -> dict:
    validated_url = validate_github_url(repository_url)
    with TemporaryDirectory(prefix="aegis-root-cause-") as temp_dir:
        repo_path = Path(temp_dir) / "repository"
        clone_public_repo(validated_url, repo_path)
        return attribute_root_cause(repo_path, finding)


def _matches_original(candidate: SecurityFinding, original: SecurityFinding) -> bool:
    same_identifier = candidate.id == original.id or (original.cve and candidate.cve == original.cve)
    same_package = not original.package or candidate.package == original.package
    return same_identifier and same_package


def verify_patched_repository(repository_url: str, patched_repository_url: str | None, finding: SecurityFinding) -> dict:
    if not patched_repository_url:
        return {
            "status": "VERIFICATION_REQUIRED", "verified": False,
            "reason": "Provide a patched repository revision containing the proposed fix.", "finding_id": finding.id,
        }
    validated_url = validate_github_url(patched_repository_url)
    with TemporaryDirectory(prefix="aegis-verification-") as temp_dir:
        repo_path = Path(temp_dir) / "repository"
        clone_public_repo(validated_url, repo_path)
        scanner = scan_with_trivy if finding.source == "trivy" else scan_with_osv
        result = scanner(repo_path)
        if result.get("status") != "completed":
            return {
                "status": "NOT_VERIFIED", "verified": False,
                "reason": f"{finding.source} scanner was {result.get('status', 'unavailable')} on the patched repository.", "finding_id": finding.id,
            }
        remaining = [SecurityFinding(**item) for item in result.get("findings", []) if _matches_original(SecurityFinding(**item), finding)]
        if remaining:
            return {
                "status": "NOT_VERIFIED", "verified": False,
                "reason": "The original finding is still detected in the patched repository.", "finding_id": finding.id,
                "remaining_findings": remaining,
            }
        return {
            "status": "VERIFIED", "verified": True,
            "reason": "The original finding is no longer detected by the relevant deterministic scanner.", "finding_id": finding.id,
        }