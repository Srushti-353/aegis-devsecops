from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from repository_profiler import profile_repository
from repository_scanner import clone_public_repo, validate_github_url
from scanner_osv import scan_with_osv
from scanner_trivy import scan_with_trivy
from security_models import RepositoryInvestigation, RepositoryProfile, ScannerResult, SecurityFinding
from security_triage import category_summary, deduplicate_findings, triage_findings


SUMMARY_KEYS = ("total", "critical", "high", "medium", "low", "unknown")


def _run_scanner(scanner, repo_path: Path, errors: list[str]) -> dict:
    try:
        return scanner(repo_path)
    except Exception:
        name = "osv" if scanner is scan_with_osv else "trivy"
        errors.append(f"{name} scanner failed")
        return {"scanner": name, "status": "failed", "findings": [], "error": f"{name} scanner failed"}


def _summary(findings: list[SecurityFinding]) -> dict[str, int]:
    summary = {key: 0 for key in SUMMARY_KEYS}
    summary["total"] = len(findings)
    for finding in findings:
        severity = finding.severity.lower()
        summary[severity if severity in summary and severity != "total" else "unknown"] += 1
    return summary


def investigate_repository(repository_url: str) -> RepositoryInvestigation:
    validated_url = validate_github_url(repository_url)
    started_at = datetime.now(timezone.utc)
    errors: list[str] = []
    with TemporaryDirectory(prefix="aegis-repository-") as temp_dir:
        repo_path = Path(temp_dir) / "repository"
        clone_public_repo(validated_url, repo_path)
        profile = RepositoryProfile(**profile_repository(repo_path))
        scanner_results = []
        for scanner in (scan_with_osv, scan_with_trivy):
            result = _run_scanner(scanner, repo_path, errors)
            if result.get("error") and result["error"] not in errors:
                errors.append(result["error"])
            scanner_results.append(ScannerResult(**result))
        raw_findings = [finding for result in scanner_results for finding in result.findings]
        findings = deduplicate_findings(raw_findings)
        top_findings = triage_findings(findings)
    return RepositoryInvestigation(
        investigation_id=uuid4(),
        repository_url=validated_url,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
        profile=profile,
        scanner_results=scanner_results,
        findings=findings,
        raw_finding_count=len(raw_findings),
        unique_finding_count=len(findings),
        summary=_summary(findings),
        category_summary=category_summary(findings),
        top_findings=top_findings,
        errors=errors,
    )