from __future__ import annotations

from collections.abc import Iterable

from security_models import SecurityFinding


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
CATEGORY_ORDER = {
    "secret_exposure": 0,
    "dependency_vulnerability": 1,
    "iac_misconfiguration": 2,
    "kubernetes_misconfiguration": 3,
    "container_misconfiguration": 4,
}
CATEGORY_KEYS = tuple(CATEGORY_ORDER)


def finding_key(finding: SecurityFinding | dict) -> tuple[str, str, str, str, str]:
    get = finding.get if isinstance(finding, dict) else lambda key, default="": getattr(finding, key, default)
    return (
        str(get("source", "")),
        str(get("id", "")),
        str(get("package", "")),
        str(get("installed_version", "")),
        str(get("file", "")),
    )


def deduplicate_findings(findings: Iterable[SecurityFinding]) -> list[SecurityFinding]:
    unique = {}
    for finding in findings:
        unique.setdefault(finding_key(finding), finding)
    return list(unique.values())


def triage_findings(findings: Iterable[SecurityFinding], limit: int = 10) -> list[SecurityFinding]:
    ordered = sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity.upper(), 4),
            CATEGORY_ORDER.get(finding.category, len(CATEGORY_ORDER)),
            finding.source,
            finding.id,
            finding.package,
            finding.installed_version,
            finding.file,
        ),
    )
    return ordered[:limit]


def category_summary(findings: Iterable[SecurityFinding]) -> dict[str, int]:
    summary = {category: 0 for category in CATEGORY_KEYS}
    for finding in findings:
        if finding.category in summary:
            summary[finding.category] += 1
    return summary