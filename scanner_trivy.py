from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


SECRET_PATTERN = re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+")


def redact_secret(value) -> str:
    if value is None:
        return ""
    return SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", str(value))


def _category(result: dict, item: dict) -> str:
    result_type = str(result.get("Type") or "").lower()
    item_type = str(item.get("Type") or item.get("Category") or "").lower()
    target = str(result.get("Target") or result.get("ArtifactName") or item.get("Target") or "").lower()
    metadata = " ".join(str(item.get(key, "")) for key in ("Title", "RuleID", "SecretID", "Category", "Match"))
    metadata_lower = metadata.lower()
    if result_type in {"secret", "secrets"} or item_type in {"secret", "secrets"} or any(
        marker in metadata_lower for marker in ("secret", "private-key", "private key", "asymmetric")
    ):
        return "secret_exposure"
    if result_type in {"config", "misconfig", "terraform", "kubernetes", "dockerfile"} or item_type in {
        "config", "misconfig", "terraform", "kubernetes", "dockerfile"
    }:
        if "kube" in target or "k8s" in target or "kubernetes" in target or "kube" in metadata_lower:
            return "kubernetes_misconfiguration"
        if "docker" in target or "dockerfile" in target or "container" in metadata_lower or "healthcheck" in metadata_lower:
            return "container_misconfiguration"
        return "iac_misconfiguration"
    if target.endswith((".tf", ".tf.json")) or "/terraform/" in target:
        return "iac_misconfiguration"
    if target.endswith(("dockerfile", "docker-compose.yml", "docker-compose.yaml")):
        return "container_misconfiguration"
    if target.endswith((".yaml", ".yml")) and any(marker in target for marker in ("k8s", "kube", "deployment", "service")):
        return "kubernetes_misconfiguration"
    return "dependency_vulnerability"


def _normalize(result: dict, item: dict) -> dict:
    category = _category(result, item)
    identifier = item.get("VulnerabilityID") or item.get("ID") or item.get("RuleID") or item.get("SecretID") or "trivy-finding"
    return {
        "id": redact_secret(identifier),
        "source": "trivy",
        "category": category,
        "severity": str(item.get("Severity") or "UNKNOWN").upper(),
        "title": redact_secret(item.get("Title") or item.get("Message") or item.get("RuleID") or "Trivy finding"),
        "description": redact_secret(item.get("Description") or item.get("Resolution") or ""),
        "package": redact_secret(item.get("PkgName") or item.get("PackageName") or ""),
        "installed_version": redact_secret(item.get("InstalledVersion") or ""),
        "fixed_version": redact_secret(item.get("FixedVersion") or ""),
        "cve": redact_secret(identifier if str(identifier).startswith("CVE-") else item.get("PrimaryURL", "")),
        "file": redact_secret(item.get("Target") or item.get("ArtifactName") or ""),
        "line": item.get("StartLine") or item.get("Line"),
        "confidence": "HIGH" if category != "secret_exposure" else "MEDIUM",
    }


def scan_with_trivy(repo_path: Path) -> dict:
    executable = shutil.which("trivy")
    if not executable:
        return {"scanner": "trivy", "status": "unavailable", "findings": []}
    command = [executable, "fs", "--format", "json", "--scanners", "vuln,misconfig,secret", str(repo_path)]
    try:
        completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=180, shell=False)
        payload = json.loads(completed.stdout or "{}")
        findings = []
        for result in payload.get("Results", []):
            for key in ("Vulnerabilities", "Misconfigurations", "Secrets"):
                findings.extend(_normalize(result, item) for item in result.get(key, []) or [])
        return {"scanner": "trivy", "status": "completed", "findings": findings}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return {"scanner": "trivy", "status": "failed", "findings": [], "error": "Trivy failed"}