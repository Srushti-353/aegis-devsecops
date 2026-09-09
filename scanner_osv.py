from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def _short_error(returncode: int, stderr: str) -> str:
    detail = " ".join((stderr or "").splitlines()[0].split()) if stderr else ""
    if detail:
        return detail[:160]
    return f"Scanner exited with code {returncode}"


def _unknown(value) -> str:
    return str(value) if value is not None else ""


def _normalize(entry: dict, source_file: str = "") -> dict:
    package = entry.get("package") or entry.get("dependency", {}).get("package", "")
    installed_version = entry.get("version") or entry.get("installed_version")
    if isinstance(package, dict):
        installed_version = installed_version or package.get("version", "")
        package = package.get("name", "")
    vulnerability = entry.get("vulnerability", entry)
    aliases = vulnerability.get("aliases", []) or []
    cve = next((item for item in aliases if str(item).startswith("CVE-")), "")
    affected = vulnerability.get("affected", [{}]) or [{}]
    ranges = affected[0].get("ranges", []) if isinstance(affected[0], dict) else []
    fixed = ""
    for version_event in (ranges[0].get("events", []) if ranges else []):
        if isinstance(version_event, dict) and version_event.get("fixed"):
            fixed = version_event["fixed"]
            break
    return {
        "id": _unknown(vulnerability.get("id") or entry.get("id")),
        "source": "osv",
        "category": "dependency_vulnerability",
        "severity": str(vulnerability.get("severity") or entry.get("severity") or "UNKNOWN").upper(),
        "title": _unknown(vulnerability.get("summary") or vulnerability.get("title") or entry.get("title")),
        "description": _unknown(vulnerability.get("details") or entry.get("description")),
        "package": _unknown(package),
        "installed_version": _unknown(installed_version),
        "fixed_version": _unknown(entry.get("fixed_version") or fixed),
        "cve": cve,
        "file": _unknown(entry.get("file") or source_file),
        "line": entry.get("line"),
        "confidence": "HIGH",
    }


def _entries(payload: dict) -> list[tuple[dict, str]]:
    result = []
    for result_group in payload.get("results", []):
        source_file = result_group.get("source", {}).get("path", "")
        for package in result_group.get("packages", []):
            for vulnerability in package.get("vulnerabilities", []):
                result.append(({**vulnerability, "package": package.get("package", {})}, source_file))
    for item in payload.get("vulnerabilities", []):
        result.append((item, ""))
    return result


def scan_with_osv(repo_path: Path) -> dict:
    executable = shutil.which("osv-scanner")
    if not executable:
        return {"scanner": "osv", "status": "unavailable", "findings": []}
    command = [executable, "scan", "source", "-r", "--format", "json", str(repo_path)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120, shell=False)
        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            return {"scanner": "osv", "status": "failed", "findings": [], "error": _short_error(completed.returncode, completed.stderr)}
        findings = [_normalize(entry, source_file) for entry, source_file in _entries(payload)]
        return {"scanner": "osv", "status": "completed", "findings": findings}
    except subprocess.TimeoutExpired:
        return {"scanner": "osv", "status": "failed", "findings": [], "error": "OSV scan timed out"}
    except OSError:
        return {"scanner": "osv", "status": "failed", "findings": [], "error": "Unable to start OSV Scanner"}