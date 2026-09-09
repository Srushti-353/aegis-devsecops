from __future__ import annotations

from security_models import RemediationPlan, SecurityFinding


def _dependency_plan(finding: SecurityFinding) -> RemediationPlan:
    package = finding.package or "the affected package"
    if finding.fixed_version:
        action = (
            f"Upgrade {package} from {finding.installed_version or 'the installed version'} "
            f"to a patched version such as {finding.fixed_version} or later. "
            "Select the compatible patched release for the application's dependency branch."
        )
        commands = [
            f"Suggested developer command — not executed by AEGIS: npm install {package}@{finding.fixed_version}"
        ]
        confidence = "HIGH"
    else:
        action = (
            f"Identify a compatible patched release for {package} and update the dependency. "
            "The scanner did not provide a fixed version, so AEGIS will not invent one."
        )
        commands = ["Suggested developer command — not executed by AEGIS: update the dependency using the project's normal package workflow"]
        confidence = "MEDIUM"
    return RemediationPlan(
        finding_id=finding.id,
        title=finding.title or finding.id,
        severity=finding.severity,
        category=finding.category,
        package=finding.package,
        installed_version=finding.installed_version,
        recommended_version=finding.fixed_version,
        remediation_type="dependency_update",
        action=action,
        commands=commands,
        verification=[
            "Apply the compatible dependency update",
            "Recreate the lockfile as part of the normal developer workflow",
            "Re-run the AEGIS security scan",
            "Confirm this finding ID, package, and version are no longer detected",
        ],
        confidence=confidence,
        source=finding.source,
    )


def _secret_plan(finding: SecurityFinding) -> RemediationPlan:
    return RemediationPlan(
        finding_id=finding.id,
        title=finding.title or finding.id,
        severity=finding.severity,
        category=finding.category,
        package=finding.package,
        installed_version=finding.installed_version,
        remediation_type="credential_rotation",
        action="Revoke and rotate the exposed credential, remove the secret from source, move it to an environment or secret manager, and scan repository history for exposure.",
        verification=[
            "Confirm the credential has been revoked and replaced",
            "Confirm the secret is removed from the working tree and history remediation is assessed",
            "Re-run AEGIS and confirm the scanner no longer detects this finding",
        ],
        confidence="HIGH",
        source=finding.source,
    )


def _configuration_plan(finding: SecurityFinding) -> RemediationPlan:
    is_container = finding.category == "container_misconfiguration"
    subject = "container configuration" if is_container else "infrastructure configuration"
    return RemediationPlan(
        finding_id=finding.id,
        title=finding.title or finding.id,
        severity=finding.severity,
        category=finding.category,
        remediation_type="configuration_change",
        action=f"Review the {subject} guidance for this rule and apply the smallest compatible configuration change. AEGIS does not infer a code location or invent a fix from insufficient evidence.",
        verification=[
            "Apply the reviewed configuration change through the normal developer workflow",
            "Run the relevant configuration validation",
            "Re-run AEGIS and confirm this rule ID is no longer detected",
        ],
        confidence="MEDIUM",
        source=finding.source,
    )


def plan_remediation(finding: SecurityFinding) -> RemediationPlan:
    if finding.category == "dependency_vulnerability":
        return _dependency_plan(finding)
    if finding.category == "secret_exposure":
        return _secret_plan(finding)
    if finding.category in {"container_misconfiguration", "iac_misconfiguration", "kubernetes_misconfiguration"}:
        return _configuration_plan(finding)
    return RemediationPlan(
        finding_id=finding.id,
        title=finding.title or finding.id,
        severity=finding.severity,
        category=finding.category,
        remediation_type="manual_review",
        action="Review the scanner evidence and determine a conservative remediation before changing the repository.",
        verification=["Re-run AEGIS and confirm the finding is no longer detected"],
        confidence="LOW",
        source=finding.source,
    )