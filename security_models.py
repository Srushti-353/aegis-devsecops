from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl


class RepositoryProfile(BaseModel):
    languages: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    terraform: bool = False
    kubernetes: bool = False
    docker: bool = False
    git_history_available: bool = False
    file_count: int = 0


class SecurityFinding(BaseModel):
    id: str
    source: str
    category: str
    severity: str = "UNKNOWN"
    title: str = ""
    description: str = ""
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cve: str = ""
    file: str = ""
    line: int | None = None
    confidence: str = "UNKNOWN"


class RemediationPlan(BaseModel):
    finding_id: str
    title: str
    severity: str
    category: str
    package: str = ""
    installed_version: str = ""
    recommended_version: str = ""
    remediation_type: str
    action: str
    commands: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    confidence: str
    source: str
    ai_status: str = "not_requested"


class RemediationPlanRequest(BaseModel):
    finding: SecurityFinding
    repository_url: HttpUrl


class LiveEvidenceRequest(BaseModel):
    finding: SecurityFinding
    repository_url: HttpUrl


class VerificationRequest(BaseModel):
    finding: SecurityFinding
    repository_url: HttpUrl
    patched_repository_url: HttpUrl | None = None


class ScannerResult(BaseModel):
    scanner: str
    status: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    error: str | None = None


class RepositoryInvestigation(BaseModel):
    investigation_id: UUID
    repository_url: str
    started_at: datetime
    completed_at: datetime
    profile: RepositoryProfile
    scanner_results: list[ScannerResult] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    raw_finding_count: int = 0
    unique_finding_count: int = 0
    summary: dict[str, int] = Field(default_factory=dict)
    category_summary: dict[str, int] = Field(default_factory=dict)
    top_findings: list[SecurityFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class RepositoryInvestigationRequest(BaseModel):
    repository_url: HttpUrl