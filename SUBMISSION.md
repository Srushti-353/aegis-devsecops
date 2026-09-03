# AEGIS
Root-Cause-Traceable Attack Path Remediation for DevSecOps

## One-line pitch

AEGIS traces a security exposure back to the exact engineering change that caused it, generates a controlled remediation proposal, and deterministically proves the attack path is gone.

## Problem

Most security workflows stop at detection. Teams can see that a bucket is public, but they still need to connect that exposure to the Terraform change that introduced it, correlate it with the deployment that shipped it, and verify whether the fix actually eliminates the attack path. Without that chain, remediation remains disconnected from engineering reality.

## Solution

AEGIS follows a five-stage flow:

FIND
ATTACK PATH
ROOT CAUSE
REMEDIATION
VERIFICATION

It starts from the canonical finding, proves the attack path exists, traces the exposure to the introducing commit and deployment, proposes a remediation through a controlled AI-assisted step, and then verifies closure with deterministic logic instead of trusting a model output.

## What makes AEGIS different

- commit-level engineering attribution
- deployment correlation to the exploit path
- source-of-truth IaC remediation thinking
- deterministic verification as the security authority
- AI cannot override security-critical decisions

## Google technologies used

Only the implemented technologies are listed here:

- BigQuery Sandbox: evidence and correlation layer for findings, resources, commits, deployments, and attack-path records.
- Google ADK: orchestration layer for the remediation workflow.
- Gemini API: remediation proposal generation only, with the decision boundary preserved by deterministic verification.

## Demo scenario

Canonical case:
- public sensitive bucket exposure
- risk 87
- severity CRITICAL
- resource: aegis-sensitive-data-bucket
- commit: f3a8e91
- deployment: deploy-004
- verified closure: 87 -> 0

## Architecture

The deterministic Python engine remains the source of truth for:
- attack-path existence
- risk scoring
- root-cause correlation
- final verification

AI is used only for remediation reasoning and proposal generation. It does not decide whether the path exists or whether the fix is verified.

## Current limitations

- synthetic demo data
- single canonical finding in the local scenario
- Gemini quota can affect the latest live remediation run
- deployment remains local and no-billing by design
- production connectors are not implemented yet

## Future production path

The following are future work, not implemented in this submission:

- live CSPM and SIEM ingestion
- GitHub/GitLab provider integration
- CI/CD webhook-driven workflows
- pull request creation and review automation
- Cloud Run or event-driven deployment orchestration
- broader cloud resource type coverage

These are future production extensions, not part of the current deterministic-first implementation.
