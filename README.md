# AEGIS

# Root-Cause-Traceable Attack Path Remediation for DevSecOps

## Problem

Security platforms tell teams what is exposed, but engineering still needs to trace the issue back to the change that created it and prove the fix closes the path.

## Solution

AEGIS combines deterministic security analysis with controlled AI assistance. It traces the public exposure to the Terraform change, correlates it to the introducing git commit and deployment, proposes a remediation, and verifies that the attack path is removed with deterministic logic.

## What makes AEGIS different

- It preserves the engineering causal chain: Terraform -> Git -> Deployment -> Exposure.
- It treats attack-path existence, risk score, and verification as deterministic facts.
- It separates AI remediation intent from authoritative security decisions.
- It keeps a clear human-readable evidence trail for demos and judgment.

## Architecture

AEGIS uses a local Python evidence layer, a deterministic graph and root-cause engine, and a narrow ADK/Gemini remediation step. The dashboard is presentation-only and never claims authoritative security decisions beyond the deterministic engine.

## Five-stage workflow

1. FIND
2. ATTACK PATH
3. ROOT CAUSE
4. REMEDIATION
5. VERIFICATION

## Google technologies used

- BigQuery Sandbox
- Google ADK
- Gemini API

## Deterministic vs AI responsibilities

Deterministic Python modules are the source of truth for:
- attack path existence
- risk scoring
- root-cause correlation
- final verification

AI is used only for remediation reasoning and textual proposal generation. It cannot override the deterministic verdict.

## Demo scenario

Canonical case:
- finding-0001
- PUBLIC_BUCKET_ACL
- risk 87
- severity CRITICAL
- resource aegis-sensitive-data-bucket
- introducing commit f3a8e91
- deployment deploy-004
- verified closure 87 -> 0

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## Google Cloud setup

This project is designed to use the following environment variables when available:

- AEGIS_GCP_PROJECT
- AEGIS_BIGQUERY_DATASET
- AEGIS_DEFAULT_FINDING
- AEGIS_ENV
- AEGIS_PORT
- AEGIS_DEMO_MODE

No API keys or credentials are stored in source code.

## BigQuery schema

The project includes BigQuery-compatible evidence records for findings, resources, commits, deployments, and attack paths. These are used for evidence correlation and read-only dashboard assembly.

## Running the dashboard

```bash
uvicorn app:app --reload
```

or

```bash
python3 app.py
```

## Testing

```bash
python3 -m pytest -q
```

## Security boundaries

- Deterministic logic is authoritative.
- AI decisions are constrained to proposal generation.
- Dashboard output never computes risk or attack paths independently.
- No credentials are embedded in the source tree.

## Current limitations

- The synthetic scenario is intentionally local and deterministic.
- Live BigQuery access requires an authenticated environment and is not executed in tests.
- Gemini execution can fail due to free-tier quota exhaustion, and the dashboard reflects that state honestly.

## Future production architecture

Possible future production integrations may include additional secure data exchange, orchestration, and deployment controls, but the implemented system remains the local deterministic + AI-assisted evidence workflow described above.
