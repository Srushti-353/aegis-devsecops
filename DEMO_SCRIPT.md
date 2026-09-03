# DEMO SCRIPT

## 1. Problem — 20–30 seconds

Security platforms tell teams what is exposed, but engineers still need to trace the issue to the change that created it and prove the fix closes the attack path.

## 2. Finding — 20 seconds

Show the incident:
- PUBLIC_BUCKET_ACL
- CRITICAL
- risk 87

## 3. Attack path — 30 seconds

Show:
- internet -> aegis-sensitive-data-bucket

Explain that deterministic graph analysis proves the path exists and scores the exposure.

## 4. Root cause — 30–40 seconds

Show:
- commit f3a8e91
- deployment deploy-004

Explain the causal chain from Terraform configuration to the engineering change and production deployment.

## 5. Remediation — 30–40 seconds

Explain the architecture:
- Google ADK orchestrates the remediation agent.
- Gemini proposes the source-of-truth remediation based on evidence.
- Latest Gemini execution may show quota-exceeded state, and the dashboard reflects that honestly.

## 6. Verification — 30 seconds

Show:
- 87 -> 0
- attack path removed

Explain that verification is deterministic and AI cannot override it.

## 7. Google Cloud — 30 seconds

Explain the roles:
- BigQuery: evidence and correlation layer
- Google ADK: agent orchestration
- Gemini: remediation reasoning
- Deterministic Python: security decision authority

## 8. Closing — 15 seconds

"AEGIS doesn't stop at telling you what's vulnerable. It traces the exposure to the engineering change that caused it, proposes the source-of-truth fix, and proves the attack path is gone."

## JUDGE QUESTIONS

### Why isn't this another SIEM?
Because AEGIS traces the root cause to the engineering change and proves closure with deterministic verification, not just alerting.

### Why isn't this just Wiz?
Wiz is valuable for platform visibility, but this workflow adds engineering lineage and deterministic verification tied to the exact change that created the issue.

### Why use AI at all?
AI helps generate a remediation proposal from structured evidence. It does not decide the security verdict.

### Why not let Gemini calculate risk?
Because the security decision must be deterministic and auditable. Gemini can assist with remediation text, but not final attack-path or risk decisions.

### How do you prevent hallucinated remediation?
The AI output is treated as a proposal only; the code verifies a controlled candidate patch and the deterministic engine decides whether the exposure is closed.

### Where does BigQuery fit?
BigQuery is the evidence and correlation layer for findings, commits, deployments, resources, and attack-path records.

### What happens if Gemini fails?
The system reports the state honestly, shows the deterministic known-good verification, and does not pretend a remediation succeeded.

### What is deterministic vs AI-driven?
Deterministic: attack path, risk score, root cause, verification. AI-driven: remediation proposal generation.

### How would this scale beyond the synthetic demo?
By expanding the evidence model, normalizing more IaC and deployment telemetry, and preserving the same trust boundary between AI proposal and deterministic decisioning.

### What would production integration look like?
Authenticated BigQuery reads, a controlled IaC diff pipeline, policy checks, and deterministic verification before deployment approval.
