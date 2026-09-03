# AEGIS Architecture

```mermaid
flowchart TD
    A[Security Finding] --> B[BigQuery Evidence Layer]
    B --> C[Deterministic Attack Path Engine]
    C --> D[Deterministic Root Cause Correlation]
    D --> E[Google ADK]
    E --> F[Gemini Remediation Agent]
    F --> G[Controlled IaC Candidate]
    G --> H[Deterministic Verification]
    H --> I[AEGIS Dashboard]

    T[Terraform] --> B
    GIT[Git history] --> B
    DEP[Deployment history] --> B
    FND[Security findings] --> B
```

## Decision boundary

The deterministic Python engine remains upstream of the AI remediation step. Gemini does not decide whether an attack path exists or whether the fix is verified.

## Evidence sources

- Terraform
- Git history
- deployment history
- security findings

## Operational notes

- BigQuery is used for evidence/correlation reads.
- Google ADK orchestrates the remediation workflow.
- Gemini is used only to generate a remediation proposal.
- Verification is always deterministic and authoritative.
