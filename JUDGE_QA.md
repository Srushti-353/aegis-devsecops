# AEGIS Judge Q&A

1. What problem does AEGIS solve?
   AEGIS connects a security exposure to the engineering change that caused it and proves the fix closed the path, instead of stopping at alerting.

2. Why is this not another SIEM?
   SIEMs aggregate signals. AEGIS adds engineering lineage, commit-level attribution, and deterministic closure verification.

3. Why is this not just Wiz or another CSPM?
   It is not presented as a competitor replacement. AEGIS focuses on causal tracing from IaC change to deployment to verified closure.

4. What does Gemini actually do?
   Gemini only helps generate a remediation proposal from the structured evidence trail. It does not decide risk or closure.

5. Why not let Gemini calculate risk?
   Risk and attack-path truth must be deterministic and auditable. The model is not the authority for security-critical decisions.

6. How do you prevent hallucinated remediation?
   The workflow treats AI output as a proposal, then validates the candidate against a controlled fixture and deterministic verification logic.

7. Why use deterministic verification?
   Because the final decision must be explainable, repeatable, and not subject to model drift or prompt variation.

8. How is root cause established?
   The engine correlates the finding to the Terraform exposure, then maps it to the introducing git commit and deployment history.

9. Why BigQuery?
   BigQuery provides a simple structured evidence layer for findings, resources, commits, deployments, and attack paths in a sandbox-friendly form.

10. What happens if Gemini fails?
    The system reports the state honestly, keeps the deterministic verification path visible, and does not pretend the AI remediation succeeded.

11. What happens if BigQuery is unavailable?
    The app falls back to canonical local evidence and clearly labels the dashboard as a demo fallback rather than claiming live production data.

12. Is the demo data real?
    It is synthetic but realistic: the project intentionally uses a canonical local case for deterministic demo and evaluation.

13. How would you connect this to GitHub/GitLab?
    By ingesting repository metadata, deployment events, and PR metadata into the same evidence model used today.

14. How would you create an actual PR?
    A production path would generate a remediation branch or patch, open a PR with the IaC fix, and require deterministic verification before merge.

15. How would this scale to multiple findings?
    The same evidence model can be extended to multiple findings, each with an attack path, root cause, and verification state.

16. What are the security boundaries?
    Deterministic logic decides attack existence, risk, root cause, and closure. AI only proposes remediation text or patch intent.

17. Why use Google ADK?
    It provides a structured orchestration layer while keeping the actual decision boundary in deterministic Python code.

18. What parts are currently implemented vs future?
    Implemented: local evidence model, deterministic engine, ADK integration, BigQuery evidence layer, dashboard, Docker/demo hardening. Future: live cloud connectors, broader resource coverage, deeper CI/CD integration.

19. What is the strongest differentiator?
    The combination of engineering lineage and deterministic verification turns a finding into a proven, attributable remediation story.

20. What would you build next with more time?
    More cloud resource types, live Git provider integration, PR automation, and a CI-enforced remediation gate.
