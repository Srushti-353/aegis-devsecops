# Final Demo Checklist

## BEFORE DEMO

- authenticate gcloud/ADC if required
- verify project
- verify BigQuery dataset
- verify /ready
- run tests
- start dashboard
- open finding-0001
- verify BigQuery evidence source
- verify risk 87
- verify f3a8e91
- verify deploy-004
- verify verification 87 -> 0
- verify no raw errors visible

## BACKUP MODE

Command:

AEGIS_DEMO_MODE=true uvicorn app:app --reload

Confirm the visible fallback banner says the app is using canonical local evidence.

## DEMO ORDER

1. problem
2. finding
3. attack path
4. root cause
5. remediation
6. verification
7. architecture
8. closing

## SCREENSHOTS TO CAPTURE

- overview showing CRITICAL / 87
- attack path
- root cause commit + deployment
- verification 87 -> 0
- Google architecture
- BigQuery query result
- /ready response

## FAILURE RECOVERY

### If Wi‑Fi fails
- keep the local dashboard running from the demo machine
- fallback to the canonical evidence flow
- avoid trying to re-establish cloud connectivity during the demo

### If BigQuery fails
- confirm the app is in fallback mode
- show the dashboard banner and local evidence narrative
- avoid claiming live data when the environment is offline

### If Gemini quota is exhausted
- explain the system is designed to show the deterministic verification path without pretending the AI proposal succeeded
- continue with the canonical verified fix story

### If browser cache causes stale UI
- hard refresh the page
- confirm the banner and case values still match the canonical scenario

### If server port is already in use
- stop the conflicting process or rerun with a free port
- verify /health and /ready before presenting
