# AEGIS — Day 1 Package
## A. Updated Folder Structure

Reflects: single primary attack path (public bucket), compute/SA as optional alternate
encoded in data but not required by the core engine, local-first development.

```
aegis/
├── terraform/                        # AEGIS platform infra — NOT built Day 1 (Day 6)
│
├── scenario/                         # THE canonical demo scenario — Day 1 focus
│   ├── target_infra/
│   │   ├── main.tf                   # vulnerable: public bucket via allUsers binding
│   │   │                             #   + optional/alternate compute+SA path (commented as ALT)
│   │   └── main.patched.tf           # ground-truth fixed version
│   ├── commit_history.json           # synthetic git log, one commit is the culprit
│   ├── deployment_events.json        # synthetic GitHub-Actions-style apply events
│   ├── finding.json                  # the seeded security finding
│   └── schema/
│       ├── resource.schema.json
│       ├── commit.schema.json
│       ├── deployment_event.schema.json
│       └── finding.schema.json
│
├── services/
│   └── orchestrator/                 # NOT built Day 1 — starts Day 2+
│       └── app/
│           ├── agents/               # find_agent, trace_agent, remediation_agent, verify_agent
│           ├── tools/                # graph_tools, terraform_parser_tools, patch_tools, verify_tools
│           └── models/               # schemas.py (pydantic mirror of scenario/schema/*.json)
│
├── bigquery/schemas/                 # NOT built Day 1 — Day 6 (cloud integration phase)
├── dashboard/looker_studio/          # NOT built Day 1 — Day 6
├── local/                            # docker-compose, Makefile — introduced Day 2 once tools exist
│
├── tests/
│   └── test_day1_acceptance.py       # Day 1 gate — must be 100% green before Day 2 starts
│
└── README.md
```

Naming note: **"Remediation Agent"** replaces "Fix Agent" throughout, matching change #4/#8 —
its only output is a proposed Terraform patch (diff + explanation), never an applied change.

---

## B. Exact Day 1 Files (create in this order)

1. `scenario/schema/resource.schema.json`
2. `scenario/schema/commit.schema.json`
3. `scenario/schema/deployment_event.schema.json`
4. `scenario/schema/finding.schema.json`
5. `scenario/target_infra/main.tf`
6. `scenario/target_infra/main.patched.tf`
7. `scenario/commit_history.json`
8. `scenario/deployment_events.json`
9. `scenario/finding.json`
10. `tests/test_day1_acceptance.py`

No Python application code, no ADK, no Gemini, no GCP calls on Day 1. Pure static
scenario authoring + schema definition + a pytest file that checks it's all internally
consistent. This is deliberate: if the story isn't airtight as data, no amount of agent
code fixes it later.

---

## I. Day 1 Acceptance Criteria (enforced by `tests/test_day1_acceptance.py`)

1. All four JSON files parse and validate against their schema.
2. Both `.tf` files parse cleanly with `python-hcl2`.
3. `finding.json.resource_name` matches a `google_storage_bucket` resource name in `main.tf`.
4. `main.tf` contains exactly one `google_storage_bucket_iam_member` binding with
   `member = "allUsers"` on the sensitive bucket — this is *the* vulnerability, singular.
5. `commit_history.json` contains exactly one commit whose diff adds the `allUsers` line,
   and its `commit_sha` matches a `deployment_events.json` entry with `status = "success"`.
6. `main.patched.tf` contains **no** `allUsers` (or `allAuthenticatedUsers`) binding
   anywhere, and the sensitive bucket resource name is unchanged from `main.tf`
   (so a diff between the two files is meaningful).
7. The optional alternate path (compute instance + service account bucket access) is
   present in `main.tf`/`main.patched.tf` but the test suite does **not** require it to
   resolve to anything — it's inert data until Day 5+ if you choose to wire it in.
8. Every finding/commit/deployment record shares no invented resource names — all three
   files reference the exact same bucket name string, byte for byte.
