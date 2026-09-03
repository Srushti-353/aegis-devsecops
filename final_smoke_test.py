#!/usr/bin/env python3
"""Safe end-to-end smoke test for the AEGIS demo package.

Default behavior is local-only and does not make Gemini calls or write to BigQuery.
Use --live-bigquery only for an explicit, authenticated check.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from fastapi.testclient import TestClient

from app import app
from bigquery_tools import get_attack_path, get_finding, get_root_cause_evidence
from config import get_default_finding
from day3_workflow import deterministic_verification_tool
from ui_service import get_dashboard_case


FAILURES: list[str] = []


def record(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def check_config() -> None:
    record(get_default_finding() == "finding-0001", "default finding should remain finding-0001")


def check_canonical_case() -> None:
    finding = get_finding("finding-0001")
    record(bool(finding), "finding-0001 should exist locally")
    record(finding.get("finding_id") == "finding-0001", "finding id mismatch")

    attack = get_attack_path("finding-0001")
    record(bool(attack), "attack path should exist")
    record(attack.get("path_exists") is True, "attack path should exist before fix")
    record(int(attack.get("risk_score", 0)) == 87, "risk should remain 87")

    root = get_root_cause_evidence("finding-0001")
    record(root.get("introducing_commit") == "f3a8e91", "introducing commit should remain f3a8e91")
    record(root.get("deployment_id") == "deploy-004", "deployment should remain deploy-004")

    verification = deterministic_verification_tool("finding-0001")
    record(int(verification.get("before_risk", 0)) == 87, "before risk should be 87")
    record(int(verification.get("after_risk", 0)) == 0, "after risk should be 0")


def check_health_and_dashboard() -> None:
    client = TestClient(app)
    health = client.get("/health")
    record(health.status_code == 200, "health endpoint should return 200")
    record(health.json().get("status") == "ok", "health status should be ok")

    case = get_dashboard_case("finding-0001")
    record(case["attack_path"]["risk_score"] == 87, "dashboard case risk should remain 87")
    record(case["root_cause"]["commit_sha"] == "f3a8e91", "dashboard case commit should remain f3a8e91")
    record(case["verification"]["after_risk"] == 0, "dashboard verification should be 0")


def check_live_bigquery(args: argparse.Namespace) -> None:
    if not args.live_bigquery:
        return
    try:
        import bigquery_tools
        client = bigquery_tools.get_bigquery_client()
        if client is None:
            raise RuntimeError("BigQuery client unavailable")
        finding = bigquery_tools.get_finding("finding-0001", client=client)
        record(bool(finding), "live BigQuery finding-0001 should exist")
    except Exception as exc:  # pragma: no cover - explicit live path only
        FAILURES.append(f"live BigQuery check failed: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS local smoke test")
    parser.add_argument("--live-bigquery", action="store_true", help="explicitly verify live BigQuery access")
    args = parser.parse_args()

    try:
        check_config()
        check_canonical_case()
        check_health_and_dashboard()
        check_live_bigquery(args)
    except Exception as exc:  # pragma: no cover - fail-fast guard
        FAILURES.append(f"unexpected smoke test error: {exc}")

    if FAILURES:
        print("FAIL")
        for item in FAILURES:
            print(f" - {item}")
        return 1

    print("PASS")
    print("AEGIS canonical case and dashboard checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
