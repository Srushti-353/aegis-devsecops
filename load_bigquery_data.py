#!/usr/bin/env python3
"""Load the canonical AEGIS scenario into BigQuery.

This script is intentionally defensive: it does not run in tests and is only a
small data-loading utility for an already-configured environment.
"""

from __future__ import annotations

from bigquery_tools import load_aegis_data


def main() -> int:
    summary = load_aegis_data()
    print("AEGIS BigQuery load complete")
    print(f"Findings: {summary.get('findings', 0)}")
    print(f"Resources: {summary.get('resources', 0)}")
    print(f"Commits: {summary.get('commits', 0)}")
    print(f"Deployments: {summary.get('deployments', 0)}")
    print(f"Attack paths: {summary.get('attack_paths', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
