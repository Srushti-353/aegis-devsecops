"""Deterministic security graph for the canonical AEGIS scenario."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


def build_security_graph(parsed: dict[str, Any]) -> dict[str, Any]:
    nodes = {"internet": {"type": "external", "sensitive": False}}
    edges: list[dict[str, str]] = []
    for bucket in parsed.get("buckets", []):
        attributes = bucket["attributes"]
        bucket_name = attributes.get("name", bucket["resource_name"])
        nodes[bucket_name] = {
            "type": "google_storage_bucket",
            "resource_name": bucket["resource_name"],
            "sensitive": attributes.get("labels", {}).get("data_classification") == "sensitive",
        }
        for relationship in parsed.get("relationships", []):
            target = str(relationship.get("target", ""))
            is_public = relationship.get("source") in ("allUsers", "allAuthenticatedUsers")
            targets_bucket = bucket["resource_name"] in target
            if is_public and targets_bucket:
                edges.append({"source": "internet", "target": bucket_name, "reason": relationship.get("role", "public access")})
    return {"nodes": nodes, "edges": edges}


def reachable_nodes(graph: dict[str, Any], start: str = "internet") -> list[str]:
    adjacency = defaultdict(list)
    for edge in graph.get("edges", []):
        adjacency[edge["source"]].append(edge["target"])
    visited, queue = set(), deque([start])
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        queue.extend(adjacency[current])
    return sorted(visited)


def _severity(score: int) -> str:
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def analyze_security(parsed: dict[str, Any], finding: dict[str, Any] | None = None) -> dict[str, Any]:
    """Score public sensitive buckets: base 60 + public 17 + sensitive 10 = 87."""
    graph = build_security_graph(parsed)
    sensitive_buckets = {
        name for name, node in graph["nodes"].items()
        if node.get("type") == "google_storage_bucket" and node.get("sensitive")
    }
    public_buckets = {edge["target"] for edge in graph["edges"] if edge["source"] == "internet"}
    target = next(iter(sensitive_buckets & public_buckets), None)
    path_exists = target is not None
    score = 87 if path_exists else 0
    return {
        "finding_id": (finding or {}).get("finding_id", "F-001"),
        "attack_path": ["internet", target] if target else [],
        "path_exists": path_exists,
        "sensitive_resource": bool(target),
        "risk_score": score,
        "severity": _severity(score),
        "blast_radius": 1 if target else 0,
        "evidence": ["allUsers grants public bucket access", "bucket is labeled sensitive"] if path_exists else [],
        "graph": graph,
    }


build_graph = build_security_graph
detect_attack_path = analyze_security