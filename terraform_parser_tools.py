"""Deterministic Terraform extraction for the canonical AEGIS scenario."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import hcl2


def unquote(value: Any) -> Any:
    """Normalize literal quote characters returned by python-hcl2 8.x."""
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {unquote(key): _normalize(item) for key, item in value.items() if key != "__is_block__"}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return unquote(value)


def parse_terraform(path: str | Path | None = None, content: str | None = None) -> dict[str, Any]:
    """Parse Terraform configuration into resources and relationships.
    
    Args:
        path: Path to .tf file (mutually exclusive with content)
        content: Terraform HCL as string (mutually exclusive with path)
    
    One of path or content must be provided.
    """
    if path is not None:
        source = Path(path)
        if not source.is_file():
            raise FileNotFoundError(f"Terraform file not found or is not a file: {source}")
        with source.open() as terraform_file:
            parsed = _normalize(hcl2.load(terraform_file))
        source_file = str(source)
    elif content is not None:
        # Parse from string for candidate patches
        import io
        parsed = _normalize(hcl2.load(io.StringIO(content)))
        source_file = "<candidate>"
    else:
        raise ValueError("Either path or content must be provided")

    resources = []
    for resource_block in parsed.get("resource", []):
        for resource_type, named_blocks in resource_block.items():
            for resource_name, attributes in named_blocks.items():
                resources.append({
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "attributes": attributes,
                    "source_file": source_file,
                })

    buckets = [resource for resource in resources if resource["resource_type"] == "google_storage_bucket"]
    relationships = [
        {
            "source": attributes.get("member"),
            "target": attributes.get("bucket"),
            "role": attributes.get("role"),
            "resource_name": resource["resource_name"],
        }
        for resource in resources
        if resource["resource_type"] == "google_storage_bucket_iam_member"
        for attributes in [resource["attributes"]]
    ]
    return {"source_file": source_file, "resources": resources, "buckets": buckets, "relationships": relationships}


def parse_terraform_json(path: str | Path) -> str:
    return json.dumps(parse_terraform(path), sort_keys=True, indent=2)


def iter_resources(parsed: dict[str, Any], resource_type: str | None = None) -> Iterable[dict[str, Any]]:
    for resource in parsed.get("resources", []):
        if resource_type is None or resource["resource_type"] == resource_type:
            yield resource


def extract_bucket_configuration(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    return list(iter_resources(parsed, "google_storage_bucket"))


def extract_iam_relationships(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    return list(parsed.get("relationships", []))


parse_file = parse_terraform