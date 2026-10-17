"""Build a descriptive identity-by-operation coverage matrix offline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import load_validated_inputs


def build_coverage(spec_path: Path, config_path: Path) -> dict[str, Any]:
    """Describe configured identity/GET-operation pairs; do not infer policy gaps."""
    spec, config = load_validated_inputs(spec_path, config_path)
    operations = [
        f"GET {path}"
        for path, path_item in spec["paths"].items()
        if isinstance(path_item, dict) and isinstance(path_item.get("get"), dict)
    ]
    identities = list(config["identities"])
    cells: dict[tuple[str, str], list[dict[str, Any]]] = {
        (operation, identity): [] for operation in operations for identity in identities
    }
    for check in config["checks"]:
        key = (check["operation"], check["identity"])
        cells[key].append({"id": check["id"], "expected_status": check["expected_status"]})

    required = {(item["operation"], item["identity"]) for item in config.get("coverage", {}).get("required", [])}
    missing_required = sorted(pair for pair in required if not cells.get(pair))
    satisfied_required = len(required) - len(missing_required)
    required_check_ids = set(config.get("coverage", {}).get("required_checks", []))
    configured_check_ids = {check["id"] for check in config["checks"]}
    missing_required_check_ids = sorted(required_check_ids - configured_check_ids)
    satisfied_required_checks = len(required_check_ids) - len(missing_required_check_ids)

    configured_pairs = sum(bool(cell_checks) for cell_checks in cells.values())
    total_pairs = len(operations) * len(identities)
    return {
        "identities": identities,
        "operations": operations,
        "cells": cells,
        "required": required,
        "missing_required": missing_required,
        "required_pairs": len(required),
        "satisfied_required": satisfied_required,
        "required_check_ids": required_check_ids,
        "missing_required_check_ids": missing_required_check_ids,
        "required_check_count": len(required_check_ids),
        "satisfied_required_checks": satisfied_required_checks,
        "configured_pairs": configured_pairs,
        "total_pairs": total_pairs,
    }


def render_coverage_table(coverage: dict[str, Any]) -> str:
    """Render a compact Markdown matrix for terminals and issue descriptions."""
    identities = coverage["identities"]
    header = ["GET operation", *identities]
    rows = [header]
    for operation in coverage["operations"]:
        row = [operation]
        for identity in identities:
            pair = (operation, identity)
            checks = coverage["cells"][pair]
            if checks:
                marker = "[required] " if pair in coverage["required"] else ""
                row.append(marker + "; ".join(f"{item['id']} [{','.join(map(str, item['expected_status']))}]" for item in checks))
            elif pair in coverage["required"]:
                row.append("[MISSING REQUIRED]")
            else:
                row.append("[not configured]")
        rows.append(row)

    widths = [max(len(row[index]) for row in rows) for index in range(len(header))]
    lines = ["| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |" for row in rows]
    lines.insert(1, "| " + " | ".join("-" * width for width in widths) + " |")
    lines.append("")
    lines.append(f"Configured identity/operation pairs: {coverage['configured_pairs']} / {coverage['total_pairs']}")
    lines.append(f"Required pairs satisfied: {coverage['satisfied_required']} / {coverage['required_pairs']}")
    lines.append(f"Required check IDs satisfied: {coverage['satisfied_required_checks']} / {coverage['required_check_count']}")
    if coverage["missing_required"]:
        lines.append("Missing required pairs: " + ", ".join(f"{identity} / {operation}" for operation, identity in coverage["missing_required"]))
    if coverage["missing_required_check_ids"]:
        lines.append("Missing required check IDs: " + ", ".join(coverage["missing_required_check_ids"]))
    lines.append("An unconfigured cell means no scenario is defined; it does not indicate a vulnerability.")
    lines.append("Offline coverage view. No network requests were sent; token values were not read.")
    return "\n".join(lines)
