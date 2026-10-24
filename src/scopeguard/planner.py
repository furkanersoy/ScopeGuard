"""Build a safe, offline preview of validated scenario requests."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from .config import _parse_operation, is_loopback_host, load_validated_inputs


def build_plan(spec_path: Path, config_path: Path) -> dict[str, Any]:
    """Return request metadata for a scenario without reading secrets or using the network."""
    _, config = load_validated_inputs(spec_path, config_path)
    target = config["target"]
    base_url = target["base_url"].rstrip("/")
    parsed = urlsplit(base_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    checks = []

    for check in config["checks"]:
        method, path_template = _parse_operation(check["operation"], "scenario operation")
        path = re.sub(
            r"\{([^{}]+)\}",
            lambda match: quote(str(check.get("path", {})[match.group(1)]), safe=""),
            path_template,
        )
        checks.append(
            {
                "id": check["id"],
                "identity": check["identity"],
                "method": method,
                "url": f"{base_url}{path}",
                "expected_status": check["expected_status"],
                "assertions": [
                    {
                        "pointer": assertion["pointer"],
                        "operator": "equals" if "equals" in assertion else "not_equals",
                    }
                    for assertion in check.get("assert_json", [])
                ],
            }
        )

    remote = not is_loopback_host(host)
    return {
        "target": f"{parsed.scheme}://{host}:{port}",
        "remote": remote,
        "max_requests": target["max_requests"],
        "check_count": len(checks),
        "checks": checks,
    }
