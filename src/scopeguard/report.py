"""Render redacted ScopeGuard results for humans."""

from __future__ import annotations

from typing import Any


def _cell(value: Any) -> str:
    """Escape untrusted/configured text for a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render the already-redacted JSON report without adding response data."""
    summary = report["summary"]
    lines = [
        "# ScopeGuard report",
        "",
        f"- Generated: {_cell(report['generated_at'])}",
        f"- Version: {_cell(report['version'])}",
        f"- OpenAPI: {_cell(report['spec_file'])}",
        f"- Scenario: {_cell(report['scenario_file'])}",
        "",
        "## Summary",
        "",
        "| PASS | FAIL | SKIPPED | ERROR |",
        "| ---: | ---: | ---: | ---: |",
        f"| {summary['PASS']} | {summary['FAIL']} | {summary['SKIPPED']} | {summary['ERROR']} |",
        "",
        "## Checks",
        "",
        "| Status | Check | Identity | Operation | Expected | Actual | Assertions |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for result in report["results"]:
        actual = result.get("actual_status", result.get("reason", "-"))
        assertions = "; ".join(
            f"{item['pointer']} {item['operator']}: {item['status']}"
            for item in result.get("assertions", [])
        ) or "-"
        lines.append(
            "| " + " | ".join(
                _cell(value)
                for value in (
                    result["status"],
                    result["id"],
                    result["identity"],
                    result["operation"],
                    ", ".join(map(str, result["expected_status"])),
                    actual,
                    assertions,
                )
            ) + " |"
        )
    lines.extend(
        [
            "",
            "Response bodies, assertion values, and credential values are not included in this report.",
            "",
        ]
    )
    return "\n".join(lines)
