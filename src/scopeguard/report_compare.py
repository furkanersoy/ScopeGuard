"""Compare two local ScopeGuard JSON reports without network access."""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .config import ValidationError
from .local_scan import _atomic_write


def _load(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > 25_000_000:
            raise ValidationError(f"report exceeds the 25 MB limit: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValidationError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValidationError(f"unsupported ScopeGuard report format: {path}")
    return data


def _key(finding: dict[str, Any]) -> str:
    identity = {
        name: finding.get(name)
        for name in ("rule_id", "file", "line", "package", "version", "vulnerability_id")
    }
    return json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compare_reports(previous_path: Path, current_path: Path) -> dict[str, Any]:
    """Compare active findings; suppressions remain separate in each input report."""
    previous = _load(previous_path)
    current = _load(current_path)
    old_items = [item for item in previous["findings"] if isinstance(item, dict)]
    new_items = [item for item in current["findings"] if isinstance(item, dict)]
    old_counts = Counter(_key(item) for item in old_items)
    new_counts = Counter(_key(item) for item in new_items)
    old_by_key = {_key(item): item for item in old_items}
    new_by_key = {_key(item): item for item in new_items}
    entries: list[dict[str, Any]] = []

    for key, count in new_counts.items():
        shared = min(count, old_counts.get(key, 0))
        for _ in range(shared):
            entries.append({"state": "unchanged", "finding": new_by_key[key]})
        for _ in range(count - shared):
            entries.append({"state": "added", "finding": new_by_key[key]})
    for key, count in old_counts.items():
        removed = count - min(count, new_counts.get(key, 0))
        for _ in range(removed):
            entries.append({"state": "resolved", "finding": old_by_key[key]})

    entries.sort(key=lambda item: (item["state"], item["finding"].get("file", ""), item["finding"].get("rule_id", "")))
    return {
        "tool": "ScopeGuard",
        "mode": "report-comparison",
        "previous_report": previous_path.name,
        "current_report": current_path.name,
        "summary": {
            "added": sum(1 for item in entries if item["state"] == "added"),
            "resolved": sum(1 for item in entries if item["state"] == "resolved"),
            "unchanged": sum(1 for item in entries if item["state"] == "unchanged"),
            "suppressed_previous": len(previous.get("suppressed_findings") or []),
            "suppressed_current": len(current.get("suppressed_findings") or []),
        },
        "entries": entries,
    }


def render_comparison_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# ScopeGuard report comparison", "",
        f"- Previous: {report['previous_report']}",
        f"- Current: {report['current_report']}",
        f"- Added: {summary['added']} · Resolved: {summary['resolved']} · Unchanged: {summary['unchanged']}",
        f"- Suppressed: {summary['suppressed_previous']} → {summary['suppressed_current']}", "",
        "| State | Rule | File | Line | Advisory / Package | Finding |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for item in report["entries"]:
        finding = item["finding"]
        identifier = finding.get("vulnerability_id", finding.get("package", ""))
        lines.append(
            f"| {item['state']} | {finding.get('rule_id', '')} | {finding.get('file', '')} | "
            f"{finding.get('line') or ''} | {identifier} | {finding.get('title', '')} |"
        )
    return "\n".join(lines) + "\n"


def render_comparison_html(report: dict[str, Any]) -> str:
    summary = report["summary"]
    rows = []
    for item in report["entries"]:
        finding = item["finding"]
        cells = [
            item["state"], finding.get("rule_id", ""), finding.get("file", ""),
            str(finding.get("line") or ""),
            finding.get("vulnerability_id", finding.get("package", "")),
            finding.get("title", ""),
        ]
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in cells) + "</tr>")
    body = "\n".join(rows) or '<tr><td colspan="6">No comparison entries.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScopeGuard report comparison</title>
<style>body{{font:14px system-ui,sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #8888;padding:.5rem;text-align:left}}td{{overflow-wrap:anywhere}}</style>
<h1>ScopeGuard report comparison</h1>
<p>Added: {summary['added']} · Resolved: {summary['resolved']} · Unchanged: {summary['unchanged']}</p>
<p>Suppressed: {summary['suppressed_previous']} → {summary['suppressed_current']}</p>
<table><thead><tr><th>State</th><th>Rule</th><th>File</th><th>Line</th><th>Advisory / Package</th><th>Finding</th></tr></thead>
<tbody>{body}</tbody></table></html>
"""


def write_comparison_reports(
    report: dict[str, Any],
    output_path: Path,
    markdown_path: Path | None = None,
    html_path: Path | None = None,
) -> None:
    paths = [output_path.resolve()]
    if markdown_path is not None:
        paths.append(markdown_path.resolve())
    if html_path is not None:
        paths.append(html_path.resolve())
    if len(set(paths)) != len(paths):
        raise ValidationError("comparison output paths must be different")
    _atomic_write(output_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    if markdown_path is not None:
        _atomic_write(markdown_path, render_comparison_markdown(report))
    if html_path is not None:
        _atomic_write(html_path, render_comparison_html(report))
