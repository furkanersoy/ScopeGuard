"""Create a reasoned, expiring suppression from a saved local report."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from typing import TextIO

import yaml


def _read_report(path: Path) -> list[dict]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read report '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"report is not valid JSON (line {exc.lineno}, column {exc.colno})") from exc
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, list):
        raise ValueError("report does not contain a findings list")
    local_findings = [item for item in findings if isinstance(item, dict) and item.get("rule_id") and item.get("file")]
    if not local_findings:
        raise ValueError("report has no active local findings with rule and file information")
    return local_findings


def _load_existing(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read suppression file '{path}': {exc}") from exc
    except yaml.YAMLError as exc:
        raise ValueError("existing suppression file is not valid YAML") from exc
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("suppressions"), list):
        raise ValueError("existing suppression file must contain version: 1 and a suppressions list")
    entries = data["suppressions"]
    if any(not isinstance(item, dict) for item in entries):
        raise ValueError("every existing suppression entry must be a YAML mapping")
    return entries


def _validate_relative_path(value: str) -> str:
    normalized = value.replace("\\", "/").strip()
    parts = normalized.split("/")
    if (not normalized or normalized.startswith("/") or Path(normalized).is_absolute()
            or PureWindowsPath(normalized).is_absolute() or ".." in parts):
        raise ValueError("finding path must be a relative path without '..'; check the report source")
    return normalized


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_ignore_wizard(
    report_path: Path,
    output_path: Path,
    finding_number: int | None = None,
    reason: str | None = None,
    expires_text: str | None = None,
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> dict:
    """Select one active finding and add/update its suppression entry."""
    source = input_stream or sys.stdin
    output = output_stream or sys.stdout
    if report_path.resolve() == output_path.resolve():
        raise ValueError("the suppression output must not overwrite its source report")
    findings = _read_report(report_path)
    output.write("Active findings / Etkin bulgular:\n")
    for index, finding in enumerate(findings, 1):
        severity = str(finding.get("severity", "unknown")).upper()
        location = f"{finding['file']}:{finding.get('line') or '?'}"
        output.write(f"  {index}. [{severity}] {finding['rule_id']} — {location}\n")
    output.flush()

    if finding_number is None:
        raw = source.readline()
        if not raw:
            raise ValueError("no finding was selected")
        try:
            finding_number = int(raw.strip())
        except ValueError as exc:
            raise ValueError("enter one finding number from the list") from exc
    if not 1 <= finding_number <= len(findings):
        raise ValueError(f"finding number must be between 1 and {len(findings)}")
    finding = findings[finding_number - 1]

    if reason is None:
        output.write("Suppression reason / İstisna gerekçesi: ")
        output.flush()
        reason = source.readline().strip()
    reason = reason.strip()
    if not reason:
        raise ValueError("a non-empty suppression reason is required")

    default_expiry = (datetime.now(timezone.utc).date() + timedelta(days=90)).isoformat()
    if expires_text is None:
        output.write(f"Expiry date YYYY-MM-DD / Bitiş tarihi YYYY-AA-GG [{default_expiry}]: ")
        output.flush()
        expires_text = source.readline().strip() or default_expiry
    try:
        expiry = date.fromisoformat(expires_text.strip())
    except ValueError as exc:
        raise ValueError("expiry date must use YYYY-MM-DD") from exc
    if expiry.isoformat() != expires_text.strip() or expiry <= datetime.now(timezone.utc).date():
        raise ValueError("expiry date must be a future date in YYYY-MM-DD format")

    rule_id = str(finding["rule_id"]).strip()
    relative_path = _validate_relative_path(str(finding["file"]))
    entries = _load_existing(output_path)
    entry = {"rule_id": rule_id, "path": relative_path, "reason": reason, "expires": expiry.isoformat()}
    existing_index = next((i for i, item in enumerate(entries)
                           if isinstance(item, dict) and item.get("rule_id") == rule_id and item.get("path") == relative_path), None)
    updated = existing_index is not None
    if updated:
        entries[existing_index] = entry
    else:
        entries.append(entry)
    document = {"version": 1, "suppressions": entries}
    _atomic_write(output_path, yaml.safe_dump(document, sort_keys=False, allow_unicode=True))
    return {"entry": entry, "updated": updated, "output": output_path}
