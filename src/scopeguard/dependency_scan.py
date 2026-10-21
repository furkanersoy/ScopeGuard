"""Explicitly online dependency advisory checks using the public OSV query API."""

from __future__ import annotations

import json
import os
import re
import ssl
import tomllib
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .config import ValidationError

OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
MAX_LOCKFILE_BYTES = 1_000_000
MAX_DEPENDENCIES = 1_000
BATCH_SIZE = 100
MAX_RESPONSE_BYTES = 10_000_000
_SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__", "dist", "build", ".tox"}


def _normalized_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _eligible(path: Path) -> bool:
    name = path.name.lower()
    return (
        (name.startswith("requirements") and name.endswith(".txt"))
        or name in {"poetry.lock", "pipfile.lock", "package-lock.json", "npm-shrinkwrap.json", "cargo.lock", "go.sum"}
    )


def _add(
    dependencies: dict[tuple[str, str, str], list[dict[str, Any]]],
    ecosystem: str,
    name: str,
    version: str,
    file: str,
    line: int | None = None,
) -> None:
    name, version = name.strip(), version.strip()
    if not name or not version or "*" in version or version.startswith((">", "<", "~", "=")):
        return
    if ecosystem == "PyPI":
        name = _normalized_pypi(name)
    key = (ecosystem, name, version)
    dependencies.setdefault(key, []).append({"file": file, "line": line})


def _parse_requirements(source: str, relative: str, found: dict[tuple[str, str, str], list[dict[str, Any]]]) -> None:
    pin = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*(?:\[[^\]]+\])?)\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)")
    for number, raw in enumerate(source.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        match = pin.match(line)
        if not match:
            continue
        name = match.group(1).split("[", 1)[0]
        _add(found, "PyPI", name, match.group(2), relative, number)


def _parse_poetry(source: str, relative: str, found: dict[tuple[str, str, str], list[dict[str, Any]]]) -> None:
    data = tomllib.loads(source)
    for package in data.get("package", []):
        if isinstance(package, dict):
            _add(found, "PyPI", str(package.get("name", "")), str(package.get("version", "")), relative)


def _parse_pipfile_lock(source: str, relative: str, found: dict[tuple[str, str, str], list[dict[str, Any]]]) -> None:
    data = json.loads(source)
    for section in ("default", "develop"):
        packages = data.get(section, {})
        if not isinstance(packages, dict):
            continue
        for name, item in packages.items():
            version = item.get("version") if isinstance(item, dict) else None
            if isinstance(version, str):
                _add(found, "PyPI", str(name), version.removeprefix("=="), relative)


def _parse_npm_lock(source: str, relative: str, found: dict[tuple[str, str, str], list[dict[str, Any]]]) -> None:
    data = json.loads(source)
    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for path, package in packages.items():
            if not path or not isinstance(package, dict) or not isinstance(package.get("version"), str):
                continue
            marker = "node_modules/"
            if marker in path:
                name = path.rsplit(marker, 1)[-1]
                _add(found, "npm", name, package["version"], relative)
    def walk(tree: Any) -> None:
        if not isinstance(tree, dict):
            return
        for name, package in tree.items():
            if not isinstance(package, dict):
                continue
            version = package.get("version")
            if isinstance(version, str):
                _add(found, "npm", name, version, relative)
            walk(package.get("dependencies"))
    walk(data.get("dependencies"))


def _parse_cargo_lock(source: str, relative: str, found: dict[tuple[str, str, str], list[dict[str, Any]]]) -> None:
    data = tomllib.loads(source)
    for package in data.get("package", []):
        if not isinstance(package, dict):
            continue
        source_url = str(package.get("source", ""))
        if source_url.startswith("registry+"):
            _add(found, "crates.io", str(package.get("name", "")), str(package.get("version", "")), relative)


def _parse_go_sum(source: str, relative: str, found: dict[tuple[str, str, str], list[dict[str, Any]]]) -> None:
    for raw in source.splitlines():
        parts = raw.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            _add(found, "Go", parts[0], parts[1], relative)


def _collect(path: Path) -> tuple[dict[tuple[str, str, str], list[dict[str, Any]]], int]:
    if path.is_symlink():
        raise ValidationError("dependency scan root must not be a symbolic link")
    if not path.exists():
        raise ValidationError(f"dependency scan path does not exist: {path}")
    root = path.absolute()
    if root.is_file():
        files = [root] if _eligible(root) else []
    elif root.is_dir():
        files = []
        for current, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [item for item in dirs if item not in _SKIP_DIRS and not (Path(current) / item).is_symlink()]
            for name in names:
                candidate = Path(current) / name
                if candidate.is_symlink() or not _eligible(candidate):
                    continue
                files.append(candidate)
                if len(files) > MAX_DEPENDENCIES:
                    raise ValidationError("dependency scan includes too many lockfiles; narrow --path")
    else:
        raise ValidationError(f"dependency scan path is not a file or directory: {path}")

    found: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    scanned_files = 0
    for candidate in files:
        try:
            if candidate.stat().st_size > MAX_LOCKFILE_BYTES:
                continue
            source = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        relative = candidate.name if root.is_file() else candidate.relative_to(root).as_posix()
        name = candidate.name.lower()
        try:
            if name.startswith("requirements") and name.endswith(".txt"):
                _parse_requirements(source, relative, found)
            elif name == "poetry.lock":
                _parse_poetry(source, relative, found)
            elif name == "pipfile.lock":
                _parse_pipfile_lock(source, relative, found)
            elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
                _parse_npm_lock(source, relative, found)
            elif name == "cargo.lock":
                _parse_cargo_lock(source, relative, found)
            elif name == "go.sum":
                _parse_go_sum(source, relative, found)
        except (ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError):
            continue
        scanned_files += 1
        if len(found) > MAX_DEPENDENCIES:
            raise ValidationError("dependency inventory exceeds 1,000 unique package versions; narrow --path")
    if not files:
        raise ValidationError("no supported dependency lockfiles found (requirements*.txt, poetry.lock, Pipfile.lock, package-lock.json, Cargo.lock, go.sum)")
    if not found:
        raise ValidationError("supported lockfiles were found, but no exact package versions could be extracted")
    return found, scanned_files


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _query_osv(queries: list[dict[str, str]]) -> list[dict[str, Any]]:
    payload = json.dumps({
        "queries": [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for ecosystem, name, version in queries
        ],
    }).encode("utf-8")
    request = Request(
        OSV_QUERY_BATCH,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "ScopeGuard/0.2"},
        method="POST",
    )
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ValidationError(f"OSV query failed ({type(exc).__name__}); verify network access and retry") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValidationError("OSV response exceeded the 10 MB safety limit")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValidationError("OSV returned invalid JSON") from exc
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != len(queries):
        raise ValidationError("OSV returned an unexpected querybatch response")
    return results


def _severity(vulnerability: dict[str, Any]) -> str:
    metadata = vulnerability.get("database_specific", {})
    value = metadata.get("severity", "") if isinstance(metadata, dict) else ""
    normalized = str(value).strip().lower()
    return normalized if normalized in {"critical", "high", "medium", "moderate", "low"} else "unknown"


def _fixed_versions(vulnerability: dict[str, Any], package_name: str) -> list[str]:
    fixed: set[str] = set()
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {}) if isinstance(affected, dict) else {}
        if package.get("name") != package_name:
            continue
        for range_item in affected.get("ranges", []):
            for event in range_item.get("events", []):
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    return sorted(fixed)


def scan_dependencies(path: Path, language: str = "en") -> dict[str, Any]:
    """Query OSV only when this function is explicitly invoked by the online command."""
    if language not in {"en", "tr"}:
        raise ValidationError("language must be 'tr' or 'en'")
    dependencies, scanned_files = _collect(path)
    unique = list(dependencies)
    results: list[dict[str, Any]] = []
    for start in range(0, len(unique), BATCH_SIZE):
        batch = unique[start:start + BATCH_SIZE]
        advisories = _query_osv(batch)
        for dependency, response in zip(batch, advisories):
            if not isinstance(response, dict):
                continue
            ecosystem, package_name, version = dependency
            for vulnerability in response.get("vulns", []):
                if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str):
                    continue
                vulnerability_id = vulnerability["id"]
                fixed = _fixed_versions(vulnerability, package_name)
                summary = str(vulnerability.get("summary", "")).strip()
                severity = _severity(vulnerability)
                for location in dependencies[dependency]:
                    description = (
                        f"OSV advisory {vulnerability_id} reports {ecosystem} package "
                        f"{package_name}@{version} in an affected version range."
                    )
                    if summary:
                        description += f" Advisory summary: {summary[:400]}"
                    remediation = (
                        f"Upgrade {package_name} to a fixed version ({', '.join(fixed)}) listed by OSV."
                        if fixed else
                        f"Review OSV advisory {vulnerability_id} for mitigations; no fixed version was listed."
                    )
                    results.append({
                        "rule_id": "dependency.osv",
                        "category": "dependency",
                        "severity": severity,
                        "file": location["file"],
                        "line": location.get("line"),
                        "title": f"{vulnerability_id} — {package_name}@{version}",
                        "description": description,
                        "remediation": remediation,
                        "vulnerability_id": vulnerability_id,
                        "package": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "fixed_versions": fixed,
                    })
    return {
        "tool": "ScopeGuard",
        "mode": "online-dependency-audit",
        "language": language,
        "scanned_path": str(path.absolute()),
        "scanned_files": scanned_files,
        "checks": ["dependencies"],
        "queries_sent": len(unique),
        "database": "OSV",
        "findings": results,
        "suppressed_findings": [],
    }
