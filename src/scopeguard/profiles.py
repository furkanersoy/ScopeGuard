"""Create and load reusable local-scan profiles."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .config import ValidationError

PROFILE_CHECKS: dict[str, list[str]] = {
    "standard": ["secrets", "python", "config", "docker", "kubernetes", "terraform"],
    "secrets": ["secrets"],
    "application": ["secrets", "python", "config"],
    "containers": ["docker", "kubernetes"],
    "infrastructure": ["config", "terraform"],
}
_LANGUAGES = {"tr", "en"}
_FAIL_LEVELS = {"any", "critical", "high", "medium", "low", "none"}


def _prompt(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def _write_profile(path: Path, data: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise ValidationError(f"profile already exists: {path} (use --force to replace it)")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "# Reusable local ScopeGuard scan settings. No tokens or API targets are stored here.\n"
        + yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    )
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_profile_wizard(path: Path, *, force: bool = False) -> Path:
    """Ask for reusable local scan settings and write them without network access."""
    if path.exists() and not force:
        raise ValidationError(f"profile already exists: {path} (use --force to replace it)")
    print("This profile stores local scan settings only. It does not contact APIs or save credentials.")
    print("Bu profil yalnızca yerel tarama ayarlarını saklar. API'ye bağlanmaz ve kimlik bilgisi kaydetmez.")
    scan_path = _prompt("Project folder or file / Proje klasörü veya dosyası", ".")
    print("Profiles / Profiller:")
    for index, profile in enumerate(PROFILE_CHECKS, 1):
        print(f"  {index}. {profile}")
    selected = _prompt("Choose profile number / Profil numarasını seç", "1")
    try:
        selected_index = int(selected)
    except (ValueError, IndexError):
        raise ValidationError("choose a profile number from the list") from None
    if not 1 <= selected_index <= len(PROFILE_CHECKS):
        raise ValidationError("choose a profile number from the list")
    profile = list(PROFILE_CHECKS)[selected_index - 1]
    language = _prompt("Report language tr/en / Rapor dili tr/en", "tr").lower()
    if language not in _LANGUAGES:
        raise ValidationError("report language must be tr or en")
    report_prefix = _prompt("Report filename prefix / Rapor dosya adı öneki", "scopeguard-scan")
    if not report_prefix or Path(report_prefix).name in {"", ".", ".."}:
        raise ValidationError("report filename prefix must not be empty")
    suppressions = input("Suppressions YAML (optional; Enter to skip) / İstisna YAML dosyası (isteğe bağlı; geçmek için Enter): ").strip()
    fail_on = _prompt("Fail threshold any/critical/high/medium/low/none / Bulgu eşiği", "any").lower()
    if fail_on not in _FAIL_LEVELS:
        raise ValidationError("fail threshold must be any, critical, high, medium, low, or none")
    data: dict[str, Any] = {
        "version": 1,
        "path": scan_path,
        "profile": profile,
        "language": language,
        "report_prefix": report_prefix,
        "fail_on": fail_on,
    }
    if suppressions:
        data["suppressions"] = suppressions
    _write_profile(path, data, force=force)
    print(f"Project scan profile written to {path}")
    print(f"Run it with: scopeguard quick-scan --config \"{path}\"")
    print(f"Çalıştırmak için: scopeguard quick-scan --config \"{path}\"")
    return path


def load_scan_profile(path: Path) -> dict[str, Any]:
    """Load and validate a reusable scan profile; relative paths use its directory."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValidationError(f"cannot read scan profile '{path}': {exc.strerror or 'I/O error'}") from None
    except yaml.YAMLError as exc:
        raise ValidationError(f"invalid YAML in scan profile '{path}'") from None
    required = {"version", "path", "profile", "language", "report_prefix", "fail_on"}
    allowed = required | {"suppressions"}
    if not isinstance(data, dict) or type(data.get("version")) is not int or data.get("version") != 1:
        raise ValidationError("scan profile must be a YAML mapping with version: 1")
    if any(not isinstance(key, str) for key in data):
        raise ValidationError("scan profile keys must be strings")
    missing = required - data.keys()
    unknown = data.keys() - allowed
    if missing:
        raise ValidationError(f"scan profile is missing required keys: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(f"scan profile has unknown keys: {', '.join(sorted(unknown))}")
    if not isinstance(data["path"], str) or not data["path"].strip():
        raise ValidationError("scan profile path must be a non-empty string")
    if not isinstance(data["profile"], str) or data["profile"] not in PROFILE_CHECKS:
        raise ValidationError(f"unknown scan profile: {data['profile']!r}")
    if not isinstance(data["language"], str) or data["language"] not in _LANGUAGES:
        raise ValidationError("scan profile language must be tr or en")
    if not isinstance(data["fail_on"], str) or data["fail_on"] not in _FAIL_LEVELS:
        raise ValidationError("scan profile fail_on must be any, critical, high, medium, low, or none")
    if not isinstance(data["report_prefix"], str) or not data["report_prefix"].strip():
        raise ValidationError("scan profile report_prefix must be a non-empty string")
    if "suppressions" in data and (not isinstance(data["suppressions"], str) or not data["suppressions"].strip()):
        raise ValidationError("scan profile suppressions must be a non-empty path when provided")

    root = path.resolve().parent
    resolved = dict(data)
    for key in ("path", "report_prefix", "suppressions"):
        value = resolved.get(key)
        if value is not None:
            candidate = Path(value).expanduser()
            resolved[key] = candidate if candidate.is_absolute() else root / candidate
    suppression = resolved.get("suppressions")
    if suppression is not None and suppression.resolve() == path.resolve():
        raise ValidationError("scan profile cannot also be its suppressions file")
    return resolved
