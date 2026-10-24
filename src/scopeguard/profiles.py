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

PROFILE_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "standard": (
        "All local checks: secrets, Python, configuration, Docker, Kubernetes, and Terraform.",
        "Tüm yerel kontroller: sırlar, Python, yapılandırma, Docker, Kubernetes ve Terraform.",
    ),
    "secrets": (
        "Detect secret-like values only.",
        "Yalnızca gizli bilgiye benzeyen değerleri tara.",
    ),
    "application": (
        "Secrets, Python, and configuration checks.",
        "Sırlar, Python ve yapılandırma kontrolleri.",
    ),
    "containers": (
        "Dockerfile and Kubernetes manifest checks.",
        "Dockerfile ve Kubernetes manifest kontrolleri.",
    ),
    "infrastructure": (
        "Configuration and Terraform checks.",
        "Yapılandırma ve Terraform kontrolleri.",
    ),
}

_LANGUAGES = {"tr", "en"}
_FAIL_LEVELS = {"any", "critical", "high", "medium", "low", "none"}


def _prompt(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def _path_text(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _profile_relative_path(value: Path, profile_root: Path) -> str:
    resolved = value.expanduser().resolve()
    try:
        return os.path.relpath(resolved, profile_root.resolve())
    except ValueError:
        # Windows cannot express a relative path across different drives.
        return str(resolved)


def _prompt_choice(label: str, default: str, choices: set[str], hint: str) -> str:
    while True:
        value = _prompt(label, default).lower()
        if value in choices:
            return value
        print(hint)


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
    print("Paths are saved relative to the profile when possible; review absolute paths before sharing the file.")
    print("Yollar mümkün olduğunda profile göreli kaydedilir; dosyayı paylaşmadan önce mutlak yolları gözden geçir.")
    profile_root = path.resolve().parent
    try:
        default_scan_path = os.path.relpath(Path.cwd().resolve(), profile_root)
    except ValueError:
        # Windows cannot make a relative path between different drives.
        default_scan_path = str(Path.cwd().resolve())
    while True:
        scan_path = _path_text(_prompt("Project folder or file / Proje klasörü veya dosyası", default_scan_path))
        scan_target = Path(scan_path).expanduser()
        if not scan_target.is_absolute():
            scan_target = profile_root / scan_target
        if scan_target.exists():
            break
        print(f"Scan target not found / Tarama hedefi bulunamadı: {scan_target}")
    print("Profiles / Profiller:")
    for index, profile in enumerate(PROFILE_CHECKS, 1):
        english, turkish = PROFILE_DESCRIPTIONS[profile]
        print(f"  {index}. {profile} — {english}")
        print(f"     {turkish}")
    selected = _prompt_choice("Choose profile number / Profil numarasını seç", "1", {str(i) for i in range(1, len(PROFILE_CHECKS) + 1)}, "Choose one of the listed profile numbers / Listelenen profil numaralarından birini seçin")
    selected_index = int(selected)
    profile = list(PROFILE_CHECKS)[selected_index - 1]
    language = _prompt_choice("Report language tr/en / Rapor dili tr/en", "tr", _LANGUAGES, "Enter tr or en / tr veya en yazın")
    while True:
        report_prefix = _path_text(_prompt("Report filename prefix / Rapor dosya adı öneki", "scopeguard-scan"))
        if Path(report_prefix).name not in {"", ".", ".."}:
            break
        print("Enter a file name or relative path prefix / Dosya adı veya göreli yol öneki girin")
    while True:
        suppressions = _path_text(input("Suppressions YAML (optional; Enter to skip) / İstisna YAML dosyası (isteğe bağlı; geçmek için Enter): "))
        if not suppressions:
            break
        suppression_path = Path(suppressions).expanduser()
        if not suppression_path.is_absolute():
            suppression_path = profile_root / suppression_path
        if suppression_path.is_file():
            break
        print(f"Suppression file not found / İstisna dosyası bulunamadı: {suppression_path}")
    fail_on = _prompt_choice(
        "Fail threshold any/critical/high/medium/low/none / Bulgu eşiği", "any", _FAIL_LEVELS,
        "Enter any, critical, high, medium, low, or none / any, critical, high, medium, low veya none yazın",
    )
    stored_scan_path = _profile_relative_path(scan_target, profile_root)
    prefix_path = Path(report_prefix).expanduser()
    if not prefix_path.is_absolute():
        prefix_path = profile_root / prefix_path
    stored_report_prefix = _profile_relative_path(prefix_path, profile_root)
    data: dict[str, Any] = {
        "version": 1,
        "path": stored_scan_path,
        "profile": profile,
        "language": language,
        "report_prefix": stored_report_prefix,
        "fail_on": fail_on,
    }
    if suppressions:
        data["suppressions"] = _profile_relative_path(suppression_path, profile_root)
    _write_profile(path, data, force=force)
    print(f"Project scan profile written to {path}")
    print(f"In the `sg>` console, run: quick-scan --config \"{path}\"")
    print(f"`sg>` konsolunda şu komutu çalıştır: quick-scan --config \"{path}\"")
    print("From a system terminal, prefix the command with `scopeguard` or use the ScopeGuard launcher.")
    print("Sistem terminalinde komutun başına `scopeguard` ekle veya ScopeGuard başlatıcısını kullan.")
    return path


def load_scan_profile(path: Path) -> dict[str, Any]:
    """Load and validate a reusable scan profile; relative paths use its directory."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValidationError(f"cannot read scan profile '{path}': {exc.strerror or 'I/O error'}") from None
    except UnicodeError:
        raise ValidationError(f"scan profile '{path}' must be UTF-8 text") from None
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
