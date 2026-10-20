"""Interactive, offline creation of a starter ScopeGuard scenario."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .config import ValidationError, _read_yaml, _validate_spec, is_loopback_host, validate_inputs

_PROFILES = {
    "1": "anonymous",
    "2": "bola",
    "3": "bfla",
    "4": "custom",
}


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default if default is not None else "")


def _select_operations(spec: dict[str, Any], label: str) -> list[str]:
    choices = [
        (path, item["get"])
        for path, item in spec["paths"].items()
        if isinstance(item, dict) and isinstance(item.get("get"), dict)
    ]
    if not choices:
        raise ValidationError("OpenAPI document does not define any GET operations")
    print(f"\n{label}")
    for index, (path, operation) in enumerate(choices, 1):
        description = operation.get("summary") or operation.get("operationId") or ""
        print(f"  {index}. GET {path}" + (f" — {description}" if description else ""))
    selection = _ask("Select operation numbers, comma-separated (max 10) / İşlem numaralarını virgülle seçin (en fazla 10)")
    try:
        indexes = [int(value.strip()) for value in selection.split(",")]
    except ValueError:
        raise ValidationError("operation selection must contain comma-separated numbers") from None
    if not indexes or len(indexes) > 10 or len(set(indexes)) != len(indexes) or any(i < 1 or i > len(choices) for i in indexes):
        raise ValidationError("select between 1 and 10 distinct operation numbers from the list")
    return [choices[index - 1][0] for index in indexes]


def _path_values(path: str, *, prefix: str = "") -> dict[str, str]:
    values: dict[str, str] = {}
    for name in re.findall(r"\{([^{}]+)\}", path):
        value = _ask(f"{prefix}Sample value for {{{name}}} / {{{name}}} için örnek değer")
        if not value:
            raise ValidationError(f"a sample value is required for path parameter '{name}'")
        values[name] = value
    return values


def _expected_status(prompt: str, default: str) -> list[int]:
    value = _ask(prompt, default)
    try:
        statuses = [int(code.strip()) for code in value.split(",")]
    except ValueError:
        raise ValidationError("expected status codes must be comma-separated numbers") from None
    if not statuses or any(code < 100 or code > 599 for code in statuses):
        raise ValidationError("expected status codes must be between 100 and 599")
    return statuses


def _slug(path: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")
    return value or "root"


def _add_bearer_identity(identities: dict[str, Any], name: str, default_env: str, label: str) -> None:
    if name in identities:
        return
    env_name = _ask(f"{label} token environment variable (name only) / {label} token ortam değişkeni adı (yalnızca ad)", default_env)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
        raise ValidationError("token environment variable must be a valid environment variable name")
    identities[name] = {"auth": "bearer", "token_env": env_name}


def _check(check_id: str, operation: str, identity: str, values: dict[str, str], statuses: list[int], assertions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    check: dict[str, Any] = {
        "id": check_id,
        "operation": f"GET {operation}",
        "identity": identity,
        "path": values,
        "expected_status": statuses,
    }
    if assertions:
        check["assert_json"] = assertions
    return check


def _profiles() -> list[str]:
    print("\nChoose security check profiles / Güvenlik kontrol profillerini seçin:")
    print("  1. Anonymous access control / Anonim erişim kontrolü (authentication bypass)")
    print("  2. BOLA / IDOR horizontal access / Kullanıcılar arası nesne erişimi")
    print("  3. BFLA vertical access / Düşük yetkili kullanıcının ayrıcalıklı işleme erişimi")
    print("  4. Custom GET status check / Özel GET durum kodu kontrolü")
    answer = _ask("Choose one or more numbers, comma-separated / Bir veya daha fazla numara seçin", "1")
    try:
        selected = [item.strip() for item in answer.split(",")]
    except ValueError:
        raise ValidationError("profile selection must be comma-separated numbers") from None
    if not selected or len(set(selected)) != len(selected) or any(item not in _PROFILES for item in selected):
        raise ValidationError("choose one or more distinct profile numbers from 1 to 4")
    return [_PROFILES[item] for item in selected]


def _make_profile_checks(profile: str, spec: dict[str, Any], identities: dict[str, Any]) -> list[dict[str, Any]]:
    if profile == "anonymous":
        paths = _select_operations(spec, "Select protected GET operations to check without a token / Tokensız kontrol edilecek korumalı GET işlemlerini seçin")
        statuses = _expected_status("Expected denial status codes / Beklenen ret durum kodları", "401,403,404")
        checks = []
        for index, path in enumerate(paths, 1):
            values = _path_values(path)
            checks.append(_check(f"anonymous-denied-{index:02d}-{_slug(path)}", path, "anonymous", values, statuses))
        return checks

    if profile == "bola":
        paths = _select_operations(spec, "Select GET operations that access one object by path ID / Yol kimliğiyle tek nesneye erişen GET işlemlerini seçin")
        if any(not re.search(r"\{[^{}]+\}", path) for path in paths):
            raise ValidationError("BOLA checks require a selected path with at least one {path_parameter}")
        _add_bearer_identity(identities, "user_a", "SG_USER_A_TOKEN", "User A")
        _add_bearer_identity(identities, "user_b", "SG_USER_B_TOKEN", "User B")
        denied = _expected_status("Expected status when reading another user's object / Başka kullanıcının nesnesinde beklenen durum", "404")
        owner_pointer = _ask("JSON Pointer for the owner field / Sahip alanının JSON Pointer yolu", "/owner")
        if not owner_pointer.startswith("/"):
            raise ValidationError("owner JSON Pointer must start with '/'")
        owner_a = _ask("Expected owner value for User A / User A için beklenen sahip değeri", "user-a")
        owner_b = _ask("Expected owner value for User B / User B için beklenen sahip değeri", "user-b")
        if not owner_a or not owner_b or owner_a == owner_b:
            raise ValidationError("owner values must be non-empty and different")
        checks = []
        for index, path in enumerate(paths, 1):
            print(f"\nBOLA samples for GET {path} / {path} için BOLA örnekleri:")
            value_a = _path_values(path, prefix="User A-owned object / User A'nın nesnesi — ")
            value_b = _path_values(path, prefix="User B-owned object / User B'nin nesnesi — ")
            slug = _slug(path)
            checks.extend([
                _check(f"bola-user-a-own-{index:02d}-{slug}", path, "user_a", value_a, [200], [{"pointer": owner_pointer, "equals": owner_a}]),
                _check(f"bola-user-a-cross-{index:02d}-{slug}", path, "user_a", value_b, denied, [{"pointer": owner_pointer, "not_equals": owner_b}]),
                _check(f"bola-user-b-own-{index:02d}-{slug}", path, "user_b", value_b, [200], [{"pointer": owner_pointer, "equals": owner_b}]),
                _check(f"bola-user-b-cross-{index:02d}-{slug}", path, "user_b", value_a, denied, [{"pointer": owner_pointer, "not_equals": owner_a}]),
            ])
        return checks

    if profile == "bfla":
        paths = _select_operations(spec, "Select privileged GET operations / Ayrıcalıklı GET işlemlerini seçin")
        _add_bearer_identity(identities, "low_privilege", "SG_LOW_PRIVILEGE_TOKEN", "Low-privilege user / Düşük yetkili kullanıcı")
        statuses = _expected_status("Expected denial status codes / Beklenen ret durum kodları", "403,404")
        checks = []
        for index, path in enumerate(paths, 1):
            values = _path_values(path)
            checks.append(_check(f"bfla-low-role-denied-{index:02d}-{_slug(path)}", path, "low_privilege", values, statuses))
        return checks

    paths = _select_operations(spec, "Select GET operations for custom status checks / Özel durum kodu kontrolü yapılacak GET işlemlerini seçin")
    identities.setdefault("anonymous", {"auth": "none"})
    statuses = _expected_status("Expected HTTP status codes / Beklenen HTTP durum kodları", "200")
    checks = []
    for index, path in enumerate(paths, 1):
        values = _path_values(path)
        checks.append(_check(f"custom-get-{index:02d}-{_slug(path)}", path, "anonymous", values, statuses))
    return checks


def run_init_wizard(spec_path: Path, output_path: Path, *, force: bool = False) -> Path:
    """Generate a validated starter scenario without sending network requests."""
    spec = _validate_spec(_read_yaml(spec_path, "OpenAPI"))
    if output_path.exists() and not force:
        raise ValidationError(f"output file already exists: {output_path} (use --force to replace it)")
    print("ScopeGuard init creates a starter scenario only; it does not contact the API.")
    print("ScopeGuard init başlangıç senaryosu oluşturur; API'ye bağlanmaz.")
    base_url = _ask("API base URL / API temel adresi", "http://127.0.0.1:8000").rstrip("/")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValidationError("base URL must be an http(s) origin without credentials, path, query, or fragment")
    try:
        parsed.port
    except ValueError:
        raise ValidationError("base URL contains an invalid port") from None
    host = parsed.hostname.lower()
    remote = not is_loopback_host(host)
    if remote:
        if parsed.scheme != "https":
            raise ValidationError("remote API targets must use HTTPS")
        confirmation = _ask(f"Allow exact remote host {host}:{parsed.port or 443} in this scenario? This still requires --allow-remote when running [y/N] / Bu uzak hedefe izin verilsin mi? Çalıştırırken yine --allow-remote gerekir", "n").lower()
        if confirmation not in {"y", "yes", "e", "evet"}:
            raise ValidationError("remote target was not enabled; no scenario was written")

    selected_profiles = _profiles()
    identities: dict[str, Any] = {"anonymous": {"auth": "none"}}
    checks: list[dict[str, Any]] = []
    for profile in selected_profiles:
        checks.extend(_make_profile_checks(profile, spec, identities))
    if not checks:
        raise ValidationError("selected profiles did not produce any checks")
    if len(checks) > 100:
        raise ValidationError("selected profiles create more than 100 requests; choose fewer operations")

    actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target: dict[str, Any] = {
        "base_url": base_url,
        "allowed_hosts": [host],
        "allow_remote": remote,
        "max_requests": max(10, len(checks)),
        "timeout_seconds": 5,
        "follow_redirects": False,
    }
    if remote:
        target["allowed_ports"] = [actual_port]
    config: dict[str, Any] = {
        "version": 1,
        "target": target,
        "identities": identities,
        "checks": checks,
        "coverage": {"required": [], "required_checks": []},
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists() and not force:
        raise ValidationError(f"output file already exists: {output_path} (use --force to replace it)")
    content = (
        "# Starter scenario generated by `scopeguard init`. Review expected statuses and sample IDs before running.\n"
        "# This file stores environment variable names, never token values.\n"
        + yaml.safe_dump(config, sort_keys=False, allow_unicode=True)
    )
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=output_path.parent,
            prefix=f".{output_path.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        validate_inputs(spec_path, temporary_path)
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    print(f"Starter scenario written to {output_path}")
    print("Review IDs and expected statuses, then run `scopeguard validate` and `scopeguard plan`.")
    print("Kimlikleri ve beklenen durum kodlarını gözden geçirin; ardından validate ve plan komutlarını çalıştırın.")
    return output_path
