"""Interactive, offline creation of a starter ScopeGuard scenario."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .config import ValidationError, _validate_spec, _read_yaml, is_loopback_host, validate_inputs


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default if default is not None else "")


def _select_operations(spec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    choices = [
        (path, item["get"])
        for path, item in spec["paths"].items()
        if isinstance(item, dict) and isinstance(item.get("get"), dict)
    ]
    if not choices:
        raise ValidationError("OpenAPI document does not define any GET operations")
    print("\nAvailable GET operations / Kullanılabilir GET işlemleri:")
    for index, (path, operation) in enumerate(choices, 1):
        label = operation.get("summary") or operation.get("operationId") or ""
        print(f"  {index}. GET {path}" + (f" — {label}" if label else ""))
    selected_text = _ask("Select operation numbers, comma-separated (max 10) / İşlem numaralarını virgülle seçin (en fazla 10)")
    try:
        indexes = [int(value.strip()) for value in selected_text.split(",")]
    except ValueError:
        raise ValidationError("operation selection must contain comma-separated numbers") from None
    if not indexes or len(indexes) > 10 or len(set(indexes)) != len(indexes) or any(i < 1 or i > len(choices) for i in indexes):
        raise ValidationError("select between 1 and 10 distinct operation numbers from the list")
    return [choices[index - 1] for index in indexes]


def _scenario_check(index: int, path: str) -> dict[str, Any]:
    params = re.findall(r"\{([^{}]+)\}", path)
    values: dict[str, str] = {}
    for param in params:
        value = _ask(f"Sample value for {{{param}}} / {{{param}}} için örnek değer")
        if not value:
            raise ValidationError(f"a sample value is required for path parameter '{param}'")
        values[param] = value
    statuses_text = _ask("Expected HTTP status codes / Beklenen HTTP durum kodları (comma-separated)", "200")
    try:
        statuses = [int(value.strip()) for value in statuses_text.split(",")]
    except ValueError:
        raise ValidationError("expected status codes must be comma-separated numbers") from None
    if not statuses or any(code < 100 or code > 599 for code in statuses):
        raise ValidationError("expected status codes must be between 100 and 599")
    slug = re.sub(r"[^a-z0-9]+", "-", path.strip("/").lower()).strip("-") or "root"
    slug = re.sub(r"\{([^{}]+)\}", r"\1", slug)
    check: dict[str, Any] = {
        "id": f"check-{index:02d}-{slug}",
        "operation": f"GET {path}",
        "identity": "api_user",
        "expected_status": statuses,
    }
    check["path"] = values
    return check


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
        confirmation = _ask(f"Allow exact remote host {host}:{parsed.port or 443} in this scenario? This still requires --allow-remote when running [y/N] / Bu senaryoda yalnızca bu uzak hedefe izin verilsin mi? Çalıştırırken ayrıca --allow-remote gerekir", "n").lower()
        if confirmation not in {"y", "yes", "e", "evet"}:
            raise ValidationError("remote target was not enabled; no scenario was written")

    operations = _select_operations(spec)
    auth_choice = _ask("Use a Bearer token identity? [y/N] / Bearer token kimliği kullanılsın mı? [e/H]", "n").lower()
    use_bearer = auth_choice in {"y", "yes", "e", "evet"}
    identities: dict[str, Any] = {"anonymous": {"auth": "none"}}
    if use_bearer:
        token_env = _ask("Environment variable name (not the token) / Ortam değişkeni adı (token değil)", "SG_API_TOKEN")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token_env):
            raise ValidationError("token environment variable must be a valid environment variable name")
        identities["api_user"] = {"auth": "bearer", "token_env": token_env}
    else:
        identities = {"api_user": {"auth": "none"}}

    checks = [_scenario_check(index, path) for index, (path, _operation) in enumerate(operations, 1)]
    for check in checks:
        check["identity"] = "api_user"
    actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    config: dict[str, Any] = {
        "version": 1,
        "target": {
            "base_url": base_url,
            "allowed_hosts": [host],
            "allow_remote": remote,
            "max_requests": max(10, len(checks)),
            "timeout_seconds": 5,
            "follow_redirects": False,
        },
        "identities": identities,
        "checks": checks,
        "coverage": {"required": [], "required_checks": []},
    }
    if remote:
        config["target"]["allowed_ports"] = [actual_port]
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
