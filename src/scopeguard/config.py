"""Load and validate ScopeGuard inputs without making network requests."""

from __future__ import annotations

import ipaddress
import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


class ValidationError(ValueError):
    """Raised when a specification or scenario file is invalid."""


def _read_yaml(path: Path, label: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return yaml.safe_load(stream)
    except OSError as exc:
        raise ValidationError(f"cannot read {label} file '{path}': {exc.strerror or 'I/O error'}") from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ValidationError(f"invalid YAML in {label}{where}") from None


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValidationError(f"{label} must be a mapping")
    return value


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_target(target: Any) -> None:
    target_map = _mapping(target, "target")
    base_url = target_map.get("base_url")
    if not isinstance(base_url, str):
        raise ValidationError("target.base_url must be a URL string")

    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValidationError("target.base_url must use http or https and include a hostname")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValidationError("target.base_url must not contain credentials, query, or fragment")
    try:
        parsed.port
    except ValueError:
        raise ValidationError("target.base_url contains an invalid port") from None
    if parsed.path not in {"", "/"}:
        raise ValidationError("target.base_url must not contain a path prefix in this version")

    allowed_hosts = target_map.get("allowed_hosts")
    if not isinstance(allowed_hosts, list) or not allowed_hosts or not all(isinstance(host, str) for host in allowed_hosts):
        raise ValidationError("target.allowed_hosts must be a non-empty list of hostnames")
    hostname = parsed.hostname.lower()
    if hostname not in {host.lower() for host in allowed_hosts}:
        raise ValidationError("target.base_url hostname is not listed in target.allowed_hosts")
    remote_opt_in = target_map.get("allow_remote", False)
    if not isinstance(remote_opt_in, bool):
        raise ValidationError("target.allow_remote must be true or false")
    remote_target = not is_loopback_host(hostname)
    if remote_target:
        if not remote_opt_in:
            raise ValidationError("remote targets require target.allow_remote: true")
        if parsed.scheme != "https":
            raise ValidationError("remote targets must use HTTPS")
        if any(host.strip() != host or "*" in host or "/" in host for host in allowed_hosts):
            raise ValidationError("remote target allowlist entries must be exact hostnames; wildcards are not allowed")
        if {host.lower() for host in allowed_hosts} != {hostname}:
            raise ValidationError("remote target allowlist must contain only the exact base_url hostname")
        allowed_ports = target_map.get("allowed_ports")
        if not isinstance(allowed_ports, list) or not allowed_ports or any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in allowed_ports
        ):
            raise ValidationError("remote targets require target.allowed_ports with explicit port numbers")
        actual_port = parsed.port or 443
        if actual_port not in allowed_ports:
            raise ValidationError("target.base_url port is not listed in target.allowed_ports")
    elif any(not is_loopback_host(host.lower()) for host in allowed_hosts):
        raise ValidationError("loopback targets may list only localhost or loopback IP addresses")

    max_requests = target_map.get("max_requests")
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or not 1 <= max_requests <= 100:
        raise ValidationError("target.max_requests must be an integer from 1 to 100")
    timeout = target_map.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 30:
        raise ValidationError("target.timeout_seconds must be between 0.1 and 30")
    if target_map.get("follow_redirects") is not False:
        raise ValidationError("target.follow_redirects must be false in this prototype")


def _validate_spec(spec: Any) -> dict[str, Any]:
    spec_map = _mapping(spec, "OpenAPI document")
    version = spec_map.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise ValidationError("OpenAPI document must declare an OpenAPI 3.x version")
    paths = _mapping(spec_map.get("paths"), "OpenAPI paths")
    for path, path_item in paths.items():
        if not path.startswith("/"):
            raise ValidationError(f"OpenAPI path '{path}' must start with '/'")
        _mapping(path_item, f"OpenAPI path '{path}'")
    return spec_map


def _validate_checks(config: dict[str, Any], spec: dict[str, Any]) -> int:
    identities = _mapping(config.get("identities"), "identities")
    for name, identity in identities.items():
        identity_map = _mapping(identity, f"identity '{name}'")
        auth = identity_map.get("auth")
        if auth == "none":
            continue
        if auth != "bearer":
            raise ValidationError(f"identity '{name}' auth must be 'none' or 'bearer'")
        env_name = identity_map.get("token_env")
        if not isinstance(env_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
            raise ValidationError(f"identity '{name}' token_env must be an environment variable name")

    checks = config.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValidationError("checks must be a non-empty list")
    target = _mapping(config.get("target"), "target")
    if len(checks) > target["max_requests"]:
        raise ValidationError("number of checks exceeds target.max_requests")

    seen_ids: set[str] = set()
    paths = spec["paths"]
    for index, check in enumerate(checks, start=1):
        check_map = _mapping(check, f"checks[{index}]")
        check_id = check_map.get("id")
        if not isinstance(check_id, str) or not check_id.strip():
            raise ValidationError(f"checks[{index}].id must be a non-empty string")
        if check_id in seen_ids:
            raise ValidationError(f"duplicate check id '{check_id}'")
        seen_ids.add(check_id)

        operation = check_map.get("operation")
        if not isinstance(operation, str) or not operation.startswith("GET /"):
            raise ValidationError(f"check '{check_id}' must use a GET operation")
        path = operation[4:]
        if path not in paths or not isinstance(paths[path], dict) or not isinstance(paths[path].get("get"), dict):
            raise ValidationError(f"check '{check_id}' operation '{operation}' is missing from the OpenAPI document")

        identity_name = check_map.get("identity")
        if not isinstance(identity_name, str) or identity_name not in identities:
            raise ValidationError(f"check '{check_id}' references an unknown identity")

        params = check_map.get("path", {})
        params_map = _mapping(params, f"check '{check_id}' path parameters")
        placeholders = set(re.findall(r"\{([^{}]+)\}", path))
        if placeholders != set(params_map):
            raise ValidationError(f"check '{check_id}' path parameters must match placeholders: {', '.join(sorted(placeholders)) or '(none)'}")
        if not all(isinstance(value, (str, int)) and not isinstance(value, bool) and str(value) for value in params_map.values()):
            raise ValidationError(f"check '{check_id}' path parameter values must be non-empty strings or integers")

        statuses = check_map.get("expected_status")
        if not isinstance(statuses, list) or not statuses or any(
            isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599 for status in statuses
        ):
            raise ValidationError(f"check '{check_id}' expected_status must be a non-empty list of HTTP status codes")

        assertions = check_map.get("assert_json", [])
        if not isinstance(assertions, list):
            raise ValidationError(f"check '{check_id}' assert_json must be a list")
        for assertion_index, assertion in enumerate(assertions, start=1):
            assertion_map = _mapping(assertion, f"check '{check_id}' assert_json[{assertion_index}]")
            pointer = assertion_map.get("pointer")
            if not isinstance(pointer, str) or not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
                raise ValidationError(f"check '{check_id}' JSON assertion pointer must be a valid non-root JSON Pointer")
            operators = set(assertion_map) - {"pointer"}
            if operators not in ({"equals"}, {"not_equals"}):
                raise ValidationError(f"check '{check_id}' JSON assertion must specify exactly one of equals or not_equals")
            expected = assertion_map[next(iter(operators))]
            if not (expected is None or type(expected) in {str, int, bool} or type(expected) is float and math.isfinite(expected)):
                raise ValidationError(f"check '{check_id}' JSON assertion values must be finite JSON scalars")
    coverage = _mapping(config.get("coverage", {}), "coverage")
    required = coverage.get("required", [])
    if not isinstance(required, list):
        raise ValidationError("coverage.required must be a list")
    seen_required: set[tuple[str, str]] = set()
    for index, item in enumerate(required, start=1):
        item_map = _mapping(item, f"coverage.required[{index}]")
        if set(item_map) != {"identity", "operation"}:
            raise ValidationError(f"coverage.required[{index}] must contain exactly identity and operation")
        identity_name = item_map["identity"]
        operation = item_map["operation"]
        if not isinstance(identity_name, str) or identity_name not in identities:
            raise ValidationError(f"coverage.required[{index}] references an unknown identity")
        if not isinstance(operation, str) or not operation.startswith("GET /"):
            raise ValidationError(f"coverage.required[{index}].operation must use GET")
        path = operation[4:]
        if path not in paths or not isinstance(paths[path], dict) or not isinstance(paths[path].get("get"), dict):
            raise ValidationError(f"coverage.required[{index}] operation '{operation}' is missing from the OpenAPI document")
        pair = (identity_name, operation)
        if pair in seen_required:
            raise ValidationError(f"duplicate required coverage pair: {identity_name} / {operation}")
        seen_required.add(pair)
    return len(checks)


def load_validated_inputs(spec_path: Path, config_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load and validate OpenAPI and scenario YAML without network access."""
    spec = _validate_spec(_read_yaml(spec_path, "OpenAPI"))
    config = _mapping(_read_yaml(config_path, "scenario"), "scenario config")
    if config.get("version") != 1:
        raise ValidationError("scenario config version must be 1")
    _validate_target(config.get("target"))
    _validate_checks(config, spec)
    return spec, config


def validate_inputs(spec_path: Path, config_path: Path) -> int:
    """Validate OpenAPI and scenario YAML. Returns the number of checks."""
    _, config = load_validated_inputs(spec_path, config_path)
    return len(config["checks"])
