"""Sequential, read-only execution of validated local demo scenarios."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from . import __version__
from .config import ValidationError, load_validated_inputs

MAX_RESPONSE_BYTES = 64 * 1024
MIN_REQUEST_INTERVAL_SECONDS = 0.1


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _request_url(base_url: str, operation: str, path_params: dict[str, Any]) -> str:
    path = operation[4:]

    def replace(match: re.Match[str]) -> str:
        return quote(str(path_params[match.group(1)]), safe="")

    resolved_path = re.sub(r"\{([^{}]+)\}", replace, path)
    url = f"{base_url.rstrip('/')}{resolved_path}"
    parsed_url = urlsplit(url)
    parsed_base = urlsplit(base_url)
    if parsed_url.scheme != parsed_base.scheme or parsed_url.hostname != parsed_base.hostname or parsed_url.port != parsed_base.port:
        raise ValidationError("resolved request escaped the configured target")
    return url


def _identity_headers(identity: dict[str, Any]) -> tuple[dict[str, str] | None, str | None]:
    if identity["auth"] == "none":
        return {}, None
    env_name = identity["token_env"]
    token = os.environ.get(env_name)
    if not token:
        return None, f"required environment variable {env_name} is not set"
    if "\r" in token or "\n" in token:
        return None, f"environment variable {env_name} contains invalid header characters"
    return {"Authorization": f"Bearer {token}"}, None


def _send_get(opener: urllib.request.OpenerDirector, url: str, headers: dict[str, str], timeout: float) -> tuple[int, bytes, bool]:
    request = urllib.request.Request(url, headers={"User-Agent": f"ScopeGuard/{__version__}", **headers}, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            return response.status, body[:MAX_RESPONSE_BYTES], len(body) > MAX_RESPONSE_BYTES
    except urllib.error.HTTPError as exc:
        # Redirects are deliberately not followed; their status is evaluated as returned.
        status = exc.code
        body = exc.read(MAX_RESPONSE_BYTES + 1)
        exc.close()
        return status, body[:MAX_RESPONSE_BYTES], len(body) > MAX_RESPONSE_BYTES


def _json_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    current = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdecimal():
            index = int(part)
            if index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def _same_json_value(actual: Any, expected: Any) -> bool:
    # Python considers True == 1; JSON booleans and numbers must remain distinct.
    if isinstance(actual, bool) != isinstance(expected, bool):
        return False
    return type(actual) is type(expected) and actual == expected


def _evaluate_json_assertions(assertions: list[dict[str, Any]], body: bytes, truncated: bool) -> tuple[list[dict[str, str]], str | None]:
    if not assertions:
        return [], None
    if truncated:
        return ([{"pointer": item["pointer"], "operator": "equals" if "equals" in item else "not_equals", "status": "ERROR"} for item in assertions], "response_too_large")
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ([{"pointer": item["pointer"], "operator": "equals" if "equals" in item else "not_equals", "status": "ERROR"} for item in assertions], "response_not_json")

    results: list[dict[str, str]] = []
    for assertion in assertions:
        pointer = assertion["pointer"]
        found, actual = _json_pointer(document, pointer)
        if "equals" in assertion:
            passed = found and _same_json_value(actual, assertion["equals"])
            operator = "equals"
        else:
            passed = not found or not _same_json_value(actual, assertion["not_equals"])
            operator = "not_equals"
        results.append({"pointer": pointer, "operator": operator, "status": "PASS" if passed else "FAIL"})
    return results, None


def run_scenarios(spec_path: Path, config_path: Path, output_path: Path) -> dict[str, Any]:
    """Execute the configured GET checks and write a redacted JSON report."""
    if output_path.resolve() in {spec_path.resolve(), config_path.resolve()}:
        raise ValidationError("report output must not overwrite the OpenAPI or scenario input")

    spec, config = load_validated_inputs(spec_path, config_path)
    del spec  # Validation already confirmed every operation exists in the OpenAPI document.
    target = config["target"]
    identities = config["identities"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())
    results: list[dict[str, Any]] = []
    last_request_at = 0.0

    for check in config["checks"]:
        result: dict[str, Any] = {
            "id": check["id"],
            "identity": check["identity"],
            "operation": check["operation"],
            "expected_status": check["expected_status"],
        }
        headers, skip_reason = _identity_headers(identities[check["identity"]])
        if skip_reason:
            result.update({"status": "SKIPPED", "reason": skip_reason})
            results.append(result)
            continue

        try:
            url = _request_url(target["base_url"], check["operation"], check.get("path", {}))
            elapsed = time.monotonic() - last_request_at
            if last_request_at and elapsed < MIN_REQUEST_INTERVAL_SECONDS:
                time.sleep(MIN_REQUEST_INTERVAL_SECONDS - elapsed)
            last_request_at = time.monotonic()
            actual_status, response_body, truncated = _send_get(opener, url, headers or {}, float(target["timeout_seconds"]))
            result["actual_status"] = actual_status
            assertion_results, assertion_error = _evaluate_json_assertions(check.get("assert_json", []), response_body, truncated)
            if assertion_results:
                result["assertions"] = assertion_results
            status_matches = actual_status in check["expected_status"]
            assertion_failures = any(assertion["status"] == "FAIL" for assertion in assertion_results)
            assertion_errors = any(assertion["status"] == "ERROR" for assertion in assertion_results)
            if not status_matches or assertion_failures:
                result["status"] = "FAIL"
            elif assertion_errors:
                result["status"] = "ERROR"
                result["reason"] = assertion_error or "json_assertion_error"
            else:
                result["status"] = "PASS"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            # Avoid recording exception details that could contain user-controlled data.
            result.update({"status": "ERROR", "reason": type(exc).__name__})
        results.append(result)

    summary = {status: sum(result["status"] == status for result in results) for status in ("PASS", "FAIL", "SKIPPED", "ERROR")}
    report = {
        "tool": "ScopeGuard",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "spec_file": spec_path.name,
        "scenario_file": config_path.name,
        "summary": summary,
        "results": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report
