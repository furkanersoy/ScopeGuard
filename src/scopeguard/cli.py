"""Command-line interface for ScopeGuard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ValidationError, validate_inputs
from .runner import run_scenarios


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopeguard", description="Validate API access-check configuration.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate an OpenAPI document and scenario YAML without sending requests.")
    validate.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    validate.add_argument("--config", required=True, type=Path, help="Path to a ScopeGuard scenario YAML file")

    run = subparsers.add_parser("run", help="Run configured read-only GET checks against the explicitly scoped target.")
    run.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    run.add_argument("--config", required=True, type=Path, help="Path to a ScopeGuard scenario YAML file")
    run.add_argument("--output", required=True, type=Path, help="Path for the redacted JSON report")
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "validate":
        try:
            check_count = validate_inputs(args.spec, args.config)
        except ValidationError as exc:
            print(f"Invalid configuration: {exc}", file=sys.stderr)
            raise SystemExit(2) from None

        print(f"Valid: {args.spec}")
        print(f"Valid: {args.config}")
        print(f"{check_count} read-only GET check(s) are ready. No network requests were sent.")
        return

    if args.command == "run":
        try:
            report = run_scenarios(args.spec, args.config, args.output)
        except (ValidationError, OSError) as exc:
            print(f"Run failed: {exc}", file=sys.stderr)
            raise SystemExit(2) from None

        for result in report["results"]:
            actual = result.get("actual_status", result.get("reason", ""))
            print(f"[{result['status']}] {result['id']} (expected {result['expected_status']}, got {actual})")
        print(f"Report written to {args.output}")
        summary = report["summary"]
        if summary["ERROR"] or summary["SKIPPED"]:
            raise SystemExit(2)
        if summary["FAIL"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
