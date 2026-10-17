"""Command-line interface for ScopeGuard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ValidationError, validate_inputs
from .coverage import build_coverage, render_coverage_table
from .planner import build_plan
from .runner import run_scenarios


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopeguard", description="Validate API access-check configuration.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate an OpenAPI document and scenario YAML without sending requests.")
    validate.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    validate.add_argument("--config", required=True, type=Path, help="Path to a ScopeGuard scenario YAML file")

    plan = subparsers.add_parser("plan", help="Preview the exact configured requests without using the network or reading tokens.")
    plan.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    plan.add_argument("--config", required=True, type=Path, help="Path to a ScopeGuard scenario YAML file")

    coverage = subparsers.add_parser("coverage", help="Show configured identity-by-endpoint checks as an offline matrix.")
    coverage.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    coverage.add_argument("--config", required=True, type=Path, help="Path to a ScopeGuard scenario YAML file")
    coverage.add_argument("--strict", action="store_true", help="Exit with status 1 when a required identity/operation pair is missing")

    run = subparsers.add_parser("run", help="Run configured read-only GET checks against the explicitly scoped target.")
    run.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    run.add_argument("--config", required=True, type=Path, help="Path to a ScopeGuard scenario YAML file")
    run.add_argument("--output", required=True, type=Path, help="Path for the redacted JSON report")
    run.add_argument("--allow-remote", action="store_true", help="Allow the HTTPS target only when its exact host and port are allowlisted in the config")
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

    if args.command == "plan":
        try:
            plan = build_plan(args.spec, args.config)
        except (ValidationError, OSError) as exc:
            print(f"Plan failed: {exc}", file=sys.stderr)
            raise SystemExit(2) from None

        print(f"Target: {plan['target']} ({'REMOTE' if plan['remote'] else 'loopback'})")
        print(f"Checks: {plan['check_count']} / max requests {plan['max_requests']}")
        for check in plan["checks"]:
            print(f"- {check['id']}: {check['method']} {check['url']}")
            print(f"  Identity: {check['identity']}; expected status: {check['expected_status']}")
            for assertion in check["assertions"]:
                print(f"  JSON assertion: {assertion['pointer']} {assertion['operator']}")
        if plan["remote"]:
            print("Remote target: run requires --allow-remote. Confirm you are authorized before execution.")
        print("Offline plan only. No network requests were sent; token values were not read or displayed.")
        return

    if args.command == "coverage":
        try:
            coverage = build_coverage(args.spec, args.config)
        except (ValidationError, OSError) as exc:
            print(f"Coverage failed: {exc}", file=sys.stderr)
            raise SystemExit(2) from None
        print(render_coverage_table(coverage))
        if args.strict and coverage["missing_required"]:
            raise SystemExit(1)
        return

    if args.command == "run":
        try:
            report = run_scenarios(args.spec, args.config, args.output, allow_remote=args.allow_remote)
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
