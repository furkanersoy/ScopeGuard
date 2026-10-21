"""Command-line interface for ScopeGuard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import ValidationError, validate_inputs
from .coverage import build_coverage, render_coverage_table
from .console import colorize, run_console
from .local_scan import inspect_path, write_local_reports
from .planner import build_plan
from .runner import run_scenarios
from .wizard import run_init_wizard


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopeguard",
        description="Local-first API authorization checks with explicit scope controls.",
        epilog="Run 'scopeguard' without arguments to open the interactive console.",
    )
    parser.add_argument("--version", action="version", version=f"ScopeGuard {__version__}")
    subparsers = parser.add_subparsers(dest="command")

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
    run.add_argument("--markdown-output", type=Path, help="Optional path for a redacted Markdown summary")
    run.add_argument("--sarif-output", type=Path, help="Optional local path for a SARIF 2.1.0 findings file; no upload is performed")
    run.add_argument("--language", choices=("tr", "en"), default="en", help="Report language: Turkish (tr) or English (en); default: en")
    run.add_argument("--allow-remote", action="store_true", help="Allow the HTTPS target only when its exact host and port are allowlisted in the config")

    init = subparsers.add_parser("init", help="Interactively create and validate a starter scenario without network access.")
    init.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    init.add_argument("--output", type=Path, default=Path("scopeguard.yaml"), help="Scenario file to create (default: scopeguard.yaml)")
    init.add_argument("--force", action="store_true", help="Replace the output file if it already exists")

    inspect = subparsers.add_parser("inspect", help="Scan local source, configuration, Dockerfile, and Kubernetes patterns offline; never executes scanned code.")
    inspect.add_argument("--path", required=True, type=Path, help="File or directory to inspect")
    inspect.add_argument("--checks", nargs="+", choices=("secrets", "python", "config", "docker", "kubernetes"), default=["secrets", "python", "config", "docker", "kubernetes"], help="Checks: secrets, python, config, docker (default: all)")
    inspect.add_argument("--output", type=Path, default=Path("scopeguard-inspect.json"), help="Local JSON report path")
    inspect.add_argument("--markdown-output", type=Path, help="Optional local Markdown report path")
    inspect.add_argument("--language", choices=("tr", "en"), default="en", help="Report language: Turkish (tr) or English (en); default: en")
    return parser


def _execute(args: argparse.Namespace) -> int:
    if args.command == "inspect":
        outputs = [args.output]
        if args.markdown_output:
            outputs.append(args.markdown_output)
        try:
            report = inspect_path(args.path, args.checks, args.language, output_paths=outputs)
            write_local_reports(report, args.output, args.markdown_output)
        except (ValidationError, OSError) as exc:
            print(f"Inspection failed: {exc}", file=sys.stderr)
            return 2
        print(f"Scanned {report['scanned_files']} local file(s); findings: {len(report['findings'])}.")
        print("No code was executed and no network requests were sent. Matched secret values were omitted.")
        print(f"JSON report written to {args.output}")
        if args.markdown_output:
            print(f"Markdown report written to {args.markdown_output}")
        return 1 if report["findings"] else 0

    if args.command == "init":
        try:
            run_init_wizard(args.spec, args.output, force=args.force)
        except (ValidationError, OSError, EOFError) as exc:
            message = str(exc) or "initialization cancelled"
            print(f"Init failed: {message}", file=sys.stderr)
            return 2
        return 0

    if args.command == "validate":
        try:
            check_count = validate_inputs(args.spec, args.config)
        except ValidationError as exc:
            print(f"Invalid configuration: {exc}", file=sys.stderr)
            return 2

        print(f"Valid: {args.spec}")
        print(f"Valid: {args.config}")
        print(f"{check_count} read-only GET check(s) are ready. No network requests were sent.")
        return 0

    if args.command == "plan":
        try:
            plan = build_plan(args.spec, args.config)
        except (ValidationError, OSError) as exc:
            print(f"Plan failed: {exc}", file=sys.stderr)
            return 2

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
        return 0

    if args.command == "coverage":
        try:
            coverage = build_coverage(args.spec, args.config)
        except (ValidationError, OSError) as exc:
            print(f"Coverage failed: {exc}", file=sys.stderr)
            return 2
        print(render_coverage_table(coverage))
        if args.strict and (coverage["missing_required"] or coverage["missing_required_check_ids"]):
            return 1
        return 0

    if args.command == "run":
        try:
            report = run_scenarios(
                args.spec,
                args.config,
                args.output,
                allow_remote=args.allow_remote,
                markdown_output_path=args.markdown_output,
                sarif_output_path=args.sarif_output,
                language=args.language,
            )
        except (ValidationError, OSError) as exc:
            print(f"Run failed: {exc}", file=sys.stderr)
            return 2

        for result in report["results"]:
            actual = result.get("actual_status", result.get("reason", ""))
            status = result["status"]
            color = "green" if status == "PASS" else "red" if status in {"FAIL", "ERROR"} else "yellow"
            print(f"[{colorize(status, color)}] {result['id']} (expected {result['expected_status']}, got {actual})")
        print(f"Report written to {args.output}")
        if args.markdown_output:
            print(f"Markdown report written to {args.markdown_output}")
        if args.sarif_output:
            print(f"Local SARIF report written to {args.sarif_output}; no upload was performed")
        summary = report["summary"]
        if summary["ERROR"] or summary["SKIPPED"]:
            return 2
        if summary["FAIL"]:
            return 1
        return 0
    return 0


def _console_command(tokens: Sequence[str]) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(list(tokens))
    except SystemExit as exc:
        return int(exc.code or 0)
    if args.command is None:
        parser.print_help()
        return 0
    code = _execute(args)
    if code:
        print(f"Command finished with exit code {code}.")
    return code


def main(argv: Sequence[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    if not arguments:
        run_console(_console_command)
        return
    args = parser.parse_args(arguments)
    if args.command is None:
        parser.print_help()
        return
    code = _execute(args)
    if code:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
