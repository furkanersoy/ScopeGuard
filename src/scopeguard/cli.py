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
from .local_scan import apply_suppressions, inspect_path, write_local_reports
from .dependency_scan import scan_dependencies, validate_dependency_outputs
from .report_compare import compare_reports, write_comparison_reports
from .planner import build_plan
from .runner import run_scenarios
from .wizard import run_init_wizard
from .ignore_wizard import run_ignore_wizard
from .profiles import PROFILE_CHECKS, load_scan_profile, run_profile_wizard


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

    run = subparsers.add_parser("run", help="Run configured read-only GET, HEAD, and OPTIONS checks against the explicitly scoped target.")
    run.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    run.add_argument("--config", required=True, type=Path, help="Path to a ScopeGuard scenario YAML file")
    run.add_argument("--output", required=True, type=Path, help="Path for the redacted JSON report")
    run.add_argument("--markdown-output", type=Path, help="Optional path for a redacted Markdown summary")
    run.add_argument("--sarif-output", type=Path, help="Optional local path for a SARIF 2.1.0 findings file; no upload is performed")
    run.add_argument("--html-output", type=Path, help="Optional local path for a self-contained HTML report")
    run.add_argument("--language", choices=("tr", "en"), default="en", help="Report language: Turkish (tr) or English (en); default: en")
    run.add_argument("--allow-remote", action="store_true", help="Allow the HTTPS target only when its exact host and port are allowlisted in the config")

    init = subparsers.add_parser("init", help="Interactively create and validate a starter scenario without network access.")
    init.add_argument("--spec", required=True, type=Path, help="Path to an OpenAPI 3.x YAML or JSON file")
    init.add_argument("--output", type=Path, default=Path("scopeguard.yaml"), help="Scenario file to create (default: scopeguard.yaml)")
    init.add_argument("--force", action="store_true", help="Replace the output file if it already exists")

    inspect = subparsers.add_parser("inspect", help="Scan local source, configuration, Dockerfile, and Kubernetes patterns offline; never executes scanned code.")
    inspect.add_argument("--path", required=True, type=Path, help="File or directory to inspect")
    inspect.add_argument("--checks", nargs="+", choices=("secrets", "python", "config", "docker", "kubernetes", "terraform"), default=["secrets", "python", "config", "docker", "kubernetes", "terraform"], help="Checks: secrets, python, config, docker, kubernetes, terraform (default: all)")
    inspect.add_argument("--output", type=Path, default=Path("scopeguard-inspect.json"), help="Local JSON report path")
    inspect.add_argument("--markdown-output", type=Path, help="Optional local Markdown report path")
    inspect.add_argument("--sarif-output", type=Path, help="Optional local SARIF 2.1.0 report path; no upload is performed")
    inspect.add_argument("--html-output", type=Path, help="Optional local self-contained HTML report path")
    inspect.add_argument("--suppressions", type=Path, help="Optional YAML file of reasoned, expiring finding suppressions")
    inspect.add_argument("--language", choices=("tr", "en"), default="en", help="Report language: Turkish (tr) or English (en); default: en")
    inspect.add_argument("--fail-on", choices=("any", "critical", "high", "medium", "low", "none"), default="any", help="CI gate: fail when an active finding meets this severity threshold (default: any)")
    quick = subparsers.add_parser("quick-scan", help="Run a named offline local scan profile; defaults to the current directory.")
    quick.add_argument("--config", type=Path, help="Scan profile; defaults to .scopeguard-profile.yaml in the current folder when present")
    quick.add_argument("--path", type=Path, help="File or directory to inspect; defaults to the saved profile or current directory")
    quick.add_argument("--profile", choices=tuple(PROFILE_CHECKS), help="Override the saved preset checks")
    quick.add_argument("--output", type=Path, help="Local JSON report path; other report formats use the same filename prefix")
    quick.add_argument("--markdown-output", type=Path, help="Optional local Markdown report path")
    quick.add_argument("--sarif-output", type=Path, help="Optional local SARIF report path")
    quick.add_argument("--html-output", type=Path, help="Optional local HTML report path")
    quick.add_argument("--suppressions", type=Path, help="Optional YAML file of reasoned, expiring finding suppressions")
    quick.add_argument("--language", choices=("tr", "en"), help="Report language; defaults to saved profile or English")
    quick.add_argument("--fail-on", choices=("any", "critical", "high", "medium", "low", "none"), help="CI severity gate; defaults to saved profile or any")
    configure = subparsers.add_parser("configure", help="Create a reusable local scan profile without network access.")
    configure.add_argument("--output", type=Path, default=Path(".scopeguard-profile.yaml"), help="Profile file to create (default: .scopeguard-profile.yaml)")
    configure.add_argument("--force", action="store_true", help="Replace the profile file if it already exists")
    dependencies = subparsers.add_parser("dependencies", help="Check pinned lockfile versions against OSV; sends package names and versions over HTTPS only when --allow-network is supplied.")
    dependencies.add_argument("--path", required=True, type=Path, help="Lockfile or directory containing supported lockfiles")
    dependencies.add_argument("--allow-network", action="store_true", required=True, help="Explicitly permit HTTPS queries to api.osv.dev")
    dependencies.add_argument("--output", type=Path, default=Path("scopeguard-dependencies.json"), help="Local JSON report path")
    dependencies.add_argument("--markdown-output", type=Path, help="Optional local Markdown report path")
    dependencies.add_argument("--sarif-output", type=Path, help="Optional local SARIF 2.1.0 report path")
    dependencies.add_argument("--html-output", type=Path, help="Optional local HTML report path")
    dependencies.add_argument("--suppressions", type=Path, help="Optional YAML file of reasoned, expiring finding suppressions")
    dependencies.add_argument("--language", choices=("tr", "en"), default="en", help="Report language: Turkish (tr) or English (en); default: en")
    dependencies.add_argument("--fail-on", choices=("any", "critical", "high", "medium", "low", "none"), default="any", help="CI gate: fail when an active finding meets this severity threshold (default: any)")

    compare = subparsers.add_parser("compare", help="Compare two local ScopeGuard JSON reports and list added, resolved, and unchanged findings.")
    compare.add_argument("--previous", required=True, type=Path, help="Earlier JSON report")
    compare.add_argument("--current", required=True, type=Path, help="Newer JSON report")
    compare.add_argument("--output", type=Path, default=Path("scopeguard-diff.json"), help="Local JSON comparison path")
    compare.add_argument("--markdown-output", type=Path, help="Optional local Markdown comparison path")
    compare.add_argument("--html-output", type=Path, help="Optional local HTML comparison path")

    ignore = subparsers.add_parser("ignore", aliases=["suppress"], help="Create a reasoned, expiring suppression from a saved local report.")
    ignore.add_argument("--report", required=True, type=Path, help="Local JSON report containing the finding")
    ignore.add_argument("--output", type=Path, default=Path("scopeguard-ignore.yaml"), help="Suppression YAML to create or update")
    ignore.add_argument("--finding", type=int, help="1-based active finding number; prompts when omitted")
    ignore.add_argument("--reason", help="Why this finding is temporarily accepted; prompts when omitted")
    ignore.add_argument("--expires", help="Expiry date in YYYY-MM-DD format; defaults to 90 days from today")

    return parser


def _findings_trigger_gate(findings: list[dict], threshold: str) -> bool:
    """Return whether active findings meet the requested CI severity gate."""
    if threshold == "none":
        return False
    if threshold == "any":
        return bool(findings)
    ranks = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "unknown": 0}
    minimum = ranks[threshold]
    for finding in findings:
        severity = str(finding.get("severity", "unknown")).strip().lower()
        if severity == "yüksek":
            severity = "high"
        elif severity == "orta":
            severity = "medium"
        elif severity == "düşük":
            severity = "low"
        if ranks.get(severity, 0) >= minimum:
            return True
    return False


def _print_suppression_audit(report: dict) -> None:
    audit = report.get("suppression_audit", {})
    if not audit.get("entries"):
        return
    unused = audit.get("unused_entries", [])
    print(f"Suppression rules used: {audit.get('used_entries', 0)}/{audit['entries']}; unused: {len(unused)}.")
    for item in unused:
        print(f"  Unused suppression: {item['rule_id']} at {item['path']} (expires {item['expires']})")


def _print_suppression_next_step(report_path: Path) -> None:
    report = f'"{report_path}"'
    print(f"Create a temporary exception: choose menu option 6, or in `sg>` run `ignore --report {report}`.")
    print(f"In a system terminal, run `scopeguard ignore --report {report}`.")
    print(f"Geçici istisna için menüde 6'yı seç veya `sg>` içinde `ignore --report {report}` çalıştır.")
    print(f"Sistem terminalinde `scopeguard ignore --report {report}` komutunu kullan.")


def _profile_report_path(prefix: Path, extension: str) -> Path:
    if prefix.suffix.lower() in {".json", ".md", ".sarif", ".html"}:
        prefix = prefix.with_suffix("")
    return Path(f"{prefix}{extension}")


def _execute(args: argparse.Namespace) -> int:
    if args.command == "configure":
        try:
            run_profile_wizard(args.output, force=args.force)
        except (ValidationError, OSError) as exc:
            print(f"Profile creation failed: {exc}", file=sys.stderr)
            return 2
        except (EOFError, KeyboardInterrupt):
            print("\nProfile creation cancelled.", file=sys.stderr)
            return 2
        return 0

    if args.command == "quick-scan":
        profile_data = {}
        profile_path = args.config
        if profile_path is None:
            candidate = Path(".scopeguard-profile.yaml")
            if candidate.is_file():
                profile_path = candidate
                print(f"Found {candidate}; using the saved project scan profile.")
                print(f"{candidate} bulundu; kayıtlı proje tarama profili kullanılıyor.")
        if profile_path is not None:
            try:
                profile_data = load_scan_profile(profile_path)
            except ValidationError as exc:
                print(f"Cannot load scan profile: {exc}", file=sys.stderr)
                return 2
        profile_name = args.profile or profile_data.get("profile", "standard")
        if profile_name not in PROFILE_CHECKS:
            print(f"Cannot load scan profile: unknown profile {profile_name!r}", file=sys.stderr)
            return 2
        scan_path = args.path or profile_data.get("path") or Path(".")
        report_prefix = profile_data.get("report_prefix", Path("scopeguard-scan"))
        if args.output:
            json_output = args.output
            output_prefix = args.output.with_suffix("") if args.output.suffix.lower() in {".json", ".md", ".sarif", ".html"} else args.output
        else:
            json_output = _profile_report_path(Path(report_prefix), ".json")
            output_prefix = Path(report_prefix)
        args.command = "inspect"
        args.path = scan_path
        args.checks = PROFILE_CHECKS[profile_name]
        args.output = json_output
        args.markdown_output = args.markdown_output or _profile_report_path(output_prefix, ".md")
        args.sarif_output = args.sarif_output or _profile_report_path(output_prefix, ".sarif")
        args.html_output = args.html_output or _profile_report_path(output_prefix, ".html")
        args.suppressions = args.suppressions or profile_data.get("suppressions")
        args.language = args.language or profile_data.get("language", "en")
        args.fail_on = args.fail_on or profile_data.get("fail_on", "any")
        args.profile_file = profile_path

    if args.command in {"ignore", "suppress"}:
        try:
            result = run_ignore_wizard(args.report, args.output, args.finding, args.reason, args.expires)
        except (ValueError, OSError) as exc:
            print(f"Suppression creation failed: {exc}", file=sys.stderr)
            return 2
        action = "Updated" if result["updated"] else "Created"
        entry = result["entry"]
        print(f"{action} suppression for {entry['rule_id']} at {entry['path']}; expires {entry['expires']}.")
        print(f"Suppression file written to {result['output']}")
        print("Review suppressions periodically; the finding remains visible as suppressed in scan reports.")
        return 0

    if args.command == "inspect":
        outputs = [args.output]
        if args.markdown_output:
            outputs.append(args.markdown_output)
        if args.sarif_output:
            outputs.append(args.sarif_output)
        if args.html_output:
            outputs.append(args.html_output)
        try:
            if getattr(args, "profile_file", None) and args.profile_file.resolve() in {item.resolve() for item in outputs}:
                raise ValidationError("report outputs must not overwrite the scan profile")
            if args.suppressions and args.suppressions.resolve() in {item.resolve() for item in outputs}:
                raise ValidationError("report outputs must not overwrite the suppressions file")
            report = inspect_path(args.path, args.checks, args.language, output_paths=outputs)
            apply_suppressions(report, args.suppressions)
            write_local_reports(report, args.output, args.markdown_output, args.sarif_output, args.html_output)
        except (ValidationError, OSError) as exc:
            print(f"Inspection failed: {exc}", file=sys.stderr)
            return 2
        print(f"Scanned {report['scanned_files']} local file(s); active findings: {len(report['findings'])}; suppressed: {len(report.get('suppressed_findings', []))}.")
        _print_suppression_audit(report)
        print("No code was executed and no network requests were sent. Matched secret values were omitted.")
        print(f"JSON report written to {args.output}")
        if report["findings"]:
            _print_suppression_next_step(args.output)
        if args.markdown_output:
            print(f"Markdown report written to {args.markdown_output}")
        if args.sarif_output:
            print(f"Local SARIF report written to {args.sarif_output}; no upload was performed")
        if args.html_output:
            print(f"HTML report written to {args.html_output}")
        return 1 if _findings_trigger_gate(report["findings"], args.fail_on) else 0

    if args.command == "dependencies":
        outputs = [args.output]
        for candidate in (args.markdown_output, args.sarif_output, args.html_output):
            if candidate is not None:
                outputs.append(candidate)
        try:
            if args.suppressions and args.suppressions.resolve() in {item.resolve() for item in outputs}:
                raise ValidationError("report outputs must not overwrite the suppressions file")
            validate_dependency_outputs(args.path, outputs)
            report = scan_dependencies(args.path, args.language)
            apply_suppressions(report, args.suppressions)
            write_local_reports(report, args.output, args.markdown_output, args.sarif_output, args.html_output)
        except (ValidationError, OSError) as exc:
            print(f"Dependency scan failed: {exc}", file=sys.stderr)
            return 2
        print(f"Queried {report['queries_sent']} pinned package version(s) in {report['scanned_files']} lockfile(s) against OSV.")
        print(f"Active findings: {len(report['findings'])}; suppressed: {len(report.get('suppressed_findings', []))}.")
        _print_suppression_audit(report)
        print("Package names and versions were sent to OSV over HTTPS; manifests and source files were not uploaded.")
        print(f"JSON report written to {args.output}")
        if report["findings"]:
            _print_suppression_next_step(args.output)
        if args.markdown_output:
            print(f"Markdown report written to {args.markdown_output}")
        if args.sarif_output:
            print(f"Local SARIF report written to {args.sarif_output}; no upload was performed")
        if args.html_output:
            print(f"HTML report written to {args.html_output}")
        return 1 if _findings_trigger_gate(report["findings"], args.fail_on) else 0

    if args.command == "compare":
        try:
            outputs = [args.output, *[item for item in (args.markdown_output, args.html_output) if item is not None]]
            resolved_outputs = [item.resolve() for item in outputs]
            input_reports = {args.previous.resolve(), args.current.resolve()}
            if len(set(resolved_outputs)) != len(resolved_outputs):
                raise ValidationError("comparison output paths must be different")
            if input_reports & set(resolved_outputs):
                raise ValidationError("comparison outputs must not overwrite either input report")
            report = compare_reports(args.previous, args.current)
            write_comparison_reports(report, args.output, args.markdown_output, args.html_output)
        except (ValidationError, OSError) as exc:
            print(f"Report comparison failed: {exc}", file=sys.stderr)
            return 2
        summary = report["summary"]
        print(f"Added: {summary['added']}; resolved: {summary['resolved']}; unchanged: {summary['unchanged']}.")
        print(f"Comparison JSON written to {args.output}")
        if args.markdown_output:
            print(f"Comparison Markdown written to {args.markdown_output}")
        if args.html_output:
            print(f"Comparison HTML written to {args.html_output}")
        return 1 if summary["added"] else 0

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
        print(f"{check_count} read-only safe-method check(s) are ready. No network requests were sent.")
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
                html_output_path=args.html_output,
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
        if args.html_output:
            print(f"HTML report written to {args.html_output}")
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
    return _execute(args)


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
