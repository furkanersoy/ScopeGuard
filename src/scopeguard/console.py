"""Small dependency-free terminal UI for ScopeGuard."""

from __future__ import annotations

import os
import shlex
import sys
import time
from collections.abc import Callable, Sequence
from typing import TextIO

from . import __version__

_COLORS = {"cyan": "36", "green": "32", "yellow": "33", "red": "31", "muted": "90"}


def colorize(value: str, color: str, stream: TextIO | None = None) -> str:
    """Apply ANSI color only when the output is an interactive color terminal."""
    output = stream or sys.stdout
    if not getattr(output, "isatty", lambda: False)() or os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return value
    code = _COLORS.get(color)
    return f"\x1b[{code}m{value}\x1b[0m" if code else value


def show_banner(stream: TextIO | None = None, *, animate: bool | None = None) -> None:
    """Show the ScopeGuard mark with a short, TTY-only title animation."""
    output = stream or sys.stdout
    if animate is None:
        animate = bool(getattr(output, "isatty", lambda: False)()) and not os.environ.get("CI")
    title = "SCOPEGUARD"
    output.write("       /\\\n      /  \\\n     / SG \\\n     \\    /\n      \\  /\n       \\/\n\n  ")
    if animate and getattr(output, "isatty", lambda: False)() and os.environ.get("NO_COLOR") is None:
        for index in range(1, len(title) + 1):
            output.write("\r  " + colorize(title[:index], "cyan", output))
            output.flush()
            time.sleep(0.035)
        output.write("\n")
    else:
        output.write(colorize(title, "cyan", output) + "\n")
    output.write(f"  API authorization testing  |  v{__version__}\n")
    output.write("  Finds API access-control gaps such as BOLA/IDOR before release.\n")
    output.write("  Define checks from an OpenAPI spec; validate and preview offline, then run read-only GET checks.\n")
    output.write("  Loopback is the default. Remote testing needs an explicit allowlist and --allow-remote.\n")
    output.write("  API yetkilendirme açıklarını (BOLA/IDOR) sürüm öncesi bulur.\n")
    output.write("  OpenAPI tabanlı kontrolleri çevrimdışı doğrular; yalnızca tanımlı GET isteklerini çalıştırır.\n")
    output.write("  Varsayılan hedef yerel makinedir; uzak test için izin listesi ve --allow-remote gerekir.\n")
    output.write("  Type 'help' for commands; 'exit' to close.\n\n")
    output.flush()


def _split_command(line: str) -> list[str]:
    """Split one console line while preserving quoted Windows paths."""
    lexer = shlex.shlex(line, posix=os.name != "nt")
    lexer.whitespace_split = True
    lexer.commenters = ""
    values = list(lexer)
    if os.name == "nt":
        values = [value[1:-1] if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'" else value for value in values]
    return values


def run_console(command_handler: Callable[[Sequence[str]], int], *, input_stream: TextIO | None = None, output_stream: TextIO | None = None) -> None:
    """Run the interactive command loop until EOF or an exit command."""
    source = input_stream or sys.stdin
    output = output_stream or sys.stdout
    show_banner(output)
    while True:
        try:
            output.write(colorize("sg> ", "cyan", output))
            output.flush()
            line = source.readline()
        except KeyboardInterrupt:
            output.write("\nUse 'exit' to close ScopeGuard.\n")
            continue
        if not line:
            output.write("\nScopeGuard closed.\n")
            return
        try:
            tokens = _split_command(line.strip())
        except ValueError as exc:
            output.write(f"Could not parse command: {exc}\n")
            continue
        if not tokens:
            continue
        command, *arguments = tokens
        normalized = command.lower()
        if normalized in {"exit", "quit"}:
            output.write("ScopeGuard closed.\n")
            return
        if normalized in {"help", "?"}:
            output.write(
                "Commands:\n"
                "  validate --spec <openapi.yaml> --config <scenario.yaml>\n"
                "  plan --spec <openapi.yaml> --config <scenario.yaml>\n"
                "  coverage [--strict] --spec <openapi.yaml> --config <scenario.yaml>\n"
                "  run --spec <openapi.yaml> --config <scenario.yaml> --output <report.json>\n"
                "      [--markdown-output <report.md>] [--language tr|en]\n"
                "      Report language defaults to English; use --language tr for Turkish.\n"
                "  version | help | exit\n"
                "Quote paths that contain spaces. Commands are handled locally; no shell commands are executed.\n"
            )
            continue
        if normalized == "version":
            output.write(f"ScopeGuard {__version__}\n")
            continue
        try:
            command_handler([command, *arguments])
        except KeyboardInterrupt:
            output.write("\nCommand cancelled.\n")
