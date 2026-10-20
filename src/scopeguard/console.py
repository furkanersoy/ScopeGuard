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
    output.write(f"  API authorization testing and local security checks  |  v{__version__}\n")
    output.write("  Checks API access control and local source/configuration patterns.\n")
    output.write("  API runs use configured GET checks; local inspect is offline and never executes code.\n")
    output.write("  Loopback is the default. Remote testing needs an explicit allowlist and --allow-remote.\n")
    output.write("  API yetkilendirme açıklarını (BOLA/IDOR) sürüm öncesi bulur.\n")
    output.write("  OpenAPI tabanlı kontrolleri çevrimdışı doğrular; yalnızca tanımlı GET isteklerini çalıştırır.\n")
    output.write("  Varsayılan hedef yerel makinedir; uzak test için izin listesi ve --allow-remote gerekir.\n")
    output.write("  Choose a security section from the menu below.\n")
    output.write("  Aşağıdaki menüden güvenlik bölümünü seçin.\n\n")
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


def _show_help(output: TextIO) -> None:
    output.write(
        "Commands / Komutlar:\n"
        "  init --spec <openapi.yaml> [--output scenario.yaml] [--force]\n"
        "      EN: Create a scenario; select anonymous, BOLA/IDOR, BFLA, or custom GET checks.\n"
        "      TR: Senaryo oluşturur; anonim, BOLA/IDOR, BFLA veya özel GET kontrolleri seçilir.\n"
        "  validate | plan | coverage --spec <openapi.yaml> --config <scenario.yaml>\n"
        "      EN: Validate, preview requests, or show coverage; these commands are offline.\n"
        "      TR: Doğrular, istekleri önizler veya kapsamı gösterir; bu komutlar çevrimdışıdır.\n"
        "  run --spec <openapi.yaml> --config <scenario.yaml> --output <report.json>\n"
        "      [--markdown-output report.md] [--sarif-output report.sarif] [--language tr|en]\n"
        "      EN: Run configured read-only GET checks and save local reports.\n"
        "      TR: Tanımlı salt okunur GET kontrollerini çalıştırıp yerel rapor yazar.\n"
        "  inspect --path <file-or-folder> --checks secrets python config\n"
        "      EN: Scan local files offline; code is not run and secret values are redacted.\n"
        "      TR: Yerel dosyaları çevrimdışı tarar; kod çalışmaz, sır değerleri gizlenir.\n"
        "  menu | help | version | exit\n"
        "      EN: Return to sections | show help | show version | close ScopeGuard.\n"
        "      TR: Bölüm menüsüne dön | yardımı göster | sürümü göster | ScopeGuard'u kapat.\n"
        "Quote paths containing spaces. Commands run locally; no shell commands are executed.\n"
        "Boşluk içeren yolları tırnak içine al. Komutlar yerelde çalışır; kabuk komutu çalıştırılmaz.\n"
    )


def _answer(source: TextIO, output: TextIO, prompt: str, default: str = "") -> str | None:
    suffix = f" [{default}]" if default else ""
    output.write(f"{prompt}{suffix}: ")
    output.flush()
    try:
        value = source.readline()
    except KeyboardInterrupt:
        output.write("\nInput cancelled / Giriş iptal edildi.\n")
        return None
    if not value:
        return None
    return value.strip() or default


def _dispatch(command_handler: Callable[[Sequence[str]], int], args: list[str], output: TextIO) -> None:
    try:
        code = command_handler(args)
        if code:
            output.write(f"Command finished with exit code {code}.\n")
    except KeyboardInterrupt:
        output.write("\nCommand cancelled.\n")


def _report_sidecar(report: str, suffix: str) -> str:
    stem, extension = os.path.splitext(report)
    return (stem if extension else report) + suffix


def _api_menu(command_handler: Callable[[Sequence[str]], int], source: TextIO, output: TextIO) -> bool:
    while True:
        output.write(
            "\nAPI Security / API Güvenliği\n"
            "  1. Create a scenario / Senaryo oluştur\n"
            "  2. Validate a scenario / Senaryoyu doğrula\n"
            "  3. Preview requests / İstekleri önizle\n"
            "  4. Show coverage / Kapsamı göster\n"
            "  5. Run checks / Kontrolleri çalıştır\n"
            "  0. Back to main menu / Ana menüye dön\n"
        )
        choice = _answer(source, output, "Select an API action / API işlemi seçin", "0")
        if choice is None:
            return False
        if choice == "0":
            return True
        if choice not in {"1", "2", "3", "4", "5"}:
            output.write("Choose one of the listed options / Listelenen seçeneklerden birini seçin.\n")
            continue
        spec = _answer(source, output, "OpenAPI file / OpenAPI dosyası", "examples/api/openapi.yaml")
        if spec is None:
            return False
        if choice == "1":
            scenario = _answer(source, output, "New scenario file / Yeni senaryo dosyası", "examples/scenarios/new-scenario.yaml")
            if scenario is None:
                return False
            _dispatch(command_handler, ["init", "--spec", spec, "--output", scenario], output)
            continue
        scenario = _answer(source, output, "Scenario file / Senaryo dosyası", "examples/scenarios/local-demo.yaml")
        if scenario is None:
            return False
        commands = {
            "2": ["validate"],
            "3": ["plan"],
            "4": ["coverage"],
            "5": ["run"],
        }
        args = commands[choice] + ["--spec", spec, "--config", scenario]
        if choice == "5":
            report = _answer(source, output, "JSON report / JSON raporu", "report.json")
            if report is None:
                return False
            language = _answer(source, output, "Report language tr/en / Rapor dili tr/en", "tr")
            if language is None:
                return False
            markdown = _report_sidecar(report, ".md")
            sarif = _report_sidecar(report, ".sarif")
            args.extend(["--output", report, "--markdown-output", markdown, "--sarif-output", sarif, "--language", language])
        _dispatch(command_handler, args, output)


def _inspect_menu(command_handler: Callable[[Sequence[str]], int], source: TextIO, output: TextIO, *, secrets_only: bool) -> bool:
    section = "Secret Detection / Gizli Bilgi Taraması" if secrets_only else "Source Code & Configuration / Kaynak Kod ve Yapılandırma"
    output.write(f"\n{section}\n")
    output.write("This scan is local and offline. It does not execute source code.\n")
    output.write("Bu tarama yerel ve çevrimdışıdır. Kaynak kodu çalıştırmaz.\n")
    path = _answer(source, output, "File or folder to inspect / İncelenecek dosya veya klasör", ".")
    if path is None:
        return False
    default_report = "scopeguard-secrets.json" if secrets_only else "scopeguard-source.json"
    report = _answer(source, output, "JSON report path / JSON rapor yolu", default_report)
    if report is None:
        return False
    markdown = _answer(source, output, "Markdown report path / Markdown rapor yolu", _report_sidecar(report, ".md"))
    if markdown is None:
        return False
    language = _answer(source, output, "Report language tr/en / Rapor dili tr/en", "tr")
    if language is None:
        return False
    checks = ["secrets"] if secrets_only else ["python", "config"]
    _dispatch(command_handler, ["inspect", "--path", path, "--checks", *checks, "--output", report, "--markdown-output", markdown, "--language", language], output)
    return True


def _command_console(command_handler: Callable[[Sequence[str]], int], source: TextIO, output: TextIO, *, initial_line: str | None = None) -> bool:
    output.write("\nAdvanced command console / Gelişmiş komut konsolu. Type 'menu' to return.\n")
    while True:
        if initial_line is not None:
            line = initial_line
            initial_line = None
        else:
            try:
                output.write(colorize("sg> ", "cyan", output))
                output.flush()
                line = source.readline()
            except KeyboardInterrupt:
                output.write("\nUse 'menu' to return or 'exit' to close.\n")
                continue
        if not line:
            output.write("\nScopeGuard closed.\n")
            return False
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
            return False
        if normalized == "menu":
            return True
        if normalized in {"help", "?"}:
            _show_help(output)
            continue
        if normalized == "version":
            output.write(f"ScopeGuard {__version__}\n")
            continue
        _dispatch(command_handler, [command, *arguments], output)


def run_console(command_handler: Callable[[Sequence[str]], int], *, input_stream: TextIO | None = None, output_stream: TextIO | None = None) -> None:
    """Show the security-section menu, then dispatch to the selected local workflow."""
    source = input_stream or sys.stdin
    output = output_stream or sys.stdout
    show_banner(output)
    while True:
        output.write(
            "Main menu / Ana menü:\n"
            "  1. API Security / API Güvenliği\n"
            "  2. Source Code & Configuration / Kaynak Kod ve Yapılandırma\n"
            "  3. Secret Detection / Gizli Bilgi Taraması\n"
            "  4. Advanced command console / Gelişmiş komut konsolu\n"
            "  0. Exit / Çıkış\n"
        )
        choice = _answer(source, output, "Choose a section / Bölüm seçin", "0")
        if choice is None or choice.lower() in {"0", "exit", "quit"}:
            output.write("ScopeGuard closed.\n")
            return
        if choice == "1":
            if not _api_menu(command_handler, source, output):
                output.write("ScopeGuard closed.\n")
                return
        elif choice == "2":
            if not _inspect_menu(command_handler, source, output, secrets_only=False):
                output.write("ScopeGuard closed.\n")
                return
        elif choice == "3":
            if not _inspect_menu(command_handler, source, output, secrets_only=True):
                output.write("ScopeGuard closed.\n")
                return
        elif choice == "4":
            if not _command_console(command_handler, source, output):
                return
        elif choice.lower() in {"help", "?"}:
            _show_help(output)
        elif choice.lower() == "version":
            output.write(f"ScopeGuard {__version__}\n")
        elif choice.strip().isdigit():
            output.write("Choose 1, 2, 3, 4, or 0 / 1, 2, 3, 4 veya 0 seçin.\n")
        else:
            if not _command_console(command_handler, source, output, initial_line=choice):
                return
