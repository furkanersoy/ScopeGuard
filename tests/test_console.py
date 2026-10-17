"""Tests for the dependency-free interactive console."""

from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import patch

from scopeguard.cli import main
from scopeguard.console import _split_command, colorize, show_banner


class ConsoleTests(unittest.TestCase):
    def test_bare_command_opens_console_and_accepts_help_version_exit(self) -> None:
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO("help\nversion\nexit\n")), contextlib.redirect_stdout(output):
            main([])

        text = output.getvalue()
        self.assertIn("SCOPEGUARD", text)
        self.assertIn("validate --spec", text)
        self.assertIn("ScopeGuard 0.2.0", text)
        self.assertIn("ScopeGuard closed.", text)
        self.assertNotIn("\x1b[", text)

    def test_banner_does_not_animate_or_emit_escape_codes_when_output_is_redirected(self) -> None:
        output = io.StringIO()
        show_banner(output, animate=True)
        self.assertIn("API authorization testing", output.getvalue())
        self.assertNotIn("\x1b[", output.getvalue())

    def test_colorize_respects_no_color(self) -> None:
        output = io.StringIO()
        with patch.dict("os.environ", {"NO_COLOR": "1"}):
            value = colorize("PASS", "green", output)
        self.assertEqual(value, "PASS")

    def test_console_keeps_quoted_windows_paths_with_spaces(self) -> None:
        with patch("scopeguard.console.os.name", "nt"):
            tokens = _split_command('validate --spec "C:\\Users\\Furka\\My Project\\api.yaml" --config scenario.yaml')
        self.assertEqual(tokens[2], r"C:\Users\Furka\My Project\api.yaml")


if __name__ == "__main__":
    unittest.main()
