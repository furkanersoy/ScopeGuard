"""Tests for the descriptive offline access coverage matrix."""

from __future__ import annotations

import contextlib
import io
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from scopeguard.cli import main
from scopeguard.coverage import build_coverage, render_coverage_table

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "examples" / "api" / "openapi.yaml"
SCENARIO = ROOT / "examples" / "scenarios" / "local-demo.yaml"


class CoverageTests(unittest.TestCase):
    def test_matrix_lists_configured_checks_and_marks_empty_pairs(self) -> None:
        coverage = build_coverage(SPEC, SCENARIO)
        table = render_coverage_table(coverage)

        self.assertEqual(coverage["configured_pairs"], 4)
        self.assertEqual(coverage["total_pairs"], len(coverage["operations"]) * len(coverage["identities"]))
        self.assertIn("anonymous-health-check [200]", table)
        self.assertIn("user-b-cannot-read-user-a-record [404]", table)
        self.assertIn("[not configured]", table)
        self.assertIn("does not indicate a vulnerability", table)

    def test_cli_coverage_is_offline_and_does_not_read_or_print_secret(self) -> None:
        output = io.StringIO()
        with patch.dict(os.environ, {"SG_USER_A_TOKEN": "never-print-this"}), \
                patch("urllib.request.urlopen") as urlopen, \
                patch("sys.argv", ["scopeguard", "coverage", "--spec", str(SPEC), "--config", str(SCENARIO)]), \
                contextlib.redirect_stdout(output):
            main()

        self.assertIn("GET /records/{record_id}", output.getvalue())
        self.assertNotIn("never-print-this", output.getvalue())
        self.assertNotIn("SG_USER_A_TOKEN", output.getvalue())
        self.assertIn("No network requests were sent", output.getvalue())
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
