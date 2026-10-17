"""Tests for the descriptive offline access coverage matrix."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
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

    def test_strict_fails_when_required_pair_has_no_check(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
            config["coverage"]["required"].append(
                {"identity": "anonymous", "operation": "GET /records/{record_id}"}
            )
            scenario_path = Path(temp_dir) / "scenario.yaml"
            scenario_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

            output = io.StringIO()
            with patch("sys.argv", ["scopeguard", "coverage", "--strict", "--spec", str(SPEC), "--config", str(scenario_path)]), \
                    contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                main()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("[MISSING REQUIRED]", output.getvalue())
        self.assertIn("Required pairs satisfied: 4 / 5", output.getvalue())


if __name__ == "__main__":
    unittest.main()
