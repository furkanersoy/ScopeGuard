"""Tests for the offline scenario preview."""

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
from scopeguard.planner import build_plan

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "examples" / "api" / "openapi.yaml"
SCENARIO = ROOT / "examples" / "scenarios" / "local-demo.yaml"


class PlannerTests(unittest.TestCase):
    def test_plan_renders_encoded_path_and_never_reads_or_prints_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            scenario = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
            scenario["checks"] = [next(check for check in scenario["checks"] if check["id"] == "user-a-reads-own-record")]
            scenario["checks"][0]["path"]["record_id"] = "record/a b"
            scenario_path = Path(temp_dir) / "scenario.yaml"
            scenario_path.write_text(yaml.safe_dump(scenario, sort_keys=False), encoding="utf-8")

            output = io.StringIO()
            with patch.dict(os.environ, {"SG_USER_A_TOKEN": "do-not-print-this"}), \
                    patch("urllib.request.urlopen") as urlopen, \
                    patch("sys.argv", ["scopeguard", "plan", "--spec", str(SPEC), "--config", str(scenario_path)]), \
                    contextlib.redirect_stdout(output):
                main()

            self.assertIn("GET http://127.0.0.1:8000/records/record%2Fa%20b", output.getvalue())
            self.assertIn("Identity: user_a", output.getvalue())
            self.assertNotIn("do-not-print-this", output.getvalue())
            self.assertNotIn("SG_USER_A_TOKEN", output.getvalue())
            self.assertIn("No network requests were sent", output.getvalue())
            urlopen.assert_not_called()

    def test_remote_plan_is_offline_and_marks_runtime_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
            config["target"].update(
                {
                    "base_url": "https://staging.example.test",
                    "allowed_hosts": ["staging.example.test"],
                    "allow_remote": True,
                    "allowed_ports": [443],
                }
            )
            scenario_path = Path(temp_dir) / "remote.yaml"
            scenario_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

            plan = build_plan(SPEC, scenario_path)

        self.assertTrue(plan["remote"])
        self.assertEqual(plan["target"], "https://staging.example.test:443")
        self.assertEqual(plan["check_count"], 7)


if __name__ == "__main__":
    unittest.main()
