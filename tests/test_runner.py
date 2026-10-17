"""Integration tests against the local synthetic demo API."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import yaml

from scopeguard.config import ValidationError
from scopeguard.runner import run_scenarios
from scopeguard_demo.server import DemoHandler

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "examples" / "api" / "openapi.yaml"
SCENARIO = ROOT / "examples" / "scenarios" / "local-demo.yaml"


class QuietDemoHandler(DemoHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


class RunnerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietDemoHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.addCleanup(self._stop_server)

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)

    def _scenario_for_local_server(self, directory: Path) -> Path:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        host, port = self.server.server_address
        config["target"]["base_url"] = f"http://{host}:{port}"
        scenario = directory / "scenario.yaml"
        scenario.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        return scenario

    def test_detects_cross_user_access_and_redacts_report(self) -> None:
        directory = Path(self.temp_dir.name)
        scenario = self._scenario_for_local_server(directory)
        report_path = directory / "report.json"
        markdown_path = directory / "report.md"

        with patch.dict("os.environ", {"SG_USER_A_TOKEN": "demo-user-a", "SG_USER_B_TOKEN": "demo-user-b"}):
            report = run_scenarios(SPEC, scenario, report_path, markdown_output_path=markdown_path)

        self.assertEqual(report["summary"], {"PASS": 6, "FAIL": 1, "SKIPPED": 0, "ERROR": 0})
        results_by_id = {item["id"]: item for item in report["results"]}
        self.assertEqual(results_by_id["anonymous-cannot-read-record"]["actual_status"], 401)
        self.assertEqual(results_by_id["user-a-reads-own-record"]["assertions"][0]["status"], "PASS")
        self.assertEqual(results_by_id["user-a-cannot-read-user-b-record"]["actual_status"], 404)
        self.assertEqual(results_by_id["user-b-reads-own-record"]["assertions"][0]["status"], "PASS")
        self.assertEqual(results_by_id["user-b-cannot-read-user-a-record"]["actual_status"], 404)
        vulnerable = next(item for item in report["results"] if item["id"] == "vulnerable-route-should-deny-cross-user-read")
        self.assertEqual(vulnerable["status"], "FAIL")
        self.assertEqual(vulnerable["actual_status"], 200)
        self.assertEqual(vulnerable["assertions"][0]["status"], "FAIL")

        protected = next(item for item in report["results"] if item["id"] == "user-b-cannot-read-user-a-record")
        self.assertEqual(protected["assertions"][0]["status"], "PASS")

        report_text = report_path.read_text(encoding="utf-8")
        parsed_report = json.loads(report_text)
        self.assertEqual(parsed_report["summary"], report["summary"])
        self.assertNotIn("demo-user-a", report_text)
        self.assertNotIn("demo-user-b", report_text)
        self.assertNotIn('"user-a"', report_text)
        self.assertNotIn("Synthetic record A", report_text)
        markdown_text = markdown_path.read_text(encoding="utf-8")
        self.assertIn("# ScopeGuard report", markdown_text)
        self.assertIn("| 6 | 1 | 0 | 0 |", markdown_text)
        self.assertNotIn("demo-user-a", markdown_text)
        self.assertNotIn("Synthetic record A", markdown_text)
        self.assertNotIn("user-a`", markdown_text)

    def test_missing_token_is_skipped_without_request(self) -> None:
        directory = Path(self.temp_dir.name)
        scenario = self._scenario_for_local_server(directory)
        config = yaml.safe_load(scenario.read_text(encoding="utf-8"))
        config["checks"] = [next(check for check in config["checks"] if check["id"] == "user-a-reads-own-record")]
        scenario.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        report_path = directory / "skipped.json"

        with patch.dict("os.environ", {}, clear=True):
            report = run_scenarios(SPEC, scenario, report_path)

        self.assertEqual(report["summary"]["SKIPPED"], 1)
        self.assertNotIn("actual_status", report["results"][0])

    def test_report_cannot_overwrite_input(self) -> None:
        with self.assertRaisesRegex(ValidationError, "must not overwrite"):
            run_scenarios(SPEC, SCENARIO, SCENARIO)

    def test_report_outputs_must_be_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "same.md"
            with self.assertRaisesRegex(ValidationError, "different paths"):
                run_scenarios(SPEC, SCENARIO, output, markdown_output_path=output)

    def test_remote_target_requires_runtime_flag_before_any_request(self) -> None:
        directory = Path(self.temp_dir.name)
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["target"].update(
            {
                "base_url": "https://staging.example.test",
                "allowed_hosts": ["staging.example.test"],
                "allow_remote": True,
                "allowed_ports": [443],
            }
        )
        scenario = directory / "remote.yaml"
        scenario.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "requires the --allow-remote flag"):
            run_scenarios(SPEC, scenario, directory / "report.json")


if __name__ == "__main__":
    unittest.main()
