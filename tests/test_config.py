"""Unit tests for offline input validation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from scopeguard.config import ValidationError, validate_inputs

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "examples" / "api" / "openapi.yaml"
SCENARIO = ROOT / "examples" / "scenarios" / "local-demo.yaml"


class ConfigValidationTests(unittest.TestCase):
    def test_repository_example_is_valid(self) -> None:
        self.assertEqual(validate_inputs(SPEC, SCENARIO), 4)

    def test_rejects_remote_target_without_config_opt_in(self) -> None:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["target"]["base_url"] = "https://example.com"
        config["target"]["allowed_hosts"] = ["example.com"]
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.yaml"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "target.allow_remote: true"):
                validate_inputs(SPEC, scenario)

    def test_rejects_unknown_operation(self) -> None:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["checks"][1]["operation"] = "GET /not-in-the-spec"
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.yaml"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "missing from the OpenAPI"):
                validate_inputs(SPEC, scenario)

    def test_rejects_non_get_check(self) -> None:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["checks"][1]["operation"] = "POST /records/{record_id}"
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.yaml"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "must use a GET"):
                validate_inputs(SPEC, scenario)

    def test_rejects_path_parameter_mismatch(self) -> None:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["checks"][1]["path"] = {"other_id": "record-a"}
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.yaml"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "path parameters must match"):
                validate_inputs(SPEC, scenario)

    def test_rejects_invalid_json_pointer(self) -> None:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["checks"][2]["assert_json"] = [{"pointer": "/owner/~2", "not_equals": "user-a"}]
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.yaml"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "valid non-root JSON Pointer"):
                validate_inputs(SPEC, scenario)

    def test_remote_target_requires_explicit_https_host_and_port_allowlist(self) -> None:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["target"].update(
            {
                "base_url": "https://staging.example.test",
                "allowed_hosts": ["staging.example.test"],
                "allow_remote": True,
                "allowed_ports": [443],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.yaml"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            self.assertEqual(validate_inputs(SPEC, scenario), 4)

    def test_rejects_remote_target_without_opt_in(self) -> None:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["target"].update(
            {"base_url": "https://staging.example.test", "allowed_hosts": ["staging.example.test"]}
        )
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.yaml"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "target.allow_remote: true"):
                validate_inputs(SPEC, scenario)

    def test_rejects_remote_http_and_unlisted_port(self) -> None:
        config = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
        config["target"].update(
            {
                "base_url": "http://staging.example.test:8080",
                "allowed_hosts": ["staging.example.test"],
                "allow_remote": True,
                "allowed_ports": [443],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            scenario = Path(directory) / "scenario.yaml"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "must use HTTPS"):
                validate_inputs(SPEC, scenario)

            config["target"]["base_url"] = "https://staging.example.test:8443"
            scenario.write_text(yaml.safe_dump(config), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "port is not listed"):
                validate_inputs(SPEC, scenario)


if __name__ == "__main__":
    unittest.main()
