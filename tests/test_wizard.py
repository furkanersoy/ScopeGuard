"""Regression tests for the interactive scenario initializer."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scopeguard.config import ValidationError
from scopeguard.wizard import run_init_wizard

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "examples" / "api" / "openapi.yaml"


class InitWizardTests(unittest.TestCase):
    def test_rejects_malformed_base_url_as_validation_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scenario.yaml"
            with patch("builtins.input", return_value="http://[::1"):
                with self.assertRaisesRegex(ValidationError, "base URL is malformed"):
                    run_init_wizard(SPEC, output)
            self.assertFalse(output.exists())

    def test_force_never_overwrites_openapi_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = Path(directory) / "openapi.yaml"
            spec.write_text(SPEC.read_text(encoding="utf-8"), encoding="utf-8")
            before = spec.read_bytes()
            with self.assertRaisesRegex(ValidationError, "must not overwrite the OpenAPI document"):
                run_init_wizard(spec, spec, force=True)
            self.assertEqual(spec.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
