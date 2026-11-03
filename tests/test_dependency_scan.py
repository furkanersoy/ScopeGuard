"""Malformed lockfile and OSV-data handling tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopeguard.config import ValidationError
from scopeguard.dependency_scan import (
    _fixed_versions,
    _parse_npm_lock,
    _parse_pipfile_lock,
    validate_dependency_outputs,
)


class DependencyInputTests(unittest.TestCase):
    def test_pipfile_lock_rejects_non_object_json(self) -> None:
        with self.assertRaisesRegex(ValueError, "Pipfile.lock must contain a JSON object"):
            _parse_pipfile_lock("[]", "Pipfile.lock", {})

    def test_npm_lock_rejects_non_object_json(self) -> None:
        with self.assertRaisesRegex(ValueError, "npm lockfile must contain a JSON object"):
            _parse_npm_lock("[]", "package-lock.json", {})

    def test_fixed_version_parser_ignores_malformed_nested_data(self) -> None:
        vulnerability = {
            "affected": [None, {"package": [], "ranges": {}},
                         {"package": {"name": "demo"}, "ranges": [None, {"events": {}}]}]
        }
        self.assertEqual(_fixed_versions(vulnerability, "demo"), [])

    def test_report_cannot_overwrite_manifest_in_dependency_scan_folder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "package.json"
            original = '{"name":"demo","dependencies":{}}\n'
            manifest.write_text(original, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "must not overwrite a file in the scan path"):
                validate_dependency_outputs(root, [manifest])
            self.assertEqual(manifest.read_text(encoding="utf-8"), original)

    def test_existing_scopeguard_dependency_report_can_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "scopeguard-dependencies.json"
            output.write_text(
                '{"tool":"ScopeGuard","mode":"online-dependency-audit","scanned_files":1,"checks":["dependencies"],"findings":[]}\n',
                encoding="utf-8",
            )
            validate_dependency_outputs(root, [output])


if __name__ == "__main__":
    unittest.main()
