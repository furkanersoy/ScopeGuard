"""Malformed lockfile and OSV-data handling tests."""

from __future__ import annotations

import unittest

from scopeguard.dependency_scan import (
    _fixed_versions,
    _parse_npm_lock,
    _parse_pipfile_lock,
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


if __name__ == "__main__":
    unittest.main()
