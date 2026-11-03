"""Safety tests for local inspection report outputs."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scopeguard.config import ValidationError
from scopeguard.local_scan import inspect_path, write_local_reports


class LocalScanOutputTests(unittest.TestCase):
    def test_report_cannot_overwrite_source_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "settings.yaml"
            original = "debug: true\n"
            source.write_text(original, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "must not overwrite a file being inspected"):
                inspect_path(root, ["config"], output_paths=[source])
            self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_existing_scopeguard_reports_can_be_replaced_on_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            report_path = root / "scopeguard.json"
            report = inspect_path(root, ["python"])
            write_local_reports(report, report_path)
            rerun = inspect_path(root, ["python"], output_paths=[report_path])
            self.assertEqual(rerun["scanned_files"], 1)
            write_local_reports(rerun, report_path)


if __name__ == "__main__":
    unittest.main()
