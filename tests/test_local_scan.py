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
            original = "debug: true\\n"
            source.write_text(original, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "must not overwrite a file being inspected"):
                inspect_path(root, ["config"], output_paths=[source])
            self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_scopeguard_readme_is_not_mistaken_for_a_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            readme = root / "README.md"
            original = "# ScopeGuard\\nProject documentation.\\n"
            readme.write_text(original, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "must not overwrite a file being inspected"):
                inspect_path(root, ["secrets"], output_paths=[readme])
            self.assertEqual(readme.read_text(encoding="utf-8"), original)

    def test_scopeguard_html_page_is_not_mistaken_for_a_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            page = root / "index.html"
            original = "<!doctype html><title>ScopeGuard docs</title><p>Project page</p>"
            page.write_text(original, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "must not overwrite a file being inspected"):
                inspect_path(root, ["secrets"], output_paths=[page])
            self.assertEqual(page.read_text(encoding="utf-8"), original)

    def test_existing_scopeguard_reports_can_be_replaced_on_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app.py"
            source.write_text("print('ok')\\n", encoding="utf-8")
            report_path = root / "scopeguard.json"
            markdown_path = root / "scopeguard.md"
            sarif_path = root / "scopeguard.sarif"
            html_path = root / "scopeguard.html"
            report = inspect_path(root, ["python"])
            write_local_reports(report, report_path, markdown_path, sarif_path, html_path)
            outputs = [report_path, markdown_path, sarif_path, html_path]
            rerun = inspect_path(root, ["python"], output_paths=outputs)
            self.assertEqual(rerun["scanned_files"], 1)
            write_local_reports(rerun, *outputs)


if __name__ == "__main__":
    unittest.main()
