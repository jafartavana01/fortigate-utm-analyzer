"""Regression coverage for report output directory routing (standard library only)."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "utm.py"
SAMPLE = ROOT / "sample_config.conf"
BASE = SAMPLE.name


class OutputDirectoryTests(unittest.TestCase):
    def run_analyzer(self, cwd, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "-c", str(SAMPLE), *args],
            cwd=cwd, capture_output=True, text=True,
        )

    def test_all_report_formats_use_nested_output_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            destination = root / "reports" / "FW01"
            result = self.run_analyzer(root, "--all", "--html",
                                       "--out-dir", str(destination))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(destination.is_dir())
            produced = {p.name for p in destination.iterdir()}
            self.assertIn(BASE + "_SUMMARY.txt", produced)
            self.assertIn(BASE + "_SUMMARY.json", produced)
            self.assertIn(BASE + "_REPORT.html", produced)
            self.assertIn(BASE + "_firewall_policy_report.txt", produced)
            self.assertFalse([p for p in root.iterdir() if p.is_file()])
            summary = json.loads((destination / (BASE + "_SUMMARY.json")).read_text())
            self.assertEqual(summary["summary"]["total"], 310)

    def test_alias_accepts_relative_output_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.run_analyzer(root, "-f", "--summary",
                                       "--output-dir", "custom/reports")
            self.assertEqual(result.returncode, 0, result.stderr)
            destination = root / "custom" / "reports"
            self.assertTrue((destination / (BASE + "_firewall_policy_report.txt")).is_file())
            self.assertTrue((destination / (BASE + "_SUMMARY.txt")).is_file())
            self.assertTrue((destination / (BASE + "_SUMMARY.json")).is_file())

    def test_invalid_output_directory_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            non_directory = root / "already-a-file"
            non_directory.write_text("not a directory", encoding="utf-8")
            result = self.run_analyzer(root, "-f", "--out-dir", str(non_directory))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Cannot create output directory", result.stderr)
            self.assertEqual(non_directory.read_text(encoding="utf-8"), "not a directory")
            self.assertFalse(list(root.glob(BASE + "*")))

    def test_default_still_writes_in_working_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.run_analyzer(root, "-f", "--summary")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / (BASE + "_firewall_policy_report.txt")).is_file())
            self.assertTrue((root / (BASE + "_SUMMARY.json")).is_file())


if __name__ == "__main__":
    unittest.main()
