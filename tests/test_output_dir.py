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
    def run_analyzer(self, cwd, *args, config=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "-c", str(config or SAMPLE), *args],
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
            self.assertFalse((root / SAMPLE.stem).exists())
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

    def test_default_creates_input_stem_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.run_analyzer(root, "-f", "--summary")
            self.assertEqual(result.returncode, 0, result.stderr)
            destination = root / SAMPLE.stem
            self.assertTrue(destination.is_dir())
            self.assertTrue((destination / (BASE + "_firewall_policy_report.txt")).is_file())
            self.assertTrue((destination / (BASE + "_SUMMARY.json")).is_file())
            self.assertFalse((root / (BASE + "_SUMMARY.json")).exists())

    def test_default_for_cfg_filename_includes_html(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "firewal_001.cfg"
            config.write_bytes(SAMPLE.read_bytes())
            result = self.run_analyzer(root, "-f", "--summary", "--html", config=config)
            self.assertEqual(result.returncode, 0, result.stderr)
            destination = root / "firewal_001"
            self.assertTrue(destination.is_dir())
            self.assertTrue((destination / "firewal_001.cfg_firewall_policy_report.txt").is_file())
            self.assertTrue((destination / "firewal_001.cfg_SUMMARY.txt").is_file())
            self.assertTrue((destination / "firewal_001.cfg_SUMMARY.json").is_file())
            self.assertTrue((destination / "firewal_001.cfg_REPORT.html").is_file())
            self.assertFalse((root / "firewal_001.cfg_REPORT.html").exists())

    def test_explicit_dot_keeps_output_in_working_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = self.run_analyzer(root, "-f", "--summary", "--out-dir", ".")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / (BASE + "_firewall_policy_report.txt")).is_file())
            self.assertTrue((root / (BASE + "_SUMMARY.json")).is_file())
            self.assertFalse((root / SAMPLE.stem).exists())


if __name__ == "__main__":
    unittest.main()
