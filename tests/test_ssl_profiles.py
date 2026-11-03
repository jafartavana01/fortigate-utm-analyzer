"""Regression tests for complete SSL/SSH inspection profile enumeration."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import utm


class SSLProfileParserTests(unittest.TestCase):
    def test_two_flat_profiles_in_one_block(self):
        config = """config firewall ssl-ssh-profile
    edit "certificate-only"
        set inspection-method certificate-inspection
    next
    edit "deep-no-ca"
        set inspection-method deep-inspection
    next
end
"""
        profiles = utm.parse_ssl_profiles_v2(config)
        self.assertEqual([p["_id"] for p in profiles],
                         ["certificate-only", "deep-no-ca"])
        self.assertTrue(any("certificate-only" in f for f in utm.ssl_profile_weaknesses(profiles[0])))
        self.assertTrue(any("deep-no-ca" in f for f in utm.ssl_profile_weaknesses(profiles[1])))

    def test_nested_exempt_rows_are_not_profiles(self):
        config = """config firewall ssl-ssh-profile
    edit "profile-1"
        config ssl-exempt
            edit 1
                set type wildcard-fqdn
                set wildcard-fqdn "*.example.com"
            next
            edit 2
                set type address
                set address "internal"
            next
        end
        config https
            set status deep-inspection
            set untrusted-server-cert block
        end
        set ssl-anomalies-log enable
    next
    edit "profile-2"
        config https
            set status certificate-inspection
        end
    next
end
"""
        profiles = utm.parse_ssl_profiles_v2(config)
        self.assertEqual([p["_id"] for p in profiles], ["profile-1", "profile-2"])
        self.assertEqual(profiles[0]["https.status"], "deep-inspection")
        self.assertEqual(profiles[1]["https.status"], "certificate-inspection")
        self.assertEqual(profiles[0]["ssl-anomalies-log"], "enable")

    def test_protocol_settings_stay_in_correct_profile(self):
        config = """config firewall ssl-ssh-profile
    edit "alpha"
        config https
            set status deep-inspection
        end
        config ssh
            set inspect-all enable
        end
    next
    edit "beta"
        config https
            set status disable
        end
    next
end
"""
        profiles = utm.parse_ssl_profiles_v2(config)
        self.assertEqual(len(profiles), 2)
        self.assertEqual(profiles[0]["https.status"], "deep-inspection")
        self.assertEqual(profiles[0]["ssh.inspect-all"], "enable")
        self.assertEqual(profiles[1]["https.status"], "disable")
        self.assertNotIn("ssh.inspect-all", profiles[1])

    def test_all_repeated_blocks_across_vdoms(self):
        config = """config vdom
    edit "root"
        config firewall ssl-ssh-profile
            edit "root-profile"
                set inspection-method certificate-inspection
            next
        end
    next
    edit "branch"
        config firewall ssl-ssh-profile
            edit "branch-profile"
                set inspection-method deep-inspection
            next
        end
    next
end
"""
        profiles = utm.parse_ssl_profiles_v2(config)
        self.assertEqual([p["_id"] for p in profiles], ["root-profile", "branch-profile"])

    def test_empty_and_adjacent_sections(self):
        config = """config firewall ssl-ssh-profile
end
config firewall ssl-ssh-profile
    edit "last"
        set inspection-method certificate-inspection
    next
end
"""
        self.assertEqual([p["_id"] for p in utm.parse_ssl_profiles_v2(config)], ["last"])

    def test_cli_generates_report_and_html_for_all_profiles(self):
        config = """config firewall ssl-ssh-profile
    edit "first"
        config ssl-exempt
            edit 1
                set type address
                set address "trusted"
            next
        end
        set inspection-method certificate-inspection
    next
    edit "second"
        set inspection-method deep-inspection
    next
end
config firewall ssl-ssh-profile
    edit "third"
        set inspection-method certificate-inspection
    next
end
"""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_file = root / "multiple.cfg"
            config_file.write_text(config, encoding="utf-8")
            run = subprocess.run(
                [sys.executable, str(ROOT / "utm.py"), "-c", str(config_file),
                 "-i", "--summary", "--html"],
                cwd=temp, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            output = root / "multiple"
            report = (output / "multiple.cfg_ssl_inspection_report.txt").read_text(encoding="utf-8")
            self.assertIn("Profiles found: 3", report)
            for name in ("first", "second", "third"):
                self.assertIn("SSL/SSH Profile: " + name, report)
            data = json.loads((output / "multiple.cfg_SUMMARY.json").read_text(encoding="utf-8"))
            for name in ("first", "second", "third"):
                self.assertTrue(any(name in text for text in data["findings"]["SSL Inspection"]))
            self.assertTrue((output / "multiple.cfg_REPORT.html").exists())


if __name__ == "__main__":
    unittest.main()
