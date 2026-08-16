from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


RULES_PATH = Path(__file__).resolve().parents[1] / "local_rules.xml"


class LocalRulesTests(unittest.TestCase):
    def test_suspicious_web_file_is_child_of_webroot_rule(self):
        root = ET.parse(RULES_PATH).getroot()
        rule = next(item for item in root.findall("rule") if item.get("id") == "100203")

        self.assertEqual("100202", rule.findtext("if_sid"))
        self.assertIsNone(rule.find("if_group"))
        self.assertIn("shell", rule.findtext("match") or "")

    def test_suricata_nmap_scan_is_elevated_for_vm3_integration(self):
        root = ET.parse(RULES_PATH).getroot()
        rule = next(item for item in root.findall("rule") if item.get("id") == "100106")

        self.assertEqual("10", rule.get("level"))
        self.assertEqual("86601", rule.findtext("if_sid"))
        self.assertRegex(rule.findtext("match") or "", r"ET SCAN|Nmap|port scan")
        self.assertIn("T1046", rule.findtext("mitre/id") or "")


if __name__ == "__main__":
    unittest.main()
