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


if __name__ == "__main__":
    unittest.main()
