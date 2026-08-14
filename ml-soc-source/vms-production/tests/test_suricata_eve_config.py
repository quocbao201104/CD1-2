import importlib.util
import sys
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "suricata_eve_config.py"
SPEC = importlib.util.spec_from_file_location("suricata_eve_config", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class SuricataEveConfigTests(unittest.TestCase):
    def test_disables_only_eve_stats_output(self):
        source = """stats:
  enabled: yes
  interval: 8
outputs:
  - eve-log:
      enabled: yes
      types:
        - alert
        - anomaly:
            types:
              applayer: yes
        - stats:
            totals: yes
            threads: no
            deltas: no
        - flow
app-layer:
  protocols:
    - stats:
        enabled: yes
"""
        expected = """stats:
  enabled: yes
  interval: 8
outputs:
  - eve-log:
      enabled: yes
      types:
        - alert
        - anomaly:
            types:
              applayer: yes
        # stats output disabled: Wazuh JSON decoder field limit
        - flow
app-layer:
  protocols:
    - stats:
        enabled: yes
"""

        result, changed = MODULE.disable_eve_stats_output(source)

        self.assertTrue(changed)
        self.assertEqual(expected, result)

    def test_second_application_is_idempotent(self):
        source = """outputs:
  - eve-log:
      enabled: yes
      types:
        - alert
        # stats output disabled: Wazuh JSON decoder field limit
        - flow
"""

        result, changed = MODULE.disable_eve_stats_output(source)

        self.assertFalse(changed)
        self.assertEqual(source, result)


if __name__ == "__main__":
    unittest.main()
