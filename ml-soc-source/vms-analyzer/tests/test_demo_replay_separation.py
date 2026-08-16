import unittest
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parents[3]


def _script_path(name: str) -> Path:
    """Find lab demo scripts in a VM home directory or the source workspace."""
    home_copy = Path.home() / name
    return home_copy if home_copy.is_file() else WORKSPACE / name


DEMO_SCRIPT = _script_path("ThucThi_Demo_CD2.sh")
REPLAY_SCRIPT = _script_path("KiemThu_Replay_Correlation_CD2.sh")


class DemoReplaySeparationTests(unittest.TestCase):
    def test_main_demo_script_has_no_replay_correlation_stage(self):
        content = DEMO_SCRIPT.read_text(encoding="utf-8")

        self.assertNotIn("correlation) stage_correlation", content)
        self.assertNotIn("post_sample network_port_scan.json", content)

    def test_replay_is_explicitly_isolated_from_live_demo(self):
        content = REPLAY_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("REPLAY ONLY", content)
        self.assertIn("KHÔNG PHẢI LUỒNG LIVE", content)
        self.assertIn("network_port_scan.json", content)


if __name__ == "__main__":
    unittest.main()
