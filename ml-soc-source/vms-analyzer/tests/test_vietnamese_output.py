import unittest

from app.explainer import ai_explain
from app.playbook import playbook_for


class VietnameseOutputTests(unittest.TestCase):
    def test_explanation_uses_vietnamese_diacritics(self):
        text = ai_explain(
            {"srcip": "192.168.245.40", "agent_name": "vms-production"},
            "Web Traversal Attempt",
            90,
            {"model": "IsolationForest", "is_anomaly": True, "anomaly_score": 100},
        )

        self.assertIn("Phát hiện dấu hiệu", text)
        self.assertIn("Khuyến nghị", text)
        self.assertIn("ML cục bộ", text)
        self.assertIn("bất thường", text)

    def test_playbook_uses_vietnamese_diacritics(self):
        steps = playbook_for("Possible Server Compromise")

        self.assertIn("Tổng hợp dòng thời gian", steps[0])
        self.assertTrue(any("máy chủ" in step for step in steps))
        self.assertTrue(any("sự cố" in step for step in steps))


if __name__ == "__main__":
    unittest.main()
