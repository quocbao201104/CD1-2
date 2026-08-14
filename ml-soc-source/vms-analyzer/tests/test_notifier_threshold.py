import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.notifier import _format, notify


def result_with_risk(risk):
    return {
        "severity": "High" if risk >= 60 else "Low",
        "incident_type": "Test Incident",
        "agent": "vms-production",
        "srcip": "192.168.245.40",
        "risk_score": risk,
        "base_risk_score": risk,
        "mitre": None,
        "ml": {
            "model": "IsolationForest",
            "anomaly_score": 0,
            "is_anomaly": False,
            "risk_delta": 0,
        },
        "correlated": False,
        "analysis": "Test notification threshold",
        "playbook": ["Verify event"],
    }


class GotifyThresholdTests(unittest.TestCase):
    def test_message_uses_readable_vietnamese_sections(self):
        result = result_with_risk(100)
        result.update(
            {
                "severity": "Critical",
                "incident_type": "Possible Server Compromise",
                "base_risk_score": 90,
                "mitre": "T1190/T1505.003",
                "correlated": True,
                "analysis": "Phát hiện chuỗi hành vi bất thường trên máy chủ.",
                "playbook": ["Kiểm tra dòng thời gian", "Cô lập file nghi vấn"],
            }
        )
        result["ml"].update(
            {"anomaly_score": 100, "is_anomaly": True, "risk_delta": 10}
        )

        text = _format(result)

        self.assertIn("🚨 CẢNH BÁO BẢO MẬT", text)
        self.assertIn("Mức độ: Nghiêm trọng (Critical)", text)
        self.assertIn("Điểm theo luật: 90/100", text)
        self.assertIn("ML bổ sung: +10", text)
        self.assertIn("Bất thường: Có", text)
        self.assertIn("network → web → os", text)
        self.assertIn("KHUYẾN NGHỊ XỬ LÝ", text)

    @patch("app.notifier.requests.post")
    def test_low_risk_is_recorded_but_not_sent_to_gotify(self, post):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "incidents.md")
            with patch.dict(
                os.environ,
                {
                    "GOTIFY_URL": "http://127.0.0.1:8080",
                    "GOTIFY_APP_TOKEN": "test-app-token",
                    "GOTIFY_MIN_RISK": "60",
                },
                clear=False,
            ):
                notify(result_with_risk(30), md_path=path)

            post.assert_not_called()
            self.assertIn("Tổng điểm: 30/100", Path(path).read_text(encoding="utf-8"))

    @patch("app.notifier.requests.post")
    def test_high_risk_is_sent_to_gotify_with_utf8_json(self, post):
        post.return_value.raise_for_status.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "incidents.md")
            with patch.dict(
                os.environ,
                {
                    "GOTIFY_URL": "http://127.0.0.1:8080/",
                    "GOTIFY_APP_TOKEN": "test-app-token",
                    "GOTIFY_MIN_RISK": "60",
                },
                clear=False,
            ):
                text = notify(result_with_risk(60), md_path=path)

            post.assert_called_once_with(
                "http://127.0.0.1:8080/message",
                headers={"X-Gotify-Key": "test-app-token"},
                json={
                    "title": "⚠️ CẢNH BÁO BẢO MẬT",
                    "message": text,
                    "priority": 8,
                },
                timeout=5,
            )


if __name__ == "__main__":
    unittest.main()
