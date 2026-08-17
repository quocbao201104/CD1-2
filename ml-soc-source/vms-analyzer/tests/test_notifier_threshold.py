import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.notifier import _format, _gotify_priority, notify


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


def correlation(*, sources, confidence, ip_match, ips, has_network):
    return {
        "sources": sources,
        "confidence": confidence,
        "src_ip_match": ip_match,
        "observed_ips": ips,
        "has_network_precursor": has_network,
    }


def high_correlation_result():
    result = result_with_risk(100)
    result.update(
        {
            "severity": "Critical",
            "incident_type": "Possible Server Compromise",
            "base_risk_score": 90,
            "mitre": "T1046/T1190/T1505.003",
            "correlated": True,
            "correlation": correlation(
                sources=["network", "web", "os"],
                confidence="high",
                ip_match="true",
                ips={
                    "network": "192.168.245.40",
                    "web": "192.168.245.40",
                    "os": None,
                },
                has_network=True,
            ),
        }
    )
    return result


class GotifyThresholdTests(unittest.TestCase):
    def test_high_full_chain_uses_analysis_label_and_vietnamese_evidence(self):
        result = high_correlation_result()
        result.update(
            {
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
        self.assertIn("ML đề xuất: +10; áp dụng vào điểm: +10", text)
        self.assertIn("Bất thường: Có", text)
        self.assertIn("Nhãn phân tích: Possible Server Compromise", text)
        self.assertIn("Nguồn bằng chứng: Mạng → Web → Hệ điều hành", text)
        self.assertIn("Độ tin cậy: Cao", text)
        self.assertIn("Liên kết IP nguồn (Network/Web): Khớp", text)
        self.assertIn("Chuỗi đầy đủ Mạng → Web → Hệ điều hành được quan sát.", text)
        self.assertNotIn("cùng tác nhân", text.lower())
        self.assertIn("KHUYẾN NGHỊ XỬ LÝ", text)

    def test_suspected_web_compromise_without_network_is_not_confirmed(self):
        result = result_with_risk(70)
        result.update(
            {
                "incident_type": "Suspected Web Compromise",
                "correlated": True,
                "correlation": correlation(
                    sources=["web", "os"],
                    confidence="medium",
                    ip_match="unknown",
                    ips={"network": None, "web": "192.168.245.40", "os": None},
                    has_network=False,
                ),
            }
        )

        text = _format(result)

        self.assertIn("Nhãn phân tích: Suspected Web Compromise", text)
        self.assertIn("Độ tin cậy: Trung bình", text)
        self.assertIn("Liên kết IP nguồn (Network/Web): Không đủ dữ liệu", text)
        self.assertIn("Không quan sát network precursor", text)
        self.assertIn("chưa khẳng định máy chủ đã bị xâm nhập", text)

    def test_suspected_web_compromise_with_unlinked_precursor_is_factual(self):
        result = result_with_risk(70)
        result.update(
            {
                "incident_type": "Suspected Web Compromise",
                "correlated": True,
                "correlation": correlation(
                    sources=["network", "web", "os"],
                    confidence="medium",
                    ip_match="false",
                    ips={
                        "network": "192.168.245.41",
                        "web": "192.168.245.40",
                        "os": None,
                    },
                    has_network=True,
                ),
            }
        )

        text = _format(result)

        self.assertIn("Liên kết IP nguồn (Network/Web): Không khớp", text)
        self.assertIn("Có quan sát network precursor", text)
        self.assertIn("không quy kết các sự kiện cho cùng tác nhân", text)
        self.assertNotIn("Không quan sát network precursor", text)

    def test_correlation_output_separates_target_host_event_ip_and_missing_ip_semantics(self):
        result = result_with_risk(79)
        result.update(
            {
                "server_ip": "192.168.245.10",
                "srcip": None,
                "incident_type": "Suspected Web Compromise",
                "correlated": True,
                "correlation": {
                    **correlation(
                        sources=["network", "web", "os"],
                        confidence="medium",
                        ip_match="unknown",
                        ips={"network": "192.168.245.157", "web": None, "os": None},
                        has_network=True,
                    ),
                    "precursor_incidents": ["Network Port Scan", "Web Traversal Attempt"],
                    "current_incident": "Suspicious Web File",
                },
                "ml": {**result["ml"], "risk_delta": 10, "risk_delta_applied": 9},
            }
        )

        text = _format(result)

        self.assertIn("IP máy chủ: 192.168.245.10", text)
        self.assertIn("IP nguồn alert hiện tại: Chưa ghi nhận", text)
        self.assertIn("Mạng=192.168.245.157", text)
        self.assertIn("Web=Chưa ghi nhận IP nguồn", text)
        self.assertIn("OS/FIM=Không áp dụng", text)
        self.assertIn("Sự kiện đã quan sát: Network Port Scan → Web Traversal Attempt → Suspicious Web File", text)
        self.assertIn("ML đề xuất: +10; áp dụng vào điểm: +9", text)

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

    def test_vietnamese_template_and_incident_record_are_strict_utf8(self):
        text = _format(high_correlation_result())
        self.assertEqual(text, text.encode("utf-8").decode("utf-8"))
        self.assertNotIn("\ufffd", text)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incidents.md"
            notify(high_correlation_result(), md_path=str(path))
            persisted = path.read_bytes().decode("utf-8")

        self.assertIn("Nhãn phân tích", persisted)
        self.assertIn("Mạng → Web → Hệ điều hành", persisted)

    def test_gotify_priority_and_threshold_policy_are_unchanged(self):
        self.assertEqual(10, _gotify_priority({"severity": "Critical"}))
        self.assertEqual(8, _gotify_priority({"severity": "High"}))
        self.assertEqual(5, _gotify_priority({"severity": "Medium"}))
        self.assertEqual(3, _gotify_priority({"severity": "Low"}))


if __name__ == "__main__":
    unittest.main()
