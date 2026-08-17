import unittest
from unittest.mock import patch

from app.correlation import reset
from app.main import _pipeline


def event(source, description, ip=None):
    return {
        "source": source,
        "server": "vms-production",
        "related_ip": ip,
        "timestamp": "2026-08-16T10:00:00+07:00",
        "description": description,
        "raw": {"full_log": "", "rule_id": "test", "rule_level": 10},
    }


ML_RESULT = {
    "model": "IsolationForest",
    "anomaly_score": 0,
    "is_anomaly": False,
    "risk_delta": 0,
}


class CorrelationPipelineTests(unittest.TestCase):
    def setUp(self):
        reset()

    def tearDown(self):
        reset()

    @patch("app.main.policy_engine", return_value=[])
    @patch("app.main.notify")
    @patch("app.main.evaluate_anomaly", return_value=ML_RESULT)
    def test_web_os_pipeline_returns_medium_investigation_score(
        self, _ml, _notify, _policy
    ):
        _pipeline(event("web", "WEB: Directory traversal attempt", "192.168.245.40"))
        result = _pipeline(event("os", "SOC: Web root file modified"))

        self.assertEqual("Suspected Web Compromise", result["incident_type"])
        self.assertEqual("medium", result["correlation"]["confidence"])
        self.assertEqual("unknown", result["correlation"]["src_ip_match"])
        self.assertEqual(70, result["base_risk_score"])
        self.assertNotEqual(100, result["base_risk_score"])
        self.assertNotIn("T1505.003", result["mitre"])

    @patch("app.main.policy_engine", return_value=[])
    @patch("app.main.notify")
    @patch("app.main.evaluate_anomaly", return_value=ML_RESULT)
    def test_matching_network_web_ips_upgrade_to_high_full_chain(
        self, _ml, _notify, _policy
    ):
        _pipeline(event("network", "Suricata: ET SCAN Nmap", "192.168.245.40"))
        _pipeline(event("web", "WEB: Directory traversal attempt", "192.168.245.40"))
        result = _pipeline(event("os", "SOC: /var/www/html/shell.php modified"))

        self.assertEqual("Possible Server Compromise", result["incident_type"])
        self.assertEqual("high", result["correlation"]["confidence"])
        self.assertEqual("true", result["correlation"]["src_ip_match"])
        self.assertEqual(100, result["base_risk_score"])
        self.assertIn("T1046", result["mitre"])
        self.assertNotIn("T1505.003", result["mitre"])

    @patch("app.main.policy_engine", return_value=[])
    @patch("app.main.notify")
    @patch("app.main.evaluate_anomaly", return_value=ML_RESULT)
    def test_mismatched_network_web_ips_do_not_receive_high_tier(
        self, _ml, _notify, _policy
    ):
        _pipeline(event("network", "Suricata: ET SCAN Nmap", "192.168.245.41"))
        _pipeline(event("web", "WEB: Directory traversal attempt", "192.168.245.40"))
        result = _pipeline(event("os", "SOC: Web root file modified"))

        self.assertEqual("Suspected Web Compromise", result["incident_type"])
        self.assertEqual("medium", result["correlation"]["confidence"])
        self.assertEqual("false", result["correlation"]["src_ip_match"])
        self.assertEqual(70, result["base_risk_score"])
        self.assertNotIn("T1046", result["mitre"])

    @patch("app.main.policy_engine", return_value=[])
    @patch("app.main.notify")
    @patch(
        "app.main.evaluate_anomaly",
        return_value={**ML_RESULT, "risk_delta": 10},
    )
    def test_medium_chain_keeps_event_ip_empty_and_caps_ml_adjusted_score(
        self, _ml, _notify, _policy
    ):
        _pipeline(event("network", "Suricata: ET SCAN Nmap", "192.168.245.157"))
        _pipeline(event("web", "WEB: Directory traversal attempt", None))
        result = _pipeline(event("os", "SOC: /var/www/html/shell.php modified"))

        self.assertEqual("Suspected Web Compromise", result["incident_type"])
        self.assertEqual("medium", result["correlation"]["confidence"])
        self.assertIsNone(result["srcip"])
        self.assertEqual("192.168.245.157", result["correlation"]["observed_ips"]["network"])
        self.assertIsNone(result["correlation"]["observed_ips"]["web"])
        self.assertEqual(70, result["base_risk_score"])
        self.assertEqual(9, result["ml"]["risk_delta_applied"])
        self.assertEqual(79, result["risk_score"])


if __name__ == "__main__":
    unittest.main()
