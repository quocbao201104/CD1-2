import unittest

from app.correlation import correlate, remember, reset


class ThreeStageCorrelationTests(unittest.TestCase):
    def setUp(self):
        reset()

    def tearDown(self):
        reset()

    def test_network_and_web_alone_do_not_trigger_compromise(self):
        remember("network", "vms-production", "Network Port Scan", "192.168.245.40")

        self.assertIsNone(correlate("web", "vms-production"))

    def test_web_and_os_without_network_triggers_medium_investigation_chain(self):
        remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

        result = correlate(
            "os",
            "vms-production",
            current_incident="Web Root Modified",
        )

        self.assertTrue(result["correlated"])
        self.assertEqual("Suspected Web Compromise", result["incident_type"])
        self.assertEqual("medium", result["confidence"])
        self.assertEqual(["web", "os"], result["sources"])
        self.assertFalse(result["has_network_precursor"])
        self.assertEqual("unknown", result["src_ip_match"])
        self.assertEqual(
            {"network": None, "web": "192.168.245.40", "os": None},
            result["observed_ips"],
        )

    def test_network_after_web_does_not_upgrade_web_os_to_high(self):
        remember("web", "vms-production", "Web Sensitive Path Scan", "192.168.245.40")
        remember("network", "vms-production", "Network Port Scan", "192.168.245.40")

        result = correlate("os", "vms-production")

        self.assertEqual("Suspected Web Compromise", result["incident_type"])
        self.assertEqual("medium", result["confidence"])
        self.assertFalse(result["has_network_precursor"])

    def test_events_from_different_servers_do_not_trigger_compromise(self):
        remember("network", "server-a", "Network Port Scan", "192.168.245.40")
        remember("web", "server-b", "Web Traversal Attempt", "192.168.245.40")

        self.assertIsNone(correlate("os", "server-a"))

    def test_network_web_os_on_same_server_triggers_compromise(self):
        remember("network", "vms-production", "Network Port Scan", "192.168.245.40")
        remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

        result = correlate(
            "os",
            "vms-production",
            current_incident="Suspicious Web File",
        )

        self.assertIsNotNone(result)
        self.assertTrue(result["correlated"])
        self.assertEqual("Possible Server Compromise", result["incident_type"])
        self.assertEqual("high", result["confidence"])
        self.assertEqual(["network", "web", "os"], result["sources"])
        self.assertTrue(result["has_network_precursor"])
        self.assertEqual("true", result["src_ip_match"])
        self.assertGreaterEqual(result["time_delta_network_to_os"], 0)

    def test_missing_network_or_web_ip_keeps_chain_medium(self):
        remember("network", "vms-production", "Network Port Scan", None)
        remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

        result = correlate(
            "os",
            "vms-production",
            current_incident="Web Root Modified",
        )

        self.assertEqual("Suspected Web Compromise", result["incident_type"])
        self.assertEqual("medium", result["confidence"])
        self.assertEqual("unknown", result["src_ip_match"])
        self.assertTrue(result["has_network_precursor"])
        self.assertEqual(["network", "web", "os"], result["sources"])

    def test_mismatched_network_and_web_ips_keep_chain_medium(self):
        remember("network", "vms-production", "Network Port Scan", "192.168.245.41")
        remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

        result = correlate(
            "os",
            "vms-production",
            current_incident="Web Root Modified",
        )

        self.assertEqual("Suspected Web Compromise", result["incident_type"])
        self.assertEqual("medium", result["confidence"])
        self.assertEqual("false", result["src_ip_match"])
        self.assertEqual("192.168.245.41", result["observed_ips"]["network"])
        self.assertEqual("192.168.245.40", result["observed_ips"]["web"])


if __name__ == "__main__":
    unittest.main()
