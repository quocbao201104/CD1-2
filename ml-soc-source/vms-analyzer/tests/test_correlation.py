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

    def test_web_and_os_without_network_do_not_trigger_compromise(self):
        remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

        self.assertIsNone(correlate("os", "vms-production"))

    def test_wrong_order_does_not_trigger_compromise(self):
        remember("web", "vms-production", "Web Sensitive Path Scan", "192.168.245.40")
        remember("network", "vms-production", "Network Port Scan", "192.168.245.40")

        self.assertIsNone(correlate("os", "vms-production"))

    def test_events_from_different_servers_do_not_trigger_compromise(self):
        remember("network", "server-a", "Network Port Scan", "192.168.245.40")
        remember("web", "server-b", "Web Traversal Attempt", "192.168.245.40")

        self.assertIsNone(correlate("os", "server-a"))

    def test_network_web_os_on_same_server_triggers_compromise(self):
        remember("network", "vms-production", "Network Port Scan", "192.168.245.40")
        remember("web", "vms-production", "Web Traversal Attempt", "192.168.245.40")

        result = correlate("os", "vms-production")

        self.assertIsNotNone(result)
        self.assertTrue(result["correlated"])
        self.assertEqual(["network", "web", "os"], result["sources"])
        self.assertTrue(result["has_network_precursor"])
        self.assertGreaterEqual(result["time_delta_network_to_os"], 0)


if __name__ == "__main__":
    unittest.main()
