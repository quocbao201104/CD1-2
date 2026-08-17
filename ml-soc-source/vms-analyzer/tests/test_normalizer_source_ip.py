import unittest

from app.normalizer import from_soc_flat


class NormalizerSourceIpTests(unittest.TestCase):
    def test_fim_web_root_event_is_os_not_web_precursor(self):
        event = from_soc_flat(
            {
                "agent_name": "vms-production",
                "agent_ip": "192.168.245.10",
                "rule_description": "WEB: Web root file modified",
                "rule_level": 10,
                "full_log": "File '/var/www/html/shell.php' modified",
                "location": "syscheck",
            }
        )

        self.assertEqual("os", event["source"])

    def test_plain_nginx_access_log_yields_client_ip_and_keeps_server_ip(self):
        event = from_soc_flat(
            {
                "agent_name": "vms-production",
                "agent_ip": "192.168.245.10",
                "rule_description": "WEB: Directory traversal attempt on Nginx",
                "rule_level": 10,
                "srcip": "",
                "full_log": (
                    '192.168.245.157 - - [17/Aug/2026:12:00:00 +0700] '
                    '"GET /../../etc/passwd HTTP/1.1" 400 166 "-" "curl/8.0"'
                ),
                "location": "/var/log/nginx/access.log",
            }
        )

        self.assertEqual("192.168.245.10", event["server_ip"])
        self.assertEqual("192.168.245.157", event["related_ip"])


if __name__ == "__main__":
    unittest.main()
