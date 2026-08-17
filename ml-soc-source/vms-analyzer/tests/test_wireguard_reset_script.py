import unittest
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parents[3]
SCRIPT = WORKSPACE / "TaoLai_WireGuard_VM3.sh"


class WireGuardResetScriptTests(unittest.TestCase):
    def test_script_rebuilds_line_separated_config_without_storing_client_secret(self):
        self.assertTrue(SCRIPT.is_file(), "VM3 WireGuard reset script must exist")
        if not SCRIPT.is_file():
            return

        content = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('read -r -p "Dán PUBLIC KEY', content)
        self.assertIn('printf "[Interface]\\nAddress = %s\\nListenPort = %s\\nPrivateKey = %s', content)
        self.assertIn('AllowedIPs = %s\\n"', content)
        self.assertIn('wg genkey', content)
        self.assertIn('systemctl restart "wg-quick@${WG_INTERFACE}"', content)
        self.assertNotIn('GOTIFY_APP_TOKEN', content)


if __name__ == "__main__":
    unittest.main()
