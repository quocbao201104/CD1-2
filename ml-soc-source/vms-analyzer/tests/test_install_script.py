"""Static safety checks for the VM3 installer shell script."""

import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "install_vm3_cd2.sh"


class InstallerScriptTests(unittest.TestCase):
    def test_waits_for_analyzer_health_before_continuing(self):
        script = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertIn("wait_for_analyzer_health()", script)
        service_start = script.index("configure_analyzer_service\n", script.index('[4/7]'))
        health_wait = script.index("wait_for_analyzer_health\n", service_start)
        wireguard_stage = script.index('echo "[5/7]')
        self.assertLess(service_start, health_wait)
        self.assertLess(health_wait, wireguard_stage)

    def test_waits_for_analyzer_health_after_token_restart(self):
        script = SCRIPT_PATH.read_text(encoding="utf-8")

        restart = script.index("systemctl restart vms-analyzer")
        health_wait = script.index("wait_for_analyzer_health", restart)
        final_health = script.index("curl -fsS http://127.0.0.1:8000/health", restart)
        self.assertLess(restart, health_wait)
        self.assertLess(health_wait, final_health)

    def test_requires_wireguard_handshake_before_installing_gotify(self):
        script = SCRIPT_PATH.read_text(encoding="utf-8")

        wireguard_done = script.index("configure_wireguard\n")
        handshake_wait = script.index("wait_for_wireguard_handshake\n", wireguard_done)
        gotify_stage = script.index('echo "[6/7]')
        self.assertLess(wireguard_done, handshake_wait)
        self.assertLess(handshake_wait, gotify_stage)

    def test_has_gotify_resume_mode_without_wireguard_reconfiguration(self):
        script = SCRIPT_PATH.read_text(encoding="utf-8")

        resume_mode = script.index('= "--resume-gotify"')
        resume_handler = script.index("resume_gotify_installation()")
        resume_call = script.index("  resume_gotify_installation\n", resume_handler)
        wireguard_setup = script.index("configure_wireguard\n")

        self.assertLess(resume_mode, resume_handler)
        self.assertLess(resume_handler, resume_call)
        self.assertLess(resume_call, wireguard_setup)


if __name__ == "__main__":
    unittest.main()
