import unittest
from unittest.mock import Mock, patch
from scripts import install_recovery

class RecoveryTests(unittest.TestCase):
    @patch("scripts.install_compose_status.inspect", return_value={"status": "incomplete"})
    @patch("scripts.install_recovery.subprocess.run")
    def test_no_command_output_leaks(self, run, inspect):
        run.return_value = Mock(returncode=1, stdout="DATABASE_URL=secret", stderr="secret")
        result = install_recovery.plan()
        self.assertNotIn("secret", str(result))
        self.assertFalse(all(c["ok"] for c in result["checks"]))

    @patch("scripts.install_compose_status.inspect", return_value={"status": "incomplete"})
    @patch("scripts.install_recovery.subprocess.run", return_value=Mock(returncode=0))
    def test_stopped_stack_not_accepted(self, run, inspect):
        self.assertFalse(install_recovery.plan()["checks"][-1]["ok"])
