import unittest
from unittest.mock import Mock, patch
from scripts import install_recovery

class RecoveryTests(unittest.TestCase):
    @patch("scripts.install_recovery.subprocess.run")
    def test_no_command_output_leaks(self, run):
        run.return_value = Mock(returncode=1, stdout="DATABASE_URL=secret", stderr="secret")
        output = str(install_recovery.plan())
        self.assertNotIn("secret", output)
        self.assertFalse(install_recovery.plan()["checks"][0]["ok"])
