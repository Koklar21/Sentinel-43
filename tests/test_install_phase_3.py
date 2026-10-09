import json
import unittest
from unittest.mock import Mock, patch
from scripts import install_compose_status

class ComposeStatusTests(unittest.TestCase):
    @patch("scripts.install_compose_status.subprocess.run")
    def test_missing_services_not_ready(self, run):
        run.return_value = Mock(returncode=0, stdout=json.dumps([{"Service":"s43-db","State":"running","Health":"healthy"}]))
        self.assertEqual(install_compose_status.inspect()["status"], "incomplete")

    @patch("scripts.install_compose_status.subprocess.run")
    def test_malformed_output(self, run):
        run.return_value = Mock(returncode=0, stdout="invalid json")
        self.assertEqual(install_compose_status.inspect()["status"], "invalid-output")
