import unittest
from unittest.mock import patch, Mock
from scripts import install_host

class HostTests(unittest.TestCase):
    @patch("scripts.install_host.shutil.which", return_value=None)
    def test_missing_docker_is_incomplete(self, _):
        self.assertEqual(install_host.inspect()["docker_engine"], "unavailable")

    @patch("scripts.install_host.subprocess.run", return_value=Mock(returncode=0))
    @patch("scripts.install_host.shutil.which", return_value="/usr/bin/docker")
    def test_docker_and_compose_available(self, _, run):
        self.assertEqual(install_host.inspect()["compose"], "available")
        self.assertEqual(run.call_count, 2)
