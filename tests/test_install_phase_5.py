import unittest
from unittest.mock import Mock, patch
from scripts import install_report

class ReportTests(unittest.TestCase):
    @patch("scripts.install_compose_status.inspect", return_value={"status": "ready"})
    @patch("scripts.install_report.subprocess.run")
    def test_redacted_and_not_beta_accepted(self, run, inspect):
        run.return_value = Mock(returncode=0, stdout="POSTGRES_PASSWORD=secret", stderr="")
        report = install_report.report()
        self.assertFalse(report["beta_accepted"])
        self.assertNotIn("secret", str(report))

    @patch("scripts.install_compose_status.inspect", return_value={"status": "incomplete"})
    @patch("scripts.install_report.subprocess.run", return_value=Mock(returncode=0))
    def test_unready_stack_fails(self, run, inspect):
        self.assertEqual(install_report.report()["checks"]["compose_services"], "fail")

    @patch("scripts.install_compose_status.inspect", side_effect=OSError("unavailable"))
    @patch("scripts.install_report.subprocess.run", side_effect=OSError("unavailable"))
    def test_unavailable_is_not_success(self, run, inspect):
        report = install_report.report()
        self.assertTrue(all(v == "incomplete" for v in report["checks"].values()))
