import unittest
from unittest.mock import Mock, patch
from scripts import install_report

class ReportTests(unittest.TestCase):
    @patch("scripts.install_report.subprocess.run")
    def test_redacted_and_not_beta_accepted(self, run):
        run.return_value = Mock(returncode=0, stdout="POSTGRES_PASSWORD=secret", stderr="")
        report = install_report.report()
        self.assertFalse(report["beta_accepted"])
        self.assertNotIn("secret", str(report))

    @patch("scripts.install_report.subprocess.run", side_effect=OSError("unavailable"))
    def test_unavailable_is_not_success(self, run):
        report = install_report.report()
        self.assertTrue(all(v == "incomplete" for v in report["checks"].values()))
