import tempfile
import unittest
from pathlib import Path
from scripts import install_secrets

class SecretPreparationTests(unittest.TestCase):
    def test_missing_file_is_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(install_secrets.inspect(Path(d)/".env")[0], 2)

    def test_existing_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/".env"
            p.write_text("EXISTING=secret")
            self.assertEqual(install_secrets.inspect(p)[0], 0)
            self.assertEqual(p.read_text(), "EXISTING=secret")
