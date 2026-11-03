import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

CHECKER = Path(__file__).with_name("check_credential_examples.py")


class CredentialReportTest(unittest.TestCase):
    def test_cli_rejects_material_without_echoing_it_and_accepts_placeholders(self):
        fake = "AK" + "IA" + "A" * 16
        with tempfile.TemporaryDirectory() as directory:
            note = Path(directory) / "lab.txt"
            note.write_text(f"Use this example: {fake}\n", encoding="utf-8")
            result = subprocess.run([sys.executable, str(CHECKER), directory], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("aws_access_key_id", result.stdout)
            self.assertNotIn(fake, result.stdout + result.stderr)
            note.write_text("Use your own <AWS_ACCESS_KEY_ID> and <GOOGLE_API_KEY>\n", encoding="utf-8")
            clean = subprocess.run([sys.executable, str(CHECKER), directory], capture_output=True, text=True)
            self.assertEqual(clean.returncode, 0)


if __name__ == "__main__":
    unittest.main()
