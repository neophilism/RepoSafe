import base64
import tempfile
import unittest
from pathlib import Path

from reposafe.config import load
from scripts.prepare_runtime import prepare


class RuntimeTests(unittest.TestCase):
    def environment(self, root, *, recipient=None, drive_type="drive"):
        config = f"[gdrive]\ntype = {drive_type}\ntoken = fixture-only\n[dropbox]\ntype = dropbox\ntoken = fixture-only\n"
        return {"RUNNER_TEMP": root, "AGE_RECIPIENT": recipient or "age1" + "a" * 58,
                "RCLONE_CONFIG_B64": base64.b64encode(config.encode()).decode()}

    def test_private_runtime_files_produce_valid_working_config(self):
        with tempfile.TemporaryDirectory() as raw:
            config, remote = prepare(self.environment(raw))
            self.assertEqual(2, len(load(config).destinations))
            self.assertEqual(0, config.stat().st_mode & 0o077)
            self.assertEqual(0, remote.stat().st_mode & 0o077)
            self.assertNotIn("fixture-only", config.read_text())

    def test_recipient_cannot_inject_toml(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(ValueError):
                prepare(self.environment(raw, recipient='age1bad"] # injected'))
            self.assertEqual([], list(Path(raw).iterdir()))

    def test_wrong_provider_type_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(ValueError):
                prepare(self.environment(raw, drive_type="http"))
            self.assertEqual([], list(Path(raw).iterdir()))
