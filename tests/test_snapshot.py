import json
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from reposafe.common import BackupError, command, sha256
from reposafe.config import Config
from reposafe.snapshot import capture, git_environment


class FakeGitHub:
    token = "TOKEN_MUST_NOT_APPEAR"

    def inventory(self, config):
        return [{"id": 1, "full_name": "neophilism/private-test"}]


@unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "age tools required")
class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "identity"
        command(["age-keygen", "-o", self.key])
        self.recipient = command(["age-keygen", "-y", self.key]).decode().strip()
        self.config = Config(("neophilism",), (self.recipient,))

    def tearDown(self):
        self.temp.cleanup()

    def local_mirror(self, repo, destination, env, lfs):
        command(["git", "init", "--bare", destination])
        (destination / "private-marker").write_text("private contents")

    def test_real_encryption_roundtrip_and_no_plaintext_output(self):
        result = capture(self.config, FakeGitHub(), self.root / "out", mirror_fn=self.local_mirror)
        self.assertTrue(result.complete)
        receipt = json.loads((result.directory / "receipt.json").read_text())
        encrypted = result.directory / "snapshot.tar.gz.age"
        self.assertEqual(sha256(encrypted), receipt["files"][0]["sha256"])
        plaintext = self.root / "restored.tar.gz"
        command(["age", "-d", "-i", self.key, "-o", plaintext, encrypted])
        with tarfile.open(plaintext) as archive:
            self.assertEqual(b"private contents", archive.extractfile("snapshot/repositories/1/mirror.git/private-marker").read())
        for file in result.directory.iterdir():
            self.assertNotIn(b"TOKEN_MUST_NOT_APPEAR", file.read_bytes())
            self.assertNotIn(b"private-test", file.read_bytes())
            self.assertEqual(0, file.stat().st_mode & 0o077)
        self.assertEqual({"snapshot.tar.gz.age", "receipt.json"}, {p.name for p in result.directory.iterdir()})

    def test_partial_capture_explicit_and_still_encrypted(self):
        def fail(*args):
            raise BackupError("fixture failure")
        result = capture(self.config, FakeGitHub(), self.root / "out", mirror_fn=fail)
        self.assertFalse(result.complete)
        self.assertEqual(1, result.failed_count)

    def test_encryption_failure_leaves_no_plaintext_payload(self):
        config = Config(("neophilism",), ("invalid-recipient",))
        with self.assertRaises(BackupError):
            capture(config, FakeGitHub(), self.root / "out", mirror_fn=self.local_mirror)
        self.assertEqual([], list((self.root / "out").rglob("*.age")))

    def test_snapshots_have_unique_paths(self):
        first = capture(self.config, FakeGitHub(), self.root / "out", mirror_fn=self.local_mirror)
        second = capture(self.config, FakeGitHub(), self.root / "out", mirror_fn=self.local_mirror)
        self.assertNotEqual(first.directory, second.directory)

    def test_signed_receipt_published_only_after_encryption(self):
        from unittest.mock import patch
        from reposafe.signing import generate_keys, verify_file
        generate_keys(self.root / "signing")
        with patch.dict(os.environ, {"REPOSAFE_COLLECTOR_SIGNING_KEY_FILE": str(self.root / "signing/private.pem")}):
            result = capture(self.config, FakeGitHub(), self.root / "out", mirror_fn=self.local_mirror)
        verify_file(result.directory / "receipt.json", result.directory / "receipt.sig.json",
                    self.root / "signing/public.pem", "collector-receipt")
        self.assertFalse((result.directory / "receipt.pending.json").exists())


class EnvironmentTests(unittest.TestCase):
    def test_git_environment_removes_injected_helpers_and_tracing(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"GIT_TRACE": "1", "GIT_CONFIG_COUNT": "1", "GIT_SSH_COMMAND": "evil"}):
            env = git_environment("secret", Path("/tmp/askpass"))
        self.assertNotIn("GIT_TRACE", env)
        self.assertNotIn("GIT_CONFIG_COUNT", env)
        self.assertNotIn("GIT_SSH_COMMAND", env)
        self.assertEqual("https", env["GIT_ALLOW_PROTOCOL"])

    def test_command_failure_does_not_expose_stderr_or_arguments(self):
        with self.assertRaises(BackupError) as caught:
            command(["python3", "-c", "import sys;sys.stderr.write('secret');sys.exit(1)"])
        self.assertNotIn("secret", str(caught.exception))
