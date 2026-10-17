import json
import shutil
import tempfile
import unittest
from pathlib import Path

from reposafe.common import BackupError, command, sha256
from reposafe.config import Config
from reposafe.delivery import verify_snapshot
from reposafe.restore import restore
from reposafe.snapshot import capture


@unittest.skipUnless(shutil.which("age"), "age required")
class ChunkTests(unittest.TestCase):
    def test_chunked_snapshot_roundtrip_and_missing_or_reordered_chunk_failure(self):
        class Source:
            token = "fixture"
            def inventory(self, config):
                return [{"id": 1, "full_name": "owner/repo"}]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            identity = root / "identity"
            command(["age-keygen", "-o", identity])
            recipient = command(["age-keygen", "-y", identity]).decode().strip()
            def fixture(repo, path, env, lfs):
                path.mkdir()
                (path / "data").write_bytes(bytes(range(256)) * 10)
            config = Config(("owner",), (recipient,), chunk_bytes=256)
            result = capture(config, Source(), root / "backups", mirror_fn=fixture)
            receipt = verify_snapshot(result.directory)
            self.assertEqual(3, receipt["schema_version"])
            self.assertGreater(len(receipt["files"]), 1)
            digest = sha256(result.directory / "receipt.json")
            restore(result.directory, identity, root / "restored", trusted_sha256=digest)
            self.assertEqual(bytes(range(256)) * 10, (root / "restored/snapshot/repositories/1/mirror.git/data").read_bytes())
            receipt["files"].reverse()
            (result.directory / "receipt.json").write_text(json.dumps(receipt))
            with self.assertRaises(BackupError):
                verify_snapshot(result.directory)

    def test_snapshot_size_budget_fails_before_publication(self):
        class Source:
            token = "fixture"
            def inventory(self, config):
                return [{"id": 1, "full_name": "owner/repo"}]
        def fixture(repo, path, env, lfs):
            path.mkdir()
            (path / "data").write_bytes(b"too much data")
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(BackupError):
            capture(Config(("owner",), (), maximum_snapshot_bytes=1), Source(), Path(raw), mirror_fn=fixture)
