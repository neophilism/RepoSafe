import hashlib
import tempfile
import unittest
from pathlib import Path

from reposafe.common import BackupError, command
from reposafe.gitdata import evidence, verify_restored


class GitEvidenceTests(unittest.TestCase):
    def test_refs_and_lfs_objects_are_checked_by_content(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            source.mkdir()
            command(["git", "init", "-b", "main", source])
            data = b"large object fixture"
            oid = hashlib.sha256(data).hexdigest()
            (source / ".gitattributes").write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n")
            (source / "asset.bin").write_text(f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {len(data)}\n")
            command(["git", "-C", source, "-c", "filter.lfs.clean=cat", "add", "."])
            command(["git", "-C", source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-m", "fixture"])
            mirror = root / "mirror.git"
            command(["git", "clone", "--mirror", source, mirror])
            path = mirror / "lfs/objects" / oid[:2] / oid[2:4] / oid
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            result = evidence(mirror, None, lfs=True)
            self.assertEqual(oid, result["lfs_objects"][0]["oid"])
            verify_restored(mirror, result)
            path.write_bytes(b"corrupt")
            with self.assertRaises(BackupError):
                verify_restored(mirror, result)
            with self.assertRaises(BackupError):
                evidence(mirror, None, lfs=True)
