import io
import shutil
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reposafe.common import BackupError, command, sha256
from reposafe.config import Config, FileSource, Dataset
from reposafe.restore import extract_safely, restore, verify_contents
from reposafe.snapshot import capture, mirror


class FakeGitHub:
    token = "fixture-token"
    def inventory(self, config):
        return [{"id": 1, "full_name": "neophilism/fixture"}]


@unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "age required")
class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = self.root / "identity"
        command(["age-keygen", "-o", self.key])
        self.recipient = command(["age-keygen", "-y", self.key]).decode().strip()
        self.config = Config(("neophilism",), (self.recipient,))

    def tearDown(self):
        self.temp.cleanup()

    def synthetic_mirror(self, repo, destination, env, include_lfs):
        command(["git", "init", "--bare", destination])

    def snapshot(self, **kwargs):
        return capture(self.config, FakeGitHub(), self.root / "out", mirror_fn=self.synthetic_mirror, **kwargs)

    def test_restore_git_refs_and_enrolled_files_without_network(self):
        source = self.root / "repo"
        source.mkdir()
        command(["git", "init", "-b", "main", source])
        (source / "hello.txt").write_text("recover me")
        command(["git", "-C", source, "add", "hello.txt"])
        command(["git", "-C", source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-m", "fixture"])
        command(["git", "-C", source, "branch", "other"])
        command(["git", "-C", source, "tag", "v1"])
        expected = command(["git", "-C", source, "show-ref"])
        documents = self.root / "documents"
        documents.mkdir()
        (documents / "notes.txt").write_text("private file contents")
        self.config = Config(("neophilism",), (self.recipient,), include_lfs=False,
                             files=(FileSource("docs", documents),))
        def redirect_git(args, **kwargs):
            args = list(args)
            if "clone" in args:
                args[args.index("--") + 1] = str(source)
                kwargs["env"] = {**kwargs["env"], "GIT_ALLOW_PROTOCOL": "file"}
            return command(args, **kwargs)
        with patch("reposafe.snapshot.command", side_effect=redirect_git):
            result = capture(self.config, FakeGitHub(), self.root / "out", mirror_fn=mirror)
        digest = sha256(result.directory / "snapshot.tar.gz.age")
        output = self.root / "restore"
        manifest = restore(result.directory, self.key, output, trusted_sha256=digest)
        self.assertTrue(manifest["complete"])
        self.assertEqual(1, manifest["recovery_checks"]["git_mirrors"])
        recovered = output / "snapshot/repositories/1/mirror.git"
        command(["git", "-C", recovered, "fsck", "--full", "--strict"])
        self.assertEqual(expected, command(["git", "-C", recovered, "show-ref"]))
        self.assertEqual(b"recover me", command(["git", "-C", recovered, "show", "main:hello.txt"]))
        self.assertEqual("private file contents", (output / "snapshot/files/docs/notes.txt").read_text())
        self.assertEqual(0, output.stat().st_mode & 0o077)
        (output / "snapshot/files/docs/notes.txt").write_text("corrupted")
        with self.assertRaises(BackupError):
            verify_contents(output / "snapshot", run_id=result.run_id)

    def test_wrong_key_and_wrong_trusted_digest_leave_no_output(self):
        result = self.snapshot()
        wrong = self.root / "wrong-key"
        command(["age-keygen", "-o", wrong])
        output = self.root / "restore"
        with self.assertRaises(BackupError):
            restore(result.directory, wrong, output)
        self.assertFalse(output.exists())
        with self.assertRaises(BackupError):
            restore(result.directory, self.key, output, trusted_sha256="0" * 64)
        self.assertFalse(output.exists())

    def test_database_dataset_roundtrips_through_encrypted_snapshot(self):
        from dataclasses import replace
        source = self.root / "live.sqlite"
        with sqlite3.connect(source) as db:
            db.execute("CREATE TABLE records(value TEXT)")
            db.execute("INSERT INTO records VALUES ('recover database contents')")
        self.config = replace(self.config, datasets=(Dataset("db", "sqlite", source),))
        result = self.snapshot()
        output = self.root / "database-restore"
        manifest = restore(result.directory, self.key, output)
        self.assertTrue(manifest["complete"])
        self.assertEqual(1, manifest["recovery_checks"]["sqlite_databases"])
        with sqlite3.connect(output / "snapshot/datasets/db/database.sqlite") as db:
            self.assertEqual("recover database contents", db.execute("SELECT value FROM records").fetchone()[0])
        self.config = replace(self.config, datasets=(Dataset("db", "sqlite", self.root / "missing-database"),))
        self.assertFalse(self.snapshot().complete)

    def test_restore_never_overwrites_existing_directory(self):
        result = self.snapshot()
        output = self.root / "existing"
        output.mkdir()
        (output / "keep").write_text("original")
        with self.assertRaises(BackupError):
            restore(result.directory, self.key, output)
        self.assertEqual("original", (output / "keep").read_text())

    def test_disappeared_repository_makes_snapshot_partial_but_keeps_visible_data(self):
        result = self.snapshot(expected_repository_ids=(1, 2))
        self.assertFalse(result.complete)
        self.assertEqual(1, result.missing_count)
        with self.assertRaises(BackupError):
            restore(result.directory, self.key, self.root / "restore")
        manifest = restore(result.directory, self.key, self.root / "partial", allow_partial=True)
        self.assertEqual([2], manifest["missing_repository_ids"])

    def test_unlisted_nested_inventory_file_is_rejected(self):
        result = self.snapshot()
        output = self.root / "restore"
        restore(result.directory, self.key, output)
        nested = output / "snapshot/extra"
        nested.mkdir()
        (nested / "content-manifest.json").write_text("unlisted")
        with self.assertRaises(BackupError):
            verify_contents(output / "snapshot", run_id=result.run_id)


class UnsafeArchiveTests(unittest.TestCase):
    def test_malicious_paths_links_devices_and_duplicates_are_rejected(self):
        for kind in ("traversal", "absolute", "symlink", "hardlink", "fifo", "duplicate", "dot", "sparse"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                archive = root / "bad.tar.gz"
                with tarfile.open(archive, "w:gz") as target:
                    entry = tarfile.TarInfo({"traversal":"snapshot/../../escaped", "absolute":"/escaped", "dot":"."}.get(kind, "snapshot/item"))
                    if kind == "symlink":
                        entry.type, entry.linkname = tarfile.SYMTYPE, "../../escaped"
                    elif kind == "hardlink":
                        entry.type, entry.linkname = tarfile.LNKTYPE, "../../escaped"
                    elif kind == "fifo":
                        entry.type = tarfile.FIFOTYPE
                    elif kind == "sparse":
                        entry.type = tarfile.GNUTYPE_SPARSE
                    target.addfile(entry)
                    if kind == "duplicate":
                        target.addfile(entry)
                output = root / "output"
                output.mkdir(mode=0o700)
                with self.assertRaises(BackupError):
                    extract_safely(archive, output)
                self.assertFalse((root / "escaped").exists())

    def test_extraction_member_and_byte_budgets(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "too-large.tar.gz"
            with tarfile.open(archive, "w:gz") as target:
                for i in range(2):
                    entry = tarfile.TarInfo(f"snapshot/{i}")
                    entry.size = 4
                    target.addfile(entry, io.BytesIO(b"data"))
            for limits in ({"maximum_bytes":3}, {"maximum_members":1}):
                output = root / str(len(list(root.iterdir())))
                output.mkdir()
                with self.assertRaises(BackupError):
                    extract_safely(archive, output, **limits)
