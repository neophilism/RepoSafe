import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reposafe.common import BackupError
from reposafe.config import FileSource
from reposafe.sources import FileCollector


class FileSourceTests(unittest.TestCase):
    def test_many_empty_files_cannot_escape_byte_limits_via_entry_exhaustion(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            source.mkdir()
            for name in ("a", "b", "c"):
                (source / name).touch()
            with self.assertRaisesRegex(BackupError, "entry budget"):
                FileCollector(FileSource("files", source, maximum_entries=2)).collect(root / "copy")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "input"
        self.source.mkdir()
        (self.source / "notes.txt").write_text("valuable data")
        self.destination = self.root / "captured"

    def tearDown(self):
        self.temp.cleanup()

    def test_regular_files_and_explicit_exclusions(self):
        (self.source / "cache.tmp").write_text("exclude")
        result = FileCollector(FileSource("docs", self.source, ("*.tmp",))).collect(self.destination)
        self.assertEqual(1, result["files"])
        self.assertEqual("valuable data", (self.destination / "notes.txt").read_text())
        self.assertFalse((self.destination / "cache.tmp").exists())

    def test_symlinks_and_fifos_are_rejected(self):
        (self.source / "link").symlink_to(self.root / "not-enrolled")
        with self.assertRaises(BackupError):
            FileCollector(FileSource("docs", self.source)).collect(self.destination)
        (self.source / "link").unlink()
        os.mkfifo(self.source / "pipe")
        with self.assertRaises(BackupError):
            FileCollector(FileSource("docs", self.source)).collect(self.root / "other")

    def test_symlink_ancestor_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(BackupError):
            FileCollector(FileSource("docs", alias / "notes.txt")).collect(self.destination)

    def test_byte_limit_fails_instead_of_truncating(self):
        with self.assertRaisesRegex(BackupError, "budget"):
            FileCollector(FileSource("docs", self.source, maximum_bytes=1)).collect(self.destination)

    def test_recursive_backup_overlap_is_rejected(self):
        with self.assertRaisesRegex(BackupError, "overlap"):
            FileCollector(FileSource("docs", self.source), forbidden=(self.source / "backups",)).collect(self.destination)

    def test_file_mutation_during_copy_is_rejected(self):
        path = self.source / "notes.txt"
        real_fstat = os.fstat
        calls = []
        def changing_stat(descriptor):
            calls.append(descriptor)
            if len(calls) == 2:
                path.write_text("data changed while reading")
            return real_fstat(descriptor)
        with patch("reposafe.sources.os.fstat", side_effect=changing_stat), self.assertRaises(BackupError):
            FileCollector(FileSource("note", path)).collect(self.destination)
