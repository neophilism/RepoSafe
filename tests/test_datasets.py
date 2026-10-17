import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from reposafe.common import BackupError, command
from reposafe.config import Dataset, load
from reposafe.datasets import export_dataset, postgres_export, remote_export, remote_listing


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_sqlite_online_backup_includes_committed_wal_and_excludes_uncommitted_writes(self):
        path = self.root / "live.sqlite"
        with sqlite3.connect(path) as live:
            live.execute("PRAGMA journal_mode=WAL")
            live.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)")
            live.execute("INSERT INTO records(value) VALUES ('committed in WAL')")
            live.commit()
            live.execute("INSERT INTO records(value) VALUES ('not committed')")
            result = export_dataset(Dataset("db", "sqlite", path), self.root / "export")
            self.assertEqual("complete", result["status"])
            with sqlite3.connect(self.root / "export/database.sqlite") as recovered:
                self.assertEqual([("committed in WAL",)], recovered.execute("SELECT value FROM records").fetchall())
                self.assertEqual("ok", recovered.execute("PRAGMA integrity_check").fetchone()[0])

    def test_sqlite_invalid_link_missing_source_and_budget_remove_partial_export(self):
        path = self.root / "db.sqlite"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE data(value TEXT)")
        linked = self.root / "linked"
        linked.symlink_to(path)
        for source in (Dataset("db", "sqlite", linked), Dataset("db", "sqlite", self.root / "missing"),
                       Dataset("db", "sqlite", path, maximum_bytes=1)):
            with self.subTest(source=source.path), self.assertRaises(BackupError):
                export_dataset(source, self.root / "failed")
            self.assertFalse((self.root / "failed").exists())
        self.assertFalse((self.root / "missing").exists())

    def service(self, host="db.example", sslmode="verify-full"):
        path = self.root / "services.conf"
        path.write_text(f"[backup]\nhost={host}\nsslmode={sslmode}\ndbname=fixture\nuser=readonly\n")
        path.chmod(0o600)
        return path

    def test_postgres_uses_fixed_commands_private_env_and_streamed_custom_dump(self):
        source = Dataset("db", "postgres", service="backup", credential_prefix="REPOSAFE_DATABASE", include_roles=True)
        calls = []
        def runner(args, **kwargs):
            calls.append((args, kwargs))
            if args[0] == "psql":
                return (b'[]' if "pg_roles" in args[-1] else b'{"server_version_num":170000,"database":"fixture","extensions":[]}')
            if args[0] == "pg_dump" and "--version" in args:
                return b"pg_dump (PostgreSQL) 17.6"
            if args[0] == "pg_dump":
                kwargs["output_file"].write_bytes(b"PGDMP fixture")
                return b""
            return b"; Archive catalog fixture"
        output = self.root / "export"
        output.mkdir()
        with patch.dict(os.environ, {"REPOSAFE_DATABASE_SERVICE_FILE": str(self.service()),
                                    "PGPASSWORD": "must-not-inherit", "GITHUB_BACKUP_TOKEN": "must-not-inherit"}):
            result = postgres_export(source, output, runner=runner)
        self.assertEqual("fixture", result["database"]["database"])
        self.assertTrue((output / "roles.json").exists())
        for args, kwargs in calls:
            self.assertNotIn("must-not-inherit", str(args) + str(kwargs))
            self.assertNotIn("PGPASSWORD", kwargs["env"])
            self.assertNotIn("GITHUB_BACKUP_TOKEN", kwargs["env"])
        self.assertTrue(any("output_file" in kwargs for _, kwargs in calls))

    def test_postgres_requires_tls_and_rejects_credential_helpers(self):
        from reposafe.datasets import postgres_environment
        source = Dataset("db", "postgres", service="backup", credential_prefix="REPOSAFE_DATABASE")
        path = self.service(sslmode="prefer")
        with patch.dict(os.environ, {"REPOSAFE_DATABASE_SERVICE_FILE": str(path)}), self.assertRaises(BackupError):
            postgres_environment(source)
        path.write_text("[backup]\nhost=/local/socket\noauth_client_secret_command=evil\n")
        with patch.dict(os.environ, {"REPOSAFE_DATABASE_SERVICE_FILE": str(path)}), self.assertRaises(BackupError):
            postgres_environment(source)

    def test_remote_inventory_rejects_traversal_and_duplicate_names(self):
        for listing in ([{"Path": "../private", "Size": 1, "IsDir": False}],
                        [{"Path": "a", "Size": 1, "IsDir": False}] * 2):
            with self.assertRaises(BackupError):
                remote_listing(json.dumps(listing))

    @unittest.skipUnless(shutil.which("rclone"), "rclone required")
    def test_remote_source_real_rclone_captures_files_and_checks_bytes(self):
        data = self.root / "remote"
        data.mkdir()
        (data / "document.txt").write_text("data fixture")
        config = self.root / "rclone.conf"
        config.write_text("[enrolled]\ntype = local\n")
        config.chmod(0o600)
        source = Dataset("docs", "remote", remote="enrolled:" + str(data), credential_prefix="REPOSAFE_DOCUMENTS")
        with patch.dict(os.environ, {"REPOSAFE_DOCUMENTS_RCLONE_CONFIG": str(config)}):
            result = export_dataset(source, self.root / "export")
        self.assertEqual(1, result["files"])
        self.assertEqual("data fixture", (self.root / "export/data/document.txt").read_text())
        self.assertTrue((data / "document.txt").exists())

    def test_remote_change_during_copy_fails_without_success_evidence(self):
        config = self.root / "rclone.conf"
        config.write_text("[fixture]\ntype=local\n")
        config.chmod(0o600)
        output = self.root / "export"
        output.mkdir()
        source = Dataset("docs", "remote", remote="fixture:data", credential_prefix="REPOSAFE_DOCUMENTS")
        inventories = iter([b'[{"Path":"a","Size":1,"IsDir":false}]', b'[]'])
        def runner(args, **kwargs):
            if args[1] == "lsjson":
                return next(inventories)
            (output / "data").mkdir()
            (output / "data/a").write_text("x")
            return b""
        with patch.dict(os.environ, {"REPOSAFE_DOCUMENTS_RCLONE_CONFIG": str(config)}), self.assertRaises(BackupError):
            remote_export(source, output, runner=runner)


class CommandBudgetTests(unittest.TestCase):
    def test_streamed_output_is_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "dump"
            command(["python3", "-c", "import sys;sys.stdout.buffer.write(b'x'*8192)"],
                    output_file=output, maximum_output_bytes=8192)
            self.assertEqual(8192, output.stat().st_size)
            self.assertEqual(0, output.stat().st_mode & 0o077)
            with self.assertRaises(BackupError):
                command(["python3", "-c", "print('x'*1024)"], maximum_output_bytes=1)

    def test_deadline_kills_children_holding_output_pipes(self):
        with self.assertRaisesRegex(BackupError, "deadline"):
            command(["python3", "-c", "import subprocess;subprocess.Popen(['python3','-c','import time;time.sleep(20)'])"], timeout=0.1)
