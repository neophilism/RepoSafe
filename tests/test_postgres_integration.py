"""Real isolated database restore; CI explicitly enables this required integration."""

import getpass
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reposafe.common import BackupError, command
from reposafe.config import Dataset
from reposafe.datasets import export_dataset, postgres_environment


@unittest.skipUnless(os.environ.get("REPOSAFE_POSTGRES_INTEGRATION") == "1", "requires isolated PostgreSQL tools; enabled in CI")
class PostgresIntegrationTests(unittest.TestCase):
    def test_custom_dump_recovers_rows_constraints_roles_and_extensions_into_new_database(self):
        for tool in ("initdb", "pg_ctl", "pg_dump", "pg_restore", "psql"):
            self.assertTrue(shutil.which(tool), tool + " required for CI database acceptance")
        with tempfile.TemporaryDirectory(prefix="reposafe-pg-") as raw:
            root = Path(raw)
            socket = root / "socket"
            socket.mkdir()
            data = root / "cluster"
            command(["initdb", "--pgdata", data, "--auth=trust", "--no-locale", "--encoding=UTF8", "--no-sync"])
            command(["pg_ctl", "-D", data, "-l", root / "server.log", "-o", f"-F -k {socket} -p 54389 -c listen_addresses=''", "-w", "start"])
            try:
                service = root / "pg_service.conf"
                service.write_text(f"[backup]\nhost={socket}\nport=54389\nuser={getpass.getuser()}\ndbname=postgres\n"
                                   f"[restore]\nhost={socket}\nport=54389\nuser={getpass.getuser()}\ndbname=recovered\n")
                service.chmod(0o600)
                source = Dataset("db", "postgres", service="backup", credential_prefix="REPOSAFE_DATABASE", include_roles=True)
                with patch.dict(os.environ, {"REPOSAFE_DATABASE_SERVICE_FILE": str(service)}):
                    env = postgres_environment(source)
                    # Fixture setup uses a separate explicit local admin environment.
                    admin = {**env, "PGOPTIONS": ""}
                    command(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-c",
                        "CREATE TABLE records(id integer PRIMARY KEY, value text NOT NULL); "
                        "INSERT INTO records SELECT n, 'fixture-' || n FROM generate_series(1,2000) n;"], env=admin)
                    result = export_dataset(source, root / "export")
                    self.assertTrue(result["database"]["extensions"])
                    self.assertTrue((root / "export/roles.json").is_file())
                    command(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-c", "CREATE DATABASE recovered"], env=admin)
                    recovery = {**admin, "PGSERVICE": "restore"}
                    command(["pg_restore", "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl",
                             "--dbname=service=restore", root / "export/database.dump"], env=recovery)
                    restored = command(["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c",
                                        "SELECT count(*), count(DISTINCT id) FROM records"], env=recovery)
                    self.assertEqual(b"2000|2000", restored.strip())
                    with self.assertRaises(BackupError):
                        command(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-c", "INSERT INTO records VALUES (1, 'duplicate')"], env=recovery)
            finally:
                command(["pg_ctl", "-D", data, "-m", "immediate", "-w", "stop"])
