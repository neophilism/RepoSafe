"""Fixed, bounded adapters: SQLite online backup, PostgreSQL dump, remote exports."""

import configparser
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .common import BackupError, command, sha256, write_json
from .config import FileSource
from .format import safe_relative
from .signing import read_regular
from .sources import FileCollector


def tool_environment():
    return {k: v for k, v in os.environ.items() if k in
            ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")}


def private_setting(prefix, suffix, *, required=True):
    value = os.environ.get(prefix + suffix)
    if not value and not required:
        return None
    if not value or not Path(value).is_absolute():
        raise BackupError("dataset needs a dedicated absolute private credential file")
    read_regular(value, 1024 ** 2, private=True)
    return value


def sqlite_export(source, output):
    path = source.path
    if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not stat.S_ISREG(path.stat().st_mode):
        raise BackupError("SQLite source must be a regular database without symlink ancestors")
    deadline = time.monotonic() + source.timeout_seconds
    database = output / "database.sqlite"
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)) as incoming, closing(sqlite3.connect(database)) as target:
        database.chmod(0o600)
        incoming.enable_load_extension(False)
        incoming.execute("PRAGMA trusted_schema=OFF")
        incoming.execute("PRAGMA query_only=ON")
        page_size = incoming.execute("PRAGMA page_size").fetchone()[0]

        def progress(status, remaining, total):
            if time.monotonic() >= deadline or total * page_size > source.maximum_bytes:
                raise BackupError("SQLite backup exceeded its deadline or byte budget")

        incoming.backup(target, pages=256, progress=progress, sleep=0.05)
        target.enable_load_extension(False)
        target.execute("PRAGMA trusted_schema=OFF")
        target.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        if target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise BackupError("SQLite backup failed integrity checking")
        evidence = {"sqlite_version": sqlite3.sqlite_version,
                    "user_version": target.execute("PRAGMA user_version").fetchone()[0],
                    "consistency": "SQLite online-backup API transaction-consistent snapshot, including committed WAL"}
    if database.stat().st_size > source.maximum_bytes:
        raise BackupError("SQLite export exceeds its byte budget")
    return evidence


def postgres_environment(source):
    service_file = private_setting(source.credential_prefix, "_SERVICE_FILE")
    passfile = private_setting(source.credential_prefix, "_PASSFILE", required=False)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(read_regular(service_file, 1024 ** 2, private=True).decode())
        service = parser[source.service]
        host = service.get("host", "")
        if not host or (not host.startswith("/") and service.get("sslmode") != "verify-full"):
            raise ValueError
        # Avoid shell/command credential helpers added by newer libpq versions.
        if any("command" in key or key == "service" for key in service):
            raise ValueError
    except (ValueError, KeyError, configparser.Error, UnicodeError):
        raise BackupError("PostgreSQL service requires an explicit socket or verified TLS host") from None
    env = tool_environment()
    env.update({"PGSERVICE": source.service, "PGSERVICEFILE": service_file,
        "PGCONNECT_TIMEOUT": "30", "PGAPPNAME": "RepoSafe",
        "PGOPTIONS": "-c default_transaction_read_only=on -c lock_timeout=60000"})
    if passfile:
        env["PGPASSFILE"] = passfile
    else:
        # Never silently consult an ambient ~/.pgpass; trusted service can use cert/socket auth.
        env["PGPASSFILE"] = os.devnull
    return env


DATABASE_INFO = """SELECT json_build_object(
 'server_version_num', current_setting('server_version_num')::integer,
 'database', current_database(),
 'extensions', (SELECT coalesce(json_agg(json_build_object('name', extname, 'version', extversion)), '[]'::json) FROM pg_extension))"""
ROLE_INFO = """SELECT coalesce(json_agg(json_build_object('name', rolname, 'superuser', rolsuper,
 'inherit', rolinherit, 'create_role', rolcreaterole, 'create_database', rolcreatedb,
 'login', rolcanlogin, 'replication', rolreplication, 'connection_limit', rolconnlimit,
 'valid_until', rolvaliduntil, 'bypass_rls', rolbypassrls)), '[]'::json) FROM pg_roles"""


def postgres_export(source, output, *, runner=command):
    env = postgres_environment(source)
    deadline = time.monotonic() + source.timeout_seconds

    def run(args, **kwargs):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BackupError("PostgreSQL export exceeded its deadline")
        return runner(args, env=env, timeout=remaining, **kwargs)

    info = json.loads(run(["psql", "-X", "--no-password", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", DATABASE_INFO]))
    version = run(["pg_dump", "--version"]).decode().strip()
    match = re.search(r"\(PostgreSQL\) (\d+)", version)
    if not match or int(match[1]) * 10000 < info["server_version_num"] // 10000 * 10000:
        raise BackupError("pg_dump must be at least the source server major version")
    dump = output / "database.dump"
    run(["pg_dump", "--no-password", "--format=custom", "--serializable-deferrable", "--lock-wait-timeout=60s"],
        output_file=dump, maximum_output_bytes=source.maximum_bytes)
    toc = run(["pg_restore", "--list", dump], maximum_output_bytes=16 * 1024 ** 2)
    if not toc.startswith(b";") or dump.stat().st_size == 0:
        raise BackupError("PostgreSQL custom dump has no valid archive catalog")
    (output / "archive-list.txt").write_bytes(toc)
    (output / "archive-list.txt").chmod(0o600)
    if source.include_roles:
        roles = json.loads(run(["psql", "-X", "--no-password", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", ROLE_INFO]))
        if not isinstance(roles, list):
            raise BackupError("invalid PostgreSQL role metadata")
        write_json(output / "roles.json", roles)
    return {"database": info, "pg_dump_version": version, "archive_sha256": sha256(dump),
            "role_metadata_requested": source.include_roles, "role_passwords": "not exported; independent secret escrow required",
            "consistency": "single-database serializable-deferrable logical snapshot; role metadata has a separate capture window",
            "recovery_requirement": "compatible PostgreSQL/extensions, separately reviewed roles and pg_restore into an isolated NEW database"}


def remote_listing(raw):
    listing = json.loads(raw)
    if not isinstance(listing, list) or len(listing) > 100000:
        raise BackupError("remote inventory exceeds its file count limit")
    result = {}
    for entry in listing:
        path = entry["Path"]
        safe_relative(path)
        if path in result or entry.get("IsDir") is not False or entry.get("IsLink") or type(entry["Size"]) is not int or entry["Size"] < -1:
            raise BackupError("remote inventory has duplicate, linked or unsupported objects")
        result[path] = {key: entry.get(key) for key in ("Size", "ModTime", "Hashes", "ID", "MimeType")}
    return result


def remote_export(source, output, *, runner=command):
    config_file = private_setting(source.credential_prefix, "_RCLONE_CONFIG")
    env = tool_environment()
    flags = ["--config", config_file, "--log-level", "ERROR", "--retries", "3"]
    if source.export_formats:
        flags += ["--drive-export-formats", ",".join(source.export_formats)]
    deadline = time.monotonic() + source.timeout_seconds

    def run(args, **kwargs):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BackupError("remote export exceeded its deadline")
        return runner(["rclone", *args, *flags], env=env, timeout=remaining, **kwargs)

    before = remote_listing(run(["lsjson", source.remote, "--recursive", "--files-only", "--hash"]))
    if sum(max(0, e["Size"]) for e in before.values()) > source.maximum_bytes:
        raise BackupError("remote inventory exceeds its byte budget")
    data = output / "data"
    run(["copy", source.remote, data, "--immutable", "--max-transfer", str(source.maximum_bytes),
         "--cutoff-mode", "cautious", "--max-size", str(source.maximum_bytes)])
    after = remote_listing(run(["lsjson", source.remote, "--recursive", "--files-only", "--hash"]))
    if before != after:
        raise BackupError("remote inventory changed during capture")
    if not data.exists():
        data.mkdir(mode=0o700)
    actual = {p.relative_to(data).as_posix(): p for p in data.rglob("*") if p.is_file()}
    if set(actual) != set(before) or any(p.is_symlink() for p in data.rglob("*")):
        raise BackupError("remote copy omitted or changed an enrolled object")
    total = sum(p.stat().st_size for p in actual.values())
    if total > source.maximum_bytes:
        raise BackupError("remote export exceeds its byte budget")
    for path, entry in before.items():
        if entry["Size"] >= 0 and actual[path].stat().st_size != entry["Size"]:
            raise BackupError("remote copy size differs from its inventory")
    run(["check", source.remote, data, "--one-way", "--download"])
    write_json(output / "remote-inventory.json", {"schema_version": 1, "files": before})
    return {"files": len(actual), "bytes": total, "export_formats": list(source.export_formats),
            "consistency": "stable before/after inventory plus downloaded-byte check; no cross-object transaction or source version-history export"}


def export_dataset(source, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, mode=0o700)
    started = datetime.now(timezone.utc).isoformat()
    try:
        if source.kind == "sqlite":
            evidence = sqlite_export(source, destination)
        elif source.kind == "postgres":
            evidence = postgres_export(source, destination)
        elif source.kind == "remote":
            evidence = remote_export(source, destination)
        else:
            raise BackupError("unsupported dataset adapter")
        if sum(p.stat().st_size for p in destination.rglob("*") if p.is_file()) > source.maximum_bytes:
            raise BackupError("dataset output exceeds its byte budget")
        result = {"name": source.name, "kind": source.kind, "owner": source.owner, "status": "complete",
                  "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
                  "rpo_hours": source.rpo_hours, "rto_hours": source.rto_hours, **evidence}
        write_json(destination / "dataset.json", result)
        return result
    except Exception as error:
        shutil.rmtree(destination)
        if isinstance(error, BackupError):
            raise
        raise BackupError("dataset export unavailable, inconsistent or invalid") from None
