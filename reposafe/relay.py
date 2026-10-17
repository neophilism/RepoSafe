"""Read-only SFTP queue polling with pinned host keys and no remote deletion."""

import configparser
import os
import re
from pathlib import Path

from .common import BackupError, command, storage_check
from .datasets import tool_environment
from .runner import run_lock
from .signing import read_regular


def pull_queue(remote, inbox, config_file, known_hosts, kind, maximum_bytes, *, runner=command):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*:[^\r\n\x00]*", remote) or kind not in ("captures", "catalogs", "events", "offline-proofs") or maximum_bytes < 1:
        raise BackupError("invalid enrolled SFTP queue")
    try:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(read_regular(config_file, 1024 ** 2, private=True).decode())
        name = remote.split(":", 1)[0]
        if set(parser.sections()) != {name} or parser[name].get("type") != "sftp" or parser[name].get("disable_hashcheck", "").lower() not in ("true", "1"):
            raise ValueError
        if any(key.endswith("command") or key in ("ssh", "shell_type") for key in parser[name]):
            raise ValueError
        if not read_regular(known_hosts, 1024 ** 2).strip():
            raise ValueError
    except (OSError, ValueError, configparser.Error):
        raise BackupError("queue transport needs one read-only SFTP remote, disabled remote shell hash commands and pinned known-hosts file") from None
    inbox = Path(inbox).absolute()
    with run_lock(inbox.parent / (inbox.name + "-pull-state")):
        if inbox.is_symlink() or any(p.is_symlink() for p in inbox.parents):
            raise BackupError("queue inbox cannot have symlink ancestors")
        inbox.mkdir(mode=0o700, exist_ok=True)
        if inbox.stat().st_mode & 0o077:
            raise BackupError("queue inbox must be private")
        patterns = {"captures": ("/*/snapshot.tar.gz.age", "/*/chunk-*.age", "/*/receipt.json", "/*/receipt.sig.json"),
                    "catalogs": ("/*/catalog.json", "/*/catalog.sig.json"),
                    "events": ("/*/event.json", "/*/event.sig.json", "/*/catalogs/*/catalog.json", "/*/catalogs/*/catalog.sig.json"),
                    "offline-proofs": ("/*/copy.json", "/*/copy.sig.json")}[kind]
        flags = [flag for pattern in patterns for flag in ("--include", pattern)]
        flags += ["--exclude", "*", "--config", str(config_file), "--sftp-known-hosts-file", str(known_hosts),
                  "--sftp-disable-hashcheck", "--immutable", "--log-level", "ERROR", "--max-transfer", str(maximum_bytes),
                  "--cutoff-mode", "cautious", "--retries", "3"]
        check = lambda: storage_check(inbox, maximum_bytes, 128 * 1024 ** 2)
        check()
        runner(["rclone", "copy", remote, inbox, *flags], env=tool_environment(), timeout=3600, guard=check)
        check()
    return {"schema_version": 1, "kind": kind, "transport": "host-key-pinned SFTP", "remote_deletion": False,
            "status": "pulled; consumers must verify signatures, bytes, completeness and freshness"}
