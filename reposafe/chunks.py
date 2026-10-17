"""Bounded independently encrypted archive chunks; full snapshots need no prior run."""

import os
from pathlib import Path

from .common import BackupError, command, sha256


def encrypt_archive(archive, destination, recipients, chunk_bytes):
    flags = [a for recipient in recipients for a in ("-r", recipient)]
    entries = []
    temporary = archive.parent / "plaintext-chunk"
    try:
        if not chunk_bytes:
            paths = [(archive, "snapshot.tar.gz.age")]
            for source, name in paths:
                target = destination / name
                command(["age", "--encrypt", *flags, "-o", target, source])
                target.chmod(0o600)
                entries.append({"name": name, "bytes": target.stat().st_size, "sha256": sha256(target)})
        else:
            with archive.open("rb") as source:
                for index in range(10001):
                    data = source.read(chunk_bytes)
                    if not data:
                        break
                    if index == 10000:
                        raise BackupError("snapshot exceeds its encrypted chunk count limit")
                    with temporary.open("wb") as part:
                        os.chmod(temporary, 0o600)
                        part.write(data)
                    name = f"chunk-{index:06d}.age"
                    target = destination / name
                    command(["age", "--encrypt", *flags, "-o", target, temporary])
                    target.chmod(0o600)
                    entries.append({"name": name, "bytes": target.stat().st_size, "sha256": sha256(target)})
            if not entries:
                raise BackupError("archive has no content")
        return entries
    except BackupError:
        for target in destination.glob("*.age"):
            target.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)
