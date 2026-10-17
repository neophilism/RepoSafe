"""Offline recovery. Never contacts GitHub, executes code or overwrites."""

import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path

from .common import BackupError, command, sha256
from .delivery import verify_snapshot
from .format import CONTENT_MANIFEST, SHA256, safe_relative


def extract_safely(archive, output, *, maximum_bytes=100 * 1024 ** 3, maximum_members=1_000_000):
    """Accept only canonical snapshot paths, directories and regular non-sparse files."""
    output = Path(output)
    seen = set()
    size = 0
    with tarfile.open(archive, "r|gz") as source:
        for member in source:
            name = member.name.rstrip("/") if member.isdir() else member.name
            path = safe_relative(name)
            if path.parts[0] != "snapshot" or name in seen:
                raise BackupError("archive contains unexpected or duplicate paths")
            seen.add(name)
            if len(seen) > maximum_members or member.size < 0:
                raise BackupError("archive exceeds extraction limits")
            target = output.joinpath(*path.parts)
            if member.isdir():
                if member.size:
                    raise BackupError("invalid archive directory")
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            elif member.isfile() and not member.issparse():
                size += member.size
                if size > maximum_bytes:
                    raise BackupError("archive exceeds extraction byte budget")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with source.extractfile(member) as incoming, target.open("xb") as outgoing:
                    os.chmod(target, 0o600)
                    shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
                if target.stat().st_size != member.size:
                    raise BackupError("archive contains a truncated file")
            else:
                raise BackupError("archive contains a link, device or unsupported member")
    return output / "snapshot"


def verify_contents(root, *, run_id):
    try:
        inventory_path = root / CONTENT_MANIFEST
        if inventory_path.stat().st_size > 128 * 1024 ** 2:
            raise ValueError
        inventory = json.loads(inventory_path.read_text())
        if inventory["schema_version"] != 1 or not isinstance(inventory["files"], list):
            raise ValueError
        expected = set()
        for entry in inventory["files"]:
            name = entry["path"]
            path = safe_relative(name)
            if name == CONTENT_MANIFEST or name in expected:
                raise ValueError
            expected.add(name)
            target = root.joinpath(*path.parts)
            if not SHA256.fullmatch(entry["sha256"]) or type(entry["bytes"]) is not int or entry["bytes"] < 0:
                raise ValueError
            if not target.is_file() or target.stat().st_size != entry["bytes"] or sha256(target) != entry["sha256"]:
                raise ValueError
        actual = {p.relative_to(root).as_posix() for p in root.rglob("*")
                  if p.is_file() and p.relative_to(root).as_posix() != CONTENT_MANIFEST}
        if expected != actual:
            raise ValueError
        manifest_path = root / "manifest.json"
        if manifest_path.stat().st_size > 16 * 1024 ** 2:
            raise ValueError
        manifest = json.loads(manifest_path.read_text())
        if manifest["schema_version"] != 2 or manifest["run_id"] != run_id or type(manifest["complete"]) is not bool:
            raise ValueError
        return manifest
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        raise BackupError("restored payload content verification failed") from None


def restore(directory, identity, output, *, trusted_sha256=None, collector_key=None, allow_partial=False,
            maximum_bytes=100 * 1024 ** 3, maximum_members=1_000_000):
    if type(maximum_bytes) is not int or maximum_bytes < 1 or maximum_members < 1:
        raise BackupError("invalid restore limits")
    receipt = verify_snapshot(directory)
    if collector_key:
        from .signing import verify_file
        verify_file(Path(directory) / "receipt.json", Path(directory) / "receipt.sig.json", collector_key, "collector-receipt")
    if receipt["schema_version"] not in (2, 3):
        raise BackupError("safe restore requires v2/v3; use documented manual v1 recovery")
    ciphertext = Path(directory) / "snapshot.tar.gz.age"
    trusted_target = Path(directory) / "receipt.json" if receipt["schema_version"] == 3 else ciphertext
    if trusted_sha256 is not None and (not SHA256.fullmatch(trusted_sha256) or sha256(trusted_target) != trusted_sha256):
        raise BackupError("ciphertext does not match independently trusted digest")
    if not receipt["complete"] and not allow_partial:
        raise BackupError("partial snapshot requires explicit --allow-partial")
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or any(p.is_symlink() for p in output.parents):
        raise BackupError("restore output must be new and have no symlink ancestors")
    created = False
    try:
        output.mkdir(mode=0o700)
        created = True
        with tempfile.TemporaryDirectory(prefix=".reposafe-decrypt-", dir=output.parent) as raw:
            archive = Path(raw) / "snapshot.tar.gz"
            if receipt["schema_version"] == 3:
                if receipt["compressed_bytes"] > maximum_bytes + maximum_members * 1024:
                    raise BackupError("decrypted archive would exceed restore storage budget")
                with archive.open("xb") as joined:
                    for entry in receipt["files"]:
                        part = Path(raw) / "part"
                        command(["age", "-d", "-i", identity, "-o", part, Path(directory) / entry["name"]])
                        if joined.tell() + part.stat().st_size > receipt["compressed_bytes"]:
                            raise BackupError("decrypted chunks exceed declared archive size")
                        with part.open("rb") as incoming:
                            shutil.copyfileobj(incoming, joined, length=1024 * 1024)
                        part.unlink()
                if archive.stat().st_size != receipt["compressed_bytes"]:
                    raise BackupError("decrypted chunk set is incomplete")
            else:
                command(["age", "-d", "-i", identity, "-o", archive, ciphertext])
            root = extract_safely(archive, output, maximum_bytes=maximum_bytes, maximum_members=maximum_members)
            manifest = verify_contents(root, run_id=receipt["run_id"])
            if manifest["complete"] != receipt["complete"]:
                raise BackupError("inner and outer completion status disagree")
        return manifest
    except (OSError, ValueError, tarfile.TarError):
        if created:
            shutil.rmtree(output)
        raise BackupError("restore failed; output removed") from None
    except BackupError:
        if created:
            shutil.rmtree(output)
        raise
