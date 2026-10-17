"""Enrolled removable-media copies with signed read-back evidence; never format."""

import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .common import BackupError, command, sha256, write_json
from .config import FileSource
from .delivery import RUN_ID, transfer_files, verify_snapshot
from .kit import copy_file, file_inventory, verify_files, verify_kit, fsync_tree
from .runner import run_lock
from .signing import read_regular, sign_file, verify_bytes, verify_file
from .sources import FileCollector
from .witness import verify_event


def mount_identity(root):
    root = Path(root).absolute()
    if root.is_symlink() or any(p.is_symlink() for p in root.parents) or not root.is_dir() or not os.path.ismount(root):
        raise BackupError("offline media must be explicitly mounted at a regular enrolled path")
    uuid = command(["findmnt", "--raw", "--noheadings", "--output", "UUID", "--mountpoint", root]).decode().strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", uuid):
        raise BackupError("offline filesystem needs a stable readable UUID")
    return uuid.lower()


def enroll_media(root, media_id, filesystem_uuid, signing_key, *, encrypted_acknowledged=False, identity=mount_identity):
    root = Path(root).absolute()
    if (not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", media_id) or not encrypted_acknowledged or
        not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", filesystem_uuid) or identity(root) != filesystem_uuid.lower()):
        raise BackupError("media enrollment needs the matching filesystem UUID and operator confirmation of encrypted media")
    marker = root / ".reposafe"
    if marker.exists() or marker.is_symlink():
        raise BackupError("media already has enrollment state; never replace it automatically")
    marker.mkdir(mode=0o700)
    try:
        write_json(marker / "media.json", {"schema_version": 1, "kind": "offline-media", "media_id": media_id,
            "filesystem_uuid": filesystem_uuid.lower(), "encrypted_media_operator_acknowledged": True,
            "enrolled_at": datetime.now(timezone.utc).isoformat()})
        sign_file(marker / "media.json", signing_key, marker / "media.sig.json", "offline-media")
    except Exception:
        shutil.rmtree(marker)
        raise


def media_policy(root, pinned_key, *, identity=mount_identity):
    try:
        root = Path(root).absolute()
        actual = identity(root)
        raw = read_regular(root / ".reposafe/media.json", 65536)
        verify_bytes(raw, json.loads(read_regular(root / ".reposafe/media.sig.json", 4096)), pinned_key, "offline-media")
        marker = json.loads(raw)
        if (marker["schema_version"] != 1 or marker["kind"] != "offline-media" or
            marker["encrypted_media_operator_acknowledged"] is not True or marker["filesystem_uuid"] != actual or
            not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", marker["media_id"])):
            raise ValueError
        return marker
    except BackupError:
        raise
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        raise BackupError("offline media identity/enrollment validation failed") from None


def verify_copy(directory, copy_key, collector_key, witness_key, kit_key):
    directory = Path(directory)
    try:
        raw = read_regular(directory / "copy.json", 16 * 1024 ** 2)
        verify_bytes(raw, json.loads(read_regular(directory / "copy.sig.json", 4096)), copy_key, "offline-copy")
        report = json.loads(raw)
        if report["schema_version"] != 1 or report["kind"] != "offline-copy" or report["verified"] is not True:
            raise ValueError
        verify_files(directory, report["files"], excluded=("copy.json", "copy.sig.json"))
        receipt = verify_snapshot(directory / "snapshot")
        digest = verify_file(directory / "snapshot/receipt.json", directory / "snapshot/receipt.sig.json", collector_key, "collector-receipt")
        event, event_digest = verify_event(directory / "evidence/event.json", witness_key, return_digest=True)
        verify_kit(directory / "recovery-kit", kit_key, require_tools=True)
        if (not receipt["complete"] or receipt["run_id"] != report["run_id"] or digest != report["receipt_sha256"] or
            event["receipt_sha256"] != digest or event["run_id"] != receipt["run_id"] or
            event_digest != report["witness_event_sha256"] or event["captured_at"] != report["captured_at"]):
            raise ValueError
        return report
    except BackupError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise BackupError("offline copy verification failed") from None


def export_offline(directory, root, media_key, signing_key, collector_key, event_path, witness_key, kit, kit_key,
                   *, identity=mount_identity, minimum_free_bytes=128 * 1024 ** 2):
    directory, root, kit, event_path = map(Path, (directory, root, kit, event_path))
    marker = media_policy(root, media_key, identity=identity)
    receipt = verify_snapshot(directory)
    digest = verify_file(directory / "receipt.json", directory / "receipt.sig.json", collector_key, "collector-receipt")
    event, event_digest = verify_event(event_path, witness_key, return_digest=True)
    if not receipt["complete"] or event["run_id"] != receipt["run_id"] or event["receipt_sha256"] != digest:
        raise BackupError("offline export requires a complete capture and matching pinned witness event")
    verify_kit(kit, kit_key, require_tools=True)
    from .signing import private_public_key
    with run_lock(root / ".reposafe/state"):
        target = root / "RepoSafe" / receipt["run_id"]
        if target.exists():
            report = verify_copy(target, private_public_key(signing_key), collector_key, witness_key, kit_key)
            if report["receipt_sha256"] != digest or report["media_id"] != marker["media_id"]:
                raise BackupError("existing offline generation disagrees with enrollment")
            return target
        size = sum(entry["bytes"] for entry in receipt["files"]) + sum(e["bytes"] for e in file_inventory(kit)) + 64 * 1024 ** 2
        if shutil.disk_usage(root).free < size + minimum_free_bytes:
            raise BackupError("insufficient free space on enrolled offline media")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.parent.is_symlink():
            raise BackupError("offline generation root cannot be a symlink")
        with tempfile.TemporaryDirectory(prefix=".copy-", dir=target.parent) as raw:
            stage = Path(raw)
            for name in transfer_files(directory, receipt):
                copy_file(directory / name, stage / "snapshot" / name)
            for name in ("event.json", "event.sig.json"):
                copy_file(event_path.with_name(name), stage / "evidence" / name, maximum=16 * 1024 ** 2)
            for item in event["destinations"]:
                source = event_path.parent / "catalogs" / item["destination"]
                if sha256(source / "catalog.json") != item["catalog_sha256"]:
                    raise BackupError("offline catalog differs from its witnessed hash")
                for name in ("catalog.json", "catalog.sig.json"):
                    copy_file(source / name, stage / "evidence/catalogs" / item["destination"] / name, maximum=16 * 1024 ** 2)
            FileCollector(FileSource("recovery-kit", kit.absolute(), maximum_bytes=20 * 1024 ** 3)).collect(stage / "recovery-kit")
            fsync_tree(stage)
            entries = file_inventory(stage)
            # Read every byte back before signing publication; the new generation is atomic.
            verify_files(stage, entries)
            report = {"schema_version": 1, "kind": "offline-copy", "verified": True,
                "media_id": marker["media_id"], "filesystem_uuid": marker["filesystem_uuid"],
                "run_id": receipt["run_id"], "captured_at": event["captured_at"], "receipt_sha256": digest,
                "witness_event_sha256": event_digest, "verified_at": datetime.now(timezone.utc).isoformat(),
                "files": entries, "physical_disconnect": "operator action required; software read-back does not prove disconnection"}
            write_json(stage / "copy.json", report)
            sign_file(stage / "copy.json", signing_key, stage / "copy.sig.json", "offline-copy")
            verify_copy(stage, private_public_key(signing_key), collector_key, witness_key, kit_key)
            if identity(root) != marker["filesystem_uuid"]:
                raise BackupError("offline media identity changed during copy")
            fsync_tree(stage)
            os.rename(stage, target)
            descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return target
