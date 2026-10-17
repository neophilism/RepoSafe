"""Copy ciphertext only; verify bytes; publish the receipt last; never delete."""

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

from .common import BackupError, command, sha256

RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")


def verify_snapshot(directory):
    directory = Path(directory)
    try:
        receipt_path = directory / "receipt.json"
        if directory.is_symlink() or receipt_path.is_symlink() or not receipt_path.is_file() or receipt_path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError
        receipt = json.loads(receipt_path.read_text())
        if receipt["schema_version"] not in (1, 2, 3) or not RUN_ID.fullmatch(receipt["run_id"]):
            raise ValueError
        datetime.strptime(receipt["run_id"][:16], "%Y%m%dT%H%M%SZ")
        if type(receipt["complete"]) is not bool or type(receipt["repositories"]) is not int or receipt["repositories"] < 0:
            raise ValueError
        entries = receipt["files"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 10000:
            raise ValueError
        expected_names = ([f"chunk-{i:06d}.age" for i in range(len(entries))] if receipt["schema_version"] == 3 else ["snapshot.tar.gz.age"])
        if [entry["name"] for entry in entries] != expected_names:
            raise ValueError
        for entry in entries:
            payload = directory / entry["name"]
            if type(entry["bytes"]) is not int or entry["bytes"] < 1:
                raise ValueError
            if payload.is_symlink() or payload.stat().st_size != entry["bytes"] or sha256(payload) != entry["sha256"]:
                raise ValueError
        if receipt["schema_version"] == 3 and (receipt["archive_format"] != "tar.gz" or type(receipt["compressed_bytes"]) is not int or receipt["compressed_bytes"] < 1):
            raise ValueError
        return receipt
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise BackupError("snapshot integrity or receipt validation failed") from None


@dataclass(frozen=True)
class Delivery:
    name: str
    required: bool
    verified: bool
    evidence: dict | None = None


class Rclone:
    def __init__(self, config_file=None, *, runner=command):
        self.config_file = config_file or os.environ.get("RCLONE_CONFIG")
        self.runner = runner

    def deliver(self, directory, destination, run_id):
        target = destination.remote + "/" + run_id
        flags = ["--log-level", "ERROR", "--retries", "3", "--low-level-retries", "5"]
        if self.config_file:
            flags.extend(["--config", self.config_file])
        # Only these explicit filenames can leave the runner; extra local files cannot leak.
        receipt = verify_snapshot(directory)
        for filename in (*[entry["name"] for entry in receipt["files"]], "receipt.json"):
            selection = ["--include", "/" + filename]
            self.runner(["rclone", "copy", directory, target, "--immutable", "--no-update-modtime", *selection, *flags])
            self.runner(["rclone", "check", directory, target, "--one-way", "--download", *selection, *flags])
        return {"provider": "rclone", "objects": receipt["files"], "immutability": "client overwrite guard only"}


def deliver_all(directory, destinations, *, transport=None):
    receipt = verify_snapshot(directory)
    results = []
    for destination in destinations:
        try:
            if transport is not None:
                selected = transport
            elif destination.kind == "rclone":
                selected = Rclone()
            else:
                from .vault import ObjectVault
                selected = ObjectVault(destination)
            evidence = selected.deliver(Path(directory), destination, receipt["run_id"])
            results.append(Delivery(destination.name, destination.required, True, evidence))
        except BackupError:
            # Continue to other providers even after a required provider fails.
            results.append(Delivery(destination.name, destination.required, False))
    return results


def delivery_succeeded(results):
    return bool(results) and any(r.required for r in results) and all(r.verified for r in results if r.required)
