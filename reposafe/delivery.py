"""Copy ciphertext only; verify bytes; publish the receipt last; never delete."""

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .common import BackupError, command, sha256

RUN_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\Z")


def verify_snapshot(directory):
    directory = Path(directory)
    try:
        receipt_path = directory / "receipt.json"
        if directory.is_symlink() or receipt_path.is_symlink():
            raise ValueError
        receipt = json.loads(receipt_path.read_text())
        if receipt["schema_version"] != 1 or not RUN_ID.fullmatch(receipt["run_id"]):
            raise ValueError
        if type(receipt["complete"]) is not bool or type(receipt["repositories"]) is not int:
            raise ValueError
        if len(receipt["files"]) != 1 or receipt["files"][0]["name"] != "snapshot.tar.gz.age":
            raise ValueError
        entry = receipt["files"][0]
        payload = directory / entry["name"]
        if payload.is_symlink() or payload.stat().st_size != entry["bytes"] or sha256(payload) != entry["sha256"]:
            raise ValueError
        return receipt
    except (OSError, ValueError, TypeError, KeyError):
        raise BackupError("snapshot integrity or receipt validation failed") from None


@dataclass(frozen=True)
class Delivery:
    name: str
    required: bool
    verified: bool


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
        for filename in ("snapshot.tar.gz.age", "receipt.json"):
            selection = ["--include", "/" + filename]
            self.runner(["rclone", "copy", directory, target, "--immutable", "--no-update-modtime", *selection, *flags])
            self.runner(["rclone", "check", directory, target, "--one-way", "--download", *selection, *flags])


def deliver_all(directory, destinations, *, transport=None):
    receipt = verify_snapshot(directory)
    transport = transport or Rclone()
    results = []
    for destination in destinations:
        try:
            transport.deliver(Path(directory), destination, receipt["run_id"])
            results.append(Delivery(destination.name, destination.required, True))
        except BackupError:
            # Continue to other providers even after a required provider fails.
            results.append(Delivery(destination.name, destination.required, False))
    return results


def delivery_succeeded(results):
    return bool(results) and any(r.required for r in results) and all(r.verified for r in results if r.required)
