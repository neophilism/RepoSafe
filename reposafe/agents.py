"""Single-destination delivery with no source credentials, and signed evidence."""

import base64
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .common import BackupError, atomic_json, sha256, write_json
from .config import FileSource
from .delivery import deliver_all, verify_snapshot, receipt_shape
from .runner import run_lock
from .signing import private_public_key, read_regular, sign_file, verify_bytes, verify_file
from .sources import FileCollector


def catalog_receipt(catalog, collector_key):
    try:
        raw = base64.b64decode(catalog["receipt_b64"], validate=True)
        if len(raw) > 8 * 1024 ** 2 or hashlib.sha256(raw).hexdigest() != catalog["receipt_sha256"]:
            raise ValueError
        verify_bytes(raw, catalog["collector_signature"], collector_key, "collector-receipt")
        signature_raw = base64.b64decode(catalog["collector_signature_b64"], validate=True)
        if len(signature_raw) > 4096 or json.loads(signature_raw) != catalog["collector_signature"]:
            raise ValueError
        receipt = json.loads(raw)
        receipt_shape(receipt)
        if receipt["run_id"] != catalog["run_id"] or catalog["schema_version"] != 1 or catalog["verified"] is not True:
            raise ValueError
        return receipt
    except (KeyError, ValueError, TypeError, RecursionError):
        raise BackupError("invalid signed delivery catalog") from None


def deliver_agent(config, directory, destination_name, state_dir, collector_key, writer_key,
                  *, transport=None, maximum_age_hours=48):
    if any(os.environ.get(name) for name in ("GITHUB_BACKUP_TOKEN", "GITHUB_APP_PRIVATE_KEY_FILE")):
        raise BackupError("delivery agent must not hold source credentials")
    selected = [d for d in config.destinations if d.name == destination_name]
    if len(selected) != 1:
        raise BackupError("select exactly one configured delivery destination")
    destination = selected[0]
    with run_lock(state_dir) as state_root:
        state_path = state_root / "agent.json"
        try:
            state = json.loads(read_regular(state_path, 16 * 1024 ** 2)) if state_path.exists() else {"schema_version": 1, "runs": {}}
            if state["schema_version"] != 1 or not isinstance(state["runs"], dict):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise BackupError("invalid delivery agent state") from None
        with tempfile.TemporaryDirectory(prefix="reposafe-agent-", dir=config.work_dir) as raw:
            stage = Path(raw) / "snapshot"
            FileCollector(FileSource("ciphertext-spool", Path(directory).absolute(),
                          maximum_bytes=config.maximum_snapshot_bytes * 2 + 16 * 1024 ** 2),
                          forbidden=(state_root, Path(raw))).collect(stage)
            receipt = verify_snapshot(stage)
            digest = verify_file(stage / "receipt.json", stage / "receipt.sig.json", collector_key, "collector-receipt")
            captured = datetime.strptime(receipt["run_id"][:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            if "captured_at" in receipt:
                from .witness import timestamp
                precise = timestamp(receipt["captured_at"])
                if precise.tzinfo is None or precise.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ") != receipt["run_id"][:16]:
                    raise BackupError("receipt capture time disagrees with run ID")
                captured = precise.astimezone(timezone.utc)
            now = datetime.now(timezone.utc)
            if captured > now + timedelta(minutes=5) or now - captured > timedelta(hours=maximum_age_hours):
                raise BackupError("delivery queue item is stale or from a future clock")
            existing = state["runs"].get(receipt["run_id"])
            final = state_root / "catalogs" / receipt["run_id"]
            if existing and existing["receipt_sha256"] != digest:
                raise BackupError("run ID reused with different signed contents")
            if final.exists():
                verify_file(final / "catalog.json", final / "catalog.sig.json", private_public_key(writer_key), "writer-catalog")
                previous = json.loads(read_regular(final / "catalog.json", 16 * 1024 ** 2))
                if previous["receipt_sha256"] != digest or previous["destination"] != destination.name:
                    raise BackupError("existing agent catalog disagrees with the queue item")
                return final / "catalog.json", receipt["complete"]
            result = deliver_all(stage, (destination,), transport=transport)[0]
            if not result.verified:
                atomic_json(state_path, {**state, "last_failure_at": now.isoformat(), "last_failure_destination": destination.name})
                raise BackupError("destination delivery failed; no success catalog was published")
            catalog = {"schema_version": 1, "destination": destination.name, "run_id": receipt["run_id"],
                "receipt_b64": base64.b64encode((stage / "receipt.json").read_bytes()).decode(),
                "collector_signature": json.loads(read_regular(stage / "receipt.sig.json", 4096)),
                "collector_signature_b64": base64.b64encode(read_regular(stage / "receipt.sig.json", 4096)).decode(),
                "receipt_sha256": digest, "verified": True, "evidence": result.evidence,
                "completed_at": datetime.now(timezone.utc).isoformat()}
            final.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix=".catalog-", dir=final.parent) as pending:
                pending = Path(pending)
                write_json(pending / "catalog.json", catalog)
                sign_file(pending / "catalog.json", writer_key, pending / "catalog.sig.json", "writer-catalog")
                # One same-filesystem directory rename publishes both files atomically.
                os.rename(pending, final)
            state["runs"][receipt["run_id"]] = {"receipt_sha256": digest, "catalog_sha256": sha256(final / "catalog.json")}
            atomic_json(state_path, state)
            return final / "catalog.json", receipt["complete"]


def verify_catalog(path, writer_key, collector_key, *, return_raw=False):
    path = Path(path)
    try:
        raw = read_regular(path, 16 * 1024 ** 2)
        signature = read_regular(path.with_name("catalog.sig.json"), 4096)
        verify_bytes(raw, json.loads(signature), writer_key, "writer-catalog")
        catalog = json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        raise BackupError("invalid writer catalog JSON") from None
    receipt = catalog_receipt(catalog, collector_key)
    return (catalog, receipt, raw, signature) if return_raw else (catalog, receipt)
