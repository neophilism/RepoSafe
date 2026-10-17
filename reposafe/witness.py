"""Independent catalog verification, cloud read-back, monotonic signed witnessing."""

import json
import base64
import hashlib
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .agents import verify_catalog
from .common import BackupError, atomic_json, sha256, write_json
from .runner import run_lock
from .signing import private_public_key, read_regular, sign_file, verify_file
from .vault import ObjectVault


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise BackupError("invalid evidence timestamp") from None


def witness(config, catalogs, writer_keys, collector_key, state_dir, signing_key,
            *, minimum_immutable=1, vault_factory=ObjectVault, clock=None):
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    destinations = {d.name: d for d in config.destinations}
    required = {d.name for d in config.destinations if d.required}
    if not required or minimum_immutable < 0:
        raise BackupError("witness needs required destinations and a valid immutable-copy policy")
    results, receipt, receipt_digest = {}, None, None
    for path in catalogs:
        try:
            hint = json.loads(read_regular(path, 16 * 1024 ** 2))["destination"]
            if hint not in destinations or hint not in writer_keys or hint in results:
                raise ValueError
            catalog, candidate, raw, signature = verify_catalog(path, writer_keys[hint], collector_key, return_raw=True)
            if catalog["destination"] != hint:
                raise ValueError
            if not candidate["complete"]:
                raise BackupError("partial captures cannot become complete witness events")
            if receipt is None:
                receipt, receipt_digest = candidate, catalog["receipt_sha256"]
            elif receipt_digest != catalog["receipt_sha256"] or receipt != candidate:
                raise BackupError("delivery catalogs refer to different snapshot generations")
            if timestamp(catalog["completed_at"]) > now + timedelta(minutes=5):
                raise BackupError("delivery evidence is from a future clock")
            results[hint] = (catalog, raw, signature)
        except (KeyError, ValueError, TypeError):
            raise BackupError("witness needs one valid signed catalog per required destination") from None
    if not required <= set(results) or receipt is None:
        raise BackupError("required destination catalog missing")
    try:
        captured = datetime.strptime(receipt["run_id"][:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        if "captured_at" in receipt:
            precise = timestamp(receipt["captured_at"])
            if precise.strftime("%Y%m%dT%H%M%SZ") != receipt["run_id"][:16]:
                raise BackupError("witness capture time disagrees with run ID")
            captured = precise
    except (ValueError, KeyError):
        raise BackupError("invalid witness snapshot identifier") from None
    if captured > now + timedelta(minutes=5) or now - captured > timedelta(hours=30):
        raise BackupError("witness refuses stale or future snapshot success")
    verified_immutable, summaries = 0, []
    for name, (catalog, raw, signature) in results.items():
        destination, evidence = destinations[name], catalog["evidence"]
        independently_checked = False
        minimum_until = None
        if destination.kind in ("s3", "b2"):
            if not isinstance(evidence, dict) or evidence.get("bucket") != destination.bucket:
                raise BackupError("catalog bucket does not match witness policy")
            vault = vault_factory(destination, read_only=True)
            vault.retention_anchor = captured
            vault.inspect()
            expected = {entry["name"]: entry for entry in receipt["files"]}
            expected["receipt.json"] = {"sha256": receipt_digest}
            expected["receipt.sig.json"] = {"sha256": hashlib.sha256(base64.b64decode(catalog["collector_signature_b64"], validate=True)).hexdigest()}
            seen = set()
            records = evidence.get("objects", [])
            if not isinstance(records, list) or len(records) != len(expected):
                raise BackupError("witness object version inventory is invalid")
            for record in records:
                if not isinstance(record, dict) or not all(k in record for k in ("key", "version_id", "sha256", "bytes")) or not isinstance(record["key"], str):
                    raise BackupError("witness object version record is invalid")
                prefix = f"{destination.prefix}/{receipt['run_id']}/"
                if not record["key"].startswith(prefix):
                    raise BackupError("witness object outside expected prefix")
                filename = record["key"][len(prefix):]
                if filename not in expected or filename in seen:
                    raise BackupError("witness object set contains extra or duplicate entries")
                seen.add(filename)
                if expected[filename] is not None and expected[filename]["sha256"] != record["sha256"]:
                    raise BackupError("witness catalog object hash differs from collector evidence")
                expected_size = expected[filename].get("bytes")
                if type(record["bytes"]) is not int or record["bytes"] < 1 or (expected_size is not None and record["bytes"] != expected_size):
                    raise BackupError("witness catalog object size differs from collector evidence")
                if filename == "receipt.json" and record["bytes"] != len(base64.b64decode(catalog["receipt_b64"], validate=True)):
                    raise BackupError("witness receipt size differs from collector evidence")
                if filename == "receipt.sig.json" and record["bytes"] != len(base64.b64decode(catalog["collector_signature_b64"], validate=True)):
                    raise BackupError("witness signature size differs from collector evidence")
                try:
                    checked = vault.verify_version(record["key"], record["version_id"], record["sha256"], record["bytes"])
                    until = timestamp(checked["retain_until"])
                except BackupError:
                    raise
                except Exception:
                    raise BackupError("independent vault verification failed") from None
                minimum_until = until if minimum_until is None else min(minimum_until, until)
            if seen != set(expected):
                raise BackupError("witness catalog lacks required payload/receipt/signature versions")
            independently_checked = True
            if destination.required:
                verified_immutable += 1
        summaries.append({"destination": name, "required": destination.required, "provider": destination.kind,
                          "catalog_sha256": hashlib.sha256(raw).hexdigest(), "independent_cloud_readback": independently_checked,
                          "minimum_retain_until": minimum_until.isoformat() if minimum_until else None})
    if verified_immutable < minimum_immutable:
        raise BackupError("witness did not verify enough independent immutable destinations")
    with run_lock(state_dir) as root:
        state_path = root / "witness.json"
        try:
            previous = json.loads(read_regular(state_path, 1024 ** 2)) if state_path.exists() else {
                "schema_version": 1, "sequence": 0, "event_sha256": None, "captured_at": None}
            if previous["schema_version"] != 1 or type(previous["sequence"]) is not int:
                raise ValueError
            if previous["captured_at"] and captured <= timestamp(previous["captured_at"]):
                raise BackupError("witness rejects duplicate or rolled-back snapshot generations")
        except (ValueError, KeyError, TypeError):
            raise BackupError("witness state is invalid; preserve independent sequence anchors") from None
        event = {"schema_version": 1, "kind": "witness-event", "sequence": previous["sequence"] + 1,
                 "previous_sha256": previous["event_sha256"], "run_id": receipt["run_id"],
                 "captured_at": captured.isoformat(), "witnessed_at": now.isoformat(),
                 "receipt_sha256": receipt_digest, "complete": True, "destinations": summaries,
                 "independently_verified_immutable_copies": verified_immutable}
        target = root / "events" / f"{event['sequence']:012d}-{receipt['run_id']}"
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Recovery after a crash can adopt only its own matching, already signed event.
        if target.exists():
            verify_file(target / "event.json", target / "event.sig.json", private_public_key(signing_key), "witness-event")
            existing = json.loads(read_regular(target / "event.json", 16 * 1024 ** 2))
            if existing["receipt_sha256"] != receipt_digest or existing["previous_sha256"] != previous["event_sha256"]:
                raise BackupError("existing witness event conflicts with current chain")
        else:
            import tempfile, os
            with tempfile.TemporaryDirectory(prefix=".witness-", dir=target.parent) as pending:
                pending = Path(pending)
                for name, (_, raw, signature) in results.items():
                    directory = pending / "catalogs" / name
                    directory.mkdir(parents=True, mode=0o700)
                    for filename, content in (("catalog.json", raw), ("catalog.sig.json", signature)):
                        with (directory / filename).open("xb") as output:
                            (directory / filename).chmod(0o600)
                            output.write(content)
                            output.flush()
                            os.fsync(output.fileno())
                write_json(pending / "event.json", event)
                sign_file(pending / "event.json", signing_key, pending / "event.sig.json", "witness-event")
                os.rename(pending, target)
        atomic_json(state_path, {"schema_version": 1, "sequence": event["sequence"],
            "event_sha256": sha256(target / "event.json"), "captured_at": captured.isoformat(),
            "event_path": str(target / "event.json")})
        return target / "event.json"


def verify_event(path, pinned_key, *, minimum_sequence=1, previous_sha256=None):
    path = Path(path)
    verify_file(path, path.with_name("event.sig.json"), pinned_key, "witness-event")
    try:
        event = json.loads(read_regular(path, 16 * 1024 ** 2))
        if (event["schema_version"] != 1 or event["kind"] != "witness-event" or
            type(event["sequence"]) is not int or event["sequence"] < minimum_sequence or event["complete"] is not True):
            raise ValueError
        if previous_sha256 is not None and event["previous_sha256"] != previous_sha256:
            raise ValueError
        timestamp(event["captured_at"])
        timestamp(event["witnessed_at"])
        return event
    except (ValueError, KeyError, TypeError):
        raise BackupError("witness event violates sequence/chain policy") from None
