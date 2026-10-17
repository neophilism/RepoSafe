"""Hash-bound owner acceptance; generated records start with every check pending."""

import json
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .common import BackupError, sha256, write_json
from .format import safe_relative
from .signing import read_regular, verify_bytes
from .witness import timestamp, verify_event

CHECKS = ("reviewed_release_installed", "private_inventory_reconciled", "source_scopes_read_only",
          "all_required_deliveries", "s3_version_retention_and_delete_denial", "b2_version_retention_and_delete_denial",
          "clean_restore_and_application_checks", "external_failure_and_missing_monitor_alerts",
          "next_real_daily_run", "offline_disconnect_and_restore", "independent_key_account_custody", "recurring_costs_accepted")


def template(output):
    value = {"schema_version": 1, "kind": "production-acceptance", "reviewed_commit": None,
        "accepted_at": None, "witness_event": None, "monitor_report": None,
        "checks": {name: {"status": "pending", "evidence": []} for name in CHECKS},
        "meaning": "owner attestation bound to real private evidence; code tests are not production acceptance"}
    write_json(output, value)
    return value


def evidence_file(root, name):
    relative = safe_relative(name)
    path = root.joinpath(*relative.parts)
    if any(p.is_symlink() for p in [path, *path.parents]) or not path.is_file():
        raise BackupError("acceptance evidence must be a regular file in its private evidence directory")
    return path


def verify_acceptance(document, owner_key, witness_key, *, clock=None):
    document = Path(document).absolute()
    root = document.parent
    try:
        raw = read_regular(document, 16 * 1024 ** 2)
        verify_bytes(raw, json.loads(read_regular(document.with_name("acceptance.sig.json"), 4096)), owner_key, "production-acceptance")
        value = json.loads(raw)
        if (value["schema_version"] != 1 or value["kind"] != "production-acceptance" or
            not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", value["reviewed_commit"]) or set(value["checks"]) != set(CHECKS)):
            raise ValueError
        accepted = timestamp(value["accepted_at"])
        now = (clock or (lambda: datetime.now(timezone.utc)))()
        if accepted > now + timedelta(minutes=5):
            raise ValueError
        checked_files, bound = 0, {}
        for name in CHECKS:
            check = value["checks"][name]
            if check["status"] != "accepted" or not isinstance(check["evidence"], list) or not 1 <= len(check["evidence"]) <= 100:
                raise BackupError("production acceptance still has pending/unsubstantiated checks")
            for item in check["evidence"]:
                path = evidence_file(root, item["path"])
                if path.stat().st_size > 128 * 1024 ** 2 or sha256(path) != item["sha256"]:
                    raise BackupError("production acceptance evidence hash mismatch")
                if item["path"] in bound and bound[item["path"]] != item["sha256"]:
                    raise BackupError("production evidence has contradictory hashes")
                bound[item["path"]] = item["sha256"]
                checked_files += 1
        if not {value["witness_event"], value["monitor_report"]} <= set(bound):
            raise BackupError("acceptance must hash-bind its exact witness and monitor evidence")
        event, event_digest = verify_event(evidence_file(root, value["witness_event"]), witness_key, return_digest=True)
        if event_digest != bound[value["witness_event"]] or timestamp(event["witnessed_at"]) > accepted:
            raise BackupError("acceptance witness changed or postdates owner acceptance")
        providers = {item["provider"] for item in event["destinations"] if item["required"] and item["independent_cloud_readback"]}
        required = {item["destination"] for item in event["destinations"] if item["required"]}
        convenience = {item["destination"] for item in event["destinations"] if item["required"] and item["provider"] == "rclone"}
        if event["independently_verified_immutable_copies"] < 2 or not {"s3", "b2"} <= providers or not {"drive", "dropbox"} <= convenience:
            raise BackupError("production acceptance needs Drive/Dropbox and both immutable provider kinds")
        monitor_raw = read_regular(evidence_file(root, value["monitor_report"]), 1024 ** 2)
        if hashlib.sha256(monitor_raw).hexdigest() != bound[value["monitor_report"]]:
            raise BackupError("acceptance monitor report changed")
        monitored = json.loads(monitor_raw)
        if (monitored["healthy"] is not True or monitored["sequence"] < event["sequence"] or
            timestamp(monitored["checked_at"]) < timestamp(event["captured_at"]) or timestamp(monitored["checked_at"]) > accepted):
            raise BackupError("acceptance monitor report is unhealthy or does not cover the witnessed generation")
        return {"schema_version": 1, "kind": "verified-owner-acceptance", "owner_attestation_valid": True,
            "accepted_at": accepted.isoformat(), "reviewed_commit": value["reviewed_commit"], "checks": len(CHECKS),
            "evidence_files": checked_files, "witness_sequence": event["sequence"],
            "scope": "signed historical operator acceptance; current health still requires the independent monitor"}
    except BackupError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise BackupError("production acceptance record is invalid or incomplete") from None
