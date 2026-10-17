"""Independent signed-evidence deadline monitor; no success heartbeat trust."""

import json
import os
import re
import shutil
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .common import BackupError, atomic_json
from .github import NoRedirect
from .runner import run_lock
from .signing import read_regular, verify_bytes
from .witness import timestamp, verify_event


@dataclass(frozen=True)
class MonitorPolicy:
    required_destinations: tuple[str, ...]
    minimum_immutable: int = 2
    maximum_age_hours: int = 30
    minimum_retention_hours: int = 24
    maximum_offline_days: int | None = 7
    minimum_free_bytes: int = 128 * 1024 ** 2


def event_paths(inbox):
    inbox = Path(inbox)
    if inbox.is_symlink() or not inbox.is_dir():
        raise BackupError("witness inbox unavailable")
    found = []
    for index, path in enumerate(inbox.iterdir()):
        if index >= 10000:
            raise BackupError("witness inbox exceeds its entry budget")
        if path.is_dir() and not path.is_symlink() and (path / "event.json").exists():
            found.append(path / "event.json")
    return found


def check_event_policy(event, policy, now):
    captured, witnessed = timestamp(event["captured_at"]), timestamp(event["witnessed_at"])
    if max(captured, witnessed) > now + timedelta(minutes=5):
        raise BackupError("future signed evidence")
    if witnessed - captured > timedelta(hours=policy.maximum_age_hours):
        raise BackupError("witness attested a stale capture")
    required = {item["destination"] for item in event["destinations"] if item["required"]}
    if not set(policy.required_destinations) <= required or event["independently_verified_immutable_copies"] < policy.minimum_immutable:
        raise BackupError("signed event does not meet monitor copy policy")
    providers = {item["provider"] for item in event["destinations"] if item["required"] and item["independent_cloud_readback"]}
    if len(providers) < min(2, policy.minimum_immutable):
        raise BackupError("monitor requires independent immutable provider kinds")


def check_offline(path, key, state, policy, now, issues):
    if policy.maximum_offline_days is None:
        return
    if not path or not key:
        issues.append("offline_evidence_missing")
        return
    try:
        raw = read_regular(path, 16 * 1024 ** 2)
        envelope = json.loads(read_regular(Path(path).with_name("copy.sig.json"), 4096))
        digest = verify_bytes(raw, envelope, key, "offline-copy")
        report = json.loads(raw)
        verified = timestamp(report["verified_at"])
        captured = timestamp(report["captured_at"])
        if report["schema_version"] != 1 or report["kind"] != "offline-copy" or report["verified"] is not True or verified > now + timedelta(minutes=5) or captured > verified:
            raise ValueError
        previous = state.get("offline")
        if previous and (verified < timestamp(previous["verified_at"]) or
                         verified == timestamp(previous["verified_at"]) and digest != previous["sha256"]):
            issues.append("offline_evidence_rollback")
            return
        state["offline"] = {"verified_at": verified.isoformat(), "sha256": digest}
        if now - min(verified, captured) > timedelta(days=policy.maximum_offline_days):
            issues.append("offline_copy_stale")
    except (BackupError, OSError, ValueError, TypeError, KeyError, RecursionError):
        issues.append("offline_evidence_invalid")


def monitor(inbox, witness_key, state_dir, policy, *, offline_report=None, offline_key=None, clock=None):
    if (not policy.required_destinations or policy.minimum_immutable < 0 or policy.maximum_age_hours < 1 or
        policy.minimum_retention_hours < 0 or policy.maximum_offline_days is not None and policy.maximum_offline_days < 1):
        raise BackupError("invalid independent monitor policy")
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    issues, sequence, age = [], 0, None
    with run_lock(state_dir) as root:
        state_path = root / "monitor.json"
        try:
            state = json.loads(read_regular(state_path, 16 * 1024 ** 2, private=True)) if state_path.exists() else {
                "schema_version": 1, "sequence": 0, "event_sha256": None, "last_event": None}
            if state["schema_version"] != 1 or type(state["sequence"]) is not int or state["sequence"] < 0:
                raise ValueError
            if state["sequence"] and (not re.fullmatch(r"[a-f0-9]{64}", state["event_sha256"]) or not state["last_event"]):
                raise ValueError
        except (BackupError, OSError, ValueError, TypeError, KeyError, RecursionError):
            return {"schema_version": 1, "healthy": False, "checked_at": now.isoformat(),
                    "sequence": None, "age_hours": None, "issues": ["monitor_state_invalid"]}
        candidates, forks = {}, set()
        try:
            paths = event_paths(inbox)
        except (BackupError, OSError):
            paths = []
            issues.append("witness_inbox_unavailable")
        for path in paths:
            try:
                event, digest = verify_event(path, witness_key, return_digest=True)
                number = event["sequence"]
                if number < state["sequence"]:
                    continue
                if number == state["sequence"]:
                    if digest != state["event_sha256"]:
                        issues.append("witness_sequence_replaced")
                    continue
                if number in candidates and candidates[number][1] != digest:
                    issues.append("witness_sequence_fork")
                    forks.add(number)
                candidates[number] = (event, digest)
            except (BackupError, OSError, ValueError, TypeError, KeyError, RecursionError):
                issues.append("witness_event_invalid")
        for number, (event, digest) in sorted(candidates.items()):
            if number in forks:
                break
            if number != state["sequence"] + 1 or event["previous_sha256"] != state["event_sha256"]:
                issues.append("witness_chain_gap")
                break
            try:
                check_event_policy(event, policy, now)
                if state["last_event"] and timestamp(event["captured_at"]) <= timestamp(state["last_event"]["captured_at"]):
                    raise BackupError("capture timestamp rollback")
            except BackupError:
                issues.append("witness_event_policy_failed")
                break
            state.update(sequence=number, event_sha256=digest, last_event=event)
        event = state["last_event"]
        if event is None:
            issues.append("no_verified_complete_backup")
        else:
            try:
                check_event_policy(event, policy, now)
                age = (now - timestamp(event["captured_at"])).total_seconds() / 3600
                if age > policy.maximum_age_hours:
                    issues.append("backup_stale")
                for destination in event["destinations"]:
                    if destination["required"] and destination["independent_cloud_readback"]:
                        if timestamp(destination["minimum_retain_until"]) < now + timedelta(hours=policy.minimum_retention_hours):
                            issues.append("retention_horizon_short")
            except (BackupError, KeyError, TypeError):
                issues.append("last_backup_policy_failed")
        if shutil.disk_usage(root).free < policy.minimum_free_bytes:
            issues.append("monitor_disk_low")
        check_offline(offline_report, offline_key, state, policy, now, issues)
        atomic_json(state_path, state)
        sequence = state["sequence"]
    return {"schema_version": 1, "healthy": not issues, "checked_at": now.isoformat(), "sequence": sequence,
            "age_hours": round(age, 3) if age is not None else None, "issues": sorted(set(issues))}


def notify(report, url, *, opener=None):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise BackupError("alert endpoint must be operator-configured HTTPS without credentials in userinfo")
    request = urllib.request.Request(url, data=json.dumps(report, sort_keys=True).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "RepoSafe-monitor/1"}, method="POST")
    try:
        with (opener or urllib.request.build_opener(NoRedirect())).open(request, timeout=15) as response:
            if not 200 <= response.status < 300:
                raise ValueError
            response.read(1024)
    except Exception:
        raise BackupError("independent alert delivery failed") from None
