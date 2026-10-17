"""Read-only retention/cost proposals. This module has no deletion executor."""

import hashlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

from .agents import verify_catalog
from .common import BackupError
from .monitor import event_paths
from .vault import ObjectVault
from .witness import timestamp, verify_event


def retention_report(config, inbox, witness_key, writer_keys, collector_key, *, latest_sequence, latest_sha256,
                     minimum_generations=30, minimum_age_days=90, safety_hours=72, rates=None,
                     daily_bytes=None, audit=None, without_live_audit=False, clock=None):
    if (type(latest_sequence) is not int or latest_sequence < 1 or minimum_generations < 1 or
        minimum_age_days < 1 or safety_hours < 1 or daily_bytes is not None and (type(daily_bytes) is not int or daily_bytes < 0)):
        raise BackupError("invalid retention proposal policy or independent anchor")
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    events, by_sequence = [], {}
    for path in event_paths(inbox):
        event, digest = verify_event(path, witness_key, return_digest=True)
        if event["sequence"] > latest_sequence:
            raise BackupError("retention inputs exceed the independently trusted latest sequence")
        if event["sequence"] in by_sequence:
            raise BackupError("retention input contains duplicate witness sequences")
        by_sequence[event["sequence"]] = (path, event, digest)
    ordered = [by_sequence[n] for n in sorted(by_sequence)]
    if not ordered or ordered[-1][1]["sequence"] != latest_sequence or ordered[-1][2] != latest_sha256:
        raise BackupError("retention evidence does not reach the independent sequence/hash anchor")
    for index, (path, event, digest) in enumerate(ordered):
        if timestamp(event["captured_at"]) > now + timedelta(minutes=5):
            raise BackupError("retention evidence is from a future clock")
        if index and (event["sequence"] != ordered[index - 1][1]["sequence"] + 1 or
                      event["previous_sha256"] != ordered[index - 1][2] or
                      timestamp(event["captured_at"]) <= timestamp(ordered[index - 1][1]["captured_at"])):
            raise BackupError("retention evidence has a missing/forked/rolled-back chain")
    survivors = {event["run_id"] for _, event, _ in ordered[-minimum_generations:]}
    destinations = {d.name: d for d in config.destinations}
    current_required = {d.name for d in config.destinations if d.required}
    objects, vaults = {}, {}
    for path, event, _ in ordered:
        if not current_required <= {item["destination"] for item in event["destinations"] if item["required"]}:
            raise BackupError("retention evidence predates current required-copy policy; review policy migration separately")
        for summary in event["destinations"]:
            name = summary["destination"]
            if name not in destinations or name not in writer_keys:
                raise BackupError("retention catalog destination/key is not independently enrolled")
            destination = destinations[name]
            if destination.kind not in ("s3", "b2"):
                continue
            catalog_path = path.parent / "catalogs" / name / "catalog.json"
            catalog, receipt, raw, _ = verify_catalog(catalog_path, writer_keys[name], collector_key, return_raw=True)
            if (hashlib.sha256(raw).hexdigest() != summary["catalog_sha256"] or
                receipt["run_id"] != event["run_id"] or catalog["receipt_sha256"] != event["receipt_sha256"] or
                catalog["destination"] != name or catalog["evidence"]["bucket"] != destination.bucket):
                raise BackupError("maintenance catalog differs from its independently witnessed contents")
            for record in catalog["evidence"]["objects"]:
                if (not isinstance(record["key"], str) or not record["key"].startswith(f"{destination.prefix}/{receipt['run_id']}/") or
                    type(record["bytes"]) is not int or record["bytes"] < 1 or not record["version_id"] or record["version_id"] == "null"):
                    raise BackupError("invalid maintenance object version record")
                identity = (name, destination.bucket, record["key"], record["version_id"])
                item = objects.setdefault(identity, {"destination": name, "bucket": destination.bucket, **record,
                                                     "references": [], "keep_reasons": []})
                if item["sha256"] != record["sha256"] or item["bytes"] != record["bytes"]:
                    raise BackupError("shared version has contradictory signed contents")
                item["references"].append(event["run_id"])
                if event["run_id"] in survivors:
                    item["keep_reasons"].append("minimum_surviving_generations")
                if now - timestamp(event["captured_at"]) < timedelta(days=minimum_age_days):
                    item["keep_reasons"].append("minimum_age")
    for item in objects.values():
        item["keep_reasons"] = sorted(set(item["keep_reasons"]))
        if item["keep_reasons"]:
            item["decision"] = "keep"
            continue
        if without_live_audit:
            item["decision"] = "blocked_unverified"
            continue
        try:
            if audit:
                live = audit(destinations[item["destination"]], item)
            else:
                if item["destination"] not in vaults:
                    vault = ObjectVault(destinations[item["destination"]], read_only=True)
                    vault.inspect()
                    vaults[item["destination"]] = vault
                live = vaults[item["destination"]].audit_version(item)
            until = timestamp(live["retain_until"])
            if live["mode"] != "COMPLIANCE" or live["legal_hold"] not in ("ON", "OFF"):
                raise BackupError("unknown live lock/hold state")
            item["live_audit"] = live
            if live["legal_hold"] == "ON":
                item["decision"] = "blocked_legal_hold"
            elif until > now - timedelta(hours=safety_hours):
                item["decision"] = "blocked_retention_or_clock_margin"
            else:
                item["decision"] = "eligible_for_separate_review"
        except Exception:
            item["decision"] = "blocked_unverified"
    costs = []
    for name, rate in (rates or {}).items():
        if name not in destinations:
            raise BackupError("cost rate destination is not enrolled")
        try:
            rate = Decimal(str(rate))
            if not rate.is_finite() or rate < 0 or rate > 100000:
                raise ValueError
        except (InvalidOperation, ValueError):
            raise BackupError("storage rates must be explicit nonnegative finite USD/GiB-month values") from None
        known_bytes = sum(item["bytes"] for item in objects.values() if item["destination"] == name)
        forecast = daily_bytes * destinations[name].retention_days if daily_bytes is not None else None
        costs.append({"destination": name, "provided_usd_per_gib_month": str(rate), "known_bytes": known_bytes,
            "known_monthly_storage_usd": str((Decimal(known_bytes) / 1024 ** 3 * rate).quantize(Decimal("0.01"))),
            "full_daily_forecast_bytes": forecast,
            "full_daily_forecast_storage_usd": str((Decimal(forecast) / 1024 ** 3 * rate).quantize(Decimal("0.01"))) if forecast is not None else None})
    return {"schema_version": 1, "kind": "retention-proposal", "read_only": True, "created_at": now.isoformat(),
        "anchor_sequence": latest_sequence, "anchor_sha256": latest_sha256, "minimum_generations": minimum_generations,
        "minimum_age_days": minimum_age_days, "clock_safety_hours": safety_hours,
        "known_generations": len(ordered), "known_versions": len(objects),
        "eligible_versions": sum(item["decision"] == "eligible_for_separate_review" for item in objects.values()),
        "objects": list(objects.values()), "costs": costs,
        "limitations": "catalog-known versions only; no bucket billing inventory; request/read-back/egress/tax/other generations excluded; no deletion executor"}
