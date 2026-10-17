"""Operational commands run independently of source collection."""

import json
import os

from .common import BackupError


def register(commands):
    check = commands.add_parser("monitor", help="independently verify freshness, event continuity and copy policy")
    check.add_argument("--inbox", required=True)
    check.add_argument("--witness-key", required=True)
    check.add_argument("--state-dir", required=True)
    check.add_argument("--required-destination", action="append", required=True)
    check.add_argument("--minimum-immutable", type=int, default=2)
    check.add_argument("--maximum-age-hours", type=int, default=30)
    check.add_argument("--minimum-retention-hours", type=int, default=24)
    check.add_argument("--maximum-offline-days", type=int, default=7)
    check.add_argument("--without-offline", action="store_true", help="explicitly waive offline-copy health checks")
    check.add_argument("--offline-report")
    check.add_argument("--offline-key")
    check.add_argument("--notify", action="store_true", help="POST aggregate health to REPOSAFE_ALERT_URL, including failures")
    kit = commands.add_parser("kit-build", help="bundle a clean reviewed source revision, tools, wheels and public roots")
    kit.add_argument("--source-root", required=True)
    kit.add_argument("--revision", required=True)
    kit.add_argument("--output", required=True)
    kit.add_argument("--signing-key", required=True)
    kit.add_argument("--public-root", action="append", required=True, help="name=public-PEM-file")
    kit.add_argument("--tool", action="append", default=[], help="approved-tool-name=regular-file")
    kit.add_argument("--wheel", action="append", default=[])
    verify = commands.add_parser("kit-verify", help="verify recovery kit against an external public root")
    verify.add_argument("directory")
    verify.add_argument("--key", required=True)
    verify.add_argument("--require-tools", action="store_true")
    media = commands.add_parser("media-enroll", help="enroll an already encrypted, mounted removable filesystem; never format")
    media.add_argument("--root", required=True)
    media.add_argument("--media-id", required=True)
    media.add_argument("--filesystem-uuid", required=True)
    media.add_argument("--signing-key", required=True)
    media.add_argument("--encrypted-media-acknowledged", action="store_true", required=True)
    copy = commands.add_parser("offline-export", help="copy a witnessed generation and recovery kit to enrolled media")
    copy.add_argument("directory")
    copy.add_argument("--media-root", required=True)
    copy.add_argument("--media-key", required=True)
    copy.add_argument("--signing-key", required=True)
    copy.add_argument("--collector-key", required=True)
    copy.add_argument("--event", required=True)
    copy.add_argument("--witness-key", required=True)
    copy.add_argument("--kit", required=True)
    copy.add_argument("--kit-key", required=True)
    verify = commands.add_parser("offline-verify", help="read back every signed offline copy/kit file")
    verify.add_argument("directory")
    for name in ("copy", "collector", "witness", "kit"):
        verify.add_argument("--" + name + "-key", required=True)
    plan = commands.add_parser("retention-plan", help="read-only, anchored version/lock/hold/cost proposal; no delete API")
    plan.add_argument("--events", required=True)
    plan.add_argument("--witness-key", required=True)
    plan.add_argument("--writer-key", action="append", required=True)
    plan.add_argument("--collector-key", required=True)
    plan.add_argument("--latest-sequence", type=int, required=True)
    plan.add_argument("--latest-sha256", required=True)
    plan.add_argument("--minimum-generations", type=int, default=30)
    plan.add_argument("--minimum-age-days", type=int, default=90)
    plan.add_argument("--safety-hours", type=int, default=72)
    plan.add_argument("--storage-rate", action="append", default=[], help="destination=USD-per-GiB-month; no assumed prices")
    plan.add_argument("--daily-bytes", type=int)
    plan.add_argument("--without-live-audit", action="store_true", help="cost/keep-only report; no eligible versions")
    plan.add_argument("--output", required=True)


def dispatch(args):
    from .security_cli import mappings
    if args.action == "kit-build":
        from .kit import build_kit
        manifest = build_kit(args.source_root, args.revision, args.output, args.signing_key,
            mappings(args.public_root), tools=mappings(args.tool), wheels=args.wheel)
        print(f"signed recovery kit built; tool/dependency files present={manifest['ready_for_drill']}; clean-machine drill still required")
        return 0
    if args.action == "kit-verify":
        from .kit import verify_kit
        verify_kit(args.directory, args.key, require_tools=args.require_tools)
        print("recovery-kit signature and all file bytes verified")
        return 0
    if args.action == "media-enroll":
        from .offline import enroll_media
        enroll_media(args.root, args.media_id, args.filesystem_uuid, args.signing_key,
                     encrypted_acknowledged=args.encrypted_media_acknowledged)
        print("mounted encrypted-media enrollment signed; no disk formatting performed")
        return 0
    if args.action == "offline-export":
        from .offline import export_offline
        export_offline(args.directory, args.media_root, args.media_key, args.signing_key, args.collector_key,
                       args.event, args.witness_key, args.kit, args.kit_key)
        print("offline generation and recovery kit read back and signed; unmount and disconnect media")
        return 0
    if args.action == "offline-verify":
        from .offline import verify_copy
        verify_copy(args.directory, args.copy_key, args.collector_key, args.witness_key, args.kit_key)
        print("offline copy, witness, ciphertexts and recovery kit verified")
        return 0
    if args.action == "retention-plan":
        from .config import load
        from .common import write_json
        from .retention import retention_report
        report = retention_report(load(args.config), args.events, args.witness_key, mappings(args.writer_key), args.collector_key,
            latest_sequence=args.latest_sequence, latest_sha256=args.latest_sha256, minimum_generations=args.minimum_generations,
            minimum_age_days=args.minimum_age_days, safety_hours=args.safety_hours, rates=mappings(args.storage_rate),
            daily_bytes=args.daily_bytes, without_live_audit=args.without_live_audit)
        write_json(args.output, report)
        print(f"read-only retention proposal written; known versions={report['known_versions']}; eligible for separate review={report['eligible_versions']}")
        return 0
    if args.action == "monitor":
        from .monitor import MonitorPolicy, monitor, notify
        policy = MonitorPolicy(tuple(args.required_destination), args.minimum_immutable,
            args.maximum_age_hours, args.minimum_retention_hours, None if args.without_offline else args.maximum_offline_days)
        report = monitor(args.inbox, args.witness_key, args.state_dir, policy,
                         offline_report=args.offline_report, offline_key=args.offline_key)
        if args.notify:
            try:
                url = os.environ.get("REPOSAFE_ALERT_URL")
                if not url:
                    raise BackupError("monitor alert endpoint not configured")
                notify(report, url)
            except BackupError:
                report["healthy"] = False
                report["issues"].append("alert_delivery_failed")
        print(json.dumps(report, sort_keys=True))
        return 0 if report["healthy"] else 1
    return None
