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


def dispatch(args):
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
