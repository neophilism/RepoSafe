import argparse
import os
import sys

from .common import BackupError
from .config import load
from .github import GitHub
from .snapshot import capture
from .delivery import deliver_all, delivery_succeeded, verify_snapshot
from .runner import execute
from .restore import restore
from .auth import client_from_environment
from . import security_cli


def main(argv=None):
    parser = argparse.ArgumentParser(description="Encrypted GitHub backups; no secret output")
    parser.add_argument("--config", default="reposafe.toml")
    commands = parser.add_subparsers(dest="action", required=True)
    security_cli.register(commands)
    commands.add_parser("validate", help="validate configuration without network access")
    snapshot = commands.add_parser("snapshot", help="capture and encrypt configured repositories")
    snapshot.add_argument("--output", default="backups")
    run = commands.add_parser("run", help="capture and independently verify each destination")
    run.add_argument("--output", default="backups")
    run.add_argument("--state-dir", default="state")
    collect = commands.add_parser("collect", help="stateful signed ciphertext collection, with no destination credentials")
    collect.add_argument("--output", default="backups")
    collect.add_argument("--state-dir", default="state")
    deliver = commands.add_parser("deliver", help="retry an existing encrypted snapshot")
    deliver.add_argument("directory")
    verify = commands.add_parser("verify", help="verify local ciphertext against its receipt")
    verify.add_argument("directory")
    recovery = commands.add_parser("restore", help="decrypt and verify v2 into a NEW local directory")
    recovery.add_argument("directory")
    recovery.add_argument("--identity", required=True)
    recovery.add_argument("--output", required=True)
    recovery.add_argument("--trusted-sha256")
    recovery.add_argument("--collector-key", help="independently pinned collector public key or rotation ring")
    recovery.add_argument("--allow-partial", action="store_true")
    recovery.add_argument("--maximum-bytes", type=int, default=100 * 1024 ** 3)
    recovery.add_argument("--maximum-members", type=int, default=1_000_000)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        handled = security_cli.dispatch(args)
        if handled is not None:
            return handled
        if args.action == "restore":
            manifest = restore(args.directory, args.identity, args.output,
                               trusted_sha256=args.trusted_sha256, collector_key=args.collector_key, allow_partial=args.allow_partial,
                               maximum_bytes=args.maximum_bytes, maximum_members=args.maximum_members)
            print(f"restored and content verified; complete={manifest['complete']}; provenance={'pinned signature or digest' if args.trusted_sha256 or args.collector_key else 'not independently authenticated'}")
            return 0
        if args.action == "verify":
            verify_snapshot(args.directory)
            print("ciphertext matches receipt; receipt authenticity requires separate trust")
            return 0
        config = load(args.config)
        if args.action == "validate":
            print("configuration valid")
            return 0
        if args.action == "collect":
            from .runner import collect_only
            result = collect_only(config, client_from_environment(config), args.output, args.state_dir)
            print(f"capture complete={result.complete}; repositories={result.repository_count}; missing={result.missing_count}")
            return 0 if result.complete else 1
        if args.action in ("run", "deliver") and not any(d.required for d in config.destinations):
            raise BackupError("at least one required destination must be configured")
        if args.action == "deliver":
            receipt = verify_snapshot(args.directory)
            results = deliver_all(args.directory, config.destinations)
            print(f"destinations verified={sum(r.verified for r in results)}/{len(results)}")
            return 0 if receipt["complete"] and delivery_succeeded(results) else 1
        if args.action == "run":
            result, results, success = execute(config, client_from_environment(config),
                                               args.output, args.state_dir)
            print(f"capture complete={result.complete}; failed={result.failed_count}; coverage missing={result.missing_count}; destinations verified={sum(r.verified for r in results)}/{len(results)}")
            return 0 if success else 1
        result = capture(config, client_from_environment(config), args.output)
        print(f"encrypted snapshot created; repositories={result.repository_count}; failed={result.failed_count}")
        return 0 if result.complete else 1
    except BackupError as error:
        print(f"RepoSafe: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("RepoSafe: local I/O failed; inspect privately on the runner", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
