import argparse
import os
import sys

from .common import BackupError
from .config import load
from .github import GitHub
from .snapshot import capture
from .delivery import deliver_all, delivery_succeeded, verify_snapshot


def main(argv=None):
    parser = argparse.ArgumentParser(description="Encrypted GitHub backups; no secret output")
    parser.add_argument("--config", default="reposafe.toml")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("validate", help="validate configuration without network access")
    snapshot = commands.add_parser("snapshot", help="capture and encrypt configured repositories")
    snapshot.add_argument("--output", default="backups")
    run = commands.add_parser("run", help="capture and independently verify each destination")
    run.add_argument("--output", default="backups")
    deliver = commands.add_parser("deliver", help="retry delivery of an existing encrypted snapshot")
    deliver.add_argument("directory")
    verify = commands.add_parser("verify", help="verify local ciphertext against its receipt")
    verify.add_argument("directory")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        config = load(args.config)
        if args.action == "validate":
            print("configuration valid")
            return 0
        if args.action == "verify":
            verify_snapshot(args.directory)
            print("ciphertext matches receipt; receipt authenticity requires separate trust")
            return 0
        if args.action in ("run", "deliver") and not any(d.required for d in config.destinations):
            raise BackupError("at least one required destination must be configured")
        if args.action == "deliver":
            receipt = verify_snapshot(args.directory)
            results = deliver_all(args.directory, config.destinations)
            print(f"destinations verified={sum(r.verified for r in results)}/{len(results)}")
            return 0 if receipt["complete"] and delivery_succeeded(results) else 1
        result = capture(config, GitHub(os.environ.get("GITHUB_BACKUP_TOKEN", "")), args.output)
        print(f"encrypted snapshot created; repositories={result.repository_count}; failed={result.failed_count}")
        if args.action == "run":
            results = deliver_all(result.directory, config.destinations)
            print(f"destinations verified={sum(r.verified for r in results)}/{len(results)}")
            return 0 if result.complete and delivery_succeeded(results) else 1
        return 0 if result.complete else 1
    except BackupError as error:
        print(f"RepoSafe: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
